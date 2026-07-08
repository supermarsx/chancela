//! The fail-closed RBAC **enforcement gate** (t64-E3) — the access-control layer every sensitive
//! endpoint passes through.
//!
//! [`require_permission`] resolves the acting principal's effective scoped authority (via the frozen
//! E2 seam [`effective_permissions_for_actor`]) and checks it against a `(permission, scope)` pair
//! with [`chancela_authz::has_permission`], building the book→entity relation ([`BookScope`]) from
//! `state.books` at check time. A missing permission is a **403** ([`ApiError::Forbidden`]) — honest,
//! generic, and non-enumerating (it never reveals whether the addressed resource exists).
//!
//! ## Scope resolution (plan §3.3)
//!
//! The handler resolves the **target scope** from the request before the check:
//! - entity ops → `Entity(id)`; book ops → `Book(id)` (its entity is resolved via [`BookScope`]);
//! - act / document / signature ops → the act's owning `Book` ([`scope_of_act`], with a `Global`
//!   fallback for an unknown act so a missing act is indistinguishable from one in an unseen scope);
//! - ledger-recovery / data / settings / reference / users / roles / delegations → `Global`.
//!
//! ## 401 vs 403 reconciliation
//!
//! - **401** — no / invalid / expired session (the [`CurrentActor`] extractor; unchanged since t41).
//! - **403** — a valid session that (a) no longer names an active user ([`resolve_principal_id`]),
//!   (b) lacks the permission at the target scope (here), or (c) fails the t51 cross-user credential
//!   proof. All three render as [`ApiError::Forbidden`] with a generic message, so a permission
//!   failure never leaks resource existence differently than a not-found (a caller who *does* clear
//!   the check then receives the handler's own honest `404`).
//!
//! ## Principal-source-agnostic
//!
//! [`require_permission_with`] takes an already-resolved [`ScopedPermissionSet`], not a session, so
//! t65's api-key principals compose against the exact same gate. [`require_permission`] is the
//! session-actor convenience over it.

use std::collections::HashMap;

use time::OffsetDateTime;

use chancela_authz::{
    BookId as AuthzBookId, EntityId as AuthzEntityId, Permission, Scope, ScopedPermissionSet,
    has_permission,
};
use chancela_core::{ActId, BookId, EntityId};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;
use crate::roles::effective_permissions_for_actor;

/// The single, honest, generic refusal for a missing permission. It never names the permission, the
/// scope, or the resource — a `403` here is indistinguishable across "you lack this verb", "you lack
/// it at this scope", and "this resource is outside your scope", so it is a non-enumerating oracle.
pub(crate) const FORBIDDEN: &str = "sem permissão para esta operação neste âmbito";

fn forbidden() -> ApiError {
    ApiError::Forbidden(FORBIDDEN.to_owned())
}

/// Snapshot the live book→entity relation from `state.books` for [`BookScope`] resolution. Taken at
/// check time (a brief read lock, released before the check runs), so a scoped grant is evaluated
/// against the current ownership graph. An unknown book resolves to `None` → covered only by a
/// `Global` grant (fail-closed).
async fn book_relation(state: &AppState) -> HashMap<AuthzBookId, AuthzEntityId> {
    let books = state.books.read().await;
    books
        .values()
        .map(|b| (AuthzBookId(b.id.0), AuthzEntityId(b.entity_id.0)))
        .collect()
}

/// **Core gate (principal-source-agnostic).** Does `eff` satisfy `perm` at `scope`, given the live
/// book→entity relation? `403` if not. t65's api-key principals call this with the api-key's
/// resolved [`ScopedPermissionSet`]; the session path uses [`require_permission`].
pub async fn require_permission_with(
    state: &AppState,
    eff: &ScopedPermissionSet,
    perm: Permission,
    scope: Scope,
) -> Result<(), ApiError> {
    let relation = book_relation(state).await;
    let books = move |b: AuthzBookId| relation.get(&b).copied();
    if has_permission(eff, perm, scope, &books) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// **The gate.** Resolve the session actor's effective permissions and require `perm` at `scope`.
///
/// `401` if no session (already enforced by the [`CurrentActor`] extractor before the handler runs),
/// `403` if the session no longer names an active user or the permission is missing at `scope`.
/// Fail-closed: any resolution failure denies.
pub async fn require_permission(
    state: &AppState,
    actor: &CurrentActor,
    perm: Permission,
    scope: Scope,
) -> Result<(), ApiError> {
    authorizer(state, actor).await?.require(perm, scope)
}

/// A resolved principal's authority plus the book→entity relation, snapshotted once so a handler can
/// run **many** checks (notably the per-row list filtering of note²) without re-resolving the stores
/// or re-locking `state.books` for each row.
pub struct Authorizer {
    eff: ScopedPermissionSet,
    relation: HashMap<AuthzBookId, AuthzEntityId>,
}

impl Authorizer {
    /// Does the principal hold `perm` covering `scope`?
    #[must_use]
    pub fn permits(&self, perm: Permission, scope: Scope) -> bool {
        let books = |b: AuthzBookId| self.relation.get(&b).copied();
        has_permission(&self.eff, perm, scope, &books)
    }

    /// Require `perm` at `scope`, `403` otherwise.
    pub fn require(&self, perm: Permission, scope: Scope) -> Result<(), ApiError> {
        if self.permits(perm, scope) {
            Ok(())
        } else {
            Err(forbidden())
        }
    }
}

/// Resolve the session actor into an [`Authorizer`] (its effective authority + the live book→entity
/// relation). `401` without a session, `403` if the session names no active user. Used by the list
/// endpoints for per-row filtering (note²) and available to any handler running several checks.
pub async fn authorizer(state: &AppState, actor: &CurrentActor) -> Result<Authorizer, ApiError> {
    let now = OffsetDateTime::now_utc();
    let (_principal, eff) = effective_permissions_for_actor(state, actor, now).await?;
    let relation = book_relation(state).await;
    Ok(Authorizer { eff, relation })
}

/// The target [`Scope`] for an **entity** operation.
#[must_use]
pub fn scope_of_entity(id: EntityId) -> Scope {
    Scope::Entity(AuthzEntityId(id.0))
}

/// The target [`Scope`] for a **book** operation. An unknown book id is still `Book(id)` — the
/// [`BookScope`] relation returns `None` for it, so it is covered only by a `Global` grant, which
/// keeps a missing book non-enumerating (a `Global` holder proceeds and the handler returns its own
/// `404`; a scoped holder gets `403`).
#[must_use]
pub fn scope_of_book(id: BookId) -> Scope {
    Scope::Book(AuthzBookId(id.0))
}

/// The target [`Scope`] for an operation on an **act**: the act's owning book, resolved from state.
///
/// When the act is unknown the scope falls back to `Global` (there is no book to name). This keeps a
/// missing act indistinguishable from one in a scope the caller cannot see: a caller lacking the
/// verb globally gets `403` either way, while a caller who holds it globally proceeds and receives
/// the handler's own honest `404`.
pub async fn scope_of_act(state: &AppState, act: ActId) -> Scope {
    let acts = state.acts.read().await;
    match acts.get(&act) {
        Some(a) => Scope::Book(AuthzBookId(a.book_id.0)),
        None => Scope::Global,
    }
}

// =================================================================================================
// Fail-closed route classification + the router-walk coverage test (plan §3.3 / E8 guard, landed
// early here so no sensitive endpoint can ship ungated by omission).
// =================================================================================================

/// How a router path is access-controlled. The [`ROUTE_CLASSIFICATION`] table records one of these
/// for **every** path the router serves; the [`tests::router_walk_every_route_is_classified`] walk
/// fails if a `.route(...)` appears in `lib.rs` without a matching entry, so adding a new sensitive
/// endpoint without gating it breaks the build. Test-only: this is the E8 coverage guard's fixture,
/// not runtime state (the gate itself is `require_permission`, wired per handler).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteClass {
    /// Unauthenticated by design: health, the session login/inspect/roster, and the `/v1` +
    /// `/health` catch-all 404s. NOT gated.
    Exempt,
    /// Any valid session, no specific permission: the permissions/roles/catalog introspection the
    /// web needs to gate its own UI.
    Session,
    /// Gated by `require_permission` (a specific verb at a per-endpoint-resolved scope), possibly
    /// composed with step-up re-auth and/or the t51 cross-user proof.
    Gated,
}

/// **FROZEN (plan §3.3).** Every router path → its access-control class. This is the authoritative
/// fail-closed map: the coverage test asserts the router's actual `.route(...)` set equals this
/// table's key set, so a new route is a compile-green-but-test-red failure until it is classified
/// (and, if `Gated`, wired to `require_permission`).
#[cfg(test)]
pub(crate) const ROUTE_CLASSIFICATION: &[(&str, RouteClass)] = &[
    // --- Exempt (unauthenticated) ---------------------------------------------------------------
    ("/health", RouteClass::Exempt),
    ("/v1/session", RouteClass::Exempt),
    ("/v1/session/roster", RouteClass::Exempt),
    ("/v1", RouteClass::Exempt),
    ("/v1/{*rest}", RouteClass::Exempt),
    ("/health/{*rest}", RouteClass::Exempt),
    // --- Any valid session (introspection for the web permissions context) ----------------------
    ("/v1/session/permissions", RouteClass::Session),
    // --- Entities -------------------------------------------------------------------------------
    ("/v1/entities", RouteClass::Gated), // GET entity.read@Global · POST entity.create@Global
    ("/v1/entities/{id}", RouteClass::Gated), // GET entity.read@Entity · PATCH entity.update@Entity
    ("/v1/entities/import-from-registry", RouteClass::Gated), // POST entity.create@Global
    ("/v1/entities/{id}/registry", RouteClass::Gated), // GET entity.read@Entity
    ("/v1/entities/{id}/registry/import", RouteClass::Gated), // POST entity.registry.import@Entity
    ("/v1/entities/{id}/chronology", RouteClass::Gated), // GET entity.read@Entity
    ("/v1/registry/lookup", RouteClass::Gated), // POST entity.read@Global
    // --- Books ----------------------------------------------------------------------------------
    ("/v1/books", RouteClass::Gated), // GET book.read@Global · POST book.open@Entity
    ("/v1/books/{id}", RouteClass::Gated), // GET book.read@Book
    ("/v1/books/{id}/close", RouteClass::Gated), // POST book.close@Book
    ("/v1/books/{id}/acts", RouteClass::Gated), // GET book.read@Book
    ("/v1/books/{id}/export", RouteClass::Gated), // POST book.export@Book
    ("/v1/books/import", RouteClass::Gated), // POST book.import@Global
    ("/v1/books/{id}/start-over", RouteClass::Gated), // POST book.start_over@Book + step-up
    // --- Acts -----------------------------------------------------------------------------------
    ("/v1/acts", RouteClass::Gated), // POST act.draft@Book(body.book_id)
    ("/v1/acts/{id}", RouteClass::Gated), // GET act.read@Book · PATCH act.edit@Book
    ("/v1/acts/{id}/advance", RouteClass::Gated), // POST act.advance@Book
    ("/v1/acts/{id}/compliance", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/seal", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/archive", RouteClass::Gated), // POST act.archive@Book
    ("/v1/acts/{id}/document/preview", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/document/generate", RouteClass::Gated), // POST document.generate@Book
    ("/v1/acts/{id}/document", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/document/bundle", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/signature/cmd/initiate", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/cmd/confirm", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/signature", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/document/signed", RouteClass::Gated), // GET act.read@Book
    ("/v1/templates", RouteClass::Gated), // GET act.read@Global
    // --- Ledger ---------------------------------------------------------------------------------
    ("/v1/ledger/events", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/verify", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/integrity", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/attestations/{seq}", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/recovery/reanchor", RouteClass::Gated), // POST ledger.recover@Global + step-up
    ("/v1/ledger/recovery/restore", RouteClass::Gated), // POST ledger.recover@Global + step-up
    // --- Data management ------------------------------------------------------------------------
    ("/v1/data/reset", RouteClass::Gated), // POST data.wipe@Global + step-up
    ("/v1/data/start-over", RouteClass::Gated), // POST data.start_over@Global + step-up
    ("/v1/backup", RouteClass::Gated),     // POST data.backup@Global
    ("/v1/dashboard", RouteClass::Gated),  // GET act.read@Global
    // --- Settings -------------------------------------------------------------------------------
    ("/v1/settings", RouteClass::Gated), // GET settings.read@Global · PUT settings.manage@Global
    // --- Reference: CAE + law -------------------------------------------------------------------
    ("/v1/cae", RouteClass::Gated),          // GET cae.read@Global
    ("/v1/cae/refresh", RouteClass::Gated),  // POST cae.refresh@Global
    ("/v1/cae/updates", RouteClass::Gated),  // GET cae.read@Global
    ("/v1/cae/sections", RouteClass::Gated), // GET cae.read@Global
    ("/v1/cae/{code}", RouteClass::Gated),   // GET cae.read@Global
    ("/v1/cae/{code}/children", RouteClass::Gated), // GET cae.read@Global
    ("/v1/law", RouteClass::Gated),          // GET law.read@Global
    ("/v1/law/{id}/fetch", RouteClass::Gated), // POST law.manage@Global
    ("/v1/law/{id}/pdf", RouteClass::Gated), // GET law.read@Global · DELETE law.manage@Global
    // --- Users ----------------------------------------------------------------------------------
    ("/v1/users", RouteClass::Gated), // GET user.read@Global · POST user.manage@Global (bootstrap exempt)
    ("/v1/users/{id}", RouteClass::Gated), // GET user.read@Global · PATCH user.manage@Global
    ("/v1/users/{id}/secret", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
    ("/v1/users/{id}/attestation-key", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
    ("/v1/users/{id}/recovery", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
];

/// Classify a router path against [`ROUTE_CLASSIFICATION`].
#[cfg(test)]
fn classify(path: &str) -> Option<RouteClass> {
    ROUTE_CLASSIFICATION
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract every `.route("<path>", ...)` path literal from the router source. A tiny hand parser
    /// (no regex dep): find each `.route(`, skip to the next `"`, read to the closing `"`.
    fn router_paths_from_source() -> Vec<String> {
        const SRC: &str = include_str!("lib.rs");
        // Only walk the `router()` builder, not the whole file (the module has test routers too).
        let start = SRC
            .find("pub fn router(")
            .expect("router() must exist in lib.rs");
        let body = &SRC[start..];
        let end = body.find("\n}\n").map(|e| e + start).unwrap_or(SRC.len());
        let region = &SRC[start..end];

        let mut paths = Vec::new();
        let mut rest = region;
        while let Some(idx) = rest.find(".route(") {
            rest = &rest[idx + ".route(".len()..];
            // Skip whitespace / newlines to the opening quote.
            let Some(q) = rest.find('"') else { break };
            let after = &rest[q + 1..];
            let Some(close) = after.find('"') else { break };
            paths.push(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        paths
    }

    /// **Fail-closed router walk (E8 guard).** Every route the router serves must be classified in
    /// [`ROUTE_CLASSIFICATION`]. A new `.route(...)` added without a classification fails here — so a
    /// sensitive endpoint cannot ship ungated by omission — and a stale classification entry (a route
    /// removed from the router) fails too, keeping the frozen §3.3 map honest.
    #[test]
    fn router_walk_every_route_is_classified() {
        let router_paths = router_paths_from_source();
        assert!(
            router_paths.len() >= 40,
            "router walk found only {} paths — the parser likely broke",
            router_paths.len()
        );

        // (a) Every router path is classified.
        for path in &router_paths {
            assert!(
                classify(path).is_some(),
                "UNGATED ROUTE: {path:?} is served by router() but absent from \
                 ROUTE_CLASSIFICATION — classify it (Exempt/Session/Gated) and, if sensitive, wire \
                 require_permission into its handler(s)"
            );
        }

        // (b) No stale classification: every table path is actually served.
        for (path, _) in ROUTE_CLASSIFICATION {
            assert!(
                router_paths.iter().any(|p| p == path),
                "STALE CLASSIFICATION: {path:?} is in ROUTE_CLASSIFICATION but no longer served by \
                 router()"
            );
        }
    }

    /// The three unauthenticated endpoints stay exempt (bootstrap-no-lockout: the roster + session
    /// login must be reachable signed-out, and health is liveness).
    #[test]
    fn the_exempt_set_is_exactly_the_unauth_surface() {
        assert_eq!(classify("/health"), Some(RouteClass::Exempt));
        assert_eq!(classify("/v1/session"), Some(RouteClass::Exempt));
        assert_eq!(classify("/v1/session/roster"), Some(RouteClass::Exempt));
        // Sensitive endpoints are never exempt.
        assert_eq!(classify("/v1/data/reset"), Some(RouteClass::Gated));
        assert_eq!(classify("/v1/entities"), Some(RouteClass::Gated));
    }
}
