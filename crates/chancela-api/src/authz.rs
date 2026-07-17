//! The fail-closed RBAC **enforcement gate** (t64-E3) — the access-control layer every sensitive
//! endpoint passes through.
//!
//! [`require_permission`] resolves the acting principal's effective scoped authority (via the frozen
//! E2 seam [`effective_permissions_for_actor`]) and checks it against a `(permission, scope)` pair
//! with [`chancela_authz::has_permission`], building the live resource-parent graph
//! ([`BookScope`]) from application state at check time. A missing permission is a **403**
//! ([`ApiError::Forbidden`]) — honest,
//! generic, and non-enumerating (it never reveals whether the addressed resource exists).
//!
//! ## Scope resolution (plan §3.3)
//!
//! The handler resolves the **target scope** from the request before the check:
//! - entity ops → `Entity(id)`; book ops → `Book(id)` (its entity is resolved via [`BookScope`]);
//! - act / document / signature ops → first-class `Act(id)` ([`scope_of_act`]); its live Act→Book
//!   parent lets existing Book/Entity/Tenant grants narrow to it, while unknown acts fail closed;
//! - shared-library ops → first-class `TemplateLibrary(id)` with a live Tenant parent;
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
    ActId as AuthzActId, ArchiveId as AuthzArchiveId, BookId as AuthzBookId, BookScope,
    EntityId as AuthzEntityId, IntegrationId as AuthzIntegrationId, Permission,
    RepositoryId as AuthzRepositoryId, Role, Scope, ScopedPermissionSet,
    TemplateLibraryId as AuthzTemplateLibraryId, TenantId as AuthzTenantId, has_permission,
};
use chancela_core::{ActId, BookId, EntityId, TemplateLibraryId};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;
use crate::roles::effective_permissions_for_actor;
use crate::users::UserId;

/// The single, honest, generic refusal for a missing permission. It never names the permission, the
/// scope, or the resource — a `403` here is indistinguishable across "you lack this verb", "you lack
/// it at this scope", and "this resource is outside your scope", so it is a non-enumerating oracle.
pub(crate) const FORBIDDEN: &str = "sem permissão para esta operação neste âmbito";

pub(crate) fn forbidden() -> ApiError {
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

/// Snapshot the live **entity→tenant** relation from `state.entities` (wp26 tenancy). Each entity
/// carries its own `tenant_id` (defaulting to the singleton default tenant for pre-tenancy data), so
/// this is the authoritative feed for the `Scope::Tenant` narrowing level. Taken at check time (a
/// brief read lock). An entity with no row resolves to `None` → covered by no `Tenant` grant
/// (fail-closed). In a single-tenant deployment every entity maps to the one default tenant, so a
/// `Tenant` grant behaves exactly like `Global`-over-that-tenant and nothing else changes.
async fn tenant_relation(state: &AppState) -> HashMap<AuthzEntityId, AuthzTenantId> {
    let entities = state.entities.read().await;
    entities
        .values()
        .map(|e| (AuthzEntityId(e.id.0), AuthzTenantId(e.tenant_id.0)))
        .collect()
}

/// Snapshot the live act→book relation. Unknown acts have no parent and therefore cannot be reached
/// by a Book/Entity/Tenant grant; Global or an exact Act grant is still evaluated normally.
async fn act_relation(state: &AppState) -> HashMap<AuthzActId, AuthzBookId> {
    let acts = state.acts.read().await;
    acts.values()
        .map(|act| (AuthzActId(act.id.0), AuthzBookId(act.book_id.0)))
        .collect()
}

/// Snapshot the live template-library→tenant relation (DAT-03/WFL-32). A group is a convenience
/// aggregate, not an authorization scope, so shared libraries narrow directly from their tenant.
async fn template_library_relation(
    state: &AppState,
) -> HashMap<AuthzTemplateLibraryId, AuthzTenantId> {
    let libraries = state.group_template_libraries.read().await;
    libraries
        .values()
        .map(|library| {
            (
                AuthzTemplateLibraryId(library.id.0),
                AuthzTenantId(library.tenant_id.0),
            )
        })
        .collect()
}

/// Snapshot the ZK repository→tenant and immutable archive→repository graph from the same durable
/// index projection. Reading both under one lock prevents a permission decision from observing an
/// archive without its repository parent during index replacement.
async fn repository_archive_relations(
    state: &AppState,
) -> (
    HashMap<AuthzRepositoryId, AuthzTenantId>,
    HashMap<AuthzArchiveId, AuthzRepositoryId>,
) {
    let store = state.zk_repositories.read().await;
    let mut repositories: HashMap<AuthzRepositoryId, AuthzTenantId> = store
        .repository_parents()
        .into_iter()
        .map(|(repository, tenant)| (AuthzRepositoryId(repository), AuthzTenantId(tenant)))
        .collect();
    let archives = store
        .archive_parents()
        .into_iter()
        .map(|(archive, repository)| (AuthzArchiveId(archive), AuthzRepositoryId(repository)))
        .collect();
    drop(store);
    let targets = state.connector_targets.read().await;
    let (_, connector_repositories) = crate::connector_jobs::scope_parents(&targets);
    for (repository, tenant) in connector_repositories {
        match repositories.get(&repository) {
            Some(existing) if *existing != tenant => {
                // A UUID collision across authoritative stores is ambiguous. Remove the relation so
                // narrow authorization fails closed instead of selecting either tenant.
                repositories.remove(&repository);
            }
            _ => {
                repositories.insert(repository, tenant);
            }
        }
    }
    (repositories, archives)
}

async fn integration_relation(state: &AppState) -> HashMap<AuthzIntegrationId, AuthzTenantId> {
    let targets = state.connector_targets.read().await;
    crate::connector_jobs::scope_parents(&targets).0
}

/// A point-in-time snapshot of every authoritative parent relation currently represented by the
/// API stores. This is deliberately shared by request authorization, delegation validation, and
/// API-key attenuation: using one graph prevents those security boundaries from disagreeing about
/// whether a narrow scope is contained by a wider one.
pub(crate) struct ScopeRelations {
    books: HashMap<AuthzBookId, AuthzEntityId>,
    tenants: HashMap<AuthzEntityId, AuthzTenantId>,
    acts: HashMap<AuthzActId, AuthzBookId>,
    template_libraries: HashMap<AuthzTemplateLibraryId, AuthzTenantId>,
    integrations: HashMap<AuthzIntegrationId, AuthzTenantId>,
    repositories: HashMap<AuthzRepositoryId, AuthzTenantId>,
    archives: HashMap<AuthzArchiveId, AuthzRepositoryId>,
}

impl BookScope for ScopeRelations {
    fn entity_of(&self, book: AuthzBookId) -> Option<AuthzEntityId> {
        self.books.get(&book).copied()
    }
    fn tenant_of(&self, entity: AuthzEntityId) -> Option<AuthzTenantId> {
        self.tenants.get(&entity).copied()
    }
    fn book_of_act(&self, act: AuthzActId) -> Option<AuthzBookId> {
        self.acts.get(&act).copied()
    }
    fn parent_of_template_library(&self, library: AuthzTemplateLibraryId) -> Option<Scope> {
        self.template_libraries
            .get(&library)
            .copied()
            .map(Scope::Tenant)
    }
    fn parent_of_integration(&self, integration: AuthzIntegrationId) -> Option<Scope> {
        self.integrations
            .get(&integration)
            .copied()
            .map(Scope::Tenant)
    }
    fn parent_of_repository(&self, repository: AuthzRepositoryId) -> Option<Scope> {
        self.repositories
            .get(&repository)
            .copied()
            .map(Scope::Tenant)
    }
    fn parent_of_archive(&self, archive: AuthzArchiveId) -> Option<Scope> {
        self.archives.get(&archive).copied().map(Scope::Repository)
    }
}

/// Snapshot the complete live scope graph without retaining any store locks. Callers that perform
/// several checks should build this once and reuse it for the duration of their decision.
pub(crate) async fn scope_relations(state: &AppState) -> ScopeRelations {
    let (repositories, archives) = repository_archive_relations(state).await;
    ScopeRelations {
        books: book_relation(state).await,
        tenants: tenant_relation(state).await,
        acts: act_relation(state).await,
        template_libraries: template_library_relation(state).await,
        integrations: integration_relation(state).await,
        repositories,
        archives,
    }
}

/// **Core gate (principal-source-agnostic).** Does `eff` satisfy `perm` at `scope`, given the live
/// authoritative resource-parent graph? `403` if not. t65's api-key principals call this with the api-key's
/// resolved [`ScopedPermissionSet`]; the session path uses [`require_permission`].
pub async fn require_permission_with(
    state: &AppState,
    eff: &ScopedPermissionSet,
    perm: Permission,
    scope: Scope,
) -> Result<(), ApiError> {
    let relations = scope_relations(state).await;
    if has_permission(eff, perm, scope, &relations) {
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

/// A resolved principal's authority plus the resource-parent graph, snapshotted once so a handler can
/// run **many** checks (notably the per-row list filtering of note²) without re-resolving the stores
/// or re-locking `state.books` for each row.
pub struct Authorizer {
    principal: Option<UserId>,
    eff: ScopedPermissionSet,
    relations: ScopeRelations,
}

impl Authorizer {
    /// Borrow the exact live relation snapshot used for every check in this authorization decision.
    fn rel(&self) -> &ScopeRelations {
        &self.relations
    }
}

impl Authorizer {
    /// The resolved acting session principal. API-key principals are intentionally non-interactive:
    /// they can pass ordinary permission gates but cannot stand in for a user on self-service or
    /// session-only flows.
    pub fn principal(&self) -> Result<UserId, ApiError> {
        self.principal.ok_or_else(|| {
            ApiError::Forbidden("chave API não abre uma sessão interativa".to_owned())
        })
    }

    /// Does the principal hold `perm` covering `scope`?
    #[must_use]
    pub fn permits(&self, perm: Permission, scope: Scope) -> bool {
        has_permission(&self.eff, perm, scope, self.rel())
    }

    /// Require `perm` at `scope`, `403` otherwise.
    pub fn require(&self, perm: Permission, scope: Scope) -> Result<(), ApiError> {
        if self.permits(perm, scope) {
            Ok(())
        } else {
            Err(forbidden())
        }
    }

    /// **Subset invariant (role authoring, t64-E4).** May the principal *create or edit* a role whose
    /// contents are `permission_set`? True iff every permission is within the principal's OWN
    /// effective authority at `Global` (a catalog role is assignable anywhere, so its contents must be
    /// within the global ceiling). Holding `role.manage` does **not** exempt this — the meta gate and
    /// this check are independent.
    #[must_use]
    pub fn can_define_role<'a>(
        &self,
        permission_set: impl IntoIterator<Item = &'a Permission>,
    ) -> bool {
        chancela_authz::can_define_role(&self.eff, permission_set, self.rel())
    }

    /// **Subset invariant (role assignment, t64-E4).** May the principal *assign* `role` at `scope`?
    /// True iff every permission in the role's set is within the principal's own authority covering
    /// `scope`. Blocks granting a pre-existing "fat" role (or Owner) you do not fully hold. Holding
    /// `role.assign` does **not** exempt this.
    #[must_use]
    pub fn can_assign_role(&self, role: &Role, scope: Scope) -> bool {
        chancela_authz::can_assign_role(&self.eff, role, scope, self.rel())
    }

    /// **Delegation invariant (t64-E4).** May the principal *delegate* `perm` at `scope`? True iff
    /// `perm` is non-meta AND the principal holds it **via a role** covering `scope`. The via-role
    /// requirement forbids re-delegation structurally (a received permission is never a role grant).
    #[must_use]
    pub fn can_delegate(&self, perm: Permission, scope: Scope) -> bool {
        chancela_authz::can_delegate(&self.eff, perm, scope, self.rel())
    }
}

/// Resolve the session actor into an [`Authorizer`] (its effective authority + the live
/// resource-parent graph). `401` without a session, `403` if the session names no active user. Used by the list
/// endpoints for per-row filtering (note²) and available to any handler running several checks.
pub async fn authorizer(state: &AppState, actor: &CurrentActor) -> Result<Authorizer, ApiError> {
    if let Some(principal) = actor.api_key_principal() {
        return Ok(Authorizer {
            principal: None,
            eff: principal.effective_permissions.clone(),
            relations: scope_relations(state).await,
        });
    }

    let now = OffsetDateTime::now_utc();
    let (principal, eff) = effective_permissions_for_actor(state, actor, now).await?;
    Ok(Authorizer {
        principal: Some(principal),
        eff,
        relations: scope_relations(state).await,
    })
}

/// The target [`Scope`] for a **tenant** operation (wp26 tenancy). Used by the tenant collection CRUD
/// and the tenant-aware entity create (wp27-e1) as well as the two-tenant isolation fixture; the
/// narrowing relation is fed from `state.entities`.
#[must_use]
pub fn scope_of_tenant(id: chancela_core::TenantId) -> Scope {
    Scope::Tenant(AuthzTenantId(id.0))
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

/// The target [`Scope`] for an operation on an **act**. Kept async for call-site compatibility; the
/// live act→book relation is supplied by [`Authorizer`] during the permission check.
pub async fn scope_of_act(_state: &AppState, act: ActId) -> Scope {
    Scope::Act(AuthzActId(act.0))
}

/// The target [`Scope`] for a shared template library.
#[must_use]
pub fn scope_of_template_library(id: TemplateLibraryId) -> Scope {
    Scope::TemplateLibrary(AuthzTemplateLibraryId(id.0))
}

/// The target [`Scope`] for an operation on a follow-up row: the owning act's book, resolved
/// through the stored `follow_up.act_id`.
///
/// Unknown follow-ups fall back to `Global`: only a genuinely global grant may proceed to the
/// handler's honest not-found response, while scoped callers receive the same generic forbidden
/// result. The follow-up lock is released before resolving the act scope.
pub async fn scope_of_follow_up(state: &AppState, follow_up: &str) -> Scope {
    let act_id = {
        let follow_ups = state.follow_ups.read().await;
        follow_ups.get(follow_up).map(|f| f.act_id)
    };
    match act_id {
        Some(act_id) => scope_of_act(state, act_id).await,
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
    // wp25 observability probes — unauthenticated like `/health`. `/livez` (liveness) and `/readyz`
    // (narrow degraded-mode readiness) carry no data, only a status. `/metrics` exposes operational
    // counters/gauges with no PII or secrets; it is Exempt to keep scraping simple, but deployments
    // must expose it only on the internal network / behind an allowlist, never publicly.
    ("/metrics", RouteClass::Exempt),
    ("/livez", RouteClass::Exempt),
    ("/readyz", RouteClass::Exempt),
    ("/v1/session", RouteClass::Exempt),
    ("/v1/session/roster", RouteClass::Exempt),
    // The password strength ruleset — public knowledge the onboarding checklist renders before any
    // session exists (t68). Read-only, no secrets; mirrors the roster's unauth-onboarding rationale.
    ("/v1/session/password-policy", RouteClass::Exempt),
    // External signer invite token envelope: token-authenticated, tracking-only, no canonical
    // document bytes and no qualified-signature completion.
    ("/v1/signature/external-invites/lookup", RouteClass::Exempt),
    (
        "/v1/signature/external-invites/document/working-copy",
        RouteClass::Exempt,
    ),
    ("/v1/signature/external-invites/respond", RouteClass::Exempt),
    ("/v1", RouteClass::Exempt),
    ("/v1/{*rest}", RouteClass::Exempt),
    ("/api", RouteClass::Exempt),
    ("/api/", RouteClass::Exempt),
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
    // --- Top-level tenant collection (wp27-e1; dedicated Tenant* verbs wired by wp27-e2) -------
    ("/v1/tenants", RouteClass::Gated), // GET tenant.read@Tenant (per-row) · POST tenant.create@Global
    ("/v1/tenants/{tenant_id}", RouteClass::Gated), // GET tenant.read@Tenant
    // --- Company groups + shared versioned template libraries ---------------------------------
    ("/v1/tenants/{tenant_id}/groups", RouteClass::Gated),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/entities/{entity_id}",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/dashboard",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/revisions",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/history",
        RouteClass::Gated,
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/revisions/{revision}",
        RouteClass::Gated,
    ),
    // --- Opt-in zero-knowledge repositories ---------------------------------------------------
    (
        "/v1/tenants/{tenant_id}/repository-policy",
        RouteClass::Gated,
    ), // settings.read/manage@Tenant
    ("/v1/tenants/{tenant_id}/repositories", RouteClass::Gated), // settings.read/manage@Tenant
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}",
        RouteClass::Gated,
    ), // settings.read/manage@Repository
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/uploads",
        RouteClass::Gated,
    ), // data.backup@Repository
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/uploads/{upload_id}/ciphertext",
        RouteClass::Gated,
    ), // data.backup@Repository
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects",
        RouteClass::Gated,
    ), // data.export@Repository
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/manifest",
        RouteClass::Gated,
    ), // data.export@Archive
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/ciphertext",
        RouteClass::Gated,
    ), // data.export@Archive
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/readability-package",
        RouteClass::Gated,
    ), // data.export@Archive + book.export@Book + step-up
    // --- Books ----------------------------------------------------------------------------------
    ("/v1/books", RouteClass::Gated), // GET book.read@Global · POST book.open@Entity
    ("/v1/books/{id}", RouteClass::Gated), // GET book.read@Book
    ("/v1/books/{id}/close", RouteClass::Gated), // POST book.close@Book
    ("/v1/books/{id}/acts", RouteClass::Gated), // GET book.read@Book
    ("/v1/books/paper-import/validate", RouteClass::Gated), // POST book.import@Global (read-only)
    ("/v1/books/paper-import", RouteClass::Gated), // GET/POST book.import@Global (list/preserve package)
    ("/v1/books/paper-import/{id}", RouteClass::Gated), // GET book.import@Global (metadata)
    ("/v1/books/paper-import/{id}/ocr/enqueue", RouteClass::Gated), // POST book.import@Global (metadata-only OCR status)
    ("/v1/books/paper-import/{id}/ocr-status", RouteClass::Gated), // PATCH book.import@Global (metadata-only OCR status)
    ("/v1/books/paper-import/{id}/ocr/run", RouteClass::Gated), // POST book.import@Global (local non-authoritative OCR draft)
    ("/v1/books/paper-import/{id}/ocr-drafts", RouteClass::Gated), // GET/POST book.import@Global (non-authoritative OCR drafts)
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/review",
        RouteClass::Gated,
    ), // PATCH book.import@Global (OCR draft review metadata)
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft",
        RouteClass::Gated,
    ), // POST act.draft@Book (accepted OCR draft to mutable act draft)
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier",
        RouteClass::Gated,
    ), // POST book.import@Global (metadata-only accepted OCR dossier)
    (
        "/v1/books/paper-import/{id}/conversion-dossiers",
        RouteClass::Gated,
    ), // GET book.import@Global (metadata-only OCR dossier list)
    (
        "/v1/books/paper-import/{id}/ocr-canonical-rehearsal",
        RouteClass::Gated,
    ), // GET book.import@Global (read-only local OCR/canonical rehearsal)
    ("/v1/books/paper-import/{id}/bytes", RouteClass::Gated), // GET book.import@Global (package bytes)
    ("/v1/books/{id}/legal-hold", RouteClass::Gated),         // GET/PUT/DELETE book.export@Book
    ("/v1/books/{id}/archive/package", RouteClass::Gated),    // GET book.export@Book
    (
        "/v1/books/{id}/archive/local-dglab-interchange-manifest",
        RouteClass::Gated,
    ), // GET book.export@Book (read-only local manifest)
    ("/v1/books/{id}/archive/disposal", RouteClass::Gated), // GET/POST book.export@Book (dry-run only)
    ("/v1/books/{id}/export", RouteClass::Gated),           // POST book.export@Book
    ("/v1/books/import/preflight", RouteClass::Gated),      // POST book.import@Global (read-only)
    ("/v1/books/import", RouteClass::Gated),                // POST book.import@Global
    ("/v1/books/{id}/start-over", RouteClass::Gated),       // POST book.start_over@Book + step-up
    // --- Acts -----------------------------------------------------------------------------------
    ("/v1/acts", RouteClass::Gated), // POST act.draft@Book(body.book_id)
    ("/v1/acts/{id}", RouteClass::Gated), // GET act.read@Book · PATCH act.edit@Book
    ("/v1/acts/{id}/advance", RouteClass::Gated), // POST act.advance@Book
    ("/v1/acts/{id}/human-verification", RouteClass::Gated), // POST act.advance@Book
    ("/v1/acts/{id}/compliance", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/seal", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/archive", RouteClass::Gated), // POST act.archive@Book
    ("/v1/acts/{id}/follow-ups", RouteClass::Gated), // GET act.read@Book · POST act.edit@Book
    ("/v1/follow-ups/{id}", RouteClass::Gated), // PATCH act.edit@Book(follow_up.act_id)
    ("/v1/follow-ups/{id}/complete", RouteClass::Gated), // POST act.edit@Book(follow_up.act_id)
    ("/v1/acts/{id}/convening/dispatch", RouteClass::Gated), // POST act.edit@Book (t61-E1)
    ("/v1/acts/{id}/document/preview", RouteClass::Gated), // GET act.read@Book
    ("/v1/acts/{id}/document/generate", RouteClass::Gated), // POST document.generate@Book
    ("/v1/acts/{act_id}/documents/generated", RouteClass::Gated), // GET act.read@Book
    ("/v1/documents/generated/{document_id}", RouteClass::Gated), // GET act.read@Book(document.act_id)
    (
        "/v1/documents/generated/{document_id}/dispatch-evidence",
        RouteClass::Gated,
    ), // GET act.read@Book(document.act_id) · POST document.generate@Book(document.act_id)
    ("/v1/acts/{id}/document", RouteClass::Gated),                // GET act.read@Book
    ("/v1/acts/{id}/document/working-copy", RouteClass::Gated),   // GET act.read@Book
    ("/v1/acts/{id}/document/office", RouteClass::Gated),         // GET act.read@Book
    ("/v1/acts/{id}/document/bundle", RouteClass::Gated),         // GET act.read@Book
    ("/v1/documents/import", RouteClass::Gated), // POST document.generate@Global|Book
    ("/v1/documents/imported", RouteClass::Gated), // GET act.read@Global|Book(act_id)
    ("/v1/documents/imported/{id}", RouteClass::Gated), // GET act.read@import scope
    ("/v1/documents/imported/{id}/bytes", RouteClass::Gated), // GET act.read@import scope
    ("/v1/documents/imported/{id}/review", RouteClass::Gated), // PATCH document.generate@import scope
    ("/v1/documents/import/validate", RouteClass::Gated), // POST act.read@Global (read-only validation)
    ("/v1/external-validator-reports", RouteClass::Gated), // GET settings.read@Global · POST settings.manage@Global
    (
        "/v1/external-validator-reports/{case_id}/{validator_family}",
        RouteClass::Gated,
    ), // GET settings.read@Global
    (
        "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report",
        RouteClass::Gated,
    ), // GET settings.read@Global
    ("/v1/signature/pdf/validate", RouteClass::Gated), // POST act.read@Global (read-only technical PDF/PAdES validation)
    ("/v1/signature/asic/inspect", RouteClass::Gated), // POST act.read@Global (read-only technical ASiC signature inspection)
    ("/v1/signature/xades/sign", RouteClass::Gated), // POST signing.perform@Global (local technical XAdES)
    ("/v1/signature/xades/validate", RouteClass::Gated), // POST act.read@Global (read-only technical XAdES/XMLDSig validation)
    ("/v1/signature/asic/sign", RouteClass::Gated), // POST signing.perform@Global (local technical ASiC)
    ("/v1/scap/providers", RouteClass::Gated),      // POST act.read@Global (SCAP provider lookup)
    ("/v1/scap/attributes", RouteClass::Gated),     // POST act.read@Global (SCAP attribute lookup)
    ("/v1/scap/sign", RouteClass::Gated), // POST signing.perform@Global (SCAP attribute signing)
    ("/v1/acts/{id}/signature/cmd/initiate", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/cmd/confirm", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/cc/sign", RouteClass::Gated), // POST signing.perform@Book (co-located)
    ("/v1/signature/cc/batch-sign", RouteClass::Gated), // POST signing.perform@Book(each requested act) / co-located permission checks
    (
        "/v1/acts/{id}/signature/local/pkcs12/sign",
        RouteClass::Gated,
    ), // POST signing.perform@Book (local software certificate)
    (
        "/v1/acts/{id}/signature/local/pkcs12/sign-stored",
        RouteClass::Gated,
    ), // POST signing.perform@Book (stored local software certificate)
    ("/v1/acts/{id}/signature/dss/attach", RouteClass::Gated), // POST signing.perform@Book
    (
        "/v1/acts/{id}/signature/dss/collect-revocation",
        RouteClass::Gated,
    ), // POST signing.perform@Book
    (
        "/v1/acts/{id}/signature/archive-timestamp/append",
        RouteClass::Gated,
    ), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/ltv/execute", RouteClass::Gated), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/ltv/renew", RouteClass::Gated), // POST signing.perform@Book
    // Generic provider-parameterized remote signing (t59-s3): CMD + any configured CSC QTSP.
    (
        "/v1/acts/{id}/signature/remote/{provider}/initiate",
        RouteClass::Gated,
    ), // POST signing.perform@Book
    (
        "/v1/signature/remote/{provider}/batch-initiate",
        RouteClass::Gated,
    ), // POST signing.perform@Book(each requested act)
    (
        "/v1/acts/{id}/signature/remote/{provider}/confirm",
        RouteClass::Gated,
    ), // POST signing.perform@Book
    ("/v1/acts/{id}/signature/official/import", RouteClass::Gated), // POST signing.perform@Book
    (
        "/v1/acts/{id}/signature/external-invites",
        RouteClass::Gated,
    ), // GET/POST signing.perform@Book
    (
        "/v1/acts/{id}/signature/external-invites/{invite_id}/revoke",
        RouteClass::Gated,
    ), // POST signing.perform@Book
    (
        "/v1/acts/{id}/external-signing/envelopes",
        RouteClass::Gated,
    ), // GET/POST signing.perform@Book
    ("/v1/external-signing/envelopes/{id}", RouteClass::Gated), // GET/PATCH signing.perform@Book(envelope.act_id)
    ("/v1/signature/providers", RouteClass::Gated), // GET signing.perform@Global (the picker)
    (
        "/v1/signature/provider-credentials/status",
        RouteClass::Gated,
    ), // GET settings.read@Global (read-only credential storage metadata)
    ("/v1/signature/provider-credentials", RouteClass::Gated), // GET settings.read@Global (metadata only)
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries",
        RouteClass::Gated,
    ), // POST settings.manage@Global
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/reorder",
        RouteClass::Gated,
    ), // POST settings.manage@Global
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}",
        RouteClass::Gated,
    ), // PATCH/DELETE settings.manage@Global
    ("/v1/acts/{id}/signature", RouteClass::Gated),            // GET act.read@Book
    ("/v1/acts/{id}/document/signed", RouteClass::Gated),      // GET act.read@Book
    ("/v1/templates", RouteClass::Gated), // GET act.read@Global · POST template.manage@Global
    ("/v1/templates/{id}", RouteClass::Gated), // PUT/DELETE template.manage@Global
    ("/v1/templates/{id}/export", RouteClass::Gated), // GET act.read@Global
    ("/v1/templates/import", RouteClass::Gated), // POST template.manage@Global (dry_run preflight = read-only)
    // --- Ledger ---------------------------------------------------------------------------------
    ("/v1/ledger/events", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/events/page", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/archive/document", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/verify", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/integrity", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/attestations/{seq}", RouteClass::Gated), // GET ledger.read@Global
    ("/v1/ledger/recovery/reanchor", RouteClass::Gated), // POST ledger.recover@Global + step-up
    ("/v1/ledger/recovery/restore", RouteClass::Gated), // POST ledger.recover@Global + step-up
    ("/v1/ledger/recovery/restore/preflight", RouteClass::Gated), // POST ledger.recover@Global + step-up preflight
    // --- Data management ------------------------------------------------------------------------
    ("/v1/data/reset", RouteClass::Gated), // POST data.wipe@Global + step-up
    ("/v1/data/status", RouteClass::Gated), // GET settings.read@Global
    ("/v1/data/cleanup", RouteClass::Gated), // POST settings.manage@Global
    ("/v1/data/key-rotation", RouteClass::Gated), // POST settings.manage@Global + interactive session
    ("/v1/data/key-rotation/preflight", RouteClass::Gated), // POST settings.manage@Global (read-only)
    ("/v1/data/start-over", RouteClass::Gated),             // POST data.start_over@Global + step-up
    ("/v1/backup", RouteClass::Gated),                      // POST data.backup@Global
    ("/v1/backup/recovery-drills", RouteClass::Gated), // GET/POST ledger.recover@Global (preflight-only receipt)
    ("/v1/sync/handoff-preflight", RouteClass::Gated), // GET ledger.recover@Global (read-only local evidence report)
    (
        "/v1/tenants/{tenant_id}/connector-targets",
        RouteClass::Gated,
    ), // GET settings.read@Tenant · POST settings.manage@Tenant
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}",
        RouteClass::Gated,
    ), // GET settings.read@Integration · PATCH/DELETE settings.manage@Integration
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}/probe",
        RouteClass::Gated,
    ), // POST settings.read@Integration + outbound allowlist
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}/run",
        RouteClass::Gated,
    ), // POST data.export|data.backup@Repository
    ("/v1/tenants/{tenant_id}/connector-jobs", RouteClass::Gated), // GET data.export|data.backup@Repository (filtered)
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}",
        RouteClass::Gated,
    ), // GET data.export|data.backup@Repository
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}/cancel",
        RouteClass::Gated,
    ), // POST data.export|data.backup@Repository
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}/retry",
        RouteClass::Gated,
    ), // POST data.export|data.backup@Repository
    ("/v1/dashboard", RouteClass::Gated),                          // GET act.read@Global
    ("/v1/notifications/triage", RouteClass::Gated),               // GET act.read@Global
    ("/v1/notifications/triage/{id}", RouteClass::Gated),          // PATCH act.read@Global
    // --- Settings -------------------------------------------------------------------------------
    ("/v1/settings", RouteClass::Gated), // GET settings.read@Global · PUT settings.manage@Global
    ("/v1/platform/services", RouteClass::Gated), // GET settings.read@Global
    (
        "/v1/platform/services/{id}/actions/{action}",
        RouteClass::Gated,
    ), // POST settings.manage@Global
    ("/v1/platform/logs", RouteClass::Gated), // GET settings.read@Global
    ("/v1/platform/logs/forwarded", RouteClass::Gated), // POST platform.logs.write@Global
    // --- Reference: CAE + law -------------------------------------------------------------------
    ("/v1/cae", RouteClass::Gated),          // GET cae.read@Global
    ("/v1/cae/refresh", RouteClass::Gated),  // POST cae.refresh@Global
    ("/v1/cae/updates", RouteClass::Gated),  // GET cae.read@Global
    ("/v1/cae/sections", RouteClass::Gated), // GET cae.read@Global
    ("/v1/cae/{code}", RouteClass::Gated),   // GET cae.read@Global
    ("/v1/cae/{code}/children", RouteClass::Gated), // GET cae.read@Global
    ("/v1/trust/status", RouteClass::Gated), // GET cae.read@Global (read-only trust reference)
    ("/v1/trust/catalog", RouteClass::Gated), // GET cae.read@Global (read-only trust reference)
    ("/v1/trust/refresh", RouteClass::Gated), // POST cae.refresh@Global (operator TSL import)
    ("/v1/trust/tsa", RouteClass::Gated),    // GET cae.read@Global (read-only TSA diagnostics)
    ("/v1/trust/providers/{id}", RouteClass::Gated), // GET cae.read@Global
    ("/v1/trust/services/{id}", RouteClass::Gated), // GET cae.read@Global
    ("/v1/law", RouteClass::Gated),          // GET law.read@Global
    ("/v1/law/corpus", RouteClass::Gated),   // GET law.read@Global (corpus reader)
    ("/v1/law/corpus/search", RouteClass::Gated), // GET law.read@Global (full-text search)
    ("/v1/law/corpus/{diploma}", RouteClass::Gated), // GET law.read@Global
    ("/v1/law/corpus/{diploma}/{article}", RouteClass::Gated), // GET law.read@Global
    ("/v1/law/citations/resolve", RouteClass::Gated), // POST law.read@Global
    ("/v1/law/{id}/fetch", RouteClass::Gated), // POST law.manage@Global
    ("/v1/law/{id}/pdf", RouteClass::Gated), // GET law.read@Global · DELETE law.manage@Global
    // --- Users ----------------------------------------------------------------------------------
    ("/v1/users", RouteClass::Gated), // GET user.read@Global · POST user.manage@Global (bootstrap exempt)
    ("/v1/users/{id}", RouteClass::Gated), // GET user.read@Global · PATCH user.manage@Global
    ("/v1/users/{id}/secret", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
    ("/v1/users/{id}/attestation-key", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
    ("/v1/users/{id}/recovery", RouteClass::Gated), // self OR user.manage@Global (+ t51 proof)
    ("/v1/privacy/users/{id}/export", RouteClass::Gated), // GET user.manage@Global
    ("/v1/privacy/users/{id}/dsr-requests", RouteClass::Gated), // GET/POST user.manage@Global
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/complete",
        RouteClass::Gated,
    ), // POST user.manage@Global
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/preflight",
        RouteClass::Gated,
    ), // POST user.manage@Global (read-only erasure preflight)
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/approve",
        RouteClass::Gated,
    ), // POST user.manage@Global
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/execute",
        RouteClass::Gated,
    ), // POST user.manage@Global
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/rectification",
        RouteClass::Gated,
    ), // POST user.manage@Global
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/restriction",
        RouteClass::Gated,
    ), // POST user.manage@Global
    ("/v1/privacy/dsr-requests/{id}", RouteClass::Gated), // PATCH user.manage@Global
    ("/v1/privacy/dsr-requests/{id}/complete", RouteClass::Gated), // POST user.manage@Global
    ("/v1/privacy/processors", RouteClass::Gated),  // GET/POST user.manage|settings.manage@Global
    ("/v1/privacy/processors/{id}", RouteClass::Gated), // PATCH user.manage|settings.manage@Global
    ("/v1/privacy/dpia-template", RouteClass::Gated), // GET user.manage|settings.manage@Global
    ("/v1/privacy/dpias", RouteClass::Gated),       // GET/POST user.manage|settings.manage@Global
    ("/v1/privacy/dpias/{id}", RouteClass::Gated),  // PATCH user.manage|settings.manage@Global
    ("/v1/privacy/breach-playbooks", RouteClass::Gated), // GET/POST user.manage|settings.manage@Global
    ("/v1/privacy/breach-playbooks/{id}", RouteClass::Gated), // PATCH user.manage|settings.manage@Global
    ("/v1/privacy/transfer-controls", RouteClass::Gated), // GET/POST user.manage|settings.manage@Global
    ("/v1/privacy/transfer-controls/{id}", RouteClass::Gated), // PATCH user.manage|settings.manage@Global
    ("/v1/privacy/retention-policies", RouteClass::Gated), // GET/POST user.manage|settings.manage@Global
    ("/v1/privacy/retention-policies/dry-run", RouteClass::Gated), // POST user.manage|settings.manage@Global, non-destructive
    ("/v1/privacy/retention-due-candidates", RouteClass::Gated), // GET user.manage|settings.manage@Global, read-only scanner
    (
        "/v1/privacy/retention-due-candidates/{candidate_id}/resolution",
        RouteClass::Gated,
    ), // POST user.manage|settings.manage@Global, evidence-only
    (
        "/v1/privacy/retention-candidate-resolutions",
        RouteClass::Gated,
    ), // GET user.manage|settings.manage@Global
    ("/v1/privacy/retention-executions", RouteClass::Gated), // GET user.manage|settings.manage@Global
    (
        "/v1/privacy/retention-executions/{id}/review-closure",
        RouteClass::Gated,
    ), // POST user.manage|settings.manage@Global
    ("/v1/privacy/retention-policies/{id}", RouteClass::Gated), // PATCH user.manage|settings.manage@Global
    // --- API keys -------------------------------------------------------------------------------
    ("/v1/api-keys", RouteClass::Gated), // GET/POST user.manage@Global + interactive session
    ("/v1/api-keys/{id}", RouteClass::Gated), // DELETE user.manage@Global + interactive session
    ("/v1/api-keys/{id}/rotate", RouteClass::Gated), // POST user.manage@Global + interactive session
    // --- RBAC management (t64-E4) ---------------------------------------------------------------
    ("/v1/roles", RouteClass::Gated), // GET list (any session) · POST role.manage@Global + subset
    ("/v1/roles/{id}", RouteClass::Gated), // PATCH/DELETE role.manage@Global + subset + protected-Owner
    (
        "/v1/roles/{id}/seeded-drift-reconciliation",
        RouteClass::Gated,
    ), // GET proposal/POST apply role.manage@Global + seeded-only subset-preserving reconciliation
    ("/v1/permissions", RouteClass::Session), // GET the verb catalog (any valid session)
    ("/v1/users/{id}/roles", RouteClass::Gated), // POST/DELETE role.assign@scope + subset + last-Owner
    ("/v1/delegations", RouteClass::Gated), // GET own/all · POST delegation.grant@scope + invariant
    ("/v1/delegations/{id}", RouteClass::Gated), // DELETE grantor OR delegation.revoke@scope
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
    use std::collections::BTreeSet;

    use chancela_apikey::{ApiKey, ApiKeyGrant, KeySpec};
    use chancela_authz::{
        RoleAssignment, RoleCatalog, RoleId, UserId as AuthzUserId, effective_permissions,
    };
    use serde_json::json;
    use uuid::Uuid;

    use crate::roles::ScopeInput;
    use crate::session::ScopeView;

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

    #[test]
    fn complete_scope_graph_attenuates_api_keys_to_live_leaf_resources() {
        let tenant_a = AuthzTenantId(Uuid::from_u128(1));
        let tenant_b = AuthzTenantId(Uuid::from_u128(2));
        let entity_a = AuthzEntityId(Uuid::from_u128(10));
        let entity_b = AuthzEntityId(Uuid::from_u128(20));
        let book_a = AuthzBookId(Uuid::from_u128(100));
        let book_b = AuthzBookId(Uuid::from_u128(200));
        let act_a = AuthzActId(Uuid::from_u128(1_000));
        let act_b = AuthzActId(Uuid::from_u128(2_000));
        let library_a = AuthzTemplateLibraryId(Uuid::from_u128(10_000));
        let repository_a = AuthzRepositoryId(Uuid::from_u128(20_000));
        let repository_b = AuthzRepositoryId(Uuid::from_u128(20_001));
        let archive_a = AuthzArchiveId(Uuid::from_u128(30_000));

        let relations = ScopeRelations {
            books: HashMap::from([(book_a, entity_a), (book_b, entity_b)]),
            tenants: HashMap::from([(entity_a, tenant_a), (entity_b, tenant_b)]),
            acts: HashMap::from([(act_a, book_a), (act_b, book_b)]),
            template_libraries: HashMap::from([(library_a, tenant_a)]),
            integrations: HashMap::new(),
            repositories: HashMap::from([(repository_a, tenant_a), (repository_b, tenant_b)]),
            archives: HashMap::from([(archive_a, repository_a)]),
        };

        let role_id = RoleId(Uuid::from_u128(42));
        let creator_id = AuthzUserId(Uuid::from_u128(43));
        let mut roles = RoleCatalog::new();
        roles.insert(Role {
            id: role_id,
            name: "tenant operator".to_owned(),
            permission_set: BTreeSet::from([
                Permission::ActRead,
                Permission::TemplateManage,
                Permission::DataExport,
            ]),
            protected: false,
        });
        let creator = effective_permissions(
            creator_id,
            &[RoleAssignment::new(role_id, Scope::Tenant(tenant_a))],
            &roles,
            &[],
            OffsetDateTime::UNIX_EPOCH,
        );
        let spec = |name: &str, grant| KeySpec {
            name: name.to_owned(),
            principal_grant: grant,
            created_by: creator_id,
            created_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            rate_limit: None,
        };

        assert!(
            ApiKey::issue(
                &creator,
                &roles,
                &relations,
                spec(
                    "act-a",
                    ApiKeyGrant::perms([Permission::ActRead], Scope::Act(act_a)),
                ),
            )
            .is_ok(),
            "a tenant-scoped creator may attenuate a key to an act in that tenant"
        );
        assert!(
            ApiKey::issue(
                &creator,
                &roles,
                &relations,
                spec(
                    "library-a",
                    ApiKeyGrant::perms(
                        [Permission::TemplateManage],
                        Scope::TemplateLibrary(library_a),
                    ),
                ),
            )
            .is_ok(),
            "a tenant-scoped creator may attenuate a key to its shared template library"
        );
        assert!(
            ApiKey::issue(
                &creator,
                &roles,
                &relations,
                spec(
                    "archive-a",
                    ApiKeyGrant::perms([Permission::DataExport], Scope::Archive(archive_a)),
                ),
            )
            .is_ok(),
            "a tenant-scoped creator may attenuate through Repository to its Archive leaf"
        );
        assert!(
            ApiKey::issue(
                &creator,
                &roles,
                &relations,
                spec(
                    "repository-b",
                    ApiKeyGrant::perms([Permission::DataExport], Scope::Repository(repository_b),),
                ),
            )
            .is_err(),
            "cross-tenant repository attenuation must fail closed"
        );
        assert!(
            ApiKey::issue(
                &creator,
                &roles,
                &relations,
                spec(
                    "act-b",
                    ApiKeyGrant::perms([Permission::ActRead], Scope::Act(act_b)),
                ),
            )
            .is_err(),
            "cross-tenant leaf attenuation must fail closed"
        );
    }

    #[test]
    fn scope_wire_accepts_and_renders_every_preserved_and_additive_kind() {
        let id = Uuid::from_u128(99);
        let cases = [
            (json!({"kind": "global"}), Scope::Global),
            (
                json!({"kind": "tenant", "id": id}),
                Scope::Tenant(AuthzTenantId(id)),
            ),
            (
                json!({"kind": "entity", "id": id}),
                Scope::Entity(AuthzEntityId(id)),
            ),
            (
                json!({"kind": "book", "id": id}),
                Scope::Book(AuthzBookId(id)),
            ),
            (json!({"kind": "act", "id": id}), Scope::Act(AuthzActId(id))),
            (
                json!({"kind": "folder", "id": id}),
                Scope::Folder(chancela_authz::FolderId(id)),
            ),
            (
                json!({"kind": "template_library", "id": id}),
                Scope::TemplateLibrary(AuthzTemplateLibraryId(id)),
            ),
            (
                json!({"kind": "archive", "id": id}),
                Scope::Archive(chancela_authz::ArchiveId(id)),
            ),
            (
                json!({"kind": "integration", "id": id}),
                Scope::Integration(chancela_authz::IntegrationId(id)),
            ),
            (
                json!({"kind": "repository", "id": id}),
                Scope::Repository(chancela_authz::RepositoryId(id)),
            ),
        ];

        for (wire, expected) in cases {
            let input: ScopeInput = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(Scope::from(input), expected);
            assert_eq!(
                serde_json::to_value(ScopeView::from(expected)).unwrap(),
                wire
            );
        }
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

    /// The deliberate unauthenticated surface stays exempt (bootstrap/session liveness plus
    /// token-authenticated external-invite tracking; no canonical document bytes or signing
    /// completion).
    #[test]
    fn the_exempt_set_is_the_deliberate_unauth_surface() {
        assert_eq!(classify("/health"), Some(RouteClass::Exempt));
        assert_eq!(classify("/v1/session"), Some(RouteClass::Exempt));
        assert_eq!(classify("/v1/session/roster"), Some(RouteClass::Exempt));
        assert_eq!(
            classify("/v1/signature/external-invites/lookup"),
            Some(RouteClass::Exempt)
        );
        assert_eq!(
            classify("/v1/signature/external-invites/document/working-copy"),
            Some(RouteClass::Exempt)
        );
        assert_eq!(
            classify("/v1/signature/external-invites/respond"),
            Some(RouteClass::Exempt)
        );
        // Sensitive endpoints are never exempt.
        assert_eq!(classify("/v1/data/reset"), Some(RouteClass::Gated));
        assert_eq!(classify("/v1/entities"), Some(RouteClass::Gated));
        assert_eq!(
            classify("/v1/acts/{id}/human-verification"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn external_signer_invite_routes_are_classified_as_gated() {
        assert_eq!(
            classify("/v1/acts/{id}/signature/external-invites"),
            Some(RouteClass::Gated)
        );
        assert_eq!(
            classify("/v1/acts/{id}/signature/external-invites/{invite_id}/revoke"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn external_signer_public_envelope_routes_are_classified_as_exempt() {
        assert_eq!(
            classify("/v1/signature/external-invites/lookup"),
            Some(RouteClass::Exempt)
        );
        assert_eq!(
            classify("/v1/signature/external-invites/document/working-copy"),
            Some(RouteClass::Exempt)
        );
        assert_eq!(
            classify("/v1/signature/external-invites/respond"),
            Some(RouteClass::Exempt)
        );
    }

    #[test]
    fn office_document_export_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/acts/{id}/document/office"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn generated_document_download_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/documents/generated/{document_id}"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn act_generated_documents_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/acts/{act_id}/documents/generated"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn local_dglab_interchange_manifest_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/books/{id}/archive/local-dglab-interchange-manifest"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn paper_book_ocr_canonical_rehearsal_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/books/paper-import/{id}/ocr-canonical-rehearsal"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn sync_handoff_preflight_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/sync/handoff-preflight"),
            Some(RouteClass::Gated)
        );
    }

    #[test]
    fn external_validator_report_download_route_is_classified_as_gated() {
        assert_eq!(
            classify("/v1/external-validator-reports/{case_id}/{validator_family}"),
            Some(RouteClass::Gated)
        );
        assert_eq!(
            classify("/v1/external-validator-reports/{case_id}/{validator_family}/raw-report"),
            Some(RouteClass::Gated)
        );
    }
}
