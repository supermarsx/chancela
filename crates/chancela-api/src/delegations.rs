//! The delegation store (`delegations.json`) — active **and** revoked scoped delegations (t64-E2).
//!
//! Mirrors the `users.json` / `roles.json` discipline: an atomic write-through, a malformed-tolerant
//! load, and `#[serde(default)]` throughout. A [`StoredDelegation`] wraps the frozen
//! [`chancela_authz::Delegation`] security model (`from`/`to`/`roles`/`scope`/`starts_at`/
//! `expires_at`/`legal_basis`/`revoked`/`suspended`) and adds the durable **audit** fields the crate
//! deliberately left to the API layer —
//! a stable [`DelegationId`], the `granted_at` timestamp, and the `revoked_at`/`revoked_by`
//! attribution recorded when a delegation is revoked (E4 wires the revoke endpoint).
//!
//! **A delegation hands over a FUNÇÃO (t44).** The record stores role ids, so what it conveys is
//! resolved live from the catalog at every authorization decision; the pre-t44
//! `permission`/`extra_permissions` fields are retained so stored permission-shaped records keep
//! resolving unchanged, but no new one is ever written.
//!
//! Revoked delegations are retained (never deleted) so the ledger + this store together form a
//! complete, reversible audit trail; the inner `revoked` flag — and the reversible `suspended` one —
//! make them contribute **nothing** to [`chancela_authz::effective_permissions`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::{
    Delegation, DelegationRefusal, Permission, RoleCatalog, RoleId, Scope, UserId as AuthzUserId,
};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::authorizer;
use crate::error::ApiError;
use crate::roles::ScopeInput;
use crate::session::ScopeView;
use crate::users::UserId;

pub const DELEGATIONS_FILE: &str = "delegations.json";
pub const MAX_DELEGATION_LEGAL_BASIS_CHARS: usize = 1024;

/// Opaque identifier of a stored delegation. Transparent UUID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DelegationId(pub Uuid);

impl std::fmt::Display for DelegationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A durable delegation record: the frozen [`chancela_authz::Delegation`] model (flattened, so the
/// on-disk shape is `{ id, granted_at, from, to, permission, scope, starts_at, expires_at?,
/// legal_basis?, revoked, revoked_at?, revoked_by? }`) plus the API-layer audit fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDelegation {
    /// Stable id (audit + revoke lookup).
    pub id: DelegationId,
    /// When the delegation was granted (RFC 3339).
    pub granted_at: String,
    /// When it was revoked (RFC 3339), if it has been. Set alongside `inner.revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Who revoked it, if revoked (grantor or a `delegation.revoke` holder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<AuthzUserId>,
    /// The frozen security model (grantor/grantee/permission/scope/expiry/revoked).
    #[serde(flatten)]
    pub inner: Delegation,
}

impl StoredDelegation {
    /// Build an active delegation record around a freshly-granted [`Delegation`].
    #[must_use]
    pub fn new(id: DelegationId, granted_at: String, inner: Delegation) -> Self {
        StoredDelegation {
            id,
            granted_at,
            revoked_at: None,
            revoked_by: None,
            inner,
        }
    }

    /// The frozen `chancela-authz` model this record wraps — what
    /// [`chancela_authz::effective_permissions`] consumes.
    #[must_use]
    pub fn authz(&self) -> &Delegation {
        &self.inner
    }
}

/// Load the delegation table from a `delegations.json` array, or `None` when the file is absent or
/// malformed (mirrors [`crate::users::load_users`] — a bad file never blocks startup). Duplicate ids
/// collapse to the last occurrence.
pub(crate) fn load_delegations(path: &Path) -> Option<HashMap<DelegationId, StoredDelegation>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<StoredDelegation>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|d| (d.id, d)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid delegations document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

/// Atomically write the delegation table to `delegations.json` (tmp file + rename), sorted by
/// `granted_at` then id for a deterministic document. Mirrors [`crate::users::write_users_atomic`].
pub(crate) fn write_delegations_atomic(
    path: &Path,
    delegations: &HashMap<DelegationId, StoredDelegation>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&StoredDelegation> = delegations.values().collect();
    list.sort_by(|a, b| a.granted_at.cmp(&b.granted_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Persist the live delegation table through to `delegations.json` when the state is file-backed.
/// A no-op for pure in-memory state (`delegations_path` is `None`). Call after any mutation (E4).
pub(crate) async fn persist_delegations(state: &AppState) -> Result<(), ApiError> {
    // wp16 P3b: route to the active source (Postgres `delegations` table, else `delegations.json`).
    // File behaviour on SQLite/single-node is unchanged.
    crate::sidecar_store::persist_delegations(state).await
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| DELEGATIONS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

// =================================================================================================
// Scoped-delegation endpoints (t64-E4; role-shaped t44): grant / list / suspend / resume / revoke.
// A grant enforces the delegation invariant server-side for EVERY permission inside every delegated
// função (non-meta AND held VIA A ROLE at the scope → no privilege escalation, no re-delegation);
// suspension and revocation take effect immediately, where authority resolves. FROZEN DTOs.
// =================================================================================================

/// Body of `POST /v1/delegations` — hand **one or several funções** to a grantee, optionally scoped
/// and optionally expiring.
///
/// A delegation assigns a **função**, not a hand-picked bag of verbs: `roles` carries role ids. Each
/// is resolved against the live catalog and validated *per permission it contains* by
/// [`grant_delegation`] (`403`, naming the offending verb); an unknown role id is also a `403`. New
/// grants must carry a non-empty operator-supplied local evidence/rationale string in `legal_basis`.
///
/// **Permission-shaped grants are gone.** The pre-t44 `permission`/`permissions` fields are still
/// *accepted by the parser* only so a stale client receives a controlled, explanatory `422` instead
/// of a bare deserialisation error. Stored permission-shaped records keep resolving; no new one can
/// be created.
#[derive(Deserialize)]
pub struct GrantDelegation {
    pub to: Uuid,
    /// The delegated **funções** (role ids). Every função is validated permission-by-permission;
    /// one bad verb inside one função refuses the whole request (see [`grant_delegation`]).
    #[serde(default)]
    pub roles: Vec<Uuid>,
    /// Retired: the legacy single permission. Present only to produce an explanatory `422`.
    #[serde(default)]
    pub permission: Option<Permission>,
    /// Retired: the legacy permission array. Present only to produce an explanatory `422`.
    #[serde(default)]
    pub permissions: Vec<Permission>,
    pub scope: ScopeInput,
    /// RFC 3339 start timestamp; absent ⇒ starts at grant time.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// RFC 3339 expiry; absent ⇒ until revoked.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Required evidence/rationale for new grants. Kept optional at the DTO boundary so missing
    /// requests receive a controlled 422 instead of a serde extraction error.
    #[serde(default)]
    pub legal_basis: Option<String>,
}

/// One delegated **função**, rendered with the authority it carries so an operator handing over a
/// role can see exactly what they are handing over. `permissions` is resolved **live** from the
/// catalog at render time, so it always shows what the delegation conveys *now*; a função that has
/// left the catalog renders with `known: false` and an empty set (it conveys nothing).
#[derive(Serialize)]
pub struct DelegatedRoleView {
    pub id: String,
    /// The função's human name — what the picker and the row show.
    pub name: String,
    /// The verbs the função currently grants, in the role's deterministic order.
    pub permissions: Vec<String>,
    /// Whether the função still exists in the catalog.
    pub known: bool,
}

/// A delegation rendered for the web (FROZEN for E7/t62). No secret material — only attribution,
/// the delegated funções (with their current contents), the scope, and lifecycle timestamps.
#[derive(Serialize)]
pub struct DelegationView {
    pub id: String,
    pub from: String,
    pub to: String,
    /// The delegated funções, in grant order. Empty **only** for a legacy permission-shaped record.
    pub roles: Vec<DelegatedRoleView>,
    /// Legacy: the primary verb of a pre-t44 permission-shaped record. Absent on role-shaped ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// Every verb this delegation currently conveys — the legacy verbs unioned with the live
    /// contents of the delegated funções. The flat view of `roles`, for display and for the ledger.
    pub permissions: Vec<String>,
    pub scope: ScopeView,
    pub granted_at: String,
    pub starts_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    pub revoked: bool,
    /// Reversibly paused. A suspended delegation conveys nothing (enforced where authority
    /// resolves, not by filtering this list).
    pub suspended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

/// Render a stored delegation against the **live** role catalog. The catalog is required because a
/// role-shaped delegation's authority is not stored in the record — it is whatever its funções grant
/// right now (see [`chancela_authz::effective_permissions`]).
pub(crate) fn delegation_view(d: &StoredDelegation, catalog: &RoleCatalog) -> DelegationView {
    let roles = d
        .inner
        .roles()
        .iter()
        .map(|&role_id| match catalog.get(role_id) {
            Some(role) => DelegatedRoleView {
                id: role_id.0.to_string(),
                name: role.name.clone(),
                permissions: role
                    .permission_set
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect(),
                known: true,
            },
            None => DelegatedRoleView {
                id: role_id.0.to_string(),
                name: role_id.0.to_string(),
                permissions: Vec::new(),
                known: false,
            },
        })
        .collect();
    DelegationView {
        id: d.id.0.to_string(),
        from: d.inner.from.0.to_string(),
        to: d.inner.to.0.to_string(),
        roles,
        permission: d.inner.permission.map(|p| p.as_str().to_owned()),
        permissions: d
            .inner
            .granted_permissions(catalog)
            .into_iter()
            .map(|p| p.as_str().to_owned())
            .collect(),
        scope: ScopeView::from(d.inner.scope),
        granted_at: d.granted_at.clone(),
        starts_at: d.inner.starts_at.format(&Rfc3339).unwrap_or_default(),
        expires_at: d.inner.expires_at.and_then(|t| t.format(&Rfc3339).ok()),
        legal_basis: d.inner.legal_basis.clone(),
        revoked: d.inner.revoked,
        suspended: d.inner.suspended,
        revoked_at: d.revoked_at.clone(),
        revoked_by: d.revoked_by.map(|u| u.0.to_string()),
    }
}

/// Append a chained `delegation.*` audit event (honest actor, no secret material).
///
/// The event is scoped `delegation:{uuid}`, a keyword-shaped application scope, so it lands on the
/// shared `application` audit chain. It must **not** be a *bare* UUID: the ledger classifies a bare
/// UUID as a `company:{uuid}` book-action chain whose genesis kind must be `entity.created`
/// (WFL-11), so a `delegation.*` event opening such a chain would fail `Ledger::verify()` after the
/// mutation. The `application` chain fixes no genesis kind, keeping verify() healthy (wp19-fix).
async fn record_delegation_event(
    state: &AppState,
    view: &DelegationView,
    kind: &str,
    justification: &str,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(view)?;
    let actor_name = actor.resolve("api");
    let scope = format!("delegation:{}", view.id);
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_name, &scope, kind, Some(justification), &bytes);
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// `GET /v1/delegations` — the delegations the caller may see: a `delegation.revoke`\@Global holder
/// sees **all**, everyone else sees only delegations they granted or received. Any valid session.
pub async fn list_delegations(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<DelegationView>>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    let principal = AuthzUserId(authz.principal()?.0);
    let can_see_all = authz.permits(Permission::DelegationRevoke, Scope::Global);

    let catalog = state.roles.read().await;
    let table = state.delegations.read().await;
    let mut list: Vec<DelegationView> = table
        .values()
        .filter(|d| can_see_all || d.inner.from == principal || d.inner.to == principal)
        .map(|d| delegation_view(d, &catalog))
        .collect();
    list.sort_by(|a, b| a.granted_at.cmp(&b.granted_at).then(a.id.cmp(&b.id)));
    Ok(Json(list))
}

/// `POST /v1/delegations` — hand one or more **funções** to a grantee: scoped, revocable,
/// suspendable, optionally expiring. Gated `delegation.grant` at the delegation's scope, **and** the
/// DELEGATION INVARIANT applied to **every permission inside every função** independently: each must
/// be non-meta AND held by the actor **via a role** covering that scope. The via-role rule makes
/// re-delegation structurally impossible (a received permission is never a role grant).
///
/// The ceiling is deliberately *not* decided from a função's name, id or protected flag — it is the
/// same element-wise subset machinery the role-authoring and role-assignment invariants use
/// ([`chancela_authz::can_delegate_roles`]), so a small-sounding função full of authority the
/// grantor lacks is refused exactly like a large one.
///
/// **All-or-nothing.** Everything is validated before anything is written, so a request containing
/// one non-delegable or above-ceiling verb — in any of its funções — is refused *entirely* (`403`,
/// naming that verb) and no store insert, ledger event or cache invalidation happens. Naming the
/// offender is safe: the caller chose the funções and can already introspect their own authority via
/// `GET /v1/session/permissions` and the catalog via `GET /v1/roles`.
pub async fn grant_delegation(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<GrantDelegation>,
) -> Result<(StatusCode, Json<DelegationView>), ApiError> {
    let scope: Scope = req.scope.into();
    if req.permission.is_some() || !req.permissions.is_empty() {
        return Err(ApiError::Unprocessable(PERMISSION_SHAPED_GRANT.to_owned()));
    }
    let requested = requested_roles(&req.roles)?;
    let authz = authorizer(&state, &actor).await?;
    // Meta gate at the delegation's scope.
    authz.require(Permission::DelegationGrant, scope)?;
    // DELEGATION INVARIANT, PER PERMISSION INSIDE EACH FUNÇÃO: every verb the função carries must be
    // non-meta + held via a role at scope (blocks escalation AND re-delegation). One offending verb
    // in one função refuses the entire delegation. Validated against the same catalog snapshot the
    // grant is written from.
    {
        let catalog = state.roles.read().await;
        authz
            .can_delegate_roles(&requested, &catalog, scope)
            .map_err(refusal)?;
    }

    let grantor = authz.principal()?;
    let grantee = UserId(req.to);
    if !state.users.read().await.contains_key(&grantee) {
        return Err(ApiError::NotFound);
    }

    let legal_basis = normalize_grant_legal_basis(req.legal_basis)?;
    let granted_at_time = OffsetDateTime::now_utc();
    let starts_at =
        parse_optional_rfc3339(req.starts_at.as_deref(), "starts_at")?.unwrap_or(granted_at_time);
    let expires_at = parse_optional_rfc3339(req.expires_at.as_deref(), "expires_at")?;

    // `requested` is non-empty (checked above), so `with_roles` always yields a delegation.
    let mut inner = Delegation::with_roles(
        AuthzUserId(grantor.0),
        AuthzUserId(grantee.0),
        requested,
        scope,
    )
    .ok_or_else(|| ApiError::Unprocessable(EMPTY_ROLE_SET.to_owned()))?
    .starting_at(starts_at)
    .with_legal_basis(Some(legal_basis));
    if let Some(exp) = expires_at {
        inner = inner.expiring_at(exp);
    }
    let granted_at = granted_at_time.format(&Rfc3339).unwrap_or_default();
    let stored = StoredDelegation::new(DelegationId(Uuid::new_v4()), granted_at, inner);

    state
        .delegations
        .write()
        .await
        .insert(stored.id, stored.clone());
    persist_delegations(&state).await?;

    let view = delegation_view(&stored, &*state.roles.read().await);
    record_delegation_event(
        &state,
        &view,
        "delegation.granted",
        "função delegated",
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: the grantee's effective authority changed — signal other nodes (no-op on single-node).
    state.publish_role_changed(grantee.0);
    Ok((StatusCode::CREATED, Json(view)))
}

/// `DELETE /v1/delegations/{id}` — revoke a delegation. The **grantor** may always revoke their own;
/// otherwise `delegation.revoke` at the delegation's scope is required. Revocation is **immediate**
/// (a revoked delegation contributes no authority). Idempotent for an already-revoked delegation.
///
/// **Whole-set revocation.** A delegation is the unit of revocation: revoking it withdraws *every*
/// função it carries, atomically. There is deliberately no per-função revoke — they were granted
/// together under one legal basis, scope and expiry, so they are withdrawn together. To reduce a
/// grantee's delegated authority, revoke the delegation and grant a narrower função. For a
/// *reversible* pause, use [`suspend_delegation`] instead — revocation is terminal.
pub async fn revoke_delegation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<DelegationView>, ApiError> {
    let del_id = DelegationId(id);
    let authz = authorizer(&state, &actor).await?;
    let principal = AuthzUserId(authz.principal()?.0);

    let existing = state.delegations.read().await.get(&del_id).cloned();
    let existing = existing.ok_or(ApiError::NotFound)?;
    // Grantor may always revoke their own; otherwise require delegation.revoke at the delegation's scope.
    if existing.inner.from != principal {
        authz.require(Permission::DelegationRevoke, existing.inner.scope)?;
    }
    // Idempotent: already revoked → return the current view unchanged.
    if existing.inner.revoked {
        return Ok(Json(delegation_view(&existing, &*state.roles.read().await)));
    }

    let revoked_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();
    let updated = {
        let mut table = state.delegations.write().await;
        let d = table.get_mut(&del_id).ok_or(ApiError::NotFound)?;
        d.inner.revoked = true;
        d.revoked_at = Some(revoked_at);
        d.revoked_by = Some(principal);
        d.clone()
    };
    persist_delegations(&state).await?;

    let view = delegation_view(&updated, &*state.roles.read().await);
    record_delegation_event(
        &state,
        &view,
        "delegation.revoked",
        "delegation revoked",
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: the grantee's effective authority changed — signal other nodes (no-op on single-node).
    state.publish_role_changed(updated.inner.to.0);
    Ok(Json(view))
}

/// `POST /v1/delegations/{id}/suspend` — **reversibly** pause a delegation. Same authority as
/// revoke (the grantor always, otherwise `delegation.revoke` at the delegation's scope), because a
/// suspension withdraws exactly the same authority — it just does so recoverably.
///
/// A suspended delegation conveys **nothing**: [`chancela_authz::Delegation::is_active`] is false,
/// so it is stopped where delegations resolve into effective authority, not by hiding a row.
/// Idempotent. Revoked delegations cannot be suspended (revocation is terminal).
pub async fn suspend_delegation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<DelegationView>, ApiError> {
    set_suspended(state, id, actor, attestor, true).await
}

/// `POST /v1/delegations/{id}/resume` — lift a suspension. Same authority as [`suspend_delegation`].
/// The delegation resumes conveying whatever its funções grant **now**; the lifetime kept running
/// while suspended, so a delegation that expired meanwhile stays spent. Idempotent.
pub async fn resume_delegation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<DelegationView>, ApiError> {
    set_suspended(state, id, actor, attestor, false).await
}

/// The shared suspend/resume transition: authorize, no-op if already in the target state, flip,
/// persist, ledger, and signal the grantee's authority change.
async fn set_suspended(
    state: AppState,
    id: Uuid,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    suspended: bool,
) -> Result<Json<DelegationView>, ApiError> {
    let del_id = DelegationId(id);
    let authz = authorizer(&state, &actor).await?;
    let principal = AuthzUserId(authz.principal()?.0);

    let existing = state.delegations.read().await.get(&del_id).cloned();
    let existing = existing.ok_or(ApiError::NotFound)?;
    if existing.inner.from != principal {
        authz.require(Permission::DelegationRevoke, existing.inner.scope)?;
    }
    if existing.inner.revoked {
        return Err(ApiError::Unprocessable(
            "uma delegação revogada não pode ser suspensa nem retomada".to_owned(),
        ));
    }
    // Idempotent: already in the target state → nothing to transition, nothing to ledger.
    if existing.inner.suspended == suspended {
        return Ok(Json(delegation_view(&existing, &*state.roles.read().await)));
    }

    let updated = {
        let mut table = state.delegations.write().await;
        let d = table.get_mut(&del_id).ok_or(ApiError::NotFound)?;
        d.inner.suspended = suspended;
        d.clone()
    };
    persist_delegations(&state).await?;

    let view = delegation_view(&updated, &*state.roles.read().await);
    let (kind, why) = if suspended {
        ("delegation.suspended", "delegation suspended")
    } else {
        ("delegation.resumed", "delegation resumed")
    };
    record_delegation_event(&state, &view, kind, why, &actor, &attestor).await?;
    state.publish_role_changed(updated.inner.to.0);
    Ok(Json(view))
}

pub(crate) const EMPTY_ROLE_SET: &str = "uma delegação tem de indicar pelo menos uma função";

pub(crate) const PERMISSION_SHAPED_GRANT: &str = "uma delegação atribui uma função, não permissões avulsas: indique «roles» com os \
     identificadores das funções a delegar";

/// Resolve the delegated funções: first-seen order, de-duplicated. Empty ⇒ `422` (a delegation that
/// hands over no função is meaningless).
fn requested_roles(roles: &[Uuid]) -> Result<Vec<RoleId>, ApiError> {
    let mut out: Vec<RoleId> = Vec::with_capacity(roles.len());
    for &r in roles {
        let role_id = RoleId(r);
        if !out.contains(&role_id) {
            out.push(role_id);
        }
    }
    if out.is_empty() {
        return Err(ApiError::Unprocessable(EMPTY_ROLE_SET.to_owned()));
    }
    Ok(out)
}

/// Turn a delegation refusal into a `403` that names the offending verb *inside the função* and the
/// reason, and states that the whole delegation was refused (nothing was granted).
fn refusal(refusal: DelegationRefusal) -> ApiError {
    let detail = match refusal {
        DelegationRefusal::Meta(p) => format!(
            "a função contém «{}», que é uma meta-permissão e não é delegável",
            p.as_str()
        ),
        DelegationRefusal::NotHeldViaRole(p) => format!(
            "a função contém «{}», que não detém através de uma função neste âmbito, logo não a \
             pode delegar",
            p.as_str()
        ),
        DelegationRefusal::UnknownRole(id) => {
            format!("a função «{id}» não existe no catálogo")
        }
    };
    ApiError::Forbidden(format!("delegação recusada na íntegra: {detail}"))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|s| {
            OffsetDateTime::parse(s, &Rfc3339).map_err(|_| {
                ApiError::Unprocessable(format!("{field} must be an RFC 3339 timestamp"))
            })
        })
        .transpose()
}

fn normalize_grant_legal_basis(value: Option<String>) -> Result<String, ApiError> {
    let Some(raw) = value else {
        return Err(ApiError::Unprocessable(
            "legal_basis is required for new delegations".to_owned(),
        ));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Unprocessable(
            "legal_basis must not be empty".to_owned(),
        ));
    }
    let len = trimmed.chars().count();
    if len > MAX_DELEGATION_LEGAL_BASIS_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "legal_basis must be at most {MAX_DELEGATION_LEGAL_BASIS_CHARS} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(n: u128) -> AuthzUserId {
        AuthzUserId(Uuid::from_u128(n))
    }

    fn rid(n: u128) -> RoleId {
        RoleId(Uuid::from_u128(0xF00 + n))
    }

    /// A catalog holding one bespoke função.
    fn catalog_with(id: RoleId, name: &str, perms: &[Permission]) -> RoleCatalog {
        let mut c = RoleCatalog::new();
        c.insert(chancela_authz::Role {
            id,
            name: name.to_owned(),
            permission_set: perms.iter().copied().collect(),
            protected: false,
        });
        c
    }

    #[test]
    fn stored_delegation_round_trips_through_json() {
        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let starts_at = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        let inner = Delegation::new(uid(1), uid(2), Permission::ActAdvance, Scope::Global)
            .starting_at(starts_at)
            .with_legal_basis(Some("board resolution 2026-07-09".to_owned()));
        let d = StoredDelegation::new(DelegationId(Uuid::from_u128(9)), granted_at, inner);

        let bytes = serde_json::to_vec(&[&d]).expect("serialize");
        // The flattened model + audit fields are all top-level keys.
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = &value[0];
        assert!(obj.get("id").is_some());
        assert!(obj.get("granted_at").is_some());
        assert!(obj.get("permission").is_some());
        assert!(obj.get("scope").is_some());
        assert!(obj.get("starts_at").is_some());
        assert_eq!(
            obj.get("legal_basis").and_then(serde_json::Value::as_str),
            Some("board resolution 2026-07-09")
        );
        assert!(obj.get("revoked").is_some());
        // revoked_at / revoked_by are omitted while active.
        assert!(obj.get("revoked_at").is_none());
        assert!(obj.get("revoked_by").is_none());

        let back: Vec<StoredDelegation> = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, vec![d]);
    }

    #[test]
    fn legacy_stored_delegation_defaults_evidence_fields() {
        let raw = serde_json::json!([{
            "id": "00000000-0000-0000-0000-000000000009",
            "granted_at": "2026-01-01T00:00:00Z",
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.advance",
            "scope": "Global",
            "revoked": false
        }]);

        let back: Vec<StoredDelegation> = serde_json::from_value(raw).expect("legacy delegation");
        assert_eq!(back[0].inner.starts_at, OffsetDateTime::UNIX_EPOCH);
        assert_eq!(back[0].inner.legal_basis, None);

        let view = delegation_view(&back[0], &RoleCatalog::new());
        assert_eq!(view.starts_at, "1970-01-01T00:00:00Z");
        assert_eq!(view.legal_basis, None);
    }

    #[test]
    fn revoked_record_carries_attribution_and_is_inactive() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let granted_at = now.format(&Rfc3339).unwrap();
        let mut inner = Delegation::new(uid(1), uid(2), Permission::DataBackup, Scope::Global);
        inner.revoked = true;
        let d = StoredDelegation {
            revoked_at: Some(granted_at.clone()),
            revoked_by: Some(uid(1)),
            ..StoredDelegation::new(DelegationId(Uuid::from_u128(7)), granted_at, inner)
        };
        // A revoked delegation contributes nothing.
        assert!(!d.authz().is_active(now));

        let bytes = serde_json::to_vec(&[&d]).unwrap();
        let back: Vec<StoredDelegation> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back[0].revoked_by, Some(uid(1)));
        assert!(back[0].revoked_at.is_some());
    }

    #[test]
    fn delegations_json_disk_round_trip() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-rt-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);

        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let active = StoredDelegation::new(
            DelegationId(Uuid::from_u128(1)),
            granted_at.clone(),
            Delegation::new(uid(1), uid(2), Permission::ActAdvance, Scope::Global),
        );
        let mut revoked_inner =
            Delegation::new(uid(1), uid(3), Permission::DataBackup, Scope::Global);
        revoked_inner.revoked = true;
        let revoked = StoredDelegation {
            revoked_at: Some(granted_at.clone()),
            revoked_by: Some(uid(1)),
            ..StoredDelegation::new(DelegationId(Uuid::from_u128(2)), granted_at, revoked_inner)
        };

        let mut table: HashMap<DelegationId, StoredDelegation> = HashMap::new();
        table.insert(active.id, active.clone());
        table.insert(revoked.id, revoked.clone());

        write_delegations_atomic(&path, &table).expect("write");
        let loaded = load_delegations(&path).expect("load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[&active.id], active);
        assert_eq!(loaded[&revoked.id], revoked);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_ignores_a_malformed_file() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(load_delegations(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requested_roles_dedups_and_refuses_an_empty_set() {
        assert_eq!(
            requested_roles(&[rid(1).0, rid(2).0, rid(1).0]).unwrap(),
            vec![rid(1), rid(2)]
        );
        let err = requested_roles(&[]).expect_err("empty set");
        assert!(matches!(err, ApiError::Unprocessable(m) if m == EMPTY_ROLE_SET));
    }

    #[test]
    fn a_refusal_names_the_offending_permission_inside_the_funcao() {
        let err = refusal(DelegationRefusal::Meta(Permission::DelegationGrant));
        let ApiError::Forbidden(message) = err else {
            panic!("expected 403")
        };
        assert!(message.contains("delegation.grant"));
        assert!(message.contains("meta-permissão"));
        assert!(message.contains("na íntegra"));

        let err = refusal(DelegationRefusal::NotHeldViaRole(Permission::DataWipe));
        let ApiError::Forbidden(message) = err else {
            panic!("expected 403")
        };
        assert!(message.contains("data.wipe"));
        assert!(message.contains("função"));

        let err = refusal(DelegationRefusal::UnknownRole(rid(7)));
        let ApiError::Forbidden(message) = err else {
            panic!("expected 403")
        };
        assert!(message.contains(&rid(7).0.to_string()));
        assert!(message.contains("catálogo"));
    }

    #[test]
    fn the_view_names_each_funcao_and_shows_the_authority_it_carries() {
        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let catalog = catalog_with(
            rid(1),
            "Secretário",
            &[Permission::ActAdvance, Permission::ActRead],
        );
        let inner = Delegation::with_roles(uid(1), uid(2), [rid(1)], Scope::Global).unwrap();
        let d = StoredDelegation::new(DelegationId(Uuid::from_u128(3)), granted_at, inner);

        let view = delegation_view(&d, &catalog);
        // The função is named for a human, and the authority it hands over is inspectable.
        assert_eq!(view.roles.len(), 1);
        assert_eq!(view.roles[0].name, "Secretário");
        assert!(view.roles[0].known);
        assert_eq!(view.roles[0].permissions, vec!["act.read", "act.advance"]);
        // The flat set is what the delegation actually conveys, and no legacy verb is invented.
        assert_eq!(view.permissions, vec!["act.read", "act.advance"]);
        assert_eq!(view.permission, None);
        assert!(!view.suspended);

        // A função that has left the catalog is shown as unknown and conveys nothing.
        let view = delegation_view(&d, &RoleCatalog::new());
        assert!(!view.roles[0].known);
        assert!(view.roles[0].permissions.is_empty());
        assert!(view.permissions.is_empty());
    }

    #[test]
    fn a_legacy_permission_shaped_record_still_views_and_resolves() {
        let raw = serde_json::json!([{
            "id": "00000000-0000-0000-0000-000000000009",
            "granted_at": "2026-01-01T00:00:00Z",
            "from": "00000000-0000-0000-0000-000000000001",
            "to": "00000000-0000-0000-0000-000000000002",
            "permission": "act.advance",
            "scope": "Global",
            "revoked": false
        }]);
        let back: Vec<StoredDelegation> = serde_json::from_value(raw).expect("legacy delegation");
        // It needs no função: it resolves against an empty catalog exactly as it always did.
        let view = delegation_view(&back[0], &RoleCatalog::new());
        assert!(view.roles.is_empty());
        assert_eq!(view.permission.as_deref(), Some("act.advance"));
        assert_eq!(view.permissions, vec!["act.advance"]);
        assert!(back[0].authz().is_active(OffsetDateTime::UNIX_EPOCH));
    }

    #[test]
    fn a_role_shaped_record_round_trips_on_disk_and_carries_the_suspension() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-roles-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);

        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let mut inner =
            Delegation::with_roles(uid(1), uid(2), [rid(1), rid(2)], Scope::Global).unwrap();
        inner.suspended = true;
        let stored = StoredDelegation::new(DelegationId(Uuid::from_u128(1)), granted_at, inner);
        let mut table: HashMap<DelegationId, StoredDelegation> = HashMap::new();
        table.insert(stored.id, stored.clone());

        write_delegations_atomic(&path, &table).expect("write");
        let loaded = load_delegations(&path).expect("load");
        assert_eq!(loaded[&stored.id], stored);
        assert_eq!(loaded[&stored.id].authz().roles(), [rid(1), rid(2)]);
        // Suspension survives the round trip and still yields no authority.
        assert!(loaded[&stored.id].authz().suspended);
        assert!(
            !loaded[&stored.id]
                .authz()
                .is_active(OffsetDateTime::UNIX_EPOCH)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_multi_permission_record_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!("chancela-deleg-multi-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DELEGATIONS_FILE);

        let granted_at = OffsetDateTime::UNIX_EPOCH.format(&Rfc3339).unwrap();
        let stored = StoredDelegation::new(
            DelegationId(Uuid::from_u128(1)),
            granted_at,
            Delegation::with_permissions(
                uid(1),
                uid(2),
                [Permission::ActAdvance, Permission::DataBackup],
                Scope::Global,
            )
            .unwrap(),
        );
        let mut table: HashMap<DelegationId, StoredDelegation> = HashMap::new();
        table.insert(stored.id, stored.clone());

        write_delegations_atomic(&path, &table).expect("write");
        let loaded = load_delegations(&path).expect("load");
        assert_eq!(loaded[&stored.id], stored);
        assert_eq!(
            loaded[&stored.id].authz().permissions(),
            vec![Permission::ActAdvance, Permission::DataBackup]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_grant_legal_basis_is_required_trimmed_and_bounded() {
        let err = normalize_grant_legal_basis(None).expect_err("missing basis");
        assert!(matches!(err, ApiError::Unprocessable(message) if message.contains("required")));

        let err = normalize_grant_legal_basis(Some(" \t\n ".to_owned())).expect_err("blank basis");
        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("must not be empty"))
        );

        let too_long = "x".repeat(MAX_DELEGATION_LEGAL_BASIS_CHARS + 1);
        let err = normalize_grant_legal_basis(Some(too_long)).expect_err("overlong basis");
        assert!(matches!(err, ApiError::Unprocessable(message) if message.contains("at most")));

        let ok = normalize_grant_legal_basis(Some("  board minute R-17  ".to_owned()))
            .expect("trimmed legal basis");
        assert_eq!(ok, "board minute R-17");
    }
}
