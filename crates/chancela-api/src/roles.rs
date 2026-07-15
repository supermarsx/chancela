//! The role catalog store (`roles.json`) + the no-lockout role migration and the principal
//! resolution seam (t64-E2).
//!
//! Mirrors the `users.json` discipline (atomic write-through, malformed-tolerant load,
//! `#[serde(default)]` throughout the [`chancela_authz`] model): a `roles.json` array of
//! [`Role`]s is loaded into a [`RoleCatalog`], the seeded defaults are **ensured present** on load
//! ([`ensure_seeded_defaults`]) with the protected **Owner** role always forced to its canonical,
//! locked definition, and legacy `users.json` files are brought forward by
//! [`migrate_roles`] (sole/first user ⇒ Owner\@Global, the rest ⇒ Gestor\@Global) — idempotent and
//! anti-lockout.
//!
//! The **principal resolution seam** ([`effective_permissions_for`] /
//! [`resolve_principal_id`] / [`effective_permissions_for_actor`]) folds a principal's role
//! assignments (from their [`User`] record), the role catalog, and the active delegations addressed
//! to them into a [`ScopedPermissionSet`] via [`chancela_authz::effective_permissions`]. This is the
//! **frozen** signature E3's `require_permission` and t65's api-key principal compute against; it is
//! deliberately NOT wired into any endpoint yet.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use chancela_authz::{
    BookId as AuthzBookId, Delegation, EntityId as AuthzEntityId, GESTOR_ROLE_ID, OWNER_ROLE_ID,
    Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope, ScopedPermissionSet,
    TenantId as AuthzTenantId, UserId as AuthzUserId, count_owner_admin_holders,
    effective_permissions, last_owner_guard,
};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden};
use crate::error::ApiError;
use crate::session::{RoleAssignmentView, ScopeView};
use crate::users::{User, UserId};

pub const ROLES_FILE: &str = "roles.json";

/// Load the role catalog from a `roles.json` array, or `None` when the file is absent or malformed
/// (mirrors [`crate::users::load_users`] — a bad file never blocks startup, it falls back to the
/// seeded defaults). Duplicate ids collapse to the last occurrence (via [`FromIterator`]).
pub(crate) fn load_roles(path: &Path) -> Option<RoleCatalog> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<Role>>(&bytes) {
        Ok(list) => Some(list.into_iter().collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid roles document ({e}); ignoring it (falling back to \
                 the seeded defaults)",
                path.display()
            );
            None
        }
    }
}

/// Ensure the seeded default roles are present in `catalog`, returning whether it was changed
/// (so the caller persists exactly once, like the migration).
///
/// - **Owner** is always forced to its canonical, protected, all-permissions definition — its
///   permission-set is *locked* (plan §2.2/§2.3), so a tampered `roles.json` can never weaken the
///   escalation ceiling. If the stored Owner already equals the canonical one this is a no-op.
/// - Non-Owner seeded roles are inserted only when **absent** — they are editable, so a customised
///   one is never clobbered.
pub(crate) fn ensure_seeded_defaults(catalog: &mut RoleCatalog) -> bool {
    let mut changed = false;

    // The protected Owner is always canonical (locked permission-set, undeletable).
    let owner = Role::owner();
    if catalog.get(OWNER_ROLE_ID) != Some(&owner) {
        catalog.insert(owner);
        changed = true;
    }

    // The editable defaults are seeded only if missing (never overwrite a customised role).
    for role in chancela_authz::default_roles()
        .into_iter()
        .filter(|role| role.id != OWNER_ROLE_ID)
    {
        if catalog.get(role.id).is_none() {
            catalog.insert(role);
            changed = true;
        }
    }

    changed
}

/// Atomically write the catalog to `roles.json` (tmp file + rename), roles sorted by id for a
/// deterministic document. Mirrors [`crate::users::write_users_atomic`].
pub(crate) fn write_roles_atomic(path: &Path, catalog: &RoleCatalog) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut list: Vec<&Role> = catalog.iter().collect();
    list.sort_by_key(|r| r.id.0);
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, ROLES_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Persist the live role catalog through to `roles.json` when the state is file-backed. A no-op for
/// pure in-memory state (`roles_path` is `None`). Call after any catalog mutation (E4).
pub(crate) async fn persist_roles(state: &AppState) -> Result<(), ApiError> {
    // wp16 P3b: route to the active source (Postgres `roles` table, else `roles.json`). File
    // behaviour on SQLite/single-node is unchanged.
    crate::sidecar_store::persist_roles(state).await
}

fn tmp_path(path: &Path, fallback: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| fallback.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

/// **Role migration (no lockout — CRITICAL).** Bring a legacy `users.json` forward by giving every
/// user with **no** role assignments a sensible default, in a single idempotent pass:
///
/// - the **sole / earliest** user (by `created_at`, then id) becomes **Owner\@Global** — but only
///   when no Owner\@Global holder already exists (so an already-migrated set, or a fresh install
///   whose first user was bootstrapped Owner, never mints a second super-user);
/// - every other unassigned user becomes **Gestor\@Global**.
///
/// Returns whether any user was changed (so the caller rewrites `users.json` exactly once). Running
/// it again is a **no-op** (no user is left unassigned). Guarantees: old files load, ≥1 Owner
/// exists whenever ≥1 user exists, and nobody is ever locked out.
pub(crate) fn migrate_roles(users: &mut HashMap<UserId, User>) -> bool {
    // The migration targets: users that hold no role assignment, earliest first.
    let mut unassigned: Vec<UserId> = users
        .values()
        .filter(|u| u.role_assignments.is_empty())
        .map(|u| u.id)
        .collect();
    if unassigned.is_empty() {
        return false;
    }
    unassigned.sort_by(|a, b| {
        let ca = users.get(a).map(|u| u.created_at.as_str()).unwrap_or("");
        let cb = users.get(b).map(|u| u.created_at.as_str()).unwrap_or("");
        ca.cmp(cb).then(a.0.cmp(&b.0))
    });

    // If an administrative Owner already exists (already-migrated / bootstrapped), the first
    // unassigned user does NOT become a second Owner — everyone unassigned defaults to Gestor.
    let owner_exists = users.values().any(|u| {
        u.role_assignments
            .iter()
            .any(RoleAssignment::is_owner_admin)
    });

    for (i, uid) in unassigned.iter().enumerate() {
        let assignment = if !owner_exists && i == 0 {
            RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)
        } else {
            RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)
        };
        if let Some(u) = users.get_mut(uid) {
            u.role_assignments = vec![assignment];
        }
    }
    true
}

/// The role assignment a **newly created** user receives (bootstrap rule, plan §5): the first user
/// on a fresh install (`bootstrap == true`, i.e. zero users existed) becomes **Owner\@Global**;
/// every subsequent user becomes **Gestor\@Global**. Used by `create_user`.
#[must_use]
pub(crate) fn bootstrap_assignment(bootstrap: bool) -> RoleAssignment {
    if bootstrap {
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)
    } else {
        RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)
    }
}

// =================================================================================================
// Principal resolution seam (FROZEN — E3 `require_permission` + t65 api-key principal call these).
// =================================================================================================

/// **FROZEN (t64-E2).** Compute a principal's effective scoped permissions from the durable stores.
///
/// `principal` is the resolved user id — a session user (via [`resolve_principal_id`]) or, for t65,
/// the user an api-key is bound to. Reads that user's `role_assignments`, the live [`RoleCatalog`],
/// and the **active** delegations addressed to `principal`, revalidating each delegation's grantor
/// against current active users + direct role authority, and folds them through
/// [`chancela_authz::effective_permissions`] evaluated at `now`.
///
/// **Fail-closed:** an unknown or **inactive** principal yields an EMPTY [`ScopedPermissionSet`]
/// (no authority anywhere), never an error — matching the t65 "pass an empty set if the creator is
/// gone/inactive" contract. Callers that need a check compose the result with
/// [`chancela_authz::has_permission`] (E3), supplying the book→entity relation there.
pub async fn effective_permissions_for(
    state: &AppState,
    principal: UserId,
    now: OffsetDateTime,
) -> ScopedPermissionSet {
    // The principal's role assignments, or an empty authority for an unknown / inactive user.
    let (assignments, grantor_assignments): (
        Vec<RoleAssignment>,
        HashMap<AuthzUserId, Vec<RoleAssignment>>,
    ) = {
        let users = state.users.read().await;
        let assignments = match users.get(&principal) {
            Some(u) if u.active => u.role_assignments.clone(),
            _ => return ScopedPermissionSet::new(),
        };
        let grantor_assignments = users
            .values()
            .filter(|u| u.active)
            .map(|u| (AuthzUserId(u.id.0), u.role_assignments.clone()))
            .collect();
        (assignments, grantor_assignments)
    };

    let stored_delegations: Vec<Delegation> = {
        let table = state.delegations.read().await;
        table.values().map(|d| d.authz().clone()).collect()
    };

    let book_relation = current_book_relation(state).await;
    let books = |b: AuthzBookId| book_relation.get(&b).copied();
    let roles = state.roles.read().await;
    let grantor_role_authority: HashMap<AuthzUserId, ScopedPermissionSet> = grantor_assignments
        .iter()
        .map(|(&grantor, assignments)| {
            (
                grantor,
                effective_permissions(grantor, assignments, &roles, &[], now),
            )
        })
        .collect();
    let delegations: Vec<Delegation> = stored_delegations
        .into_iter()
        .filter(|d| {
            grantor_role_authority
                .get(&d.from)
                .is_some_and(|eff| eff.has_via_role(d.permission, d.scope, &books))
        })
        .collect();

    effective_permissions(
        AuthzUserId(principal.0),
        &assignments,
        &roles,
        &delegations,
        now,
    )
}

async fn current_book_relation(state: &AppState) -> HashMap<AuthzBookId, AuthzEntityId> {
    let books = state.books.read().await;
    books
        .values()
        .map(|b| (AuthzBookId(b.id.0), AuthzEntityId(b.entity_id.0)))
        .collect()
}

/// **FROZEN (t64-E2).** Resolve the session user behind a [`CurrentActor`] to their [`UserId`].
///
/// The [`CurrentActor`] extractor already rejects an absent/invalid session with `401`; this maps
/// the resolved username to the user record. A session whose username no longer names an **active**
/// user is `403` (fail-closed) — never a silent success.
pub async fn resolve_principal_id(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<UserId, ApiError> {
    if actor.is_api_key() {
        return Err(ApiError::Forbidden(
            "chave API não abre uma sessão interativa".to_owned(),
        ));
    }
    let username = actor
        .session_username()
        .ok_or_else(|| ApiError::Unauthorized("sessão requerida".to_owned()))?;
    let users = state.users.read().await;
    users
        .values()
        .find(|u| u.active && u.username == username)
        .map(|u| u.id)
        .ok_or_else(|| ApiError::Forbidden("sessão sem utilizador ativo".to_owned()))
}

/// **FROZEN (t64-E2).** Convenience for E3: resolve the session actor to `(principal, effective
/// permissions)` in one call. `401`/`403` if the session does not name an active user.
pub async fn effective_permissions_for_actor(
    state: &AppState,
    actor: &CurrentActor,
    now: OffsetDateTime,
) -> Result<(UserId, ScopedPermissionSet), ApiError> {
    let principal = resolve_principal_id(state, actor).await?;
    let effective = effective_permissions_for(state, principal, now).await;
    Ok((principal, effective))
}

// =================================================================================================
// Last-Owner guard (exposed here; E4 wires it into owner-revocation / user-deactivation).
// =================================================================================================

/// Count the principals holding an **administrative Owner** assignment (Owner role @ `Global`)
/// across all **active** users. Deduplicates by principal. The input to [`last_owner_guard`].
///
/// Only active users count: an inactive user confers no authority
/// ([`effective_permissions_for`] returns an empty set for them), so an inactive Owner does not
/// keep the instance administrable and must not satisfy the last-Owner guard.
pub async fn count_owner_admins(state: &AppState) -> usize {
    let users = state.users.read().await;
    let pairs = users.values().filter(|u| u.active).flat_map(|u| {
        let uid = AuthzUserId(u.id.0);
        u.role_assignments.iter().map(move |a| (uid, a))
    });
    count_owner_admin_holders(pairs)
}

/// **Last-Owner guard.** Whether it is currently safe to remove *one* administrative Owner (revoke
/// an Owner\@Global assignment, deactivate an Owner user, etc.) — i.e. more than one holder exists,
/// so ≥1 Owner always remains and the instance can never reach a no-super-user / locked-out state.
/// Exposed for E4; not yet wired into any endpoint. Mirrors the t45 last-active-user guard.
pub async fn last_owner_guard_ok(state: &AppState) -> bool {
    last_owner_guard(count_owner_admins(state).await)
}

// =================================================================================================
// RBAC-management endpoints (t64-E4): role CRUD + scoped role assignment. Every mutation composes the
// meta gate (`role.manage`/`role.assign`) with the escalation invariants (subset / protected-Owner /
// last-Owner), all enforced **server-side** and fail-closed. FROZEN wire DTOs for t64-E6 + t62.
// =================================================================================================

/// A [`Scope`] on the wire (request bodies). Tagged union mirroring the output
/// [`ScopeView`](crate::session::ScopeView): `{"kind":"global"}` / `{"kind":"entity","id":".."}` /
/// `{"kind":"book","id":".."}`. FROZEN for E6/t62.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScopeInput {
    Global,
    /// A tenant scope (wp26 tenancy): `{"kind":"tenant","id":".."}`. Lets an operator assign/delegate
    /// at the tenant isolation boundary so a Tenant Administrator is finally backed by a real scope.
    Tenant {
        id: Uuid,
    },
    Entity {
        id: Uuid,
    },
    Book {
        id: Uuid,
    },
}

impl From<ScopeInput> for Scope {
    fn from(s: ScopeInput) -> Self {
        match s {
            ScopeInput::Global => Scope::Global,
            ScopeInput::Tenant { id } => Scope::Tenant(AuthzTenantId(id)),
            ScopeInput::Entity { id } => Scope::Entity(AuthzEntityId(id)),
            ScopeInput::Book { id } => Scope::Book(AuthzBookId(id)),
        }
    }
}

/// Read-only drift diagnostics for an editable seeded role. Missing permissions are permissions the
/// current persisted role lacks compared with the current default seed; they are never reconciled by
/// this view.
#[derive(Debug, Serialize)]
pub struct SeededRoleDriftView {
    pub missing_default_permissions: Vec<String>,
    pub requires_manual_review: bool,
}

/// A role rendered for the web (FROZEN for E6/t62). `permissions` are dotted verb ids in the role's
/// deterministic (`BTreeSet`) order; `protected` marks the locked, undeletable Owner.
#[derive(Debug, Serialize)]
pub struct RoleView {
    pub id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub protected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seeded_role_drift: Option<SeededRoleDriftView>,
}

impl From<&Role> for RoleView {
    fn from(r: &Role) -> Self {
        let seeded_role_drift = seeded_role_drift(r);
        RoleView {
            id: r.id.0.to_string(),
            name: r.name.clone(),
            permissions: r
                .permission_set
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect(),
            protected: r.protected,
            seeded_role_drift,
        }
    }
}

fn seeded_role_drift(role: &Role) -> Option<SeededRoleDriftView> {
    let missing_default_permissions = seeded_missing_defaults(role).ok()?;
    let missing_default_permissions = permission_strings(&missing_default_permissions);
    let requires_manual_review = !missing_default_permissions.is_empty();
    Some(SeededRoleDriftView {
        missing_default_permissions,
        requires_manual_review,
    })
}

/// Explicit admin-guided reconciliation proposal/apply result for an editable seeded role. The
/// server only ever proposes/applies missing current seed defaults; extra customised permissions are
/// preserved and removals are never proposed.
#[derive(Debug, Serialize)]
pub struct SeededRoleReconciliationView {
    pub role_id: String,
    pub role_name: String,
    pub current_permissions: Vec<String>,
    pub missing_default_permissions: Vec<String>,
    pub proposed_permissions: Vec<String>,
    pub applied_permissions: Vec<String>,
    pub applied: bool,
    pub requires_manual_review: bool,
}

#[derive(Debug, Serialize)]
struct SeededRoleReconciliationEvent {
    role_id: String,
    role_name: String,
    before_permissions: Vec<String>,
    added_permissions: Vec<String>,
    after_permissions: Vec<String>,
}

fn permission_strings(permissions: &BTreeSet<Permission>) -> Vec<String> {
    permissions.iter().map(|p| p.as_str().to_owned()).collect()
}

fn seeded_missing_defaults(role: &Role) -> Result<BTreeSet<Permission>, ApiError> {
    let seeded = chancela_authz::default_roles()
        .into_iter()
        .find(|seeded| seeded.id == role.id)
        .ok_or_else(|| {
            ApiError::Conflict("a função não é uma função semeada reconciliável".to_owned())
        })?;
    if seeded.protected || role.protected || role.id == OWNER_ROLE_ID {
        return Err(ApiError::Conflict(
            "a função Proprietário está excluída da reconciliação".to_owned(),
        ));
    }
    Ok(seeded
        .permission_set
        .difference(&role.permission_set)
        .copied()
        .collect())
}

fn seeded_reconciliation_proposal(
    role: &Role,
) -> Result<(BTreeSet<Permission>, BTreeSet<Permission>), ApiError> {
    let missing = seeded_missing_defaults(role)?;
    let mut proposed = role.permission_set.clone();
    proposed.extend(missing.iter().copied());
    Ok((missing, proposed))
}

fn seeded_reconciliation_view(
    role: &Role,
    missing_default_permissions: &BTreeSet<Permission>,
    proposed_permissions: &BTreeSet<Permission>,
    applied_permissions: &BTreeSet<Permission>,
    applied: bool,
) -> SeededRoleReconciliationView {
    SeededRoleReconciliationView {
        role_id: role.id.0.to_string(),
        role_name: role.name.clone(),
        current_permissions: permission_strings(&role.permission_set),
        missing_default_permissions: permission_strings(missing_default_permissions),
        proposed_permissions: permission_strings(proposed_permissions),
        applied_permissions: permission_strings(applied_permissions),
        applied,
        requires_manual_review: !missing_default_permissions.is_empty(),
    }
}

/// One verb in the permission catalog (`GET /v1/permissions`), tagged with whether it is a
/// non-delegable meta-permission. Lets the web render the permission-matrix editor (FROZEN).
#[derive(Serialize)]
pub struct PermissionInfo {
    pub permission: String,
    pub meta: bool,
}

/// Response of `GET /v1/permissions`: the whole frozen verb catalog, in declaration order.
#[derive(Serialize)]
pub struct PermissionCatalogView {
    pub permissions: Vec<PermissionInfo>,
}

/// Body of `POST /v1/roles`. Unknown verb ids are rejected at deserialisation (a `422`).
#[derive(Deserialize)]
pub struct CreateRole {
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

/// Body of `PATCH /v1/roles/{id}`. Absent fields leave that facet unchanged.
#[derive(Deserialize)]
pub struct PatchRole {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub permissions: Option<Vec<Permission>>,
}

/// Body of `POST`/`DELETE /v1/users/{id}/roles` — the `(role, scope)` assignment to add or remove.
#[derive(Deserialize)]
pub struct RoleAssignmentInput {
    pub role_id: Uuid,
    pub scope: ScopeInput,
}

/// The `role.assigned`/`role.unassigned` audit payload (no user secrets — attribution only).
#[derive(Serialize)]
struct AssignmentEvent {
    user_id: String,
    role_id: String,
    scope: ScopeView,
}

fn validate_role_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::Unprocessable(
            "role name must not be empty".to_owned(),
        ));
    }
    if name.chars().count() > 64 {
        return Err(ApiError::Unprocessable(
            "role name must be at most 64 characters".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

fn assignment_views(assignments: &[RoleAssignment]) -> Vec<RoleAssignmentView> {
    assignments
        .iter()
        .map(|a| RoleAssignmentView {
            role_id: a.role_id.0.to_string(),
            scope: ScopeView::from(a.scope),
        })
        .collect()
}

/// Persist the user directory after a role-assignment change (mirrors `users::persist`, which is
/// private). wp16 P3b: routes to the active source (Postgres `users` table, else `users.json`).
async fn persist_users(state: &AppState) -> Result<(), ApiError> {
    crate::sidecar_store::persist_users(state).await
}

/// Append a chained `role.*` audit event (honest actor, never any secret material). Mirrors the
/// standard append + write-through + attest discipline.
///
/// `scope_id` **must be a keyword-shaped application scope** (e.g. `user:{uuid}` / `role:{uuid}`),
/// never a *bare* UUID. A bare UUID is classified by the ledger as a `company:{uuid}` book-action
/// chain whose genesis event kind is required to be `entity.created` (WFL-11); a `role.*` event as
/// that chain's genesis would fail `Ledger::verify()` after the mutation. A keyword scope lands the
/// event on the shared `application` audit chain (which fixes no genesis kind), keeping the ledger
/// verify()-healthy after every RBAC change (wp19-fix).
async fn record_role_event<T: Serialize>(
    state: &AppState,
    scope_id: &str,
    kind: &str,
    justification: &str,
    payload: &T,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(payload)?;
    let actor_name = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    ledger.append(&actor_name, scope_id, kind, Some(justification), &bytes);
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

/// `GET /v1/roles` — the role catalog. Any valid session (`401` without one; `403` if the session
/// names no active user). Introspection the web needs to render the access matrix — no specific
/// permission.
pub async fn list_roles(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<RoleView>>, ApiError> {
    resolve_principal_id(&state, &actor).await?;
    let roles = state.roles.read().await;
    let mut list: Vec<RoleView> = roles.iter().map(RoleView::from).collect();
    list.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(Json(list))
}

/// `GET /v1/permissions` — the frozen verb catalog. Any valid session (as [`list_roles`]).
pub async fn list_permissions(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<PermissionCatalogView>, ApiError> {
    resolve_principal_id(&state, &actor).await?;
    let permissions = Permission::ALL
        .iter()
        .map(|p| PermissionInfo {
            permission: p.as_str().to_owned(),
            meta: p.is_meta(),
        })
        .collect();
    Ok(Json(PermissionCatalogView { permissions }))
}

/// `GET /v1/roles/{id}/seeded-drift-reconciliation` — dry-run proposal for an editable seeded role.
/// Gated by `role.manage` because it is the review step for a privileged write path. It never
/// mutates state and never includes Owner.
pub async fn seeded_role_reconciliation_proposal(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
) -> Result<Json<SeededRoleReconciliationView>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::RoleManage, Scope::Global)?;

    let role_id = RoleId(id);
    let role = state
        .roles
        .read()
        .await
        .get(role_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let (missing, proposed) = seeded_reconciliation_proposal(&role)?;
    Ok(Json(seeded_reconciliation_view(
        &role,
        &missing,
        &proposed,
        &BTreeSet::new(),
        false,
    )))
}

/// `POST /v1/roles/{id}/seeded-drift-reconciliation` — explicit admin apply for missing seeded
/// defaults. It is idempotent, Owner-excluding, never removes permissions, and still preserves the
/// role-authoring subset invariant against the proposed post-apply permission set.
pub async fn apply_seeded_role_reconciliation(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<SeededRoleReconciliationView>, ApiError> {
    let role_id = RoleId(id);
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::RoleManage, Scope::Global)?;

    let (before, updated, applied_permissions) = {
        let mut roles = state.roles.write().await;
        let before = roles.get(role_id).cloned().ok_or(ApiError::NotFound)?;
        let (missing, proposed) = seeded_reconciliation_proposal(&before)?;
        if !authz.can_define_role(proposed.iter()) {
            return Err(forbidden());
        }
        if missing.is_empty() {
            return Ok(Json(seeded_reconciliation_view(
                &before,
                &missing,
                &proposed,
                &BTreeSet::new(),
                false,
            )));
        }

        let mut updated = before.clone();
        updated.permission_set = proposed;
        roles.insert(updated.clone());
        (before, updated, missing)
    };
    persist_roles(&state).await?;

    let remaining_missing = seeded_missing_defaults(&updated)?;
    let proposed = updated.permission_set.clone();
    let view = seeded_reconciliation_view(
        &updated,
        &remaining_missing,
        &proposed,
        &applied_permissions,
        true,
    );
    let payload = SeededRoleReconciliationEvent {
        role_id: view.role_id.clone(),
        role_name: view.role_name.clone(),
        before_permissions: permission_strings(&before.permission_set),
        added_permissions: permission_strings(&applied_permissions),
        after_permissions: view.current_permissions.clone(),
    };
    record_role_event(
        &state,
        &format!("role:{}", view.role_id),
        "role.seeded_drift_reconciled",
        "admin explicitly applied seeded role drift reconciliation",
        &payload,
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(view))
}

/// `POST /v1/roles` — create a custom role. Gated `role.manage`\@Global, **and** the SUBSET INVARIANT:
/// the whole `permission_set` must be ⊆ the actor's OWN effective authority at Global (holding
/// `role.manage` does not exempt this). New roles are never protected.
pub async fn create_role(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateRole>,
) -> Result<(StatusCode, Json<RoleView>), ApiError> {
    let name = validate_role_name(&req.name)?;
    let permission_set: BTreeSet<Permission> = req.permissions.iter().copied().collect();

    let authz = authorizer(&state, &actor).await?;
    // Meta gate: operate the role machinery.
    authz.require(Permission::RoleManage, Scope::Global)?;
    // SUBSET INVARIANT (escalation guard): cannot mint a role holding a permission you lack.
    if !authz.can_define_role(permission_set.iter()) {
        return Err(forbidden());
    }

    let role = Role {
        id: RoleId(Uuid::new_v4()),
        name,
        permission_set,
        protected: false,
    };
    state.roles.write().await.insert(role.clone());
    persist_roles(&state).await?;

    let view = RoleView::from(&role);
    record_role_event(
        &state,
        &format!("role:{}", view.id),
        "role.created",
        "custom role created",
        &view,
        &actor,
        &attestor,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(view)))
}

/// `PATCH /v1/roles/{id}` — rename and/or re-set a custom role's permissions. Gated `role.manage`.
///
/// **Protected-Owner:** a protected role (Owner) is locked — neither its name nor its permission-set
/// may be edited (`403`), closing the "edit your way out of the escalation ceiling" hole. The
/// **SUBSET INVARIANT** is enforced on the *resulting* permission-set, so an edit can never widen a
/// role beyond the actor's own authority.
pub async fn patch_role(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchRole>,
) -> Result<Json<RoleView>, ApiError> {
    let role_id = RoleId(id);
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::RoleManage, Scope::Global)?;

    let existing = state.roles.read().await.get(role_id).cloned();
    let existing = existing.ok_or(ApiError::NotFound)?;
    // Protected-Owner: the locked super-role is never edited, by anyone.
    if existing.protected {
        return Err(forbidden());
    }

    let new_name = match &req.name {
        Some(n) => validate_role_name(n)?,
        None => existing.name.clone(),
    };
    let new_perms: BTreeSet<Permission> = match &req.permissions {
        Some(p) => p.iter().copied().collect(),
        None => existing.permission_set.clone(),
    };
    // SUBSET INVARIANT on the resulting contents (narrowing is safe; widening beyond own authority is not).
    if !authz.can_define_role(new_perms.iter()) {
        return Err(forbidden());
    }

    let updated = Role {
        id: role_id,
        name: new_name,
        permission_set: new_perms,
        protected: false,
    };
    {
        let mut roles = state.roles.write().await;
        // Re-check under the write lock (protection can only ever be the seeded Owner, but stay honest).
        match roles.get(role_id) {
            None => return Err(ApiError::NotFound),
            Some(r) if r.protected => return Err(forbidden()),
            Some(_) => {}
        }
        roles.insert(updated.clone());
    }
    persist_roles(&state).await?;

    let view = RoleView::from(&updated);
    record_role_event(
        &state,
        &format!("role:{}", view.id),
        "role.updated",
        "custom role updated",
        &view,
        &actor,
        &attestor,
    )
    .await?;
    Ok(Json(view))
}

/// `DELETE /v1/roles/{id}` — delete a custom role. Gated `role.manage`. **Protected-Owner** (and any
/// protected role) is undeletable (`403`). Dangling assignments to a deleted role resolve to no
/// authority (fail-closed), so deletion can only ever *reduce* authority.
pub async fn delete_role(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<StatusCode, ApiError> {
    let role_id = RoleId(id);
    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::RoleManage, Scope::Global)?;

    let removed = {
        let mut roles = state.roles.write().await;
        let target = roles.get(role_id).cloned().ok_or(ApiError::NotFound)?;
        if !target.can_be_deleted() {
            return Err(forbidden());
        }
        // RoleCatalog has no `remove`; rebuild it without the target (FromIterator<Role>).
        let rebuilt: RoleCatalog = roles.iter().filter(|r| r.id != role_id).cloned().collect();
        *roles = rebuilt;
        target
    };
    persist_roles(&state).await?;

    let view = RoleView::from(&removed);
    record_role_event(
        &state,
        &format!("role:{}", view.id),
        "role.deleted",
        "custom role deleted",
        &view,
        &actor,
        &attestor,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/users/{id}/roles` — assign a `(role, scope)` to a user. Gated `role.assign` **at the
/// assignment's scope**, **and** the SUBSET INVARIANT at that scope (the role's perms ⊆ the actor's
/// authority covering `scope`) — so you can never grant authority you do not hold, not even by
/// assigning a pre-existing fat role or Owner. Idempotent (a duplicate assignment is a no-op).
pub async fn assign_role(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RoleAssignmentInput>,
) -> Result<Json<Vec<RoleAssignmentView>>, ApiError> {
    let target_uid = UserId(id);
    let scope: Scope = req.scope.into();
    let role_id = RoleId(req.role_id);

    let authz = authorizer(&state, &actor).await?;
    // Meta gate at the assignment's scope.
    authz.require(Permission::RoleAssign, scope)?;

    let role = state.roles.read().await.get(role_id).cloned();
    let role = role.ok_or(ApiError::NotFound)?;
    // SUBSET INVARIANT @ scope.
    if !authz.can_assign_role(&role, scope) {
        return Err(forbidden());
    }

    let assignment = RoleAssignment::new(role_id, scope);
    let assignments = {
        let mut users = state.users.write().await;
        let user = users.get_mut(&target_uid).ok_or(ApiError::NotFound)?;
        if !user.role_assignments.contains(&assignment) {
            user.role_assignments.push(assignment);
        }
        user.role_assignments.clone()
    };
    persist_users(&state).await?;

    let payload = AssignmentEvent {
        user_id: target_uid.to_string(),
        role_id: role_id.0.to_string(),
        scope: ScopeView::from(scope),
    };
    record_role_event(
        &state,
        &format!("user:{target_uid}"),
        "role.assigned",
        "role assigned to user",
        &payload,
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: signal other nodes to drop the target's cached authority (no-op on single-node).
    state.publish_role_changed(target_uid.0);
    Ok(Json(assignment_views(&assignments)))
}

/// `DELETE /v1/users/{id}/roles` — remove a `(role, scope)` assignment from a user. Gated
/// `role.assign` at the scope. **Last-Owner guard:** removing the last Owner\@Global assignment is
/// refused (`409`) so ≥1 administrative Owner always remains (no lockout). Idempotent for a
/// non-held assignment.
pub async fn unassign_role(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RoleAssignmentInput>,
) -> Result<Json<Vec<RoleAssignmentView>>, ApiError> {
    let target_uid = UserId(id);
    let scope: Scope = req.scope.into();
    let role_id = RoleId(req.role_id);

    let authz = authorizer(&state, &actor).await?;
    authz.require(Permission::RoleAssign, scope)?;

    let assignment = RoleAssignment::new(role_id, scope);
    let assignments = {
        let mut users = state.users.write().await;
        let holds = users
            .get(&target_uid)
            .ok_or(ApiError::NotFound)?
            .role_assignments
            .contains(&assignment);
        // Last-Owner guard (checked under the write lock so two concurrent removals cannot both
        // pass). Only ACTIVE Owner@Global holders count — an inactive Owner confers no authority,
        // so it must not satisfy the guard and let the last active Owner be removed.
        if holds && assignment.is_owner_admin() {
            let holders =
                count_owner_admin_holders(users.values().filter(|u| u.active).flat_map(|u| {
                    let uid = AuthzUserId(u.id.0);
                    u.role_assignments.iter().map(move |a| (uid, a))
                }));
            if !last_owner_guard(holders) {
                return Err(ApiError::Conflict(
                    "não pode remover o último Proprietário".to_owned(),
                ));
            }
        }
        let user = users.get_mut(&target_uid).ok_or(ApiError::NotFound)?;
        user.role_assignments.retain(|a| a != &assignment);
        user.role_assignments.clone()
    };
    persist_users(&state).await?;

    let payload = AssignmentEvent {
        user_id: target_uid.to_string(),
        role_id: role_id.0.to_string(),
        scope: ScopeView::from(scope),
    };
    record_role_event(
        &state,
        &format!("user:{target_uid}"),
        "role.unassigned",
        "role removed from user",
        &payload,
        &actor,
        &attestor,
    )
    .await?;
    // wp16 P3b: signal other nodes to drop the target's cached authority (no-op on single-node).
    state.publish_role_changed(target_uid.0);
    Ok(Json(assignment_views(&assignments)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegations::{DelegationId, StoredDelegation};
    use crate::users::SecretSource;
    use time::format_description::well_known::Rfc3339;

    fn user(id: u128, created_at: &str, assignments: Vec<RoleAssignment>) -> User {
        User {
            id: UserId(Uuid::from_u128(id)),
            username: format!("user{id}"),
            display_name: format!("User {id}"),
            email: None,
            created_at: created_at.to_owned(),
            active: true,
            password_hash: Some("test-password-hash".to_owned()),
            attestation_key: None,
            secret_source: SecretSource::Password,
            recovery_hash: None,
            role_assignments: assignments,
        }
    }

    fn map(users: Vec<User>) -> HashMap<UserId, User> {
        users.into_iter().map(|u| (u.id, u)).collect()
    }

    fn custom_role(id: u128, name: &str, permissions: &[Permission]) -> Role {
        Role {
            id: RoleId(Uuid::from_u128(id)),
            name: name.to_owned(),
            permission_set: permissions.iter().copied().collect(),
            protected: false,
        }
    }

    fn stored_delegation(
        id: u128,
        from: UserId,
        to: UserId,
        permission: Permission,
        scope: Scope,
        now: OffsetDateTime,
    ) -> StoredDelegation {
        let did = DelegationId(Uuid::from_u128(id));
        StoredDelegation::new(
            did,
            now.format(&Rfc3339).expect("valid timestamp"),
            Delegation::new(AuthzUserId(from.0), AuthzUserId(to.0), permission, scope),
        )
    }

    async fn state_with_rbac(
        users: Vec<User>,
        roles: RoleCatalog,
        delegations: Vec<StoredDelegation>,
    ) -> AppState {
        let state = AppState::default();
        *state.users.write().await = map(users);
        *state.roles.write().await = roles;
        *state.delegations.write().await = delegations.into_iter().map(|d| (d.id, d)).collect();
        state
    }

    fn permits(eff: &ScopedPermissionSet, permission: Permission, scope: Scope) -> bool {
        chancela_authz::has_permission(eff, permission, scope, &chancela_authz::NoBooks)
    }

    #[tokio::test]
    async fn e4_delegation_roles_active_grantor_with_direct_role_still_works() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let act_role = custom_role(0xA11CE, "Act operator", &[Permission::ActAdvance]);
        let grantor = user(
            1,
            "2026-01-01T00:00:00Z",
            vec![RoleAssignment::new(act_role.id, Scope::Global)],
        );
        let grantee = user(2, "2026-01-02T00:00:00Z", vec![]);
        let delegation = stored_delegation(
            1,
            grantor.id,
            grantee.id,
            Permission::ActAdvance,
            Scope::Global,
            now,
        );
        let state = state_with_rbac(
            vec![grantor, grantee.clone()],
            [act_role].into_iter().collect(),
            vec![delegation],
        )
        .await;

        let eff = effective_permissions_for(&state, grantee.id, now).await;

        assert!(permits(&eff, Permission::ActAdvance, Scope::Global));
        assert!(
            eff.delegated_grants()
                .any(|(p, s)| p == Permission::ActAdvance && s == Scope::Global)
        );
    }

    #[tokio::test]
    async fn e4_delegation_roles_drops_delegation_when_grantor_is_inactive() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let act_role = custom_role(0xA11CE, "Act operator", &[Permission::ActAdvance]);
        let mut grantor = user(
            1,
            "2026-01-01T00:00:00Z",
            vec![RoleAssignment::new(act_role.id, Scope::Global)],
        );
        grantor.active = false;
        let grantee = user(2, "2026-01-02T00:00:00Z", vec![]);
        let delegation = stored_delegation(
            1,
            grantor.id,
            grantee.id,
            Permission::ActAdvance,
            Scope::Global,
            now,
        );
        let state = state_with_rbac(
            vec![grantor, grantee.clone()],
            [act_role].into_iter().collect(),
            vec![delegation],
        )
        .await;

        let eff = effective_permissions_for(&state, grantee.id, now).await;

        assert!(!permits(&eff, Permission::ActAdvance, Scope::Global));
        assert_eq!(state.delegations.read().await.len(), 1);
    }

    #[tokio::test]
    async fn e4_delegation_roles_drops_delegation_when_grantor_loses_role_permission() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let narrowed_role = custom_role(0xA11CE, "Act operator", &[Permission::ActRead]);
        let grantor = user(
            1,
            "2026-01-01T00:00:00Z",
            vec![RoleAssignment::new(narrowed_role.id, Scope::Global)],
        );
        let grantee = user(2, "2026-01-02T00:00:00Z", vec![]);
        let delegation = stored_delegation(
            1,
            grantor.id,
            grantee.id,
            Permission::ActAdvance,
            Scope::Global,
            now,
        );
        let state = state_with_rbac(
            vec![grantor, grantee.clone()],
            [narrowed_role].into_iter().collect(),
            vec![delegation],
        )
        .await;

        let eff = effective_permissions_for(&state, grantee.id, now).await;

        assert!(!permits(&eff, Permission::ActAdvance, Scope::Global));
        assert_eq!(state.delegations.read().await.len(), 1);
    }

    #[tokio::test]
    async fn e4_delegation_roles_grantor_cannot_bootstrap_from_received_delegation() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let act_role = custom_role(0xA11CE, "Act operator", &[Permission::ActAdvance]);
        let delegation_manager = custom_role(
            0xDE1E6A7E,
            "Delegation manager",
            &[Permission::DelegationGrant],
        );
        let owner = user(
            1,
            "2026-01-01T00:00:00Z",
            vec![RoleAssignment::new(act_role.id, Scope::Global)],
        );
        let middle = user(
            2,
            "2026-01-02T00:00:00Z",
            vec![RoleAssignment::new(delegation_manager.id, Scope::Global)],
        );
        let grantee = user(3, "2026-01-03T00:00:00Z", vec![]);
        let received = stored_delegation(
            1,
            owner.id,
            middle.id,
            Permission::ActAdvance,
            Scope::Global,
            now,
        );
        let attempted_bootstrap = stored_delegation(
            2,
            middle.id,
            grantee.id,
            Permission::ActAdvance,
            Scope::Global,
            now,
        );
        let state = state_with_rbac(
            vec![owner, middle.clone(), grantee.clone()],
            [act_role, delegation_manager].into_iter().collect(),
            vec![received, attempted_bootstrap],
        )
        .await;

        let middle_eff = effective_permissions_for(&state, middle.id, now).await;
        assert!(permits(&middle_eff, Permission::ActAdvance, Scope::Global));
        assert!(!middle_eff.has_via_role(
            Permission::ActAdvance,
            Scope::Global,
            &chancela_authz::NoBooks
        ));

        let grantee_eff = effective_permissions_for(&state, grantee.id, now).await;
        assert!(!permits(
            &grantee_eff,
            Permission::ActAdvance,
            Scope::Global
        ));
        assert_eq!(state.delegations.read().await.len(), 2);
    }

    #[test]
    fn roles_json_disk_round_trip_including_a_custom_role() {
        let dir = std::env::temp_dir().join(format!("chancela-roles-rt-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ROLES_FILE);

        let mut cat = RoleCatalog::seeded_defaults();
        let custom = Role {
            id: chancela_authz::RoleId(Uuid::from_u128(0xC0FFEE)),
            name: "Auditor".to_owned(),
            permission_set: [
                chancela_authz::Permission::LedgerRead,
                chancela_authz::Permission::EntityRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        };
        cat.insert(custom.clone());

        write_roles_atomic(&path, &cat).expect("write");
        let loaded = load_roles(&path).expect("load");
        assert_eq!(loaded.len(), chancela_authz::default_roles().len() + 1);
        assert_eq!(loaded.owner().unwrap(), &Role::owner());
        assert_eq!(loaded.get(custom.id).unwrap(), &custom);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_seeded_defaults_seeds_complete_catalog_when_empty() {
        let mut cat = RoleCatalog::new();
        assert!(ensure_seeded_defaults(&mut cat));
        assert_eq!(cat.len(), chancela_authz::default_roles().len());
        assert!(cat.owner().unwrap().protected);
        for role in chancela_authz::default_roles() {
            assert_eq!(cat.get(role.id), Some(&role), "missing {}", role.name);
        }
        // Idempotent: a second pass changes nothing.
        assert!(!ensure_seeded_defaults(&mut cat));
    }

    #[test]
    fn ensure_seeded_defaults_forces_canonical_owner_but_keeps_custom_gestor() {
        let mut cat = RoleCatalog::seeded_defaults();
        // Tamper: weaken Owner (drop its lock + perms) and customise Gestor.
        cat.insert(Role {
            id: OWNER_ROLE_ID,
            name: "Owner".to_owned(),
            permission_set: [chancela_authz::Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        let custom_gestor = Role {
            id: GESTOR_ROLE_ID,
            name: "Gestor Personalizado".to_owned(),
            permission_set: [chancela_authz::Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        };
        cat.insert(custom_gestor.clone());

        assert!(ensure_seeded_defaults(&mut cat));
        // Owner restored to canonical (protected, all permissions).
        let owner = cat.owner().unwrap();
        assert!(owner.protected);
        assert_eq!(owner, &Role::owner());
        // The customised Gestor was NOT clobbered.
        assert_eq!(cat.get(GESTOR_ROLE_ID).unwrap(), &custom_gestor);
    }

    #[test]
    fn ensure_seeded_defaults_inserts_missing_spec_roles_without_clobbering_custom_seed() {
        let custom_api_client = Role {
            id: chancela_authz::API_CLIENT_ROLE_ID,
            name: "API Client Personalizado".to_owned(),
            permission_set: [chancela_authz::Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        };
        let mut cat: RoleCatalog = [Role::owner(), custom_api_client.clone()]
            .into_iter()
            .collect();

        assert!(ensure_seeded_defaults(&mut cat));
        assert_eq!(cat.len(), chancela_authz::default_roles().len());
        assert!(cat.get(chancela_authz::COMPANY_OWNER_ROLE_ID).is_some());
        assert!(
            cat.get(chancela_authz::CORPORATE_SECRETARY_ROLE_ID)
                .is_some()
        );
        assert!(cat.get(chancela_authz::LEGAL_COUNSEL_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::RECORDS_MANAGER_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::SIGNATORY_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::REVIEWER_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::PLATFORM_ADMIN_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::TENANT_ADMIN_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::AUDITOR_ROLE_ID).is_some());
        assert!(cat.get(chancela_authz::GUEST_ROLE_ID).is_some());
        assert_eq!(
            cat.get(chancela_authz::API_CLIENT_ROLE_ID),
            Some(&custom_api_client)
        );
    }

    #[test]
    fn customized_seeded_platform_admin_reports_missing_defaults_without_granting_them() {
        let mut custom_platform_admin = Role::platform_administrator();
        assert!(
            custom_platform_admin
                .permission_set
                .remove(&Permission::PlatformLogsWrite)
        );
        let mut cat: RoleCatalog = [Role::owner(), custom_platform_admin.clone()]
            .into_iter()
            .collect();

        assert!(ensure_seeded_defaults(&mut cat));
        let stored = cat
            .get(chancela_authz::PLATFORM_ADMIN_ROLE_ID)
            .expect("platform administrator remains present");
        assert_eq!(stored, &custom_platform_admin);
        assert!(
            !stored
                .permission_set
                .contains(&Permission::PlatformLogsWrite)
        );

        let view = RoleView::from(stored);
        assert!(!view.permissions.contains(&"platform.logs.write".to_owned()));
        let drift = view
            .seeded_role_drift
            .expect("seeded editable role has status");
        assert!(drift.requires_manual_review);
        assert_eq!(
            drift.missing_default_permissions,
            vec!["platform.logs.write".to_owned()]
        );
    }

    #[test]
    fn migrate_legacy_sole_user_becomes_owner() {
        let mut users = map(vec![user(1, "2026-01-01T00:00:00Z", vec![])]);
        assert!(migrate_roles(&mut users));
        let u = &users[&UserId(Uuid::from_u128(1))];
        assert_eq!(
            u.role_assignments,
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)]
        );
        // Idempotent.
        assert!(!migrate_roles(&mut users));
    }

    #[test]
    fn migrate_legacy_earliest_owner_rest_gestor() {
        let mut users = map(vec![
            user(3, "2026-03-01T00:00:00Z", vec![]),
            user(1, "2026-01-01T00:00:00Z", vec![]),
            user(2, "2026-02-01T00:00:00Z", vec![]),
        ]);
        assert!(migrate_roles(&mut users));
        let owner = RoleAssignment::new(OWNER_ROLE_ID, Scope::Global);
        let gestor = RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global);
        // Earliest (id 1, 2026-01) is the sole Owner; the rest are Gestor.
        assert_eq!(
            users[&UserId(Uuid::from_u128(1))].role_assignments,
            vec![owner]
        );
        assert_eq!(
            users[&UserId(Uuid::from_u128(2))].role_assignments,
            vec![gestor]
        );
        assert_eq!(
            users[&UserId(Uuid::from_u128(3))].role_assignments,
            vec![gestor]
        );
        // Exactly one Owner admin.
        assert_eq!(count_owner_admin_holders(pairs(&users)), 1);
    }

    #[test]
    fn migrate_is_back_compat_and_idempotent_with_existing_owner() {
        // A partially-populated set: one already-assigned Owner + one fresh unassigned user.
        let owner = RoleAssignment::new(OWNER_ROLE_ID, Scope::Global);
        let mut users = map(vec![
            user(1, "2026-01-01T00:00:00Z", vec![owner]),
            user(2, "2026-02-01T00:00:00Z", vec![]),
        ]);
        assert!(migrate_roles(&mut users));
        // The new user becomes Gestor (no second Owner is minted).
        assert_eq!(
            users[&UserId(Uuid::from_u128(2))].role_assignments,
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)]
        );
        assert_eq!(count_owner_admin_holders(pairs(&users)), 1);
        assert!(!migrate_roles(&mut users));
    }

    #[test]
    fn migrate_zero_users_is_noop() {
        let mut users: HashMap<UserId, User> = HashMap::new();
        assert!(!migrate_roles(&mut users));
    }

    fn pairs(users: &HashMap<UserId, User>) -> Vec<(AuthzUserId, &RoleAssignment)> {
        users
            .values()
            .flat_map(|u| {
                let uid = AuthzUserId(u.id.0);
                u.role_assignments.iter().map(move |a| (uid, a))
            })
            .collect()
    }

    #[test]
    fn bootstrap_assignment_first_is_owner_rest_gestor() {
        assert_eq!(
            bootstrap_assignment(true),
            RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)
        );
        assert_eq!(
            bootstrap_assignment(false),
            RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)
        );
    }
}
