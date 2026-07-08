//! The role catalog store (`roles.json`) + the no-lockout role migration and the principal
//! resolution seam (t64-E2).
//!
//! Mirrors the `users.json` discipline (atomic write-through, malformed-tolerant load,
//! `#[serde(default)]` throughout the [`chancela_authz`] model): a `roles.json` array of
//! [`Role`]s is loaded into a [`RoleCatalog`], the four seeded defaults are **ensured present** on
//! load ([`ensure_seeded_defaults`]) with the protected **Owner** role always forced to its
//! canonical, locked definition, and legacy `users.json` files are brought forward by
//! [`migrate_roles`] (sole/first user ⇒ Owner\@Global, the rest ⇒ Gestor\@Global) — idempotent and
//! anti-lockout.
//!
//! The **principal resolution seam** ([`effective_permissions_for`] /
//! [`resolve_principal_id`] / [`effective_permissions_for_actor`]) folds a principal's role
//! assignments (from their [`User`] record), the role catalog, and the active delegations addressed
//! to them into a [`ScopedPermissionSet`] via [`chancela_authz::effective_permissions`]. This is the
//! **frozen** signature E3's `require_permission` and t65's api-key principal compute against; it is
//! deliberately NOT wired into any endpoint yet.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use uuid::Uuid;

use chancela_authz::{
    Delegation, GESTOR_ROLE_ID, OWNER_ROLE_ID, Role, RoleAssignment, RoleCatalog, Scope,
    ScopedPermissionSet, UserId as AuthzUserId, count_owner_admin_holders, effective_permissions,
    last_owner_guard,
};

use crate::AppState;
use crate::actor::CurrentActor;
use crate::error::ApiError;
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

/// Ensure the four seeded default roles are present in `catalog`, returning whether it was changed
/// (so the caller persists exactly once, like the migration).
///
/// - **Owner** is always forced to its canonical, protected, all-permissions definition — its
///   permission-set is *locked* (plan §2.2/§2.3), so a tampered `roles.json` can never weaken the
///   escalation ceiling. If the stored Owner already equals the canonical one this is a no-op.
/// - **Gestor / Signatário / Leitor** are inserted only when **absent** — they are editable, so a
///   customised one is never clobbered.
pub(crate) fn ensure_seeded_defaults(catalog: &mut RoleCatalog) -> bool {
    let mut changed = false;

    // The protected Owner is always canonical (locked permission-set, undeletable).
    let owner = Role::owner();
    if catalog.get(OWNER_ROLE_ID) != Some(&owner) {
        catalog.insert(owner);
        changed = true;
    }

    // The editable defaults are seeded only if missing (never overwrite a customised role).
    for role in [Role::gestor(), Role::signatario(), Role::leitor()] {
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
// Wired by t64-E4 (role-management endpoints); E2 only lands the store + seam.
#[allow(dead_code)]
pub(crate) async fn persist_roles(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.roles_path {
        let roles = state.roles.read().await;
        write_roles_atomic(path, &roles)
            .map_err(|e| ApiError::Internal(format!("failed to persist roles: {e}")))?;
    }
    Ok(())
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
/// and the **active** delegations addressed to `principal`, and folds them through
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
    let assignments: Vec<RoleAssignment> = {
        let users = state.users.read().await;
        match users.get(&principal) {
            Some(u) if u.active => u.role_assignments.clone(),
            _ => return ScopedPermissionSet::new(),
        }
    };

    let delegations: Vec<Delegation> = {
        let table = state.delegations.read().await;
        table.values().map(|d| d.authz().clone()).collect()
    };

    let roles = state.roles.read().await;
    effective_permissions(
        AuthzUserId(principal.0),
        &assignments,
        &roles,
        &delegations,
        now,
    )
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
/// across all users. Deduplicates by principal. The input to [`last_owner_guard`].
pub async fn count_owner_admins(state: &AppState) -> usize {
    let users = state.users.read().await;
    let pairs = users.values().flat_map(|u| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::SecretSource;

    fn user(id: u128, created_at: &str, assignments: Vec<RoleAssignment>) -> User {
        User {
            id: UserId(Uuid::from_u128(id)),
            username: format!("user{id}"),
            display_name: format!("User {id}"),
            created_at: created_at.to_owned(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: SecretSource::Password,
            recovery_hash: None,
            role_assignments: assignments,
        }
    }

    fn map(users: Vec<User>) -> HashMap<UserId, User> {
        users.into_iter().map(|u| (u.id, u)).collect()
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
        assert_eq!(loaded.len(), 5);
        assert_eq!(loaded.owner().unwrap(), &Role::owner());
        assert_eq!(loaded.get(custom.id).unwrap(), &custom);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_seeded_defaults_seeds_all_four_when_empty() {
        let mut cat = RoleCatalog::new();
        assert!(ensure_seeded_defaults(&mut cat));
        assert_eq!(cat.len(), 4);
        assert!(cat.owner().unwrap().protected);
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
