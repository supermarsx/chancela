//! The authority an API key confers — its `principal_grant` (t65 plan §3.1).
//!
//! A key grants authority in one of two shapes, both reusing the frozen `chancela-authz` model:
//!
//! - [`ApiKeyGrant::Role`] — the key is assigned a catalog [`Role`](chancela_authz::Role) at a
//!   [`Scope`] (resolved through the [`RoleCatalog`] at auth time, so editing the role edits the key).
//! - [`ApiKeyGrant::Perms`] — the key holds an explicit, scoped [`Permission`] set.
//!
//! In both cases the grant reduces to a set of `(Permission, Scope)` pairs ([`ApiKeyGrant::grant_pairs`]).
//! Those pairs are the raw material the attenuation invariant and the principal seam operate on. A
//! grant that resolves to **no** pairs (a missing role, an empty permission set) is a *powerless* key.

use std::collections::BTreeSet;

use chancela_authz::{Permission, RoleCatalog, RoleId, Scope};
use serde::{Deserialize, Serialize};

/// What authority an API key confers. Persisted on the [`crate::ApiKey`]. Reuses `chancela-authz`'s
/// [`Scope`] and [`Permission`] so an api key sits in exactly the same authorization model as a
/// session — there is no parallel permission vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyGrant {
    /// A catalog role, at a scope. Resolved through the [`RoleCatalog`] at auth time (a missing role
    /// contributes nothing — fail-closed), so the key auto-tracks edits to that role.
    Role { role_id: RoleId, scope: Scope },
    /// An explicit permission set, at a scope.
    Perms {
        permissions: BTreeSet<Permission>,
        scope: Scope,
    },
}

impl ApiKeyGrant {
    /// A role-assignment grant.
    #[must_use]
    pub fn role(role_id: RoleId, scope: Scope) -> Self {
        ApiKeyGrant::Role { role_id, scope }
    }

    /// An explicit scoped permission-set grant.
    #[must_use]
    pub fn perms(permissions: impl IntoIterator<Item = Permission>, scope: Scope) -> Self {
        ApiKeyGrant::Perms {
            permissions: permissions.into_iter().collect(),
            scope,
        }
    }

    /// The single scope this grant applies at.
    #[must_use]
    pub fn scope(&self) -> Scope {
        match self {
            ApiKeyGrant::Role { scope, .. } | ApiKeyGrant::Perms { scope, .. } => *scope,
        }
    }

    /// The `(Permission, Scope)` pairs this grant confers, resolving a [`ApiKeyGrant::Role`] through
    /// `roles`. A role absent from the catalog resolves to **no** pairs (fail-closed): a key pointing
    /// at a deleted role is powerless, never over-powerful.
    #[must_use]
    pub fn grant_pairs(&self, roles: &RoleCatalog) -> Vec<(Permission, Scope)> {
        match self {
            ApiKeyGrant::Role { role_id, scope } => roles
                .get(*role_id)
                .map(|r| r.permission_set.iter().map(|&p| (p, *scope)).collect())
                .unwrap_or_default(),
            ApiKeyGrant::Perms { permissions, scope } => {
                permissions.iter().map(|&p| (p, *scope)).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_authz::{COMPANY_OWNER_ROLE_ID, OWNER_ROLE_ID, RoleId};
    use uuid::Uuid;

    #[test]
    fn role_grant_resolves_through_catalog() {
        let cat = RoleCatalog::seeded_defaults();
        let g = ApiKeyGrant::role(COMPANY_OWNER_ROLE_ID, Scope::Global);
        let pairs = g.grant_pairs(&cat);
        // Every pair is at Global and is a Gestor permission.
        let gestor = cat.get(COMPANY_OWNER_ROLE_ID).unwrap();
        assert_eq!(pairs.len(), gestor.permission_set.len());
        assert!(pairs.iter().all(|&(_, s)| s == Scope::Global));
        assert!(
            pairs
                .iter()
                .all(|&(p, _)| gestor.permission_set.contains(&p))
        );
    }

    #[test]
    fn missing_role_is_powerless() {
        let cat = RoleCatalog::new(); // empty — Owner not present
        let g = ApiKeyGrant::role(OWNER_ROLE_ID, Scope::Global);
        assert!(g.grant_pairs(&cat).is_empty());
    }

    #[test]
    fn unknown_role_id_is_powerless() {
        let cat = RoleCatalog::seeded_defaults();
        let g = ApiKeyGrant::role(RoleId(Uuid::from_u128(0xDEAD)), Scope::Global);
        assert!(g.grant_pairs(&cat).is_empty());
    }

    #[test]
    fn perms_grant_pairs_each_permission_at_the_scope() {
        let cat = RoleCatalog::new();
        let g = ApiKeyGrant::perms([Permission::EntityRead, Permission::ActRead], Scope::Global);
        let mut pairs = g.grant_pairs(&cat);
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                (Permission::EntityRead, Scope::Global),
                (Permission::ActRead, Scope::Global),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
        );
    }
}
