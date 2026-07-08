//! Roles as **data** (t64 plan §2.2) and the seeded defaults.
//!
//! A [`Role`] is a named, editable set of permissions — not a fixed enum. The *catalog* of verbs is
//! code ([`crate::Permission`]); which verbs a role grants is stored data. Four roles are seeded on a
//! fresh install: **Owner** (protected — all permissions, locked, undeletable), **Gestor**,
//! **Signatário**, **Leitor**. Each seeded role has a **deterministic** id so assignments, migration
//! and the protected-Owner checks are stable across seeds and processes.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::permission::Permission;

/// Opaque identifier of a role. Transparent UUID on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoleId(pub Uuid);

impl std::fmt::Display for RoleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Stable id of the seeded **Owner** (Proprietário) role — the protected super-role. The high bytes
/// spell an ASCII mnemonic so the seeded ids are recognisable in a `roles.json` dump.
pub const OWNER_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x6f776e6572000000_0000000000000001));
/// Stable id of the seeded **Gestor** (Operador) role.
pub const GESTOR_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x676573746f720000_0000000000000002));
/// Stable id of the seeded **Signatário** role.
pub const SIGNATARIO_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x7369676e61740000_0000000000000003));
/// Stable id of the seeded **Leitor** role.
pub const LEITOR_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x6c6569746f720000_0000000000000004));

/// A role: a named, editable permission-set. `protected` marks the Owner super-role — its
/// `permission_set` is locked and it is undeletable (see [`Role::can_be_deleted`] /
/// [`Role::can_edit_permission_set`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    /// The granted verbs. A `BTreeSet` so serialisation is deterministic.
    pub permission_set: BTreeSet<Permission>,
    /// Protected (Owner): permission_set locked, undeletable. `#[serde(default)]` so a legacy role
    /// document without the field loads as unprotected.
    #[serde(default)]
    pub protected: bool,
}

impl Role {
    /// Whether this role may be **deleted**. Protected roles (Owner) may not.
    #[must_use]
    pub fn can_be_deleted(&self) -> bool {
        !self.protected
    }

    /// Whether this role's `permission_set` may be **edited**. Protected roles (Owner) are locked —
    /// even an Owner cannot narrow the Owner role and so "edit their way out" of the escalation
    /// ceiling.
    #[must_use]
    pub fn can_edit_permission_set(&self) -> bool {
        !self.protected
    }

    /// The seeded **Owner** (Proprietário) role: every permission, protected.
    #[must_use]
    pub fn owner() -> Self {
        Role {
            id: OWNER_ROLE_ID,
            name: "Proprietário".to_owned(),
            permission_set: Permission::ALL.into_iter().collect(),
            protected: true,
        }
    }

    /// The seeded **Gestor** (Operador) role: full operational authority over entities, books, acts,
    /// documents and reference data, plus signing, `settings.read`, `ledger.read` and
    /// `data.backup`/`data.export`. Explicitly *not* user/role/delegation management,
    /// `settings.manage`, `ledger.recover`, `data.wipe` or `data.start_over`.
    #[must_use]
    pub fn gestor() -> Self {
        Role {
            id: GESTOR_ROLE_ID,
            name: "Gestor".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::EntityCreate,
                Permission::EntityUpdate,
                Permission::EntityRegistryImport,
                Permission::EntityArchive,
                Permission::BookRead,
                Permission::BookOpen,
                Permission::BookClose,
                Permission::BookExport,
                Permission::BookImport,
                Permission::BookStartOver,
                Permission::BookReopen,
                Permission::ActRead,
                Permission::ActDraft,
                Permission::ActEdit,
                Permission::ActAdvance,
                Permission::ActArchive,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::CaeRead,
                Permission::CaeRefresh,
                Permission::LawRead,
                Permission::LawManage,
                Permission::SettingsRead,
                Permission::LedgerRead,
                Permission::DataBackup,
                Permission::DataExport,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Signatário** role: read across entity/book/act/ledger plus `act.advance`,
    /// `signing.perform` and `document.generate`.
    #[must_use]
    pub fn signatario() -> Self {
        Role {
            id: SIGNATARIO_ROLE_ID,
            name: "Signatário".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::ActAdvance,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Leitor** role: read-only.
    #[must_use]
    pub fn leitor() -> Self {
        Role {
            id: LEITOR_ROLE_ID,
            name: "Leitor".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }
}

/// The seeded default roles, in a stable order (Owner, Gestor, Signatário, Leitor).
#[must_use]
pub fn default_roles() -> Vec<Role> {
    vec![
        Role::owner(),
        Role::gestor(),
        Role::signatario(),
        Role::leitor(),
    ]
}

/// An in-memory lookup of roles by id — the resolved role catalog the API loads from `roles.json`
/// and hands to [`crate::effective_permissions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleCatalog {
    roles: HashMap<RoleId, Role>,
}

impl RoleCatalog {
    /// An empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The seeded-default catalog (Owner/Gestor/Signatário/Leitor).
    #[must_use]
    pub fn seeded_defaults() -> Self {
        default_roles().into_iter().collect()
    }

    /// Insert or replace a role.
    pub fn insert(&mut self, role: Role) {
        self.roles.insert(role.id, role);
    }

    /// Look a role up by id.
    #[must_use]
    pub fn get(&self, id: RoleId) -> Option<&Role> {
        self.roles.get(&id)
    }

    /// The protected Owner role, if present.
    #[must_use]
    pub fn owner(&self) -> Option<&Role> {
        self.roles.get(&OWNER_ROLE_ID)
    }

    /// Number of roles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roles.len()
    }

    /// Whether the catalog is empty (e.g. an absent/empty `roles.json` before seeding).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    /// Iterate over the roles.
    pub fn iter(&self) -> impl Iterator<Item = &Role> {
        self.roles.values()
    }
}

impl FromIterator<Role> for RoleCatalog {
    fn from_iter<I: IntoIterator<Item = Role>>(iter: I) -> Self {
        RoleCatalog {
            roles: iter.into_iter().map(|r| (r.id, r)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_holds_every_permission_and_is_protected() {
        let owner = Role::owner();
        assert!(owner.protected);
        assert!(!owner.can_be_deleted());
        assert!(!owner.can_edit_permission_set());
        for p in Permission::ALL {
            assert!(owner.permission_set.contains(&p), "owner missing {p}");
        }
    }

    #[test]
    fn non_owner_defaults_are_editable_and_deletable() {
        for role in [Role::gestor(), Role::signatario(), Role::leitor()] {
            assert!(!role.protected);
            assert!(role.can_be_deleted());
            assert!(role.can_edit_permission_set());
        }
    }

    #[test]
    fn default_roles_are_strict_subsets_of_owner() {
        let owner = Role::owner();
        for role in [Role::gestor(), Role::signatario(), Role::leitor()] {
            assert!(role.permission_set.is_subset(&owner.permission_set));
            assert!(role.permission_set.len() < owner.permission_set.len());
        }
    }

    #[test]
    fn lesser_roles_exclude_meta_and_destructive() {
        for role in [Role::gestor(), Role::signatario(), Role::leitor()] {
            for meta in Permission::META {
                assert!(
                    !role.permission_set.contains(&meta),
                    "{} has {meta}",
                    role.name
                );
            }
            assert!(!role.permission_set.contains(&Permission::DataWipe));
            assert!(!role.permission_set.contains(&Permission::DataStartOver));
            assert!(!role.permission_set.contains(&Permission::LedgerRecover));
            assert!(!role.permission_set.contains(&Permission::UserManage));
        }
    }

    #[test]
    fn seeded_catalog_resolves_by_stable_id() {
        let cat = RoleCatalog::seeded_defaults();
        assert_eq!(cat.len(), 4);
        assert_eq!(cat.owner().unwrap().id, OWNER_ROLE_ID);
        assert_eq!(cat.get(GESTOR_ROLE_ID).unwrap().name, "Gestor");
    }
}
