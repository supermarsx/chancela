//! Roles as **data** (t64 plan §2.2) and the seeded defaults.
//!
//! A [`Role`] is a named, editable set of permissions — not a fixed enum. The *catalog* of verbs is
//! code ([`crate::Permission`]); which verbs a role grants is stored data. A conservative catalog is
//! seeded on a fresh install: **Owner** (protected — all permissions, locked, undeletable),
//! **Gestor**, **Signatário**, **Leitor**, spec-required company archetypes, **Platform
//! Administrator**, **Tenant Administrator**, **Auditor**, **Guest** and **API Client**. Each seeded
//! role has a **deterministic** id so assignments, migration and the protected-Owner checks are
//! stable across seeds and processes.

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
/// Stable id of the seeded **Platform Administrator** role.
pub const PLATFORM_ADMIN_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x706c617461646d00_0000000000000005));
/// Stable id of the seeded **Tenant Administrator** role.
pub const TENANT_ADMIN_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x74656e61646d0000_0000000000000006));
/// Stable id of the seeded **Auditor** role.
pub const AUDITOR_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x61756469746f7200_0000000000000007));
/// Stable id of the seeded **Guest** role.
pub const GUEST_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x6775657374000000_0000000000000008));
/// Stable id of the seeded **API Client** role.
pub const API_CLIENT_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x617069636c6e7400_0000000000000009));
/// Stable id of the seeded **Company Owner** role.
pub const COMPANY_OWNER_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x636f6f776e720000_000000000000000a));
/// Stable id of the seeded **Corporate Secretary** role.
pub const CORPORATE_SECRETARY_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x636f727073656300_000000000000000b));
/// Stable id of the seeded **Legal Counsel** role.
pub const LEGAL_COUNSEL_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x6c65676c636e7300_000000000000000c));
/// Stable id of the seeded **Records Manager** role.
pub const RECORDS_MANAGER_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x7265636d67720000_000000000000000d));
/// Stable id of the seeded **Signatory** role.
pub const SIGNATORY_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x7369676e74727900_000000000000000e));
/// Stable id of the seeded **Reviewer** role.
pub const REVIEWER_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x7265766965777200_000000000000000f));

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

    /// The seeded **Platform Administrator** role: broad administrative authority, including RBAC
    /// meta-permissions, but not the Owner-only destructive reset/wipe verbs.
    #[must_use]
    pub fn platform_administrator() -> Self {
        Role {
            id: PLATFORM_ADMIN_ROLE_ID,
            name: "Platform Administrator".to_owned(),
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
                Permission::LedgerRead,
                Permission::LedgerRecover,
                Permission::DataBackup,
                Permission::DataExport,
                Permission::SettingsRead,
                Permission::SettingsManage,
                Permission::PlatformLogsWrite,
                Permission::CaeRead,
                Permission::CaeRefresh,
                Permission::LawRead,
                Permission::LawManage,
                Permission::UserRead,
                Permission::UserManage,
                Permission::RoleManage,
                Permission::RoleAssign,
                Permission::DelegationGrant,
                Permission::DelegationRevoke,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Tenant Administrator** role: entity/book/act administration plus scoped
    /// assignment/delegation, without global role-definition, user-management or platform settings
    /// management.
    #[must_use]
    pub fn tenant_administrator() -> Self {
        Role {
            id: TENANT_ADMIN_ROLE_ID,
            name: "Tenant Administrator".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::EntityUpdate,
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
                Permission::LedgerRead,
                Permission::SettingsRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::UserRead,
                Permission::RoleAssign,
                Permission::DelegationGrant,
                Permission::DelegationRevoke,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Auditor** role: non-mutating inspection and export-style read access.
    #[must_use]
    pub fn auditor() -> Self {
        Role {
            id: AUDITOR_ROLE_ID,
            name: "Auditor".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::BookExport,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::SettingsRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::UserRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Guest** role: minimal read-only access, excluding ledger/settings/users.
    #[must_use]
    pub fn guest() -> Self {
        Role {
            id: GUEST_ROLE_ID,
            name: "Guest".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::CaeRead,
                Permission::LawRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **API Client** role: non-meta operational integration permissions suitable for
    /// API-key role grants and later creator-bound attenuation.
    #[must_use]
    pub fn api_client() -> Self {
        Role {
            id: API_CLIENT_ROLE_ID,
            name: "API Client".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::BookExport,
                Permission::ActRead,
                Permission::ActDraft,
                Permission::ActEdit,
                Permission::ActAdvance,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Company Owner** role: an explicit company-level operational owner archetype.
    /// It pins operational permissions directly without inheriting protected Owner or RBAC meta
    /// authority.
    #[must_use]
    pub fn company_owner() -> Self {
        Role {
            id: COMPANY_OWNER_ROLE_ID,
            name: "Company Owner".to_owned(),
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

    /// The seeded **Corporate Secretary** role: governance drafting and signing workflow support,
    /// without entity, user, role, settings, recovery or data authority.
    #[must_use]
    pub fn corporate_secretary() -> Self {
        Role {
            id: CORPORATE_SECRETARY_ROLE_ID,
            name: "Corporate Secretary".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::BookExport,
                Permission::ActRead,
                Permission::ActDraft,
                Permission::ActEdit,
                Permission::ActAdvance,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
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

    /// The seeded **Legal Counsel** role: advisory read access without law-management or workflow
    /// mutation authority.
    #[must_use]
    pub fn legal_counsel() -> Self {
        Role {
            id: LEGAL_COUNSEL_ROLE_ID,
            name: "Legal Counsel".to_owned(),
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

    /// The seeded **Records Manager** role: records intake/export and archival workflow support,
    /// excluding destructive, recovery, settings and RBAC authority.
    #[must_use]
    pub fn records_manager() -> Self {
        Role {
            id: RECORDS_MANAGER_ROLE_ID,
            name: "Records Manager".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::EntityArchive,
                Permission::BookRead,
                Permission::BookOpen,
                Permission::BookClose,
                Permission::BookExport,
                Permission::BookImport,
                Permission::ActRead,
                Permission::ActArchive,
                Permission::DocumentGenerate,
                Permission::LedgerRead,
                Permission::DataExport,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Signatory** role: an explicit English archetype for spec ROL-02 with a pinned
    /// signing workflow permission set.
    #[must_use]
    pub fn signatory() -> Self {
        Role {
            id: SIGNATORY_ROLE_ID,
            name: "Signatory".to_owned(),
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

    /// The seeded **Reviewer** role: review/approval workflow support without signing authority.
    #[must_use]
    pub fn reviewer() -> Self {
        Role {
            id: REVIEWER_ROLE_ID,
            name: "Reviewer".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::ActAdvance,
                Permission::DocumentGenerate,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }
}

/// The seeded default roles, in a stable order. The original four ids/order are preserved first for
/// backwards compatibility.
#[must_use]
pub fn default_roles() -> Vec<Role> {
    vec![
        Role::owner(),
        Role::gestor(),
        Role::signatario(),
        Role::leitor(),
        Role::company_owner(),
        Role::corporate_secretary(),
        Role::legal_counsel(),
        Role::records_manager(),
        Role::signatory(),
        Role::reviewer(),
        Role::platform_administrator(),
        Role::tenant_administrator(),
        Role::auditor(),
        Role::guest(),
        Role::api_client(),
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

    /// The seeded-default catalog.
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

    fn editable_seeded_roles() -> Vec<Role> {
        vec![
            Role::gestor(),
            Role::signatario(),
            Role::leitor(),
            Role::company_owner(),
            Role::corporate_secretary(),
            Role::legal_counsel(),
            Role::records_manager(),
            Role::signatory(),
            Role::reviewer(),
            Role::platform_administrator(),
            Role::tenant_administrator(),
            Role::auditor(),
            Role::guest(),
            Role::api_client(),
        ]
    }

    fn non_admin_seeded_roles() -> Vec<Role> {
        vec![
            Role::gestor(),
            Role::signatario(),
            Role::leitor(),
            Role::company_owner(),
            Role::corporate_secretary(),
            Role::legal_counsel(),
            Role::records_manager(),
            Role::signatory(),
            Role::reviewer(),
            Role::auditor(),
            Role::guest(),
            Role::api_client(),
        ]
    }

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
        for role in editable_seeded_roles() {
            assert!(!role.protected);
            assert!(role.can_be_deleted());
            assert!(role.can_edit_permission_set());
        }
    }

    #[test]
    fn default_roles_are_strict_subsets_of_owner() {
        let owner = Role::owner();
        for role in editable_seeded_roles() {
            assert!(role.permission_set.is_subset(&owner.permission_set));
            assert!(role.permission_set.len() < owner.permission_set.len());
        }
    }

    #[test]
    fn non_admin_roles_exclude_meta_and_destructive_permissions() {
        for role in non_admin_seeded_roles() {
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
    fn administrative_roles_are_the_only_non_owner_defaults_with_meta() {
        for role in [Role::platform_administrator(), Role::tenant_administrator()] {
            assert!(
                Permission::META
                    .iter()
                    .any(|meta| role.permission_set.contains(meta)),
                "{} should carry scoped administrative meta permissions",
                role.name
            );
        }

        for role in non_admin_seeded_roles() {
            assert!(
                role.permission_set.iter().all(|p| !p.is_meta()),
                "{} unexpectedly carries meta permissions",
                role.name
            );
        }
    }

    #[test]
    fn api_client_role_is_api_key_compatible() {
        let role = Role::api_client();
        assert!(!role.permission_set.is_empty());
        assert!(role.permission_set.iter().all(|p| !p.is_meta()));
        for forbidden in [
            Permission::UserManage,
            Permission::SettingsManage,
            Permission::PlatformLogsWrite,
            Permission::LedgerRecover,
            Permission::DataWipe,
            Permission::DataStartOver,
        ] {
            assert!(
                !role.permission_set.contains(&forbidden),
                "API Client has {forbidden}"
            );
        }
    }

    #[test]
    fn seeded_catalog_includes_spec_roles_by_stable_id() {
        let cat = RoleCatalog::seeded_defaults();
        assert_eq!(cat.len(), 15);

        for (id, raw, name) in [
            (
                OWNER_ROLE_ID,
                0x6f776e6572000000_0000000000000001,
                "Proprietário",
            ),
            (
                GESTOR_ROLE_ID,
                0x676573746f720000_0000000000000002,
                "Gestor",
            ),
            (
                SIGNATARIO_ROLE_ID,
                0x7369676e61740000_0000000000000003,
                "Signatário",
            ),
            (
                LEITOR_ROLE_ID,
                0x6c6569746f720000_0000000000000004,
                "Leitor",
            ),
            (
                PLATFORM_ADMIN_ROLE_ID,
                0x706c617461646d00_0000000000000005,
                "Platform Administrator",
            ),
            (
                TENANT_ADMIN_ROLE_ID,
                0x74656e61646d0000_0000000000000006,
                "Tenant Administrator",
            ),
            (
                AUDITOR_ROLE_ID,
                0x61756469746f7200_0000000000000007,
                "Auditor",
            ),
            (GUEST_ROLE_ID, 0x6775657374000000_0000000000000008, "Guest"),
            (
                API_CLIENT_ROLE_ID,
                0x617069636c6e7400_0000000000000009,
                "API Client",
            ),
            (
                COMPANY_OWNER_ROLE_ID,
                0x636f6f776e720000_000000000000000a,
                "Company Owner",
            ),
            (
                CORPORATE_SECRETARY_ROLE_ID,
                0x636f727073656300_000000000000000b,
                "Corporate Secretary",
            ),
            (
                LEGAL_COUNSEL_ROLE_ID,
                0x6c65676c636e7300_000000000000000c,
                "Legal Counsel",
            ),
            (
                RECORDS_MANAGER_ROLE_ID,
                0x7265636d67720000_000000000000000d,
                "Records Manager",
            ),
            (
                SIGNATORY_ROLE_ID,
                0x7369676e74727900_000000000000000e,
                "Signatory",
            ),
            (
                REVIEWER_ROLE_ID,
                0x7265766965777200_000000000000000f,
                "Reviewer",
            ),
        ] {
            assert_eq!(id.0, Uuid::from_u128(raw), "{name} id changed");
            assert_eq!(cat.get(id).unwrap().name, name);
        }
        assert_eq!(cat.owner().unwrap().id, OWNER_ROLE_ID);
    }

    #[test]
    fn explicit_company_archetypes_have_pinned_conservative_defaults() {
        assert_eq!(
            Role::company_owner().permission_set,
            permissions([
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
            ])
        );
        assert_eq!(
            Role::corporate_secretary().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::BookRead,
                Permission::BookExport,
                Permission::ActRead,
                Permission::ActDraft,
                Permission::ActEdit,
                Permission::ActAdvance,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
            ])
        );
        assert_eq!(
            Role::legal_counsel().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
            ])
        );
        assert_eq!(
            Role::records_manager().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::EntityArchive,
                Permission::BookRead,
                Permission::BookOpen,
                Permission::BookClose,
                Permission::BookExport,
                Permission::BookImport,
                Permission::ActRead,
                Permission::ActArchive,
                Permission::DocumentGenerate,
                Permission::LedgerRead,
                Permission::DataExport,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
            ])
        );
        assert_eq!(
            Role::signatory().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::ActAdvance,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
            ])
        );
        assert_eq!(
            Role::reviewer().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::BookRead,
                Permission::ActRead,
                Permission::LedgerRead,
                Permission::ActAdvance,
                Permission::DocumentGenerate,
            ])
        );

        assert!(
            !Role::reviewer()
                .permission_set
                .contains(&Permission::SigningPerform),
            "Reviewer does not receive signing.perform by default"
        );
    }

    #[test]
    fn explicit_company_archetypes_exclude_sensitive_platform_and_meta_authority() {
        for role in [
            Role::company_owner(),
            Role::corporate_secretary(),
            Role::legal_counsel(),
            Role::records_manager(),
            Role::signatory(),
            Role::reviewer(),
        ] {
            for forbidden in [
                Permission::RoleManage,
                Permission::RoleAssign,
                Permission::DelegationGrant,
                Permission::DelegationRevoke,
                Permission::UserManage,
                Permission::SettingsManage,
                Permission::PlatformLogsWrite,
                Permission::LedgerRecover,
                Permission::DataWipe,
                Permission::DataStartOver,
            ] {
                assert!(
                    !role.permission_set.contains(&forbidden),
                    "{} unexpectedly holds {forbidden}",
                    role.name
                );
            }
        }
    }

    fn permissions(perms: impl IntoIterator<Item = Permission>) -> BTreeSet<Permission> {
        perms.into_iter().collect()
    }

    #[test]
    fn platform_log_write_is_seeded_only_to_owner_and_platform_admin() {
        for role in default_roles() {
            let has_write = role.permission_set.contains(&Permission::PlatformLogsWrite);
            match role.id {
                OWNER_ROLE_ID | PLATFORM_ADMIN_ROLE_ID => {
                    assert!(has_write, "{} should hold platform.logs.write", role.name)
                }
                _ => assert!(
                    !has_write,
                    "{} should not hold platform.logs.write by default",
                    role.name
                ),
            }
        }
    }
}
