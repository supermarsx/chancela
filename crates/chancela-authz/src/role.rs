//! Roles as **data** (t64 plan §2.2) and the seeded defaults.
//!
//! A [`Role`] is a named, editable set of permissions — not a fixed enum. The *catalog* of verbs is
//! code ([`crate::Permission`]); which verbs a role grants is stored data. A conservative catalog is
//! seeded on a fresh install: **Owner** (protected — all permissions, locked, undeletable), the
//! spec ROL-02 archetypes (**Company Owner**, **Corporate Secretary**, **Legal Counsel**, **Records
//! Manager**, **Signatory**, **Reviewer**, **Platform Administrator**, **Tenant Administrator**,
//! **Auditor**, **Guest**, **API Client**) and **Reader**. Each seeded role has a **deterministic**
//! id so assignments, migration and the protected-Owner checks are stable across seeds and
//! processes.
//!
//! ## Seeded names are English; the UI translates them (t87)
//!
//! Every seeded role's stored `name` is **English**, matching the workspace convention of English
//! identifiers with Portuguese reserved for user-facing copy. The name is not what a pt-PT operator
//! reads: the web client resolves a seeded role's **id** to a localised name through
//! `enum.roleName.<slug>` in the message catalogs (`apps/web/src/i18n/roleNameLabels.ts`).
//! Operator-authored role names are data and are never translated — the client only translates a
//! seeded id whose stored name is still the canonical English one, so renaming a seeded role makes
//! the operator's own words win.
//!
//! ## Retired ids ([`RETIRED_SEEDED_ROLES`])
//!
//! Two seeded roles were **Portuguese-named duplicates** of an English archetype with a
//! byte-identical permission set, and were retired in favour of it. Their ids are never re-seeded
//! and **never reused**, but they remain meaningful forever: they appear in append-only ledger
//! events, which are never rewritten. Both the migration (which reassigns live holders) and the
//! client label map (which still names them, marked retired) key off this table.

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

/// Stable id of the seeded **Owner** role — the protected super-role. The high bytes
/// spell an ASCII mnemonic so the seeded ids are recognisable in a `roles.json` dump.
pub const OWNER_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x6f776e6572000000_0000000000000001));
/// **Retired (t87)** id of the former **Gestor** role — a Portuguese-named duplicate of
/// [`COMPANY_OWNER_ROLE_ID`] with a byte-identical permission set. Never re-seeded, never reused;
/// kept because past ledger events name it. See [`RETIRED_SEEDED_ROLES`].
pub const RETIRED_GESTOR_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x676573746f720000_0000000000000002));
/// **Retired (t87)** id of the former **Signatário** role — a Portuguese-named duplicate of
/// [`SIGNATORY_ROLE_ID`] with a byte-identical permission set. Never re-seeded, never reused; kept
/// because past ledger events name it. See [`RETIRED_SEEDED_ROLES`].
pub const RETIRED_SIGNATARIO_ROLE_ID: RoleId =
    RoleId(Uuid::from_u128(0x7369676e61740000_0000000000000003));
/// Stable id of the seeded **Reader** role.
pub const READER_ROLE_ID: RoleId = RoleId(Uuid::from_u128(0x6c6569746f720000_0000000000000004));
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

/// Retired seeded roles and the surviving role each was merged into: `(retired, successor)`.
///
/// A pair is listed here **only** when the two permission sets were identical, so reassignment
/// grants exactly the authority the holder already had — never more, never less. The retired id is
/// removed from the seeded catalog and is never reused for anything new.
pub const RETIRED_SEEDED_ROLES: &[(RoleId, RoleId)] = &[
    (RETIRED_GESTOR_ROLE_ID, COMPANY_OWNER_ROLE_ID),
    (RETIRED_SIGNATARIO_ROLE_ID, SIGNATORY_ROLE_ID),
];

/// The role a retired id was merged into, or `None` if `id` is not retired.
///
/// This is the whole migration rule: a holder of a retired role becomes a holder of its successor.
#[must_use]
pub fn retired_role_successor(id: RoleId) -> Option<RoleId> {
    RETIRED_SEEDED_ROLES
        .iter()
        .find(|(retired, _)| *retired == id)
        .map(|(_, successor)| *successor)
}

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

/// Why a role is refused as the self-signup default role. See [`Role::signup_default_refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupDefaultRefusal {
    /// The protected Owner role. Self-signup into the super-role is never configurable.
    Protected,
    /// The role holds a permission on [`Permission::SELF_SIGNUP_FORBIDDEN`].
    HoldsPrivilegedPermission(Permission),
}

impl std::fmt::Display for SignupDefaultRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignupDefaultRefusal::Protected => f.write_str(
                "it is the protected Owner role, which self-signup may never grant",
            ),
            SignupDefaultRefusal::HoldsPrivilegedPermission(p) => write!(
                f,
                "it holds {p}, which a self-signed-up account may never receive"
            ),
        }
    }
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

    /// Why this role may **not** be the self-signup default role (t95 §2.6), or `None` if it may.
    ///
    /// Self-signup hands an unauthenticated stranger exactly one role. This is the single shared
    /// predicate behind that ceiling, and it must be consulted from **both** ends:
    ///
    /// 1. when `auth.signup.default_role` is chosen (settings validation), and
    /// 2. when **any** role's permission-set is edited — because the ceiling is otherwise trivially
    ///    bypassable by picking an innocuous role as the signup default and then editing that role
    ///    to hold `settings.manage`.
    ///
    /// Checking only (1) is the bug this function exists to make impossible to write twice.
    #[must_use]
    pub fn signup_default_refusal(&self) -> Option<SignupDefaultRefusal> {
        if self.protected {
            return Some(SignupDefaultRefusal::Protected);
        }
        // Iterate the ceiling rather than the role's set, so the reported verb is deterministic
        // (the ceiling's declaration order) instead of the role's storage order.
        Permission::SELF_SIGNUP_FORBIDDEN
            .into_iter()
            .find(|p| self.permission_set.contains(p))
            .map(SignupDefaultRefusal::HoldsPrivilegedPermission)
    }

    /// The seeded **Owner** role: every permission, protected.
    #[must_use]
    pub fn owner() -> Self {
        Role {
            id: OWNER_ROLE_ID,
            name: "Owner".to_owned(),
            permission_set: Permission::ALL.into_iter().collect(),
            protected: true,
        }
    }

    /// The seeded **Reader** role: read-only.
    #[must_use]
    pub fn reader() -> Self {
        Role {
            id: READER_ROLE_ID,
            name: "Reader".to_owned(),
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
    /// meta-permissions, full tenant provisioning/administration (`tenant.create`/`tenant.read`/
    /// `tenant.admin`), the two t22 security-configuration verbs `legal_hold.manage` and
    /// `trust.manage`, and the four t27 verbs split off the broad authorities it already held
    /// (`privacy.manage`/`retention.manage` from `user.manage`|`settings.manage`;
    /// `ledger.reanchor`/`ledger.restore` from `ledger.recover`) — so the split preserves its exact
    /// reach. It still lacks the Owner-only destructive reset/wipe verbs.
    #[must_use]
    pub fn platform_administrator() -> Self {
        Role {
            id: PLATFORM_ADMIN_ROLE_ID,
            name: "Platform Administrator".to_owned(),
            permission_set: [
                Permission::TenantRead,
                Permission::TenantCreate,
                Permission::TenantAdmin,
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
                Permission::LegalHoldManage,
                Permission::ActRead,
                Permission::ActDraft,
                Permission::ActEdit,
                Permission::ActAdvance,
                // t30: grandfathered from `act.advance`, which this role holds.
                Permission::ActRevert,
                Permission::ActArchive,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
                Permission::LedgerRead,
                Permission::LedgerRecover,
                // t27: grandfathered from `ledger.recover`, which this role holds.
                Permission::LedgerReanchor,
                Permission::LedgerRestore,
                Permission::DataBackup,
                Permission::DataExport,
                // t27: grandfathered from `user.manage` / `settings.manage`, both held below.
                Permission::PrivacyManage,
                Permission::RetentionManage,
                Permission::SettingsRead,
                Permission::SettingsManage,
                Permission::PlatformLogsWrite,
                Permission::CaeRead,
                Permission::CaeRefresh,
                Permission::LawRead,
                Permission::LawManage,
                Permission::TrustManage,
                Permission::UserRead,
                Permission::UserManage,
                Permission::UserInvite,
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

    /// The seeded **Tenant Administrator** role: reads and administers its own tenant
    /// (`tenant.read`/`tenant.admin`) plus entity/book/act administration, scoped
    /// assignment/delegation and `user.invite` (t95), without global role-definition, the wider
    /// `user.manage`, or platform settings management. It deliberately lacks `tenant.create` — minting a tenant is a platform-level
    /// provisioning act reserved for the Owner and Platform Administrator.
    #[must_use]
    pub fn tenant_administrator() -> Self {
        Role {
            id: TENANT_ADMIN_ROLE_ID,
            name: "Tenant Administrator".to_owned(),
            permission_set: [
                Permission::TenantRead,
                Permission::TenantAdmin,
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
                // t30: grandfathered from `act.advance`, which this role holds.
                Permission::ActRevert,
                Permission::ActArchive,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
                Permission::LedgerRead,
                Permission::SettingsRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::UserRead,
                Permission::UserInvite,
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
                // t30: grandfathered from `act.advance`, which this role holds.
                Permission::ActRevert,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Company Owner** role (spec ROL-02): the company-level operational archetype and
    /// the **default role a newly created user receives**. Full operational authority over entities,
    /// books, acts, documents and reference data, plus signing, `settings.read`, `ledger.read` and
    /// `data.backup`/`data.export`. Explicitly *not* user/role/delegation management,
    /// `settings.manage`, `ledger.recover`, `data.wipe` or `data.start_over` — it pins operational
    /// permissions directly without inheriting protected Owner or RBAC meta authority.
    ///
    /// t87 merged the former **Gestor** role into this one: the two permission sets were
    /// byte-identical, so the merge changed nobody's authority. See [`RETIRED_SEEDED_ROLES`].
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
                Permission::ActRevert,
                Permission::ActArchive,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
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
    /// plus `user.invite` (t95), without entity, user-management, role, settings, recovery or data
    /// authority.
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
                Permission::ActRevert,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
                // t95: the secretary convenes the people who attend the acts, so inviting them is
                // part of the job. Still no `user.manage` — this role cannot edit, re-role or
                // deactivate an existing account.
                Permission::UserInvite,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }

    /// The seeded **Legal Counsel** role: advisory read access without law-management or workflow
    /// mutation authority, plus `legal_hold.manage` — placing and lifting a litigation hold, and
    /// authorising archive disposal, is the one mutation this advisory role exists to perform (t22).
    #[must_use]
    pub fn legal_counsel() -> Self {
        Role {
            id: LEGAL_COUNSEL_ROLE_ID,
            name: "Legal Counsel".to_owned(),
            permission_set: [
                Permission::EntityRead,
                Permission::BookRead,
                Permission::LegalHoldManage,
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

    /// The seeded **Signatory** role (spec ROL-02): read across entity/book/act/ledger plus
    /// `act.advance`, `signing.perform` and `document.generate`.
    ///
    /// t87 merged the former **Signatário** role into this one: the two permission sets were
    /// byte-identical, so the merge changed nobody's authority. See [`RETIRED_SEEDED_ROLES`].
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
                Permission::ActRevert,
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
                Permission::ActRevert,
                Permission::DocumentGenerate,
            ]
            .into_iter()
            .collect(),
            protected: false,
        }
    }
}

/// The seeded default roles, in a stable order. Owner and Reader keep their original ids and lead
/// the list for backwards compatibility; the two retired ids that used to sit between them are
/// absent by construction (see [`RETIRED_SEEDED_ROLES`]).
#[must_use]
pub fn default_roles() -> Vec<Role> {
    vec![
        Role::owner(),
        Role::reader(),
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

/// Whether `id` names a role the current build seeds. Retired ids are **not** seeded and answer
/// `false` — use [`retired_role_successor`] to recognise those.
#[must_use]
pub fn is_seeded_role(id: RoleId) -> bool {
    default_roles().iter().any(|role| role.id == id)
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

    /// Remove a role by id, returning it if it was present.
    ///
    /// Used by the t87 merge migration to drop a retired seeded role from a catalog loaded off
    /// disk. Removing a role does **not** make its id available again — see
    /// [`RETIRED_SEEDED_ROLES`].
    pub fn remove(&mut self, id: RoleId) -> Option<Role> {
        self.roles.remove(&id)
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

/// The t27 verb-split **grandfather map**: holding **any** verb in `parents` grants `child`.
///
/// Splitting a broad verb into a narrow one (§ t27) strips authority from everyone who held the
/// broad verb — unless the narrow verb is granted back to them. This table is that grant. It is
/// applied in two places, from this single source of truth:
///
/// 1. **Seeded roles (code):** the constructors already bake the result in — Owner holds every verb
///    via [`Permission::ALL`], and [`Role::platform_administrator`] lists the four explicitly
///    because it held every parent. No other seeded role holds a parent, so none gains a child.
/// 2. **Operator-authored roles (on disk):** a `roles.json` loaded off disk is reconciled with
///    [`grandfather_split_verbs_catalog`] before use, so a role an operator built to hold
///    `settings.manage` keeps its privacy/retention reach after the split.
///
/// Owner + Platform Administrator held every parent, so both keep their exact reach; a role that
/// held no parent gains nothing.
pub const T27_VERB_SPLIT_GRANDFATHER: &[(Permission, &[Permission])] = &[
    (
        Permission::PrivacyManage,
        &[Permission::UserManage, Permission::SettingsManage],
    ),
    (
        Permission::RetentionManage,
        &[Permission::UserManage, Permission::SettingsManage],
    ),
    (Permission::LedgerReanchor, &[Permission::LedgerRecover]),
    (Permission::LedgerRestore, &[Permission::LedgerRecover]),
];

/// The t30 **`act.revert` grandfather map**, structured exactly like [`T27_VERB_SPLIT_GRANDFATHER`]:
/// holding **any** verb in `parents` grants `child`.
///
/// t30 introduces `act.revert` — moving an act **backward** among the pre-signature lifecycle
/// states. Unlike the t27 verbs, this is not a *split* of an existing verb but a genuinely new
/// authority; the policy (t30 D2) is that whoever can advance the lifecycle can also revert it, so
/// `act.revert` is granted to every prior holder of `act.advance`. Introducing the verb therefore
/// strips no reach. Applied from the same single source of truth as t27:
///
/// 1. **Seeded roles (code):** every constructor holding `act.advance` bakes in `act.revert`
///    (Owner via [`Permission::ALL`]), so migrating a fresh install is a no-op.
/// 2. **Operator-authored roles (on disk):** reconciled with [`grandfather_act_revert_catalog`]
///    under its **own** one-time migration marker (kept distinct from t27's, so a store already
///    migrated past t27 still picks the new verb up — see `chancela-api`).
pub const T30_ACT_REVERT_GRANDFATHER: &[(Permission, &[Permission])] =
    &[(Permission::ActRevert, &[Permission::ActAdvance])];

/// Grant each child verb in `table` whose parent the role already holds. Returns `true` if the set
/// changed. Shared engine behind [`grandfather_split_verbs`] (t27) and [`grandfather_act_revert`]
/// (t30).
///
/// **Idempotent** — a role that already holds a child is left as-is, so a second pass, or a pass
/// over an already-migrated catalog, is a no-op. **Protected roles are skipped** — Owner's set is
/// locked and already holds every verb via [`Permission::ALL`], so there is nothing to grant and its
/// lock must not be touched.
fn apply_grandfather_table(role: &mut Role, table: &[(Permission, &[Permission])]) -> bool {
    if role.protected {
        return false;
    }
    let mut changed = false;
    for (child, parents) in table {
        if role.permission_set.contains(child) {
            continue;
        }
        if parents.iter().any(|p| role.permission_set.contains(p)) {
            role.permission_set.insert(*child);
            changed = true;
        }
    }
    changed
}

/// Apply `table` across a whole catalog (e.g. a `roles.json` loaded off disk). Returns `true` if any
/// role changed. Idempotent; protected roles are untouched.
fn apply_grandfather_table_catalog(
    catalog: &mut RoleCatalog,
    table: &[(Permission, &[Permission])],
) -> bool {
    // Collect ids first: `RoleCatalog` exposes no mutable iterator, so mutate via clone→`insert`.
    let ids: Vec<RoleId> = catalog.iter().map(|role| role.id).collect();
    let mut changed = false;
    for id in ids {
        let Some(current) = catalog.get(id) else {
            continue;
        };
        let mut role = current.clone();
        if apply_grandfather_table(&mut role, table) {
            catalog.insert(role);
            changed = true;
        }
    }
    changed
}

/// Grandfather the t27 split onto one role's permission-set: grant each child verb whose parent the
/// role already holds (see [`T27_VERB_SPLIT_GRANDFATHER`]). Returns `true` if the set changed.
///
/// Idempotent and protected-role-skipping (see [`apply_grandfather_table`]). Whether the migration
/// runs at all on a given catalog is the caller's concern: it should be version-guarded so it never
/// re-adds a verb an operator later deliberately removed — see the on-disk reconciliation in
/// `chancela-api`.
#[must_use]
pub fn grandfather_split_verbs(role: &mut Role) -> bool {
    apply_grandfather_table(role, T27_VERB_SPLIT_GRANDFATHER)
}

/// Apply [`grandfather_split_verbs`] across a whole catalog (e.g. a `roles.json` loaded off disk).
/// Returns `true` if any role changed. Idempotent; protected roles are untouched.
#[must_use]
pub fn grandfather_split_verbs_catalog(catalog: &mut RoleCatalog) -> bool {
    apply_grandfather_table_catalog(catalog, T27_VERB_SPLIT_GRANDFATHER)
}

/// Grandfather the t30 `act.revert` grant onto one role's permission-set: grant `act.revert` when
/// the role already holds `act.advance` (see [`T30_ACT_REVERT_GRANDFATHER`]). Returns `true` if the
/// set changed. Idempotent; protected roles are skipped.
#[must_use]
pub fn grandfather_act_revert(role: &mut Role) -> bool {
    apply_grandfather_table(role, T30_ACT_REVERT_GRANDFATHER)
}

/// Apply [`grandfather_act_revert`] across a whole catalog. Returns `true` if any role changed.
/// Idempotent; protected roles are untouched. Runs under its own one-time migration marker in
/// `chancela-api`, independent of the t27 marker.
#[must_use]
pub fn grandfather_act_revert_catalog(catalog: &mut RoleCatalog) -> bool {
    apply_grandfather_table_catalog(catalog, T30_ACT_REVERT_GRANDFATHER)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editable_seeded_roles() -> Vec<Role> {
        vec![
            Role::reader(),
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
            Role::reader(),
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
            // t27: the recovery-split verbs are as privileged as the `ledger.recover` they came
            // from — no non-admin seeded role may hold them.
            assert!(!role.permission_set.contains(&Permission::LedgerReanchor));
            assert!(!role.permission_set.contains(&Permission::LedgerRestore));
            assert!(!role.permission_set.contains(&Permission::UserManage));
            // t27: privacy/retention administration is platform authority, never a non-admin's.
            assert!(!role.permission_set.contains(&Permission::PrivacyManage));
            assert!(!role.permission_set.contains(&Permission::RetentionManage));
            // t22. `legal_hold.manage` is intentionally absent from this battery — Legal Counsel is
            // a non-admin seeded role and holds it by design (see the note in
            // `explicit_company_archetypes_exclude_sensitive_platform_and_meta_authority`).
            assert!(!role.permission_set.contains(&Permission::TrustManage));
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

    /// t22: `legal_hold.manage` and `trust.manage` were split off `book.export` / `cae.refresh`
    /// precisely because those verbs are broadly held. The split is only worth anything if the
    /// seeded holders stay narrow, so pin both sets exhaustively — a future seed edit that widens
    /// either one has to come through this test.
    #[test]
    fn legal_hold_and_trust_verbs_are_seeded_only_to_their_intended_holders() {
        let holders = |p: Permission| -> Vec<String> {
            default_roles()
                .into_iter()
                .filter(|r| r.permission_set.contains(&p))
                .map(|r| r.name)
                .collect()
        };

        assert_eq!(
            holders(Permission::LegalHoldManage),
            vec!["Owner", "Legal Counsel", "Platform Administrator"]
        );
        assert_eq!(
            holders(Permission::TrustManage),
            vec!["Owner", "Platform Administrator"]
        );

        // The point of the split: these roles keep the broad verb they are supposed to have and
        // lose the narrow one they were reaching it through. Auditor and API Client are the two the
        // t22 audit called out by name.
        for role in [
            Role::company_owner(),
            Role::corporate_secretary(),
            Role::records_manager(),
            Role::tenant_administrator(),
            Role::auditor(),
            Role::api_client(),
        ] {
            assert!(
                role.permission_set.contains(&Permission::BookExport),
                "{} unexpectedly lost book.export",
                role.name
            );
            assert!(
                !role.permission_set.contains(&Permission::LegalHoldManage),
                "{} still reaches legal hold through book.export",
                role.name
            );
        }

        // Likewise `cae.refresh` no longer carries a TSL import with it.
        for role in [Role::company_owner()] {
            assert!(
                role.permission_set.contains(&Permission::CaeRefresh),
                "{} unexpectedly lost cae.refresh",
                role.name
            );
            assert!(
                !role.permission_set.contains(&Permission::TrustManage),
                "{} still reaches the TSL import through cae.refresh",
                role.name
            );
        }
    }

    /// t22, stated as the population rather than a hand-picked sample. Before the split, *every*
    /// `book.export` holder could set and release a legal hold. Derive that population from
    /// `default_roles()` instead of listing it, so a role added later with `book.export` cannot
    /// quietly re-acquire hold authority without this test naming it.
    #[test]
    fn every_seeded_role_that_reached_legal_hold_through_book_export_lost_it() {
        let by_export: Vec<Role> = default_roles()
            .into_iter()
            .filter(|r| r.id != OWNER_ROLE_ID && r.permission_set.contains(&Permission::BookExport))
            .collect();

        // The population is pinned: eight non-Owner roles used to reach the hold this way.
        assert_eq!(
            by_export
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Company Owner",
                "Corporate Secretary",
                "Records Manager",
                "Platform Administrator",
                "Tenant Administrator",
                "Auditor",
                "API Client",
            ]
        );

        // Exactly one of them is a deliberate seeded holder of the new verb; the other seven lost
        // the authority entirely. `book.export` is never what carries it.
        let still_holding: Vec<&str> = by_export
            .iter()
            .filter(|r| r.permission_set.contains(&Permission::LegalHoldManage))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            still_holding,
            vec!["Platform Administrator"],
            "a book.export holder regained legal_hold.manage"
        );

        // And the verb is not reachable from any other broadly-held operational verb either: no
        // role holds legal_hold.manage without being one of the three intended holders.
        let all = default_roles();
        let holders: Vec<&str> = all
            .iter()
            .filter(|r| r.permission_set.contains(&Permission::LegalHoldManage))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            holders,
            vec!["Owner", "Legal Counsel", "Platform Administrator"]
        );
    }

    #[test]
    fn user_invite_is_seeded_to_exactly_its_four_intended_holders() {
        // t95 §2.6. Pinned exhaustively and in catalog order: adding the verb to a further seeded
        // role is a decision, and this test is where it has to be made deliberately.
        let all = default_roles();
        let holders: Vec<&str> = all
            .iter()
            .filter(|r| r.permission_set.contains(&Permission::UserInvite))
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(
            holders,
            vec![
                "Owner",
                "Corporate Secretary",
                "Platform Administrator",
                "Tenant Administrator",
            ]
        );
        // The point of a separate verb: two of the four holders cannot manage users at all.
        for name in ["Corporate Secretary", "Tenant Administrator"] {
            let role = default_roles()
                .into_iter()
                .find(|r| r.name == name)
                .expect("seeded");
            assert!(
                !role.permission_set.contains(&Permission::UserManage),
                "{name} must be able to invite WITHOUT holding user.manage — that separation is \
                 the whole reason user.invite exists"
            );
        }
    }

    /// The §2.6 ceiling, from both ends. The seeded roles that may be the signup default are
    /// pinned, and — the part that actually matters — a role that is legal today becomes illegal
    /// the moment it is *edited* to hold a forbidden verb.
    #[test]
    fn signup_default_ceiling_refuses_owner_privileged_and_later_edited_roles() {
        assert!(matches!(
            Role::owner().signup_default_refusal(),
            Some(SignupDefaultRefusal::Protected)
        ));

        for eligible in [Role::guest(), Role::reader(), Role::auditor()] {
            assert_eq!(
                eligible.signup_default_refusal(),
                None,
                "{} should be an allowed signup default",
                eligible.name
            );
        }

        for privileged in [Role::platform_administrator(), Role::tenant_administrator()] {
            assert!(
                privileged.signup_default_refusal().is_some(),
                "{} must never be the signup default",
                privileged.name
            );
        }

        // The bypass the ceiling exists to close: pick Guest as the default, then edit Guest.
        for forbidden in Permission::SELF_SIGNUP_FORBIDDEN {
            let mut edited = Role::guest();
            edited.permission_set.insert(forbidden);
            assert_eq!(
                edited.signup_default_refusal(),
                Some(SignupDefaultRefusal::HoldsPrivilegedPermission(forbidden)),
                "editing {forbidden} onto a role must make it ineligible as the signup default"
            );
        }

        // `user.invite` is not a ceiling verb, so granting it does not make a role ineligible.
        let mut inviting_guest = Role::guest();
        inviting_guest.permission_set.insert(Permission::UserInvite);
        assert_eq!(inviting_guest.signup_default_refusal(), None);
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
            Permission::LegalHoldManage,
            Permission::TrustManage,
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
        assert_eq!(cat.len(), 13);

        for (id, raw, name) in [
            (OWNER_ROLE_ID, 0x6f776e6572000000_0000000000000001, "Owner"),
            (
                READER_ROLE_ID,
                0x6c6569746f720000_0000000000000004,
                "Reader",
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
                Permission::ActRevert,
                Permission::ActArchive,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
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
                Permission::ActRevert,
                Permission::SigningPerform,
                Permission::DocumentGenerate,
                Permission::TemplateManage,
                Permission::LedgerRead,
                Permission::CaeRead,
                Permission::LawRead,
                Permission::SettingsRead,
                // t95: invite only — still no user.manage.
                Permission::UserInvite,
            ])
        );
        assert_eq!(
            Role::legal_counsel().permission_set,
            permissions([
                Permission::EntityRead,
                Permission::BookRead,
                Permission::LegalHoldManage,
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
                Permission::ActRevert,
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
                Permission::ActRevert,
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
                // t27: the recovery-split verbs share `ledger.recover`'s exclusion here.
                Permission::LedgerReanchor,
                Permission::LedgerRestore,
                // t27: privacy/retention administration is platform authority, split off
                // `user.manage`|`settings.manage`, so it is excluded here for the same reason.
                Permission::PrivacyManage,
                Permission::RetentionManage,
                Permission::DataWipe,
                Permission::DataStartOver,
                // t22: importing a trusted-service list decides which signatures the product
                // considers valid — platform authority, never a company archetype's.
                //
                // `legal_hold.manage` deliberately does NOT belong on this list: Legal Counsel is
                // one of its three seeded holders, because placing and lifting a litigation hold is
                // the mutation that role exists to perform. Its holders are pinned exhaustively in
                // `legal_hold_and_trust_verbs_are_seeded_only_to_their_intended_holders` instead.
                Permission::TrustManage,
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
    fn tenant_permissions_are_seeded_only_to_owner_and_the_admin_roles() {
        use Permission::{TenantAdmin, TenantCreate, TenantRead};

        // Owner (protected super-role) holds all three via `Permission::ALL`.
        let owner = Role::owner();
        for p in [TenantRead, TenantCreate, TenantAdmin] {
            assert!(owner.permission_set.contains(&p), "owner missing {p}");
        }

        // Platform Administrator: full tenant provisioning + administration.
        let platform = Role::platform_administrator();
        assert!(platform.permission_set.contains(&TenantRead));
        assert!(platform.permission_set.contains(&TenantCreate));
        assert!(platform.permission_set.contains(&TenantAdmin));

        // Tenant Administrator: reads + administers its tenant, but MUST NOT mint tenants.
        let tenant_admin = Role::tenant_administrator();
        assert!(tenant_admin.permission_set.contains(&TenantRead));
        assert!(tenant_admin.permission_set.contains(&TenantAdmin));
        assert!(
            !tenant_admin.permission_set.contains(&TenantCreate),
            "Tenant Administrator must not hold tenant.create (platform-level provisioning)"
        );

        // No other seeded role carries any tenant verb — the tenant directory is a privileged axis.
        for role in non_admin_seeded_roles() {
            for p in [TenantRead, TenantCreate, TenantAdmin] {
                assert!(
                    !role.permission_set.contains(&p),
                    "{} unexpectedly holds {p}",
                    role.name
                );
            }
        }
    }

    /// `RoleId` is "a transparent UUID on the wire" — and `Display` is what puts it there, into
    /// ledger event payloads, delegation records and refusal messages. A `Debug`-shaped rendering
    /// (`RoleId(…)`) would be accepted by every one of those call sites and would silently make the
    /// stored id unparseable by anything reading it back.
    #[test]
    fn a_role_id_renders_as_a_bare_uuid_and_round_trips_through_that_text() {
        let rendered = OWNER_ROLE_ID.to_string();
        assert_eq!(rendered, "6f776e65-7200-0000-0000-000000000001");
        assert_eq!(
            RoleId(Uuid::parse_str(&rendered).expect("the rendering parses back as a UUID")),
            OWNER_ROLE_ID
        );
        // Not the wrapper's Debug form.
        assert!(!rendered.contains("RoleId"));
    }

    /// `is_empty` is what distinguishes "no `roles.json` yet, seed the defaults" from "a catalog
    /// that deliberately holds no role". Getting it backwards would re-seed over an operator's
    /// edited catalog, or leave a fresh install with no Owner at all.
    #[test]
    fn an_unseeded_catalog_is_empty_and_a_seeded_one_is_not() {
        let mut fresh = RoleCatalog::new();
        assert!(fresh.is_empty());
        assert_eq!(fresh.len(), 0);
        assert!(fresh.owner().is_none());

        fresh.insert(Role::reader());
        assert!(!fresh.is_empty());
        assert_eq!(fresh.len(), 1);
        // Still no Owner: a non-empty catalog is not a seeded one.
        assert!(fresh.owner().is_none());

        assert!(!RoleCatalog::seeded_defaults().is_empty());
    }

    /// `iter` is how a delegation's authority is expanded against the live catalog (t44), so it
    /// must yield every role exactly once — a catalog that silently dropped or duplicated one
    /// would under- or over-grant every delegation of it.
    #[test]
    fn iterating_a_catalog_yields_every_role_exactly_once() {
        let catalog = RoleCatalog::seeded_defaults();
        let mut ids: Vec<RoleId> = catalog.iter().map(|role| role.id).collect();
        assert_eq!(ids.len(), catalog.len());
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), catalog.len(), "iter yielded a role twice");

        let expected: BTreeSet<RoleId> = default_roles().into_iter().map(|role| role.id).collect();
        assert_eq!(ids.into_iter().collect::<BTreeSet<_>>(), expected);

        // And `insert` replaces rather than appends, so an edited role does not shadow a stale one.
        let mut edited = catalog.clone();
        edited.insert(Role {
            name: "Leitor (revisto)".to_owned(),
            ..Role::reader()
        });
        assert_eq!(edited.len(), catalog.len());
        assert_eq!(edited.get(READER_ROLE_ID).unwrap().name, "Leitor (revisto)");
        assert_eq!(edited.iter().filter(|r| r.id == READER_ROLE_ID).count(), 1);
    }

    /// t87. The defect that started this: `Signatário` and `Signatory` were two seeded roles with
    /// **byte-identical** permission sets — the same authority under two names, so an operator
    /// picking between them was choosing nothing. `Gestor` and `Company Owner` were a second,
    /// unnoticed instance of exactly the same thing.
    ///
    /// State the invariant over the whole catalog rather than over the two pairs that happened to
    /// exist, so a future seeded role cannot silently become a third duplicate. Roles that merely
    /// *look* alike are fine and must stay: Corporate Secretary is API Client + `settings.read`,
    /// Legal Counsel is Reader + `legal_hold.manage`, Reviewer is Signatory − `signing.perform`.
    /// Each of those differs, so each is a real distinction and none is merged.
    #[test]
    fn no_two_seeded_roles_share_a_permission_set() {
        let roles = default_roles();
        for (i, a) in roles.iter().enumerate() {
            for b in &roles[i + 1..] {
                assert_ne!(
                    a.permission_set, b.permission_set,
                    "{} and {} grant identical authority under two names — merge them and retire \
                     one id (see RETIRED_SEEDED_ROLES), or make the distinction real",
                    a.name, b.name
                );
            }
        }
    }

    /// A retired id must resolve to a successor that (a) is actually seeded and (b) grants *exactly*
    /// what the retired role granted. Merging into a wider role would silently escalate every
    /// holder the migration touches; merging into a narrower one would silently strip them.
    #[test]
    fn every_retired_role_merges_into_a_seeded_successor_with_identical_authority() {
        // The permission sets the two retired roles carried when they were seeded, restated here
        // because the constructors are gone. This is the only place they still exist, and it is
        // what makes the "identical authority" claim checkable rather than asserted.
        let retired_gestor = permissions([
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
            Permission::ActRevert,
            Permission::ActArchive,
            Permission::SigningPerform,
            Permission::DocumentGenerate,
            Permission::TemplateManage,
            Permission::CaeRead,
            Permission::CaeRefresh,
            Permission::LawRead,
            Permission::LawManage,
            Permission::SettingsRead,
            Permission::LedgerRead,
            Permission::DataBackup,
            Permission::DataExport,
        ]);
        let retired_signatario = permissions([
            Permission::EntityRead,
            Permission::BookRead,
            Permission::ActRead,
            Permission::LedgerRead,
            Permission::ActAdvance,
            Permission::ActRevert,
            Permission::SigningPerform,
            Permission::DocumentGenerate,
        ]);

        assert_eq!(Role::company_owner().permission_set, retired_gestor);
        assert_eq!(Role::signatory().permission_set, retired_signatario);

        let catalog = RoleCatalog::seeded_defaults();
        for (retired, successor) in RETIRED_SEEDED_ROLES {
            assert!(
                !is_seeded_role(*retired),
                "a retired id is still being seeded"
            );
            assert!(
                catalog.get(*successor).is_some(),
                "a retired role points at a successor that is not seeded"
            );
            assert_eq!(retired_role_successor(*retired), Some(*successor));
        }
        assert_eq!(retired_role_successor(OWNER_ROLE_ID), None);
    }

    /// A retired id must never come back as something else. Reusing one would make every past
    /// ledger event that names it read as a grant of authority that was never given.
    #[test]
    fn retired_ids_are_never_reused_by_a_seeded_role() {
        for (retired, _) in RETIRED_SEEDED_ROLES {
            assert!(
                default_roles().iter().all(|role| role.id != *retired),
                "a seeded role reused retired id {retired}"
            );
        }
        // And the ids are exactly the two the merge retired — pinned so a later edit that drops one
        // from the table (and so stops migrating its holders) has to come through this test.
        assert_eq!(
            RETIRED_SEEDED_ROLES
                .iter()
                .map(|(retired, _)| *retired)
                .collect::<Vec<_>>(),
            vec![RETIRED_GESTOR_ROLE_ID, RETIRED_SIGNATARIO_ROLE_ID]
        );
    }

    /// The seeded names are code-adjacent English (the workspace convention); pt-PT operators read a
    /// translation the client resolves from the id. A Portuguese seeded name would put the wrong
    /// language on the wire *and* leave the client's canonical-name check unable to tell a seeded
    /// role from one an operator renamed.
    #[test]
    fn every_seeded_role_name_is_ascii_english() {
        for role in default_roles() {
            assert!(
                role.name.is_ascii(),
                "{} is not an English seeded name — seeded names stay English and are translated \
                 client-side (see the module docs)",
                role.name
            );
            assert!(!role.name.trim().is_empty());
        }
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

    /// t27, mirroring the t22 split battery. The four verbs were split off `user.manage` /
    /// `settings.manage` (privacy/retention) and `ledger.recover` (reanchor/restore). The split is
    /// only worth anything if the seeded holders stay exactly the two roles that held every parent —
    /// Owner and Platform Administrator — so pin the population exhaustively and in catalog order. A
    /// future seed that grants one of these to a third role has to come through this test.
    #[test]
    fn t27_split_verbs_are_seeded_only_to_owner_and_platform_admin() {
        let holders = |p: Permission| -> Vec<String> {
            default_roles()
                .into_iter()
                .filter(|r| r.permission_set.contains(&p))
                .map(|r| r.name)
                .collect()
        };

        for verb in [
            Permission::PrivacyManage,
            Permission::RetentionManage,
            Permission::LedgerReanchor,
            Permission::LedgerRestore,
        ] {
            assert_eq!(
                holders(verb),
                vec!["Owner", "Platform Administrator"],
                "{verb} is seeded to the wrong set of roles"
            );
        }

        // And the parents kept their exact seeded holders — the split renames the reach, it does not
        // move who has it. All three parents are Owner + Platform Administrator only.
        for parent in [
            Permission::UserManage,
            Permission::SettingsManage,
            Permission::LedgerRecover,
        ] {
            assert_eq!(
                holders(parent),
                vec!["Owner", "Platform Administrator"],
                "{parent} holder set changed"
            );
        }
    }

    /// The grandfather rule itself (`T27_VERB_SPLIT_GRANDFATHER` + [`grandfather_split_verbs`]):
    /// every prior holder of a parent verb gains the child, a role holding no parent gains nothing,
    /// and the pass is idempotent. This is the "no reach lost" proof for operator-authored roles.
    #[test]
    fn t27_grandfather_grants_children_to_parent_holders_and_nothing_else() {
        // Build operator-shaped roles from a minimal base and vary only the parent verbs.
        let base = |perms: &[Permission]| Role {
            id: RoleId(Uuid::from_u128(0x7465737400000000_0000000000000abc)),
            name: "Custom".to_owned(),
            permission_set: perms.iter().copied().collect(),
            protected: false,
        };

        // user.manage → privacy.manage + retention.manage; NOT the ledger verbs.
        let mut um = base(&[Permission::UserManage]);
        assert!(grandfather_split_verbs(&mut um));
        assert!(um.permission_set.contains(&Permission::PrivacyManage));
        assert!(um.permission_set.contains(&Permission::RetentionManage));
        assert!(!um.permission_set.contains(&Permission::LedgerReanchor));
        assert!(!um.permission_set.contains(&Permission::LedgerRestore));

        // settings.manage → the same privacy/retention pair.
        let mut sm = base(&[Permission::SettingsManage]);
        assert!(grandfather_split_verbs(&mut sm));
        assert!(sm.permission_set.contains(&Permission::PrivacyManage));
        assert!(sm.permission_set.contains(&Permission::RetentionManage));

        // ledger.recover → ledger.reanchor + ledger.restore; NOT privacy/retention.
        let mut lr = base(&[Permission::LedgerRecover]);
        assert!(grandfather_split_verbs(&mut lr));
        assert!(lr.permission_set.contains(&Permission::LedgerReanchor));
        assert!(lr.permission_set.contains(&Permission::LedgerRestore));
        assert!(!lr.permission_set.contains(&Permission::PrivacyManage));
        assert!(!lr.permission_set.contains(&Permission::RetentionManage));

        // Holding no parent grants nothing, and the call reports no change.
        let mut none = base(&[Permission::EntityRead, Permission::BookRead]);
        assert!(!grandfather_split_verbs(&mut none));
        for child in [
            Permission::PrivacyManage,
            Permission::RetentionManage,
            Permission::LedgerReanchor,
            Permission::LedgerRestore,
        ] {
            assert!(!none.permission_set.contains(&child));
        }

        // Idempotent: a second pass over an already-migrated role changes nothing.
        assert!(!grandfather_split_verbs(&mut um));
        assert!(!grandfather_split_verbs(&mut lr));

        // Protected roles are skipped even when they hold a parent — the lock must not be touched.
        let mut protected = Role {
            protected: true,
            ..base(&[Permission::UserManage])
        };
        assert!(!grandfather_split_verbs(&mut protected));
        assert!(
            !protected
                .permission_set
                .contains(&Permission::PrivacyManage)
        );
    }

    /// The seeded catalog already bakes the grandfather result into its constructors, so migrating a
    /// fresh install must be a no-op — proof the code half and the migration half agree. And the
    /// migration must **restore** a Platform Administrator persisted *before* the split (a
    /// `roles.json` on disk that predates t27) to its exact current reach: that is the anti-lockout
    /// guarantee stated as a test.
    #[test]
    fn t27_grandfather_is_noop_on_seed_and_restores_a_pre_split_platform_admin() {
        let mut seeded = RoleCatalog::seeded_defaults();
        assert!(
            !grandfather_split_verbs_catalog(&mut seeded),
            "seeded roles already carry the split verbs; migrating a fresh install must not change \
             anything"
        );

        // A Platform Administrator as it would have been persisted before t27: today's set minus
        // the four new verbs. It still holds user.manage, settings.manage and ledger.recover.
        let mut legacy = Role::platform_administrator();
        for verb in [
            Permission::PrivacyManage,
            Permission::RetentionManage,
            Permission::LedgerReanchor,
            Permission::LedgerRestore,
        ] {
            legacy.permission_set.remove(&verb);
        }
        assert!(
            grandfather_split_verbs(&mut legacy),
            "a pre-split Platform Administrator must be migrated"
        );
        assert_eq!(
            legacy.permission_set,
            Role::platform_administrator().permission_set,
            "migration must restore the Platform Administrator's exact pre-split reach — no more, \
             no less"
        );
    }

    /// t30: the `act.revert` grandfather grants the new verb to every prior `act.advance` holder and
    /// nothing else, is idempotent, and skips protected roles. The "no reach lost" proof for
    /// operator-authored roles that could advance the lifecycle but predate the revert verb.
    #[test]
    fn t30_act_revert_grandfather_grants_to_advance_holders_and_nothing_else() {
        let base = |perms: &[Permission]| Role {
            id: RoleId(Uuid::from_u128(0x7465737430000000_0000000000000abc)),
            name: "Custom".to_owned(),
            permission_set: perms.iter().copied().collect(),
            protected: false,
        };

        // act.advance → act.revert.
        let mut adv = base(&[Permission::ActAdvance]);
        assert!(grandfather_act_revert(&mut adv));
        assert!(adv.permission_set.contains(&Permission::ActRevert));

        // No act.advance → no act.revert, and the call reports no change.
        let mut none = base(&[Permission::ActRead, Permission::ActEdit]);
        assert!(!grandfather_act_revert(&mut none));
        assert!(!none.permission_set.contains(&Permission::ActRevert));

        // Idempotent.
        assert!(!grandfather_act_revert(&mut adv));

        // Protected roles are skipped even when they hold the parent.
        let mut protected = Role {
            protected: true,
            ..base(&[Permission::ActAdvance])
        };
        assert!(!grandfather_act_revert(&mut protected));
        assert!(!protected.permission_set.contains(&Permission::ActRevert));

        // The two grandfather generations are independent: the t27 pass never grants act.revert.
        let mut adv_only = base(&[Permission::ActAdvance]);
        assert!(!grandfather_split_verbs(&mut adv_only));
        assert!(!adv_only.permission_set.contains(&Permission::ActRevert));
    }

    /// The seeded catalog already bakes `act.revert` into every `act.advance` holder, so migrating a
    /// fresh install is a no-op; and a role persisted before t30 (today's set minus `act.revert`) is
    /// restored to its exact current reach — the anti-lockout guarantee for the revert verb.
    #[test]
    fn t30_act_revert_grandfather_is_noop_on_seed_and_restores_a_pre_t30_role() {
        let mut seeded = RoleCatalog::seeded_defaults();
        assert!(
            !grandfather_act_revert_catalog(&mut seeded),
            "seeded roles already carry act.revert; migrating a fresh install must not change \
             anything"
        );

        // A Company Owner as persisted before t30: today's set minus act.revert. It still holds
        // act.advance, so the grandfather must grant act.revert back.
        let mut legacy = Role::company_owner();
        legacy.permission_set.remove(&Permission::ActRevert);
        assert!(
            grandfather_act_revert(&mut legacy),
            "a pre-t30 act.advance holder must be migrated"
        );
        assert_eq!(
            legacy.permission_set,
            Role::company_owner().permission_set,
            "migration must restore the role's exact pre-t30 reach — no more, no less"
        );
    }
}
