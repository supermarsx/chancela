//! The fine-grained permission **catalog** (t64 plan §3.1).
//!
//! Permissions are compile-time verbs: a fixed, auditable vocabulary. Which permissions a *role*
//! grants is DATA (see [`crate::role`]); the verb set itself is code — adding a verb is a reviewed
//! code change. Each variant serialises to its stable dotted id (e.g. `Permission::EntityRead` ⇄
//! `"entity.read"`), so the on-the-wire / on-disk form is human-auditable and independent of the
//! Rust variant name.

use serde::{Deserialize, Serialize};

/// A single fine-grained authorization verb.
///
/// Serialises to / from its dotted string id ([`Permission::as_str`]). Ordering is derived from
/// declaration order and is only used to give role permission-sets a deterministic serialisation
/// ([`std::collections::BTreeSet`]); it carries no authority meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    // --- Tenants ---
    /// Read a tenant: list the tenant directory (`GET /v1/tenants`, filtered per row) or read one
    /// by id (`GET /v1/tenants/{id}`). Checked at `Scope::Tenant`, so a tenant-scoped holder sees
    /// only its own tenant while a Global holder sees the whole directory. Distinct from
    /// `entity.read` so the tenant directory is its own authority axis, above the entity level.
    #[serde(rename = "tenant.read")]
    TenantRead,
    /// Create a new tenant (`POST /v1/tenants`). Minting a tenant is a platform-level provisioning
    /// act with no pre-existing tenant to narrow to, so it is checked at `Scope::Global`.
    #[serde(rename = "tenant.create")]
    TenantCreate,
    /// Administer an existing tenant (rename / configuration / archival). Reserved for the tenant
    /// mutation surface; seeded to the platform- and tenant-administrator roles.
    #[serde(rename = "tenant.admin")]
    TenantAdmin,

    // --- Entities ---
    #[serde(rename = "entity.read")]
    EntityRead,
    #[serde(rename = "entity.create")]
    EntityCreate,
    #[serde(rename = "entity.update")]
    EntityUpdate,
    #[serde(rename = "entity.registry.import")]
    EntityRegistryImport,
    /// Reserved for t62 (entity archival becomes permission-gated).
    #[serde(rename = "entity.archive")]
    EntityArchive,

    // --- Books ---
    #[serde(rename = "book.read")]
    BookRead,
    #[serde(rename = "book.open")]
    BookOpen,
    #[serde(rename = "book.close")]
    BookClose,
    #[serde(rename = "book.export")]
    BookExport,
    #[serde(rename = "book.import")]
    BookImport,
    #[serde(rename = "book.start_over")]
    BookStartOver,
    /// Reserved for t62 (book reopen becomes permission-gated).
    #[serde(rename = "book.reopen")]
    BookReopen,

    // --- Legal hold (retention / compliance) ---
    /// Set, replace or release a book-level **legal hold**, and execute archive disposal against a
    /// book. A hold is the retention control that blocks disposal of the evidentiary record, so
    /// releasing one unblocks destruction — it is a compliance authority, deliberately NOT the
    /// broadly-held `book.export` read/export authority it used to share (t22).
    #[serde(rename = "legal_hold.manage")]
    LegalHoldManage,

    // --- Acts ---
    #[serde(rename = "act.read")]
    ActRead,
    #[serde(rename = "act.draft")]
    ActDraft,
    #[serde(rename = "act.edit")]
    ActEdit,
    #[serde(rename = "act.advance")]
    ActAdvance,
    #[serde(rename = "act.archive")]
    ActArchive,

    // --- Signing ---
    /// Gates act **seal**.
    #[serde(rename = "signing.perform")]
    SigningPerform,

    // --- Documents ---
    #[serde(rename = "document.generate")]
    DocumentGenerate,

    // --- Templates ---
    /// Gates user-authored template create/edit/delete/import. Listing and export stay on
    /// `act.read`.
    #[serde(rename = "template.manage")]
    TemplateManage,

    // --- Ledger ---
    #[serde(rename = "ledger.read")]
    LedgerRead,
    #[serde(rename = "ledger.recover")]
    LedgerRecover,

    // --- Data ---
    #[serde(rename = "data.backup")]
    DataBackup,
    #[serde(rename = "data.export")]
    DataExport,
    #[serde(rename = "data.wipe")]
    DataWipe,
    #[serde(rename = "data.start_over")]
    DataStartOver,

    // --- Settings ---
    #[serde(rename = "settings.read")]
    SettingsRead,
    #[serde(rename = "settings.manage")]
    SettingsManage,

    // --- Platform operations ---
    #[serde(rename = "platform.logs.write")]
    PlatformLogsWrite,

    // --- Reference (CAE + law corpus) ---
    #[serde(rename = "cae.read")]
    CaeRead,
    #[serde(rename = "cae.refresh")]
    CaeRefresh,
    #[serde(rename = "law.read")]
    LawRead,
    #[serde(rename = "law.manage")]
    LawManage,

    // --- Trust services (TSL / LOTL) ---
    /// Import a trusted-service list (`POST /v1/trust/refresh`). The trust list decides **which
    /// signatures the product will consider valid**, so this is security configuration, not
    /// reference data — it is deliberately separate from `cae.refresh`, which it used to share
    /// (t22). Reading the trust catalog stays on `cae.read`: the risk is entirely in the import.
    #[serde(rename = "trust.manage")]
    TrustManage,

    // --- Users ---
    #[serde(rename = "user.read")]
    UserRead,
    #[serde(rename = "user.manage")]
    UserManage,
    /// Issue an **invitation** to create an account (t95 §2.6). Deliberately narrower than
    /// `user.manage`: an inviter starts the account-creation flow and the invitee finishes it by
    /// setting their own secret, so the inviter never edits, deactivates, re-roles or reads the
    /// secrets of an existing user. That is why a Tenant Administrator — which has no `user.manage`
    /// — can still invite, and why holding this verb is not a route to escalation: the created
    /// account receives `auth.signup.default_role`, which is ceiling-checked separately.
    #[serde(rename = "user.invite")]
    UserInvite,

    // --- RBAC meta (NON-DELEGABLE) ---
    #[serde(rename = "role.manage")]
    RoleManage,
    #[serde(rename = "role.assign")]
    RoleAssign,
    #[serde(rename = "delegation.grant")]
    DelegationGrant,
    #[serde(rename = "delegation.revoke")]
    DelegationRevoke,
}

impl Permission {
    /// Every permission in the catalog, in declaration order. This IS the Owner permission-set.
    pub const ALL: [Permission; 45] = [
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
        Permission::ActArchive,
        Permission::SigningPerform,
        Permission::DocumentGenerate,
        Permission::TemplateManage,
        Permission::LedgerRead,
        Permission::LedgerRecover,
        Permission::DataBackup,
        Permission::DataExport,
        Permission::DataWipe,
        Permission::DataStartOver,
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
    ];

    /// The four **meta** permissions that drive the RBAC machinery itself. They may appear in a role
    /// (e.g. Owner), but they are **never delegable** — a delegate must not be able to mint or move
    /// authority. See [`Permission::is_meta`].
    pub const META: [Permission; 4] = [
        Permission::RoleManage,
        Permission::RoleAssign,
        Permission::DelegationGrant,
        Permission::DelegationRevoke,
    ];

    /// The permissions a **self-signup default role** may never hold (t95 §2.6).
    ///
    /// Self-signup hands a stranger an account with exactly one administrator-configured role. If
    /// that role can manage users, edit or assign roles, change settings, grant delegations, or
    /// destroy the record, then "signup is open" silently means "anyone can become an
    /// administrator". These verbs are therefore a hard ceiling, not a warning.
    ///
    /// The ceiling has to be applied in **two** places to be a ceiling at all: when the default
    /// role is chosen (settings validation) and when any role's permission-set is edited — a role
    /// that is legal today can be edited to hold `settings.manage` tomorrow while remaining the
    /// configured signup default. [`crate::Role::signup_default_refusal`] is the shared check both
    /// call sites use, so neither can drift from the other.
    ///
    /// Owner is excluded by `protected`, not by this list — it holds every permission anyway, but
    /// the refusal names protection so the message is honest about *why*.
    pub const SELF_SIGNUP_FORBIDDEN: [Permission; 9] = [
        Permission::UserManage,
        Permission::RoleManage,
        Permission::RoleAssign,
        Permission::SettingsManage,
        Permission::DelegationGrant,
        Permission::DataWipe,
        Permission::DataStartOver,
        Permission::BookStartOver,
        Permission::LegalHoldManage,
    ];

    /// The stable dotted id (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Permission::TenantRead => "tenant.read",
            Permission::TenantCreate => "tenant.create",
            Permission::TenantAdmin => "tenant.admin",
            Permission::EntityRead => "entity.read",
            Permission::EntityCreate => "entity.create",
            Permission::EntityUpdate => "entity.update",
            Permission::EntityRegistryImport => "entity.registry.import",
            Permission::EntityArchive => "entity.archive",
            Permission::BookRead => "book.read",
            Permission::BookOpen => "book.open",
            Permission::BookClose => "book.close",
            Permission::BookExport => "book.export",
            Permission::BookImport => "book.import",
            Permission::BookStartOver => "book.start_over",
            Permission::BookReopen => "book.reopen",
            Permission::LegalHoldManage => "legal_hold.manage",
            Permission::ActRead => "act.read",
            Permission::ActDraft => "act.draft",
            Permission::ActEdit => "act.edit",
            Permission::ActAdvance => "act.advance",
            Permission::ActArchive => "act.archive",
            Permission::SigningPerform => "signing.perform",
            Permission::DocumentGenerate => "document.generate",
            Permission::TemplateManage => "template.manage",
            Permission::LedgerRead => "ledger.read",
            Permission::LedgerRecover => "ledger.recover",
            Permission::DataBackup => "data.backup",
            Permission::DataExport => "data.export",
            Permission::DataWipe => "data.wipe",
            Permission::DataStartOver => "data.start_over",
            Permission::SettingsRead => "settings.read",
            Permission::SettingsManage => "settings.manage",
            Permission::PlatformLogsWrite => "platform.logs.write",
            Permission::CaeRead => "cae.read",
            Permission::CaeRefresh => "cae.refresh",
            Permission::LawRead => "law.read",
            Permission::LawManage => "law.manage",
            Permission::TrustManage => "trust.manage",
            Permission::UserRead => "user.read",
            Permission::UserManage => "user.manage",
            Permission::UserInvite => "user.invite",
            Permission::RoleManage => "role.manage",
            Permission::RoleAssign => "role.assign",
            Permission::DelegationGrant => "delegation.grant",
            Permission::DelegationRevoke => "delegation.revoke",
        }
    }

    /// A meta-permission drives the RBAC machinery (`role.manage`/`role.assign`/`delegation.grant`/
    /// `delegation.revoke`). Meta-permissions are **non-delegable** (they cannot be the subject of a
    /// [`crate::Delegation`]); they may still be granted through a role.
    #[must_use]
    pub const fn is_meta(self) -> bool {
        matches!(
            self,
            Permission::RoleManage
                | Permission::RoleAssign
                | Permission::DelegationGrant
                | Permission::DelegationRevoke
        )
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_deduplicated_and_complete() {
        let set: std::collections::BTreeSet<_> = Permission::ALL.iter().copied().collect();
        assert_eq!(set.len(), Permission::ALL.len(), "ALL has duplicates");
    }

    /// `Permission::ALL` **is** the Owner permission-set, and Owner is what the first user of a
    /// fresh instance receives — so a verb missing from `ALL` silently makes the maximal role less
    /// than maximal. The exhaustive `match` makes adding a variant without touching this test a
    /// COMPILE error, and the list then catches a variant that was declared but left out of `ALL`.
    #[test]
    fn every_permission_variant_is_in_all_so_owner_is_always_maximal() {
        // The compile-time half: adding a variant without touching this test is a
        // "non-exhaustive patterns" error here, which points at the list below.
        fn is_enumerated_below(p: Permission) -> bool {
            match p {
                Permission::TenantRead
                | Permission::TenantCreate
                | Permission::TenantAdmin
                | Permission::EntityRead
                | Permission::EntityCreate
                | Permission::EntityUpdate
                | Permission::EntityRegistryImport
                | Permission::EntityArchive
                | Permission::BookRead
                | Permission::BookOpen
                | Permission::BookClose
                | Permission::BookExport
                | Permission::BookImport
                | Permission::BookStartOver
                | Permission::BookReopen
                | Permission::LegalHoldManage
                | Permission::ActRead
                | Permission::ActDraft
                | Permission::ActEdit
                | Permission::ActAdvance
                | Permission::ActArchive
                | Permission::SigningPerform
                | Permission::DocumentGenerate
                | Permission::TemplateManage
                | Permission::LedgerRead
                | Permission::LedgerRecover
                | Permission::DataBackup
                | Permission::DataExport
                | Permission::DataWipe
                | Permission::DataStartOver
                | Permission::SettingsRead
                | Permission::SettingsManage
                | Permission::PlatformLogsWrite
                | Permission::CaeRead
                | Permission::CaeRefresh
                | Permission::LawRead
                | Permission::LawManage
                | Permission::TrustManage
                | Permission::UserRead
                | Permission::UserManage
                | Permission::UserInvite
                | Permission::RoleManage
                | Permission::RoleAssign
                | Permission::DelegationGrant
                | Permission::DelegationRevoke => true,
            }
        }

        // The runtime half: every enumerated variant must actually BE in ALL (= the Owner set).
        for p in [
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
            Permission::ActArchive,
            Permission::SigningPerform,
            Permission::DocumentGenerate,
            Permission::TemplateManage,
            Permission::LedgerRead,
            Permission::LedgerRecover,
            Permission::DataBackup,
            Permission::DataExport,
            Permission::DataWipe,
            Permission::DataStartOver,
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
        ] {
            assert!(is_enumerated_below(p));
            assert!(Permission::ALL.contains(&p), "{p} missing from ALL");
        }
    }

    /// **Closes the hole in the guard above.** That test proves every variant it *lists* is in
    /// `ALL`, and its exhaustive `match` forces an author who adds a variant to touch this file —
    /// but adding one arm to the or-pattern is enough to make it compile and pass again. `ALL` is a
    /// hand-written `[Permission; N]`, so the new verb can still be missing from it, and the Owner
    /// — the first user of a fresh instance — silently stops being maximal.
    ///
    /// Counting the declarations in the source closes that: every variant carries exactly one
    /// `#[serde(rename = "…")]`, so declaring a verb without adding it to `ALL` fails here. Same
    /// technique the route-map annotation test uses (`chancela-api/src/authz.rs`).
    #[test]
    fn all_holds_every_declared_variant_not_just_the_listed_ones() {
        let src = include_str!("permission.rs");
        // Only the catalog itself is above `#[cfg(test)]`; the tests below must not be counted.
        let declarations = src
            .split("#[cfg(test)]")
            .next()
            .expect("source has a pre-test section")
            .matches("#[serde(rename = \"")
            .count();
        assert_eq!(
            declarations,
            Permission::ALL.len(),
            "{declarations} permission variants are declared but Permission::ALL holds {}: a verb \
             was added to the enum without being added to ALL, so the Owner role — and therefore \
             the first user of a fresh instance — no longer holds every permission",
            Permission::ALL.len()
        );
    }

    /// The signup ceiling is only as good as its list. Every entry must be a real catalog verb
    /// (a typo'd or removed one would silently stop being forbidden), the list must not contain
    /// duplicates, and the four RBAC meta verbs that actually mint authority — everything except
    /// `delegation.revoke`, which only ever *removes* authority — must be on it.
    #[test]
    fn self_signup_forbidden_is_a_real_deduplicated_superset_of_the_escalating_meta_verbs() {
        let set: std::collections::BTreeSet<_> =
            Permission::SELF_SIGNUP_FORBIDDEN.iter().copied().collect();
        assert_eq!(
            set.len(),
            Permission::SELF_SIGNUP_FORBIDDEN.len(),
            "SELF_SIGNUP_FORBIDDEN has duplicates"
        );
        for p in Permission::SELF_SIGNUP_FORBIDDEN {
            assert!(Permission::ALL.contains(&p), "{p} is not a catalog verb");
        }
        for escalating in [
            Permission::RoleManage,
            Permission::RoleAssign,
            Permission::DelegationGrant,
            Permission::UserManage,
        ] {
            assert!(
                set.contains(&escalating),
                "{escalating} can hand a self-signed-up stranger more authority and must be \
                 forbidden to the signup default role"
            );
        }
        // `user.invite` is deliberately NOT on the ceiling: an inviter cannot exceed its own
        // authority, and the invitee still lands on the ceiling-checked default role.
        assert!(!set.contains(&Permission::UserInvite));
    }

    #[test]
    fn meta_flag_matches_meta_array() {
        for p in Permission::ALL {
            assert_eq!(p.is_meta(), Permission::META.contains(&p), "{p}");
        }
    }

    #[test]
    fn serde_roundtrips_via_dotted_id() {
        for p in Permission::ALL {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
            let back: Permission = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn tenant_catalog_has_stable_dotted_ids() {
        // The dedicated tenant authority axis (wp27-e2, user-locked Q3): three verbs with the
        // stable serialised ids the wire/on-disk form and the route classification depend on.
        assert_eq!(Permission::TenantRead.as_str(), "tenant.read");
        assert_eq!(Permission::TenantCreate.as_str(), "tenant.create");
        assert_eq!(Permission::TenantAdmin.as_str(), "tenant.admin");
        for p in [
            Permission::TenantRead,
            Permission::TenantCreate,
            Permission::TenantAdmin,
        ] {
            assert!(Permission::ALL.contains(&p), "{p} missing from ALL");
            // Tenant verbs are ordinary (delegable) authorities, not RBAC meta.
            assert!(!p.is_meta(), "{p} must not be a meta permission");
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(
                serde_json::from_str::<Permission>(&json).unwrap(),
                p,
                "{p} does not round-trip"
            );
        }
    }
}
