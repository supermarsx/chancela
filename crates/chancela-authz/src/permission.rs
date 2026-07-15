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

    // --- Users ---
    #[serde(rename = "user.read")]
    UserRead,
    #[serde(rename = "user.manage")]
    UserManage,

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
    pub const ALL: [Permission; 39] = [
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
        Permission::UserRead,
        Permission::UserManage,
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

    /// The stable dotted id (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
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
            Permission::UserRead => "user.read",
            Permission::UserManage => "user.manage",
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
}
