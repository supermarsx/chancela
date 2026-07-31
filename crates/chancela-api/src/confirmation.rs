//! **The guarded-action registry (t56-e0).**
//!
//! The user's decision that created this module: the operator-configurable confirmation policy
//! covers **every guarded action app-wide**, not just the three in t56's original scope. That
//! promise is only safe if the action set is genuinely enumerated rather than approximated — so the
//! set is *derived* from [`crate::authz::ROUTE_CLASSIFICATION`] and held to it by a test, never
//! assembled by hand or by grep.
//!
//! # Two independent axes
//!
//! - **Strictness** ([`ConfirmationStrictness`]) — *how hard is it to proceed*: confirm, re-auth,
//!   typed phrase. Ordered.
//! - **Consequence** ([`ConfirmationConsequence`]) — *how is it framed*: destructive red styling, or
//!   a neutral acknowledge-and-proceed.
//!
//! They are deliberately not one dial. `T1 + Consequential` is a real gate with none of the
//! destructive framing — the rung a legitimate-but-consequential admin act belongs on. Calling such
//! an act "destructive" would be a security misstatement of the same class this lane forbids for
//! permission descriptions, which is why this is a **guarded-action** registry and not a
//! "destructive-action" one.
//!
//! # Floors, and why a setting can only raise them
//!
//! [`ConfirmationAction::floor`] is a compile-time constant. An operator-configured entry may raise
//! an action's strictness and can **never** lower it ([`effective_strictness`] takes the max). A
//! setting that could switch confirmation *off* for a destructive security action would be
//! privilege-escalation-by-configuration.
//!
//! # Do not floor everything high
//!
//! Over-confirming is its own failure. A typed phrase in front of a routine, reversible action
//! trains operators to type through prompts, which devalues the phrase exactly where it matters.
//! Several actions here are deliberately tiered **down** against first appearances, and several
//! consequential-looking routes are [`RouteGuard::NotGuarded`] because the handler already demands a
//! stronger, better-targeted proof than this policy could add. Every such verdict carries its
//! reason in the table below — a non-guarded verdict is where an error would hide, so it is
//! recorded as explicitly as a guarded one.
//!
//! # Exhaustiveness
//!
//! [`ROUTE_GUARD`] holds one verdict for **every** `Gated` and `Session` route.
//! `tests::route_guard_covers_every_gated_and_session_route` asserts its key set **equals** the
//! corresponding key set of the frozen `ROUTE_CLASSIFICATION`, in both directions. Since
//! `authz::tests::router_walk_every_route_is_classified` already proves no `.route(...)` escapes the
//! frozen map, no guardable route can escape this registry: a new route is compile-green but
//! **test-red** until someone records an explicit verdict for it.
//!
//! `ROUTE_CLASSIFICATION` is `#[cfg(test)]` and so cannot drive runtime behaviour; this table is
//! runtime state (the policy endpoint reads it) and the frozen map is its completeness cross-check.
//!
//! `Exempt` routes are out of scope by construction: they are unauthenticated by design, so there is
//! no acting user to step up and no session to prove anything with. A confirmation gate on one would
//! be decoration.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::attestation::verify_secret;
use crate::data::{ReAuth, require_step_up};
use crate::error::ApiError;
use crate::settings::AuthSettings;
use crate::users::User;

// =================================================================================================
// Strictness and consequence
// =================================================================================================

/// How hard an action is to proceed with. **Ordered** — `Off < Confirm < ConfirmWithReauth <
/// ConfirmWithReauthAndPhrase` — and the ordering is the whole point: [`effective_strictness`]
/// resolves a configured value against a floor by taking the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationStrictness {
    /// No confirmation. Only ever the resolved value for an action absent from the registry.
    #[default]
    Off,
    /// A confirmation dialog the operator must accept.
    Confirm,
    /// A confirmation dialog plus step-up re-authentication ([`require_step_up`]).
    ConfirmWithReauth,
    /// A confirmation dialog, step-up re-authentication, and a byte-exact typed phrase.
    ConfirmWithReauthAndPhrase,
}

/// How an action is **framed**, independent of how hard it is to proceed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationConsequence {
    /// Removes, closes, or forecloses something. Destructive framing is honest here.
    Destructive,
    /// Consequential but not destructive: a legitimate administrative act whose effect the operator
    /// should see before proceeding. Copy for these must **not** borrow destructive vocabulary.
    Consequential,
}

// =================================================================================================
// The action registry
// =================================================================================================

/// Every guarded action in the product.
///
/// Variant names for the actions sibling lanes wire are **frozen** — t51 and t54 write call sites
/// against them. Adding a variant is fine; renaming one is a coordinator-level renegotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationAction {
    // --- Book lifecycle (t51 wires) -------------------------------------------------------------
    BookClose,
    TermoAberturaAdvance,
    TermoAberturaOpen,
    TermoEncerramentoAdvance,
    TermoEncerramentoClose,
    TermoWithdraw,
    BookStartOver,
    BookArchiveDisposal,
    BookImport,
    LegalHoldRelease,
    CmdTestSignature,
    // --- Acts -----------------------------------------------------------------------------------
    ActSeal,
    ActArchive,
    ActRevert,
    ActReopen,
    // --- Users, roles, authority ----------------------------------------------------------------
    UserDisable,
    UserBulkDisable,
    UserBulkRoleChange,
    RoleAssign,
    RoleUnassign,
    RoleDelete,
    RolePermissionChange,
    RoleSeededReconciliation,
    DelegationRevoke,
    DelegationSuspend,
    ApiKeyRevoke,
    ApiKeyRotate,
    // --- Sessions, devices, factors -------------------------------------------------------------
    DevicePairing,
    PairingDeviceRevoke,
    SessionRevoke,
    SessionRevokeOthers,
    TwoFactorDisable,
    TwoFactorBackupCodesRegenerate,
    // --- Ledger and data ------------------------------------------------------------------------
    LedgerReanchor,
    LedgerRestore,
    DataKeyRotation,
    DataCleanupExports,
    DataCleanupOperational,
    PrivacyErasureExecute,
    // --- Configuration --------------------------------------------------------------------------
    SettingsReplace,
    EntityTypeDisable,
    PlatformEnvReplace,
    PlatformServiceControl,
    TrustListRefresh,
    EmailPasswordDelete,
    SearchRebuild,
    SearchPause,
    // --- Content, templates, tenancy ------------------------------------------------------------
    TemplateReplace,
    TemplateDelete,
    TemplateVersionDelete,
    TemplateVersionRestore,
    TemplateLibraryArchive,
    EntityArchive,
    GroupArchive,
    GroupEntityRemove,
    RepositoryDelete,
    RepositoryPolicyDelete,
    ConnectorTargetArchive,
    ConnectorJobCancel,
    SigningCredentialDelete,
    ExternalSignerInviteRevoke,
    StoredCredentialSignature,
    BatchSignature,
    LawPdfDelete,
}

impl ConfirmationAction {
    /// Every variant. Kept beside the wildcard-free matches below so a new variant that someone
    /// forgets to list here is caught by `tests::all_is_complete`.
    pub const ALL: &'static [Self] = &[
        Self::BookClose,
        Self::TermoAberturaAdvance,
        Self::TermoAberturaOpen,
        Self::TermoEncerramentoAdvance,
        Self::TermoEncerramentoClose,
        Self::TermoWithdraw,
        Self::BookStartOver,
        Self::BookArchiveDisposal,
        Self::BookImport,
        Self::LegalHoldRelease,
        Self::CmdTestSignature,
        Self::ActSeal,
        Self::ActArchive,
        Self::ActRevert,
        Self::ActReopen,
        Self::UserDisable,
        Self::UserBulkDisable,
        Self::UserBulkRoleChange,
        Self::RoleAssign,
        Self::RoleUnassign,
        Self::RoleDelete,
        Self::RolePermissionChange,
        Self::RoleSeededReconciliation,
        Self::DelegationRevoke,
        Self::DelegationSuspend,
        Self::ApiKeyRevoke,
        Self::ApiKeyRotate,
        Self::DevicePairing,
        Self::PairingDeviceRevoke,
        Self::SessionRevoke,
        Self::SessionRevokeOthers,
        Self::TwoFactorDisable,
        Self::TwoFactorBackupCodesRegenerate,
        Self::LedgerReanchor,
        Self::LedgerRestore,
        Self::DataKeyRotation,
        Self::DataCleanupExports,
        Self::DataCleanupOperational,
        Self::PrivacyErasureExecute,
        Self::SettingsReplace,
        Self::EntityTypeDisable,
        Self::PlatformEnvReplace,
        Self::PlatformServiceControl,
        Self::TrustListRefresh,
        Self::EmailPasswordDelete,
        Self::SearchRebuild,
        Self::SearchPause,
        Self::TemplateReplace,
        Self::TemplateDelete,
        Self::TemplateVersionDelete,
        Self::TemplateVersionRestore,
        Self::TemplateLibraryArchive,
        Self::EntityArchive,
        Self::GroupArchive,
        Self::GroupEntityRemove,
        Self::RepositoryDelete,
        Self::RepositoryPolicyDelete,
        Self::ConnectorTargetArchive,
        Self::ConnectorJobCancel,
        Self::SigningCredentialDelete,
        Self::ExternalSignerInviteRevoke,
        Self::StoredCredentialSignature,
        Self::BatchSignature,
        Self::LawPdfDelete,
    ];

    /// The stable wire identifier. This is what `GET /v1/confirmation-policy` emits, what the
    /// settings map keys on, and what the web derives its copy key from — so it is as frozen as the
    /// variant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BookClose => "book.close",
            Self::TermoAberturaAdvance => "termo_abertura.advance",
            Self::TermoAberturaOpen => "termo_abertura.open",
            Self::TermoEncerramentoAdvance => "termo_encerramento.advance",
            Self::TermoEncerramentoClose => "termo_encerramento.close",
            Self::TermoWithdraw => "termo.withdraw",
            Self::BookStartOver => "book.start_over",
            Self::BookArchiveDisposal => "book.archive_disposal",
            Self::BookImport => "book.import",
            Self::LegalHoldRelease => "legal_hold.release",
            Self::CmdTestSignature => "signature.cmd_test",
            Self::ActSeal => "act.seal",
            Self::ActArchive => "act.archive",
            Self::ActRevert => "act.revert",
            Self::ActReopen => "act.reopen",
            Self::UserDisable => "user.disable",
            Self::UserBulkDisable => "user.bulk_disable",
            Self::UserBulkRoleChange => "user.bulk_role_change",
            Self::RoleAssign => "role.assign",
            Self::RoleUnassign => "role.unassign",
            Self::RoleDelete => "role.delete",
            Self::RolePermissionChange => "role.permission_change",
            Self::RoleSeededReconciliation => "role.seeded_reconciliation",
            Self::DelegationRevoke => "delegation.revoke",
            Self::DelegationSuspend => "delegation.suspend",
            Self::ApiKeyRevoke => "api_key.revoke",
            Self::ApiKeyRotate => "api_key.rotate",
            Self::DevicePairing => "device.pairing",
            Self::PairingDeviceRevoke => "device.revoke",
            Self::SessionRevoke => "session.revoke",
            Self::SessionRevokeOthers => "session.revoke_others",
            Self::TwoFactorDisable => "two_factor.disable",
            Self::TwoFactorBackupCodesRegenerate => "two_factor.backup_codes_regenerate",
            Self::LedgerReanchor => "ledger.reanchor",
            Self::LedgerRestore => "ledger.restore",
            Self::DataKeyRotation => "data.key_rotation",
            Self::DataCleanupExports => "data.cleanup_exports",
            Self::DataCleanupOperational => "data.cleanup_operational",
            Self::PrivacyErasureExecute => "privacy.erasure_execute",
            Self::SettingsReplace => "settings.replace",
            Self::EntityTypeDisable => "entity_type.disable",
            Self::PlatformEnvReplace => "platform.env_replace",
            Self::PlatformServiceControl => "platform.service_control",
            Self::TrustListRefresh => "trust.list_refresh",
            Self::EmailPasswordDelete => "email.password_delete",
            Self::SearchRebuild => "search.rebuild",
            Self::SearchPause => "search.pause",
            Self::TemplateReplace => "template.replace",
            Self::TemplateDelete => "template.delete",
            Self::TemplateVersionDelete => "template.version_delete",
            Self::TemplateVersionRestore => "template.version_restore",
            Self::TemplateLibraryArchive => "template_library.archive",
            Self::EntityArchive => "entity.archive",
            Self::GroupArchive => "group.archive",
            Self::GroupEntityRemove => "group.entity_remove",
            Self::RepositoryDelete => "repository.delete",
            Self::RepositoryPolicyDelete => "repository.policy_delete",
            Self::ConnectorTargetArchive => "connector_target.archive",
            Self::ConnectorJobCancel => "connector_job.cancel",
            Self::SigningCredentialDelete => "signing_credential.delete",
            Self::ExternalSignerInviteRevoke => "external_signer_invite.revoke",
            Self::StoredCredentialSignature => "signature.stored_credential",
            Self::BatchSignature => "signature.batch",
            Self::LawPdfDelete => "law.pdf_delete",
        }
    }

    /// The lowest strictness this action may ever be performed at. **Wildcard-free by design**: a
    /// new variant fails to compile until someone tiers it.
    ///
    /// Tiers: `Confirm` = reversible or single-subject low blast radius · `ConfirmWithReauth` =
    /// removes access/authority or hides evidentiary state, or is multi-subject ·
    /// `ConfirmWithReauthAndPhrase` = irreversibly closes, destroys, or rewrites evidentiary state.
    #[must_use]
    pub const fn floor(self) -> ConfirmationStrictness {
        use ConfirmationStrictness::{Confirm, ConfirmWithReauth, ConfirmWithReauthAndPhrase};
        match self {
            // --- T3: irreversible evidentiary state -------------------------------------------
            // `chancela_core::book` has NO `Closed -> Open` transition and no `reopen` at all, so
            // closing is irreversible in fact, whatever the `book.reopen` verb catalog implies.
            Self::BookClose | Self::TermoEncerramentoClose => ConfirmWithReauthAndPhrase,
            // Appends the `book.opened` genesis event; a genesis cannot be un-appended.
            Self::TermoAberturaOpen => ConfirmWithReauthAndPhrase,
            // Retires the live book and replaces it with a successor. No way back.
            Self::BookStartOver => ConfirmWithReauthAndPhrase,
            // Appends a permanent, non-repeatable disposal attestation (a second execution is
            // refused `409`) — the act a legal hold exists to block. NOTE it does **not** delete
            // anything today; see the `ROUTE_GUARD` entry.
            Self::BookArchiveDisposal => ConfirmWithReauthAndPhrase,
            Self::LedgerReanchor | Self::LedgerRestore => ConfirmWithReauthAndPhrase,
            Self::DataKeyRotation => ConfirmWithReauthAndPhrase,
            // Destroys the subject DEK and VACUUMs. Genuinely unrecoverable.
            Self::PrivacyErasureExecute => ConfirmWithReauthAndPhrase,
            // Deletes retained export archives — which are the only copy of what a book/instance
            // start-over archived, i.e. the artifact that makes "nothing is erased" true.
            Self::DataCleanupExports => ConfirmWithReauthAndPhrase,
            // A "test" button that produces a real, legally binding qualified signature on every
            // press. The label is the reason for the gate, not an argument against it.
            Self::CmdTestSignature => ConfirmWithReauthAndPhrase,
            // Moves authority across many subjects in one press.
            Self::UserBulkRoleChange => ConfirmWithReauthAndPhrase,

            // --- T2: removes access/authority, hides evidentiary state, or is multi-subject ----
            // Destroys nothing and is re-appliable; it only makes material *eligible* for a
            // disposal that carries its own T3 floor. Charging a phrase here would double-charge
            // the operator for one irreversible act that happens later.
            Self::LegalHoldRelease => ConfirmWithReauth,
            Self::ActArchive => ConfirmWithReauth,
            Self::RoleDelete | Self::RolePermissionChange | Self::RoleUnassign => ConfirmWithReauth,
            Self::UserBulkDisable => ConfirmWithReauth,
            // Item 4 is a hard user requirement: minting a code enrols a new device as this
            // operator, so an unattended signed-in browser must not be one click from it.
            Self::DevicePairing => ConfirmWithReauth,
            Self::TwoFactorDisable => ConfirmWithReauth,
            Self::TrustListRefresh => ConfirmWithReauth,

            // --- T1: reversible, or single-subject with low blast radius ----------------------
            Self::UserDisable => Confirm,
            Self::TermoAberturaAdvance
            | Self::TermoEncerramentoAdvance
            | Self::TermoWithdraw
            | Self::BookImport => Confirm,
            Self::ActSeal | Self::ActRevert | Self::ActReopen => Confirm,
            Self::RoleAssign | Self::RoleSeededReconciliation => Confirm,
            Self::DelegationRevoke | Self::DelegationSuspend => Confirm,
            Self::ApiKeyRevoke | Self::ApiKeyRotate => Confirm,
            Self::PairingDeviceRevoke
            | Self::SessionRevoke
            | Self::SessionRevokeOthers
            | Self::TwoFactorBackupCodesRegenerate => Confirm,
            Self::DataCleanupOperational => Confirm,
            Self::SettingsReplace
            | Self::EntityTypeDisable
            | Self::PlatformEnvReplace
            | Self::PlatformServiceControl
            | Self::EmailPasswordDelete => Confirm,
            Self::SearchRebuild | Self::SearchPause => Confirm,
            Self::TemplateReplace
            | Self::TemplateDelete
            | Self::TemplateVersionDelete
            | Self::TemplateVersionRestore
            | Self::TemplateLibraryArchive => Confirm,
            // Retires an entity from *new authorship* and nothing else: every book, act, document
            // and ledger row stays readable, resolvable and exportable, and `unarchive` reverses it
            // with its own ledger event. A confirm step, but no re-auth and no phrase — those are
            // priced for acts that cannot be undone, and charging them here would spend the
            // operator's attention on the one archival action in the product that is cheap to
            // reverse. `unarchive` carries no floor at all: granting authorship back is not the
            // dangerous direction, and a prompt with no severity behind it devalues the real ones.
            Self::EntityArchive => Confirm,
            Self::GroupArchive
            | Self::GroupEntityRemove
            | Self::RepositoryDelete
            | Self::RepositoryPolicyDelete
            | Self::ConnectorTargetArchive
            | Self::ConnectorJobCancel => Confirm,
            Self::SigningCredentialDelete
            | Self::ExternalSignerInviteRevoke
            | Self::StoredCredentialSignature
            | Self::BatchSignature => Confirm,
            Self::LawPdfDelete => Confirm,
        }
    }

    /// How the action is framed. Independent of [`floor`](Self::floor) — see the module header.
    #[must_use]
    pub const fn consequence(self) -> ConfirmationConsequence {
        use ConfirmationConsequence::{Consequential, Destructive};
        match self {
            // Removes, closes, or forecloses something.
            Self::BookClose
            | Self::TermoEncerramentoClose
            | Self::BookStartOver
            | Self::BookArchiveDisposal
            | Self::LegalHoldRelease
            | Self::LedgerReanchor
            | Self::LedgerRestore
            | Self::PrivacyErasureExecute
            | Self::DataCleanupExports
            | Self::UserDisable
            | Self::UserBulkDisable
            | Self::UserBulkRoleChange
            | Self::RoleUnassign
            | Self::RoleDelete
            | Self::RolePermissionChange
            | Self::DelegationRevoke
            | Self::ApiKeyRevoke
            | Self::PairingDeviceRevoke
            | Self::SessionRevoke
            | Self::SessionRevokeOthers
            | Self::TwoFactorDisable
            | Self::EmailPasswordDelete
            | Self::TemplateDelete
            | Self::TemplateVersionDelete
            | Self::TemplateLibraryArchive
            | Self::GroupArchive
            | Self::GroupEntityRemove
            | Self::RepositoryDelete
            | Self::RepositoryPolicyDelete
            | Self::ConnectorTargetArchive
            | Self::SigningCredentialDelete
            | Self::ExternalSignerInviteRevoke
            | Self::LawPdfDelete => Destructive,

            // Consequential but legitimate and non-destructive. Copy for these must not borrow
            // destructive vocabulary — mislabelling a legitimate admin act as destructive trains
            // operators to click through the real guards.
            Self::TermoAberturaAdvance
            | Self::TermoAberturaOpen
            | Self::TermoEncerramentoAdvance
            | Self::TermoWithdraw
            | Self::BookImport
            | Self::CmdTestSignature
            | Self::ActSeal
            | Self::ActArchive
            | Self::ActRevert
            | Self::ActReopen
            // Deliberately **not** `Destructive`, and deliberately unlike `GroupArchive` above.
            // A `CompanyGroup` is documented in-tree as a convenience view and its archiving is
            // one-way; an entity is a legal person whose archiving is reversible, removes no
            // record, and leaves sealed acts naming their parties. Borrowing destructive
            // vocabulary for it would train operators to click through the guards that matter.
            | Self::EntityArchive
            | Self::RoleAssign
            | Self::RoleSeededReconciliation
            | Self::DelegationSuspend
            | Self::ApiKeyRotate
            | Self::DevicePairing
            | Self::TwoFactorBackupCodesRegenerate
            | Self::DataKeyRotation
            | Self::DataCleanupOperational
            | Self::SettingsReplace
            | Self::EntityTypeDisable
            | Self::PlatformEnvReplace
            | Self::PlatformServiceControl
            | Self::TrustListRefresh
            | Self::SearchRebuild
            | Self::SearchPause
            | Self::TemplateReplace
            | Self::TemplateVersionRestore
            | Self::ConnectorJobCancel
            | Self::StoredCredentialSignature
            | Self::BatchSignature => Consequential,
        }
    }

    /// The byte-exact phrase the operator must transcribe, `Some` **iff** the floor is
    /// [`ConfirmationStrictness::ConfirmWithReauthAndPhrase`] (asserted by
    /// `tests::phrase_exists_exactly_for_the_phrase_floor`).
    ///
    /// **Fixed, non-localised pt-PT — deliberate, not an oversight.** The phrase is a token to
    /// transcribe, not an instruction to read; the sentence around it *is* localised (the modal
    /// renders `t('confirm.phraseLabel', { phrase })` in all 14 locales) and only the token is
    /// fixed. Three reasons: it matches the pre-existing highest-bar operations, which already use
    /// `&'static str` constants checked byte-exact (`data.rs`'s `LIMPAR DADOS` / `REPOR FÁBRICA` /
    /// `RECOMEÇAR`); the server check must be single-valued, and accepting 14 renderings would
    /// either weaken it to set-membership or force the server to trust a client-declared locale — a
    /// proof whose accepted value the caller influences is a weaker proof; and a fixed token
    /// resists scripted confirmation slightly better.
    ///
    /// **Stated plainly rather than hidden:** an operator working in de-DE or en-US transcribes a
    /// Portuguese token. That is accepted. The i18n gates will not catch it (these strings never
    /// enter a locale catalog), which is why it is recorded here.
    #[must_use]
    pub const fn phrase(self) -> Option<&'static str> {
        match self {
            Self::BookClose | Self::TermoEncerramentoClose => Some("ENCERRAR LIVRO"),
            Self::TermoAberturaOpen => Some("ABRIR LIVRO"),
            Self::BookStartOver => Some("RECOMEÇAR LIVRO"),
            // Names what the endpoint actually does. It records a disposal; it does not delete.
            Self::BookArchiveDisposal => Some("REGISTAR DISPOSIÇÃO"),
            Self::LedgerReanchor => Some("RECONSTRUIR CADEIA"),
            Self::LedgerRestore => Some("RESTAURAR REGISTO"),
            Self::DataKeyRotation => Some("SUBSTITUIR CHAVE"),
            Self::PrivacyErasureExecute => Some("APAGAR TITULAR"),
            Self::DataCleanupExports => Some("ELIMINAR EXPORTAÇÕES"),
            Self::CmdTestSignature => Some("ASSINAR TESTE"),
            Self::UserBulkRoleChange => Some("ALTERAR PAPÉIS"),
            _ => None,
        }
    }
}

// =================================================================================================
// Route -> verdict
// =================================================================================================

/// One route's confirmation verdict. Every `Gated`/`Session` route has exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteGuard {
    /// The route's handler(s) must gate on one of these actions. More than one appears where a
    /// single route reaches materially different operations (a request flag or method selects
    /// which), so that a light operation is not force-floored to a heavy one's tier.
    Actions(&'static [ConfirmationAction]),
    /// Already gated by a hard-coded mechanism that predates this policy, and deliberately left
    /// alone: folding it in would let an operator configuration sit in front of a gate that is
    /// currently not configurable at all.
    PreExistingGate(&'static str),
    /// Deliberately not guarded, with the evidence for why. A verdict here is a claim about the
    /// handler, not an omission.
    NotGuarded(&'static str),
}

/// **Every `Gated` and `Session` route → its confirmation verdict.**
///
/// Held to `authz::ROUTE_CLASSIFICATION` by
/// `tests::route_guard_covers_every_gated_and_session_route`, which asserts set equality in both
/// directions. Adding a route without a verdict here is test-red.
pub(crate) const ROUTE_GUARD: &[(&str, RouteGuard)] = &[
    (
        "/v1/entities",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/entities/page",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/entities/{id}",
        RouteGuard::NotGuarded(
            "Edits mutable draft state and is refused once the record is frozen.",
        ),
    ),
    (
        "/v1/entities/{id}/archive",
        RouteGuard::Actions(&[ConfirmationAction::EntityArchive]),
    ),
    (
        "/v1/entities/{id}/unarchive",
        RouteGuard::NotGuarded(
            "Returns an entity to active authorship. Granting the ability to start work back is \
             not the dangerous direction, and it is separately ledgered.",
        ),
    ),
    (
        "/v1/entities/import-from-registry",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/entities/{id}/registry",
        RouteGuard::NotGuarded(
            "Accepts one backend-owned auto-update attempt carrying only worker control metadata.",
        ),
    ),
    (
        "/v1/entities/{id}/registry/import",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/entities/{id}/chronology",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/groups",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}",
        RouteGuard::Actions(&[ConfirmationAction::GroupArchive]),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/entities/{entity_id}",
        RouteGuard::Actions(&[ConfirmationAction::GroupEntityRemove]),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/dashboard",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}",
        RouteGuard::Actions(&[ConfirmationAction::TemplateLibraryArchive]),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/revisions",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/history",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/groups/{group_id}/template-libraries/{library_id}/revisions/{revision}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/zk-repositories/storage-status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/zk-repositories/shared-object-root",
        RouteGuard::NotGuarded(
            "Declares or clears the shared object root path; stored objects are untouched.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/repository-policy",
        RouteGuard::Actions(&[ConfirmationAction::RepositoryPolicyDelete]),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}",
        RouteGuard::Actions(&[ConfirmationAction::RepositoryDelete]),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/uploads",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/uploads/{upload_id}/ciphertext",
        RouteGuard::NotGuarded(
            "Uploads ciphertext for a staged upload; object versions are immutable and never replaced.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/manifest",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/ciphertext",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/repositories/{repository_id}/objects/{object_id}/versions/{version}/readability-package",
        RouteGuard::PreExistingGate(
            "Already `require_step_up` in `zk_repository::create_readability_package` (annotated in `ROUTE_CLASSIFICATION`): producing readable plaintext from a zero-knowledge repository is gated by the operator's own credential at the call site. Folding it into the policy would let an operator configuration lower an existing hard-coded gate.",
        ),
    ),
    (
        "/v1/registry/lookup",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/books",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/page",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}",
        RouteGuard::NotGuarded(
            "Replaces or clears the book's document-layout override only — no evidentiary state, no lifecycle transition.",
        ),
    ),
    (
        "/v1/books/{id}/close",
        RouteGuard::Actions(&[ConfirmationAction::BookClose]),
    ),
    (
        "/v1/books/{id}/acts",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/termo/abertura",
        RouteGuard::NotGuarded(
            "Edits mutable draft state and is refused once the record is frozen.",
        ),
    ),
    (
        "/v1/books/{id}/termo/abertura/advance",
        RouteGuard::Actions(&[ConfirmationAction::TermoAberturaAdvance]),
    ),
    (
        "/v1/books/{id}/termo/abertura/sign",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/{id}/termo/abertura/sign/pkcs12",
        RouteGuard::NotGuarded(
            "The PFX passphrase is a per-use credential proof for this exact slot signature.",
        ),
    ),
    (
        "/v1/books/{id}/termo/abertura/document",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/termo/abertura/signatures/{slot_id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/termo/abertura/open",
        RouteGuard::Actions(&[ConfirmationAction::TermoAberturaOpen]),
    ),
    (
        "/v1/books/{id}/termo/encerramento",
        RouteGuard::NotGuarded(
            "Edits mutable draft state and is refused once the record is frozen.",
        ),
    ),
    (
        "/v1/books/{id}/termo/encerramento/advance",
        RouteGuard::Actions(&[ConfirmationAction::TermoEncerramentoAdvance]),
    ),
    (
        "/v1/books/{id}/termo/encerramento/sign",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/{id}/termo/encerramento/sign/pkcs12",
        RouteGuard::NotGuarded(
            "The PFX passphrase is a per-use credential proof for this exact slot signature.",
        ),
    ),
    (
        "/v1/books/{id}/termo/encerramento/close",
        RouteGuard::Actions(&[ConfirmationAction::TermoEncerramentoClose]),
    ),
    (
        "/v1/books/paper-import/validate",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/books/paper-import",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/paper-import/{id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/paper-import/{id}/ocr/enqueue",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-status",
        RouteGuard::NotGuarded(
            "Updates only the OCR lifecycle marker on a preserved paper-book import. Metadata-only; stores no OCR output.",
        ),
    ),
    (
        "/v1/books/paper-import/{id}/ocr/run",
        RouteGuard::NotGuarded(
            "Stores bounded stdout as a non-authoritative draft; creates no canonical text.",
        ),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-drafts",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/review",
        RouteGuard::NotGuarded("Metadata-only review state on a non-authoritative OCR draft."),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/books/paper-import/{id}/conversion-dossiers",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/paper-import/{id}/ocr-canonical-rehearsal",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/paper-import/{id}/bytes",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/legal-hold",
        RouteGuard::Actions(&[ConfirmationAction::LegalHoldRelease]),
    ),
    (
        "/v1/books/{id}/archive/package",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/archive/local-dglab-interchange-manifest",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/books/{id}/archive/disposal",
        RouteGuard::Actions(&[ConfirmationAction::BookArchiveDisposal]),
    ),
    (
        "/v1/acts",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{id}",
        RouteGuard::NotGuarded(
            "Edits mutable draft state and is refused once the record is frozen.",
        ),
    ),
    (
        "/v1/acts/{id}/advance",
        RouteGuard::NotGuarded(
            "One forward pre-signature lifecycle step, reversible by `acts/{id}/revert`.",
        ),
    ),
    (
        "/v1/acts/{id}/reopen",
        RouteGuard::Actions(&[ConfirmationAction::ActReopen]),
    ),
    (
        "/v1/acts/{id}/revert",
        RouteGuard::Actions(&[ConfirmationAction::ActRevert]),
    ),
    (
        "/v1/acts/{id}/human-verification",
        RouteGuard::NotGuarded(
            "Records accept/reject of human review over AI-assisted draft text.",
        ),
    ),
    (
        "/v1/acts/{id}/body/preview",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/acts/{id}/compliance",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/seal",
        RouteGuard::Actions(&[ConfirmationAction::ActSeal]),
    ),
    (
        "/v1/acts/{id}/archive",
        RouteGuard::Actions(&[ConfirmationAction::ActArchive]),
    ),
    (
        "/v1/acts/{id}/follow-ups",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/follow-ups/{id}",
        RouteGuard::NotGuarded(
            "Edits mutable draft state and is refused once the record is frozen.",
        ),
    ),
    (
        "/v1/follow-ups/{id}/complete",
        RouteGuard::NotGuarded(
            "Marks an open follow-up row completed. Single-subject workflow bookkeeping; no evidentiary or authority consequence.",
        ),
    ),
    (
        "/v1/acts/{id}/convening/dispatch",
        RouteGuard::NotGuarded(
            "Records that a convening notice was dispatched — an append-only evidentiary assertion that removes nothing.",
        ),
    ),
    (
        "/v1/acts/{id}/document/preview",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/document/generate",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{act_id}/documents/generated",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/generated/{document_id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/generated/{document_id}/dispatch-evidence",
        RouteGuard::NotGuarded(
            "Records metadata-only dispatch evidence; sends nothing and mutates no sealed bytes.",
        ),
    ),
    (
        "/v1/acts/{id}/document/working-copy",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/document/office",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/document",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/document/bundle",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/import",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/documents/imported",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/imported/{id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/imported/{id}/review",
        RouteGuard::NotGuarded(
            "Metadata-only review-state transition; never touches canonical or signed rows.",
        ),
    ),
    (
        "/v1/documents/imported/{id}/bytes",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/documents/import/validate",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/external-validator-reports",
        RouteGuard::NotGuarded("Accepts operator-supplied technical metadata only."),
    ),
    (
        "/v1/external-validator-reports/{case_id}/{validator_family}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/signature/pdf/validate",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/signature/pdf/validate/report",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/signature/asic/inspect",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/signature/xades/sign",
        RouteGuard::NotGuarded(
            "Signs caller-supplied content and returns it; nothing is persisted.",
        ),
    ),
    (
        "/v1/signature/xades/validate",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/signature/asic/sign",
        RouteGuard::NotGuarded(
            "Signs caller-supplied content and returns it; nothing is persisted.",
        ),
    ),
    (
        "/v1/scap/providers",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/scap/attributes",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/scap/sign",
        RouteGuard::NotGuarded(
            "Signs caller-supplied content and returns it; nothing is persisted.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/cmd/initiate",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{id}/signature/cmd/confirm",
        RouteGuard::NotGuarded(
            "The signer proves possession out of band at the moment of signing (CMD OTP). An application-level re-auth would prove less, later, about the same operator.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/cc/sign",
        RouteGuard::NotGuarded(
            "The Cartão de Cidadão PIN is entered at the reader for this exact signature. Redundant.",
        ),
    ),
    (
        "/v1/signature/cc/bridge/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/signature/cc/bridge/test",
        RouteGuard::NotGuarded(
            "Signs one ephemeral, domain-separated 32-byte random challenge that exists only in memory and is never persisted (`signature::test_cc_bridge`). It produces no signature over any document and no legally binding artifact — unlike the planned CMD test signature, which does.",
        ),
    ),
    (
        "/v1/signature/cc/batch-sign",
        RouteGuard::Actions(&[ConfirmationAction::BatchSignature]),
    ),
    (
        "/v1/signature/cmd/test-signature/initiate",
        RouteGuard::Actions(&[ConfirmationAction::CmdTestSignature]),
    ),
    (
        "/v1/signature/cmd/test-signature/confirm",
        RouteGuard::Actions(&[ConfirmationAction::CmdTestSignature]),
    ),
    (
        "/v1/signature/cmd/test-signature/{test_id}/document",
        RouteGuard::NotGuarded(
            "Downloads the PDF a completed test signature already produced. Read-only; the signature itself is gated on `/v1/signature/cmd/test-signature/initiate` and `/confirm`.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/dss/attach",
        RouteGuard::NotGuarded(
            "Appends local technical evidence to an existing signed PDF; earlier evidence is preserved.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/dss/collect-revocation",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{id}/signature/archive-timestamp/append",
        RouteGuard::NotGuarded("Appends a document timestamp; earlier evidence is preserved."),
    ),
    (
        "/v1/acts/{id}/signature/ltv/execute",
        RouteGuard::NotGuarded(
            "Appends long-term validation evidence; preserves what is already there.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/ltv/renew",
        RouteGuard::NotGuarded("Appends a further evidence revision, preserving the earlier one."),
    ),
    (
        "/v1/acts/{id}/signature/remote/{provider}/initiate",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/signature/remote/{provider}/batch-initiate",
        RouteGuard::Actions(&[ConfirmationAction::BatchSignature]),
    ),
    (
        "/v1/acts/{id}/signature/remote/{provider}/confirm",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{id}/signature/official/import",
        RouteGuard::NotGuarded(
            "Stores externally produced signed bytes as imported evidence only after proving they extend this act's canonical signing PDF.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/local/pkcs12/sign",
        RouteGuard::NotGuarded(
            "The PFX passphrase is supplied for this exact signature and is a per-use credential proof.",
        ),
    ),
    (
        "/v1/acts/{id}/signature/local/pkcs12/sign-stored",
        RouteGuard::Actions(&[ConfirmationAction::StoredCredentialSignature]),
    ),
    (
        "/v1/acts/{id}/signature/external-invites",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/acts/{id}/signature/external-invites/{invite_id}/revoke",
        RouteGuard::Actions(&[ConfirmationAction::ExternalSignerInviteRevoke]),
    ),
    (
        "/v1/acts/{id}/external-signing/envelopes",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/external-signing/envelopes/{id}",
        RouteGuard::NotGuarded("Updates envelope tracking metadata; completes no signature."),
    ),
    (
        "/v1/signature/providers",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/signature/provider-credentials/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/signature/provider-credentials",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/signature/provider-credentials/cmd/ama-certificate/inspect",
        RouteGuard::NotGuarded(
            "Parses a candidate certificate the operator already holds and reports what it found. \
             `inspect_ama_certificate` writes no record, appends no ledger event, contacts no \
             provider and performs no key operation — the credential write that may follow is the \
             guarded step.",
        ),
    ),
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/reorder",
        RouteGuard::NotGuarded(
            "Sets the failover priority order of stored credential entries. No entry is created, altered or removed.",
        ),
    ),
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}/probe",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}",
        RouteGuard::Actions(&[ConfirmationAction::SigningCredentialDelete]),
    ),
    (
        "/v1/acts/{id}/signature",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/acts/{id}/document/signed",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/templates",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/templates/{id}",
        RouteGuard::Actions(&[
            ConfirmationAction::TemplateReplace,
            ConfirmationAction::TemplateDelete,
        ]),
    ),
    (
        "/v1/templates/{id}/versions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/templates/{id}/versions/{version_id}",
        RouteGuard::Actions(&[ConfirmationAction::TemplateVersionDelete]),
    ),
    (
        "/v1/templates/{id}/versions/{version_id}/restore",
        RouteGuard::Actions(&[ConfirmationAction::TemplateVersionRestore]),
    ),
    (
        "/v1/templates/{id}/export",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/templates/import",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/templates/body/preview",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/templates/document/preview",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/templates/document/preview/markdown",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/ledger/events",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/ledger/events/page",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/ledger/archive/document",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/ledger/verify",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/ledger/integrity",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/ledger/recovery/reanchor",
        RouteGuard::Actions(&[ConfirmationAction::LedgerReanchor]),
    ),
    (
        "/v1/ledger/recovery/restore",
        RouteGuard::Actions(&[ConfirmationAction::LedgerRestore]),
    ),
    (
        "/v1/ledger/recovery/restore/preflight",
        RouteGuard::NotGuarded("Read-only verification; never swaps the live DB."),
    ),
    (
        "/v1/backup/recovery-drills",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/sync/handoff-preflight",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-targets",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}",
        RouteGuard::Actions(&[ConfirmationAction::ConnectorTargetArchive]),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}/probe",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-targets/{target_id}/run",
        RouteGuard::NotGuarded(
            "Runs a configured connector target; creates job records and destroys nothing.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-jobs",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}/cancel",
        RouteGuard::Actions(&[ConfirmationAction::ConnectorJobCancel]),
    ),
    (
        "/v1/tenants/{tenant_id}/connector-jobs/{job_id}/retry",
        RouteGuard::NotGuarded("Re-runs a job; idempotent in effect and destroys nothing."),
    ),
    (
        "/v1/books/{id}/export",
        RouteGuard::NotGuarded(
            "Retains a self-verifying bundle under `exports/` and streams it. Purely additive: nothing in the book is altered or removed.",
        ),
    ),
    (
        "/v1/books/import/preflight",
        RouteGuard::NotGuarded(
            "Read-only import preview: it verifies the bundle and reports collisions but stages no durable import and appends no event.",
        ),
    ),
    (
        "/v1/books/import",
        RouteGuard::Actions(&[ConfirmationAction::BookImport]),
    ),
    (
        "/v1/books/{id}/start-over",
        RouteGuard::Actions(&[ConfirmationAction::BookStartOver]),
    ),
    (
        "/v1/data/reset",
        RouteGuard::PreExistingGate(
            "T4 data-reset family: already phrase (`LIMPAR DADOS` / `REPOR FÁBRICA`) + `require_step_up` + export-first in `data::reset_data`. Out of t56 scope by ruling — do not re-plumb or weaken it.",
        ),
    ),
    (
        "/v1/data/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/data/cleanup",
        RouteGuard::Actions(&[
            ConfirmationAction::DataCleanupExports,
            ConfirmationAction::DataCleanupOperational,
        ]),
    ),
    (
        "/v1/data/key-rotation",
        RouteGuard::Actions(&[ConfirmationAction::DataKeyRotation]),
    ),
    (
        "/v1/data/key-rotation/preflight",
        RouteGuard::NotGuarded(
            "Read-only SQLCipher rekey readiness check; the live store key is never touched. The execution route carries the T3 floor.",
        ),
    ),
    (
        "/v1/data/start-over",
        RouteGuard::PreExistingGate(
            "T4 data-reset family: already phrase (`RECOMEÇAR`) + `require_step_up` + export-first in `data::start_over_instance`. Out of t56 scope by ruling.",
        ),
    ),
    (
        "/v1/dashboard",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/search",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/search/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/search/rebuild",
        RouteGuard::Actions(&[ConfirmationAction::SearchRebuild]),
    ),
    (
        "/v1/search/pause",
        RouteGuard::Actions(&[ConfirmationAction::SearchPause]),
    ),
    (
        "/v1/search/resume",
        RouteGuard::NotGuarded(
            "Lifts a pause; the safe direction. `search/pause` carries the floor.",
        ),
    ),
    (
        "/v1/notifications/triage",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/notifications/triage/{id}",
        RouteGuard::NotGuarded("Sets one notification's read/dismissed marker."),
    ),
    (
        "/v1/me/preferences",
        RouteGuard::NotGuarded(
            "Replaces the caller's own UI preferences. Cosmetic; no authority, no evidentiary state.",
        ),
    ),
    (
        "/v1/backup",
        RouteGuard::NotGuarded("Takes a hot backup — additive, destroys nothing."),
    ),
    (
        "/v1/settings",
        RouteGuard::Actions(&[
            ConfirmationAction::SettingsReplace,
            ConfirmationAction::EntityTypeDisable,
        ]),
    ),
    (
        "/v1/search/settings",
        RouteGuard::NotGuarded(
            "Replaces only the non-secret search-worker slice; no other configuration is reachable from it and nothing is destroyed.",
        ),
    ),
    (
        "/v1/settings/email/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/settings/email/password",
        RouteGuard::Actions(&[ConfirmationAction::EmailPasswordDelete]),
    ),
    (
        "/v1/settings/email/test",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/settings/email/deliveries",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/settings/email/deliveries/{id}/resend",
        RouteGuard::NotGuarded(
            "Re-sends only messages fully derivable from durable non-secret state; token-bearing mail is refused with `422`.",
        ),
    ),
    (
        "/v1/platform/services",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/platform/env",
        RouteGuard::Actions(&[ConfirmationAction::PlatformEnvReplace]),
    ),
    (
        "/v1/platform/logs",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/platform/logs/forwarded",
        RouteGuard::NotGuarded(
            "Ingests one supervisor-forwarded structured log line. Append-only operational telemetry; no domain state.",
        ),
    ),
    (
        "/v1/platform/services/{id}/actions/{action}",
        RouteGuard::Actions(&[ConfirmationAction::PlatformServiceControl]),
    ),
    (
        "/v1/cae",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/cae/refresh",
        RouteGuard::NotGuarded(
            "Swaps the CAE catalog only when the fetched one supersedes the active one; the previous cache is preserved on failure.",
        ),
    ),
    (
        "/v1/cae/updates",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/cae/sections",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/cae/{code}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/cae/{code}/children",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/trust/status",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/trust/refresh",
        RouteGuard::Actions(&[ConfirmationAction::TrustListRefresh]),
    ),
    (
        "/v1/trust/catalog",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/trust/tsa",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/trust/providers/{id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/trust/services/{id}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law/citations/resolve",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/law/corpus",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law/corpus/search",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law/corpus/{diploma}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law/corpus/{diploma}/{article}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/law/{id}/fetch",
        RouteGuard::NotGuarded("Downloads a pinned PDF into the archive; additive."),
    ),
    (
        "/v1/law/{id}/pdf",
        RouteGuard::Actions(&[ConfirmationAction::LawPdfDelete]),
    ),
    (
        "/v1/users",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/users/page",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/users/{id}",
        RouteGuard::Actions(&[ConfirmationAction::UserDisable]),
    ),
    (
        "/v1/users/{id}/secret",
        RouteGuard::NotGuarded(
            "`users::set_secret` already demands the target's CURRENT password or a valid recovery phrase for every cross-user reset, and the current password for a self change. That is a stronger, target-bound proof than this policy's actor-bound step-up; adding one would be redundant friction.",
        ),
    ),
    (
        "/v1/users/{id}/attestation-key",
        RouteGuard::NotGuarded(
            "Same target-bound proof as `/v1/users/{id}/secret`: generation requires the target's current password, removal requires the password or a recovery phrase.",
        ),
    ),
    (
        "/v1/users/{id}/recovery",
        RouteGuard::NotGuarded(
            "Issuing/rotating a recovery phrase is gated by the same target-bound credential proof as `set_secret`, and it grants no authority — it replaces one reset credential with another.",
        ),
    ),
    (
        "/v1/users/{id}/two-factor",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/users/{id}/two-factor/totp/enrol",
        RouteGuard::NotGuarded(
            "Begins a self-only enrolment that is inert until confirmed; a confirmed factor is never silently swapped out (re-enrol over a confirmed factor is refused).",
        ),
    ),
    (
        "/v1/users/{id}/two-factor/totp/confirm",
        RouteGuard::NotGuarded(
            "Activates a factor the user just proved a live code for — the safe direction.",
        ),
    ),
    (
        "/v1/users/{id}/two-factor/totp",
        RouteGuard::Actions(&[ConfirmationAction::TwoFactorDisable]),
    ),
    (
        "/v1/users/{id}/two-factor/backup-codes",
        RouteGuard::Actions(&[ConfirmationAction::TwoFactorBackupCodesRegenerate]),
    ),
    (
        "/v1/users/{id}/passkeys",
        RouteGuard::NotGuarded(
            "GET is read-only. POST completes an enrolment the user has just proved by touching their own authenticator, which is the safe direction and is already the strongest proof available — a confirmation dialog on top would add friction without adding assurance.",
        ),
    ),
    (
        "/v1/users/{id}/passkeys/options",
        RouteGuard::NotGuarded(
            "Mints a registration challenge and nothing else: it stores no credential, and the ceremony it begins is worthless without the authenticator.",
        ),
    ),
    (
        "/v1/users/{id}/passkeys/{credential_id}",
        RouteGuard::NotGuarded(
            "Removing a passkey already demands step-up re-auth in the handler, and the account-lifecycle guard refuses the removal outright if it would leave the account unable to sign in or unable to be recovered. That is a target-bound credential proof plus a fail-closed invariant — a stricter pair than this policy's actor-bound confirmation, and adding one would be redundant friction on the one screen where a user is already being careful.",
        ),
    ),
    (
        "/v1/reauth/passkey/options",
        RouteGuard::NotGuarded(
            "Mints a re-authentication challenge. Requiring a confirmation to obtain the means of confirming is a loop; the challenge grants nothing and is redeemable only by the acting user's own credential.",
        ),
    ),
    (
        "/v1/privacy/users/{id}/export",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/privacy/users/{id}/dsr-requests",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/complete",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/preflight",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/approve",
        RouteGuard::NotGuarded(
            "The dual-control approval is a stronger gate than a confirmation: the approver must be a DISTINCT principal from the requester, echo the subject id, acknowledge the carve-outs, and match a freshly recomputed digest. Nothing is destroyed here; `erasure/execute` carries the T3 floor.",
        ),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/execute",
        RouteGuard::Actions(&[ConfirmationAction::PrivacyErasureExecute]),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/rectification",
        RouteGuard::NotGuarded(
            "Appends a rectification note; never modifies a sealed or signed payload.",
        ),
    ),
    (
        "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/restriction",
        RouteGuard::NotGuarded(
            "Appends a restriction marker; never modifies a sealed or signed payload.",
        ),
    ),
    (
        "/v1/privacy/dsr-requests/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/privacy/dsr-requests/{id}/complete",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/processors",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/processors/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/privacy/dpia-template",
        RouteGuard::NotGuarded(
            "GET is read-only. PUT replaces the operator's own guidance model and DELETE returns to the model shipped with the build; both are ledger-audited, neither touches a register record, and no sealed, signed or evidentiary state is altered or removed. The ledger retains the payload of every prior version, so a reset destroys nothing that was recorded.",
        ),
    ),
    (
        "/v1/privacy/dpias",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/dpias/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/privacy/breach-playbooks",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/breach-playbooks/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/privacy/transfer-controls",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/transfer-controls/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/privacy/retention-policies",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/privacy/retention-policies/dry-run",
        RouteGuard::NotGuarded("Read-only preview/validation; persists nothing."),
    ),
    (
        "/v1/privacy/retention-due-candidates",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/privacy/retention-due-candidates/{candidate_id}/resolution",
        RouteGuard::NotGuarded("Records evidence-only disposition; executes no disposal."),
    ),
    (
        "/v1/privacy/retention-candidate-resolutions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/privacy/retention-executions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/privacy/retention-executions/{id}/review-closure",
        RouteGuard::NotGuarded("Closes operator review evidence; executes no disposal."),
    ),
    (
        "/v1/privacy/retention-policies/{id}",
        RouteGuard::NotGuarded(
            "Updates an editable register record in place; no authority and no evidentiary state is removed.",
        ),
    ),
    (
        "/v1/api-keys",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/api-keys/{id}",
        RouteGuard::Actions(&[ConfirmationAction::ApiKeyRevoke]),
    ),
    (
        "/v1/api-keys/{id}/rotate",
        RouteGuard::Actions(&[ConfirmationAction::ApiKeyRotate]),
    ),
    (
        "/v1/ledger/attestations/{seq}",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/roles",
        RouteGuard::NotGuarded("Creates a new record; nothing existing is altered or removed."),
    ),
    (
        "/v1/roles/{id}",
        RouteGuard::Actions(&[
            ConfirmationAction::RolePermissionChange,
            ConfirmationAction::RoleDelete,
        ]),
    ),
    (
        "/v1/roles/{id}/seeded-drift-reconciliation",
        RouteGuard::Actions(&[ConfirmationAction::RoleSeededReconciliation]),
    ),
    (
        "/v1/permissions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/confirmation-policy",
        RouteGuard::NotGuarded(
            "Read-only: returns the policy shape itself (floor + effective per action) and no instance data. Guarding the endpoint that tells the UI what to guard would be circular.",
        ),
    ),
    (
        "/v1/users/{id}/roles",
        RouteGuard::Actions(&[
            ConfirmationAction::RoleAssign,
            ConfirmationAction::RoleUnassign,
        ]),
    ),
    (
        "/v1/delegations",
        RouteGuard::NotGuarded(
            "Granting a delegation is bounded by the delegation invariant (every permission must be held via a role at that scope), and it is revocable and suspendable.",
        ),
    ),
    (
        "/v1/delegations/{id}",
        RouteGuard::Actions(&[ConfirmationAction::DelegationRevoke]),
    ),
    (
        "/v1/delegations/{id}/suspend",
        RouteGuard::Actions(&[ConfirmationAction::DelegationSuspend]),
    ),
    (
        "/v1/delegations/{id}/resume",
        RouteGuard::NotGuarded(
            "Lifts a suspension, which is the safe direction: it restores only whatever the funções grant now, and an expired delegation stays spent.",
        ),
    ),
    (
        "/v1/session/permissions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/sessions",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/sessions/{session_id}",
        RouteGuard::Actions(&[ConfirmationAction::SessionRevoke]),
    ),
    (
        "/v1/sessions/revoke-others",
        RouteGuard::Actions(&[ConfirmationAction::SessionRevokeOthers]),
    ),
    (
        "/v1/auth/invites",
        RouteGuard::NotGuarded(
            "Issues an invitation bounded by `user.invite`@scope plus the role subset invariant; it grants no authority the actor does not already hold and can be left unaccepted.",
        ),
    ),
    (
        "/v1/pairing/codes",
        RouteGuard::Actions(&[ConfirmationAction::DevicePairing]),
    ),
    (
        "/v1/pairing/devices",
        RouteGuard::NotGuarded(
            "Read-only: returns data and mutates no state, so there is nothing to confirm.",
        ),
    ),
    (
        "/v1/pairing/devices/{device_id}",
        RouteGuard::Actions(&[ConfirmationAction::PairingDeviceRevoke]),
    ),
];

/// Actions with no route yet: sibling lanes are wiring the endpoint that will carry them.
///
/// The completeness test binds this **two ways** — an entry here must NOT appear in [`ROUTE_GUARD`],
/// and every action outside it MUST. So the moment t51 lands its route and records the verdict, the
/// stale entry here fails the suite; and an action can never be quietly parked here forever without
/// someone noticing it is unreachable.
// Read only by the completeness test. It is deliberately not `#[cfg(test)]`: the list is a
// standing statement about what is not yet reachable, and it should be legible in a normal build.
#[allow(dead_code)]
pub(crate) const AWAITING_ROUTE: &[(ConfirmationAction, &str)] = &[
    (
        ConfirmationAction::TermoWithdraw,
        "t51 is adding the withdraw route; `TermoInstrument::withdraw_to_draft` exists in \
         `chancela-core` but no endpoint reaches it yet.",
    ),
    (
        ConfirmationAction::UserBulkDisable,
        "t56-e4 is adding `POST /v1/users/bulk`.",
    ),
    (
        ConfirmationAction::UserBulkRoleChange,
        "t56-e4 is adding `POST /v1/users/bulk`.",
    ),
];

/// Resolve a router path to its verdict.
// t56-e0 delivers the substrate only; the surface owners (t51, t54, t56-e3/e4) add the call sites.
// Until then this has no non-test caller.
#[allow(dead_code)]
#[must_use]
pub(crate) fn guard_for_route(path: &str) -> Option<RouteGuard> {
    ROUTE_GUARD
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, g)| *g)
}

// =================================================================================================
// Settings and resolution
// =================================================================================================

/// The operator-configurable half of the policy: per-action overrides that may only **raise**
/// strictness.
///
/// Per-action rather than one global dial because the request was "which destructive actions demand
/// confirmation and how strict" — that is a map. An absent entry means "use the floor". A configured
/// entry below its floor is not an error and is not silently obeyed: [`effective_strictness`] clamps
/// it up, and the admin UI renders sub-floor levels disabled-with-explanation rather than offering a
/// level it would ignore.
///
/// **Owned by t56-e0, embedded by t56-e1.** e1 adds `#[serde(default)] pub confirmation:
/// ConfirmationSettings` to [`AuthSettings`] and fills in [`configured_strictness`]. `Default` is
/// empty, so `AuthSettings::is_default()` byte-identity — and therefore `contracts/settings.json` —
/// is unaffected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, transparent)]
pub struct ConfirmationSettings {
    /// Per-action overrides. `BTreeMap` for a deterministic serialisation order.
    pub actions: BTreeMap<ConfirmationAction, ConfirmationStrictness>,
}

impl ConfirmationSettings {
    /// Whether the slice is entirely at its default (empty) value.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.actions.is_empty()
    }
}

/// The operator's configured override for `action`, if any.
///
/// **Seam for t56-e1.** `AuthSettings` does not carry `confirmation` yet — e1 owns `settings.rs` and
/// sequences behind t54-e4 on that file. Until it lands there is no override and every action
/// resolves to its floor, which is the fail-closed direction: the policy is never weaker than the
/// floor at any point in the sequence. e1's only change here is to return
/// `settings.confirmation.actions.get(&action).copied()`.
fn configured_strictness(
    _settings: &AuthSettings,
    _action: ConfirmationAction,
) -> Option<ConfirmationStrictness> {
    None
}

/// **The only place strictness levels are compared.** No call site may compare them itself.
///
/// `max(floor, configured)` — a configured entry can raise an action's strictness and can never
/// lower it.
#[must_use]
pub fn effective_strictness(
    settings: &AuthSettings,
    action: ConfirmationAction,
) -> ConfirmationStrictness {
    let floor = action.floor();
    match configured_strictness(settings, action) {
        Some(configured) if configured > floor => configured,
        _ => floor,
    }
}

// =================================================================================================
// The handler-side gate
// =================================================================================================

/// The proof a guarded request carries. Reuses [`ReAuth`] unchanged.
///
/// Both fields are `#[serde(default)]`, so an absent `confirmation` object deserialises to an empty
/// proof and the gate refuses it — the fail-closed direction. A caller that renders a dialog but
/// forgets to thread the proof therefore gets a `403`, not a silent bypass.
/// Deliberately **no `Debug`**: [`ReAuth`] has none either, because the struct carries a plaintext
/// password and a recovery phrase, and a derived `Debug` is one `tracing` call away from putting
/// both in a log. Do not add one.
#[derive(Default, Deserialize)]
pub struct ConfirmationProof {
    #[serde(default)]
    pub reauth: ReAuth,
    #[serde(default)]
    pub confirm_phrase: Option<String>,
}

/// The uniform refusal for a missing or wrong typed phrase. Names the expected phrase — it is not a
/// secret, it is printed in the dialog; the security value is deliberateness, not obscurity.
fn phrase_required(expected: &str) -> ApiError {
    ApiError::Forbidden(format!(
        "confirmação necessária: escreva exatamente «{expected}» para continuar"
    ))
}

/// **The handler-side gate.** Resolves the effective strictness for `action` and enforces exactly
/// that much — no more, no less.
///
/// Composes with, never replaces, [`crate::authz::require_permission`], which stays the primary
/// who-may gate at every call site:
///
/// ```ignore
/// require_permission(&state, &actor, Permission::BookClose, scope_of_book(id)).await?;
/// require_confirmation(&state, &actor, ConfirmationAction::BookClose, &req.confirmation).await?;
/// ```
///
/// Every refusal is **403, never 401** — a failed credential proof must not sign the operator out
/// (the client maps `403` to an inline re-auth error and keeps the session).
pub(crate) async fn require_confirmation(
    state: &AppState,
    actor: &CurrentActor,
    action: ConfirmationAction,
    proof: &ConfirmationProof,
) -> Result<(), ApiError> {
    let strictness = {
        let settings = state.settings.read().await;
        effective_strictness(&settings.auth, action)
    };
    match strictness {
        // `Confirm` is enforced client-side by construction: there is no server-observable
        // difference between "the operator accepted a dialog" and "the operator did not". Saying so
        // here is more honest than implying a server check that cannot exist.
        ConfirmationStrictness::Off | ConfirmationStrictness::Confirm => Ok(()),
        ConfirmationStrictness::ConfirmWithReauth => {
            require_step_up(state, actor, &proof.reauth).await
        }
        ConfirmationStrictness::ConfirmWithReauthAndPhrase => {
            require_step_up(state, actor, &proof.reauth).await?;
            // A phrase floor without a phrase would be a policy that cannot be satisfied; the
            // `phrase()`/`floor()` invariant is test-pinned, so this arm is unreachable in practice.
            let expected = action.phrase().ok_or_else(|| {
                ApiError::Internal(format!(
                    "action {} is floored at phrase strictness but defines no phrase",
                    action.as_str()
                ))
            })?;
            match proof.confirm_phrase.as_deref() {
                Some(supplied) if supplied == expected => Ok(()),
                _ => Err(phrase_required(expected)),
            }
        }
    }
}

// =================================================================================================
// Device-pairing confirmation
// =================================================================================================
//
// **Why this does not go through [`require_confirmation`] above, and is not a parallel mechanism.**
//
// `ConfirmationAction::DevicePairing` guards `POST /v1/pairing/codes` — the *mint*, performed by an
// operator who already holds an interactive session. The act the user's decision is about is the
// *exchange* (`POST /v1/pairing/exchange`), the moment a device actually receives a session. That
// route is `Exempt`: it is unauthenticated by construction, because the whole point of the pairing
// handshake (`crate::pairing`) is that the operator never types their password into a remote
// WebView. So there is no [`CurrentActor`] to hand [`require_step_up`], which is what
// [`require_confirmation`] is built out of — the module header above says exactly this about
// `Exempt` routes, and it is still true.
//
// The strictness ladder is also the wrong axis. `Off < Confirm < ConfirmWithReauth <
// ConfirmWithReauthAndPhrase` answers *how hard*; the user's decision answers *with what*: any ONE
// of a password, an emailed confirmation link, or a TOTP token. That is a set of alternatives, not
// a rung. Modelling it as strictness would either collapse the three into "re-auth" (which means
// password, the one thing the pairing design exists to avoid) or invent rungs whose ordering has no
// meaning.
//
// So: the *policy* lives here, next to [`ConfirmationSettings`], because there should be one place
// an operator's confirmation configuration is read from. The *gate* takes a resolved [`User`]
// instead of an actor, and is the only difference.
//
// `/v1/pairing/exchange` is deliberately NOT added to [`ROUTE_GUARD`]: that table's key set is
// asserted equal to the `Gated`/`Session` half of the frozen `ROUTE_CLASSIFICATION`, and adding an
// `Exempt` route to it would break the exhaustiveness proof to record a verdict the strictness
// engine cannot act on anyway.

/// A proof a device pairing may be confirmed with. **Any one** of these satisfies the requirement —
/// they are alternatives, not a checklist.
///
/// The password is deliberately *one* accepted method and never the only available one: an operator
/// pairing a phone can prove themselves with a TOTP token instead, so the password never has to
/// reach the device being enrolled. A deployment that wants that guarantee absolutely can drop
/// [`Password`](Self::Password) from [`PairingConfirmationSettings::accepted`].
///
/// **There is no `EmailLink` method, and that is a decision rather than an omission.** The emailed
/// method is a code the operator **transcribes**, never a link they click. This product's outgoing
/// mail tells every recipient, in all 14 locales, that it never sends access links and that a
/// message which does should be reported to an administrator (`email_template.rs`'s
/// `welcome_never_sends`). A clickable pairing link would make our own mail train operators to
/// click exactly what we told them to report, so the promise stands unchanged and the credential
/// changed shape instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingConfirmationMethod {
    /// The operator's account password, verified on the same argon2id path as sign-in.
    Password,
    /// A live TOTP code from the operator's **confirmed** second factor.
    TotpCode,
    /// A ~79-bit code mailed to the operator's registered address at mint time and typed back in.
    /// Proves control of a second channel without any reusable secret reaching the device.
    EmailedCode,
}

impl PairingConfirmationMethod {
    /// Every variant, in wire order.
    pub const ALL: &'static [Self] = &[Self::Password, Self::TotpCode, Self::EmailedCode];

    /// The stable wire identifier (matches the serde representation).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::TotpCode => "totp_code",
            Self::EmailedCode => "emailed_code",
        }
    }
}

/// Which confirmation methods this deployment accepts for a device pairing.
///
/// Default is **every implemented method**, so an instance that has never configured anything still
/// requires a confirmation — the requirement itself is not optional, only the choice of proof is.
///
/// An operator may narrow the set (e.g. to `{totp_code}` alone, so a password can never be typed
/// into a paired device) but an **empty** set is refused by
/// [`AuthSettings::validate`](crate::settings::AuthSettings), because a set that accepts nothing
/// does not mean "no confirmation" — it means no device can ever pair, and an operator who writes
/// it almost certainly meant the opposite. Should one reach the gate anyway, the gate refuses; the
/// unsatisfiable direction is closed at both ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PairingConfirmationSettings {
    /// The accepted proofs. `BTreeSet` for a deterministic serialisation order.
    pub accepted: BTreeSet<PairingConfirmationMethod>,
}

impl Default for PairingConfirmationSettings {
    fn default() -> Self {
        PairingConfirmationSettings {
            accepted: PairingConfirmationMethod::ALL.iter().copied().collect(),
        }
    }
}

impl PairingConfirmationSettings {
    /// The accepted methods as stable wire identifiers, in a deterministic order. This is what the
    /// mint response advertises so the desktop can tell the operator what the device will ask for.
    #[must_use]
    pub fn accepted_ids(&self) -> Vec<&'static str> {
        self.accepted.iter().map(|m| m.as_str()).collect()
    }
}

/// The confirmation a device presents when it redeems a pairing code.
///
/// Every field is `#[serde(default)]`, so an exchange body carrying no confirmation at all
/// deserialises to an empty proof and the gate refuses it — the fail-closed direction. A client that
/// forgets to thread the proof gets a `403`, never a silent pairing.
///
/// Deliberately **no `Debug`**, for the same reason [`ConfirmationProof`] has none: it carries a
/// plaintext password, and a derived `Debug` is one `tracing` call away from logging it.
#[derive(Default, Deserialize)]
pub struct PairingConfirmationProof {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp_code: Option<String>,
    /// The code mailed to the operator when the pairing code was minted. Accepted in any letter
    /// case and with or without the group separators — see
    /// [`canonicalize_transcribable`](crate::auth_token::canonicalize_transcribable).
    #[serde(default)]
    pub emailed_code: Option<String>,
}

/// The single, uniform refusal for an unconfirmed pairing.
///
/// One message for every failure mode on purpose: a wrong password, a wrong TOTP code, a method the
/// deployment does not accept, a proof for a factor the operator never enrolled, and a deployment
/// that accepts nothing all read identically. A caller learns that the pairing was not confirmed
/// and nothing else — in particular not whether the bound operator holds a second factor.
///
/// `403`, not `401`, matching [`require_confirmation`]: a failed credential proof must not read as
/// "your code was bad". The pairing code is already consumed by the time this fires, so the fact
/// that the status distinguishes "valid code, bad proof" from the exchange's uniform `401` is not
/// an oracle worth anything — what it identifies is dead.
fn pairing_not_confirmed() -> ApiError {
    ApiError::Forbidden("o emparelhamento do dispositivo não foi confirmado".to_owned())
}

/// **The pairing gate.** Verify that `proof` satisfies **one** method this deployment accepts for
/// `user`, and report which one.
///
/// Fail-closed by construction: the only way out of this function without an error is a proof that
/// was both *accepted by the deployment* and *verified against the operator's own credential*. There
/// is no arm that passes for lack of a credential — unlike [`require_step_up`], which lets a
/// credential-less operator through on their session alone, because there a valid self session is
/// the strongest proof available. Here there is no session: the caller is an unauthenticated device
/// holding a code. An operator with no password and no confirmed second factor therefore cannot pair
/// a device, and that is the correct outcome rather than a lockout to route around.
pub(crate) async fn require_pairing_confirmation(
    state: &AppState,
    user: &User,
    proof: &PairingConfirmationProof,
    now: OffsetDateTime,
) -> Result<PairingConfirmationMethod, ApiError> {
    let accepted = {
        let settings = state.settings.read().await;
        settings.auth.device_pairing.accepted.clone()
    };

    // A password the deployment accepts, that the operator actually has, and that verifies.
    if accepted.contains(&PairingConfirmationMethod::Password)
        && let Some(supplied) = proof.password.as_deref()
        && let Some(stored) = user.password_hash.as_deref()
        && verify_secret(supplied, stored)
    {
        return Ok(PairingConfirmationMethod::Password);
    }

    // A live code from a **confirmed** factor. `verify_totp_for_user` owns the whole TOTP path —
    // reading the secret from the credential store and advancing `last_accepted_step` so the code
    // cannot be replayed — so there is no second TOTP implementation here.
    if accepted.contains(&PairingConfirmationMethod::TotpCode)
        && let Some(supplied) = proof.totp_code.as_deref()
        && crate::totp::verify_totp_for_user(state, user, supplied, now).await?
    {
        return Ok(PairingConfirmationMethod::TotpCode);
    }

    // The mailed code. Redeemed through the shared `auth_token` store, which removes the record
    // before returning it — so a code is spent by the attempt, not by the success, and the arms
    // below cannot leave it replayable. The subject is checked here rather than trusted: a record
    // for a different user must not confirm this pairing even though the purpose matches.
    if accepted.contains(&PairingConfirmationMethod::EmailedCode)
        && let Some(supplied) = proof.emailed_code.as_deref()
    {
        let canonical = crate::auth_token::canonicalize_transcribable(supplied);
        let redeemed = state.auth_tokens.write().await.redeem(
            crate::auth_token::AuthTokenPurpose::DevicePairingConfirmation,
            &canonical,
            now,
        );
        if let Ok(record) = redeemed
            && record.subject.user_id() == Some(user.id.0)
        {
            return Ok(PairingConfirmationMethod::EmailedCode);
        }
    }

    Err(pairing_not_confirmed())
}

// =================================================================================================
// GET /v1/confirmation-policy
// =================================================================================================

/// One action's resolved policy.
///
/// `floor` ships **alongside** `effective` on purpose: it is what lets the admin UI render a
/// sub-floor level as disabled-with-an-explanation rather than offering a level the server would
/// silently ignore.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmationActionPolicyView {
    pub action: &'static str,
    pub floor: ConfirmationStrictness,
    pub effective: ConfirmationStrictness,
    pub consequence: ConfirmationConsequence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<&'static str>,
    /// `false` while no route reaches this action yet (a sibling lane is still wiring it). The UI
    /// must not offer to configure an action that nothing can trigger.
    pub wired: bool,
}

/// `GET /v1/confirmation-policy` response.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmationPolicyView {
    pub actions: Vec<ConfirmationActionPolicyView>,
}

/// `GET /v1/confirmation-policy` — the resolved per-action policy. Any valid session may read it: it
/// is UI-shaping metadata, exactly like `GET /v1/permissions`.
///
/// **This is deliberately its own endpoint rather than a field on `auth.confirmation`.** A computed
/// map is never "default", so hanging it off `AuthSettings` would break the
/// `skip_serializing_if = "AuthSettings::is_default"` byte-identity, start serialising the `auth`
/// slice on every instance, and move `contracts/settings.json` — which has no `auth` key at all.
/// Keep the separation.
pub async fn get_confirmation_policy(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<ConfirmationPolicyView>, ApiError> {
    crate::roles::resolve_principal_id(&state, &actor).await?;
    let auth = state.settings.read().await.auth.clone();
    let wired: std::collections::BTreeSet<ConfirmationAction> = ROUTE_GUARD
        .iter()
        .filter_map(|(_, guard)| match guard {
            RouteGuard::Actions(actions) => Some(actions.iter().copied()),
            RouteGuard::PreExistingGate(_) | RouteGuard::NotGuarded(_) => None,
        })
        .flatten()
        .collect();
    let actions = ConfirmationAction::ALL
        .iter()
        .map(|&action| ConfirmationActionPolicyView {
            action: action.as_str(),
            floor: action.floor(),
            effective: effective_strictness(&auth, action),
            consequence: action.consequence(),
            phrase: action.phrase(),
            wired: wired.contains(&action),
        })
        .collect();
    Ok(Json(ConfirmationPolicyView { actions }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{ROUTE_CLASSIFICATION, RouteClass};
    use std::collections::{BTreeMap, BTreeSet};

    /// The set of routes the frozen map says are operator-authenticated, and therefore the exact set
    /// that can carry a confirmation gate.
    fn guardable_routes() -> BTreeSet<&'static str> {
        ROUTE_CLASSIFICATION
            .iter()
            .filter(|(_, class)| matches!(class, RouteClass::Gated | RouteClass::Session))
            .map(|(path, _)| *path)
            .collect()
    }

    /// **The exhaustiveness guarantee.**
    ///
    /// `router_walk_every_route_is_classified` already proves no `.route(...)` escapes
    /// `ROUTE_CLASSIFICATION`. This proves no `Gated`/`Session` entry escapes an explicit
    /// confirmation verdict. Together: a newly added guardable route cannot silently avoid the
    /// policy — it is compile-green but test-red until someone writes down what it is.
    #[test]
    fn route_guard_covers_every_gated_and_session_route() {
        let classified = guardable_routes();
        let guarded: BTreeSet<&str> = ROUTE_GUARD.iter().map(|(p, _)| *p).collect();

        let missing: Vec<_> = classified.difference(&guarded).collect();
        assert!(
            missing.is_empty(),
            "UNCLASSIFIED GUARDED ROUTE(S): {missing:?} are Gated/Session in ROUTE_CLASSIFICATION \
             but carry no confirmation verdict. Add a RouteGuard entry — RouteGuard::Actions(..) if \
             the operator must confirm, or RouteGuard::NotGuarded(\"why not\") with the evidence \
             from the handler. A missing verdict is where an error hides."
        );
        let stale: Vec<_> = guarded.difference(&classified).collect();
        assert!(
            stale.is_empty(),
            "STALE GUARD ENTR(IES): {stale:?} are in ROUTE_GUARD but are no longer Gated/Session \
             routes"
        );
    }

    #[test]
    fn route_guard_has_no_duplicate_paths() {
        let mut seen = BTreeSet::new();
        for (path, _) in ROUTE_GUARD {
            assert!(seen.insert(*path), "duplicate ROUTE_GUARD entry for {path}");
        }
    }

    /// `Exempt` routes are unauthenticated by design — no acting user, nothing to step up with — so
    /// they must not appear here. Guarding one would be decoration.
    #[test]
    fn exempt_routes_are_not_in_the_registry() {
        let exempt: BTreeSet<&str> = ROUTE_CLASSIFICATION
            .iter()
            .filter(|(_, class)| matches!(class, RouteClass::Exempt))
            .map(|(path, _)| *path)
            .collect();
        for (path, _) in ROUTE_GUARD {
            assert!(
                !exempt.contains(path),
                "{path} is Exempt (unauthenticated) and cannot carry a confirmation gate"
            );
        }
    }

    /// Two-way binding for the not-yet-routed actions: an awaiting action must be unreachable, and
    /// every other action must be reachable. So a lane that lands its route without removing the
    /// entry fails here, and an action parked here forever cannot go unnoticed.
    #[test]
    fn every_action_is_either_wired_to_a_route_or_explicitly_awaiting_one() {
        let wired: BTreeSet<ConfirmationAction> = ROUTE_GUARD
            .iter()
            .filter_map(|(_, guard)| match guard {
                RouteGuard::Actions(actions) => Some(actions.iter().copied()),
                RouteGuard::PreExistingGate(_) | RouteGuard::NotGuarded(_) => None,
            })
            .flatten()
            .collect();
        let awaiting: BTreeSet<ConfirmationAction> =
            AWAITING_ROUTE.iter().map(|(a, _)| *a).collect();

        for (action, why) in AWAITING_ROUTE {
            assert!(
                !wired.contains(action),
                "{} is listed in AWAITING_ROUTE ({why}) but a route now reaches it — remove the \
                 AWAITING_ROUTE entry",
                action.as_str()
            );
        }
        for action in ConfirmationAction::ALL {
            assert!(
                wired.contains(action) || awaiting.contains(action),
                "{} is defined but no route reaches it and it is not in AWAITING_ROUTE — either \
                 wire it or record which lane owes the route",
                action.as_str()
            );
        }
    }

    #[test]
    fn all_is_complete_and_wire_ids_are_unique() {
        let ids: BTreeSet<&str> = ConfirmationAction::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            ids.len(),
            ConfirmationAction::ALL.len(),
            "two actions share a wire id"
        );
        // `ALL` is hand-maintained beside the wildcard-free matches; a variant missing from it
        // would silently vanish from the policy endpoint. Round-trip every id through serde to
        // prove `ALL` really covers the enum's serialisation surface.
        for action in ConfirmationAction::ALL {
            let json = serde_json::to_string(action).expect("serialise");
            let back: ConfirmationAction = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(*action, back);
        }
    }

    /// A phrase floor with no phrase is unsatisfiable; a phrase below the phrase floor is a phrase
    /// nothing ever asks for. Both are bugs, so bind them exactly.
    #[test]
    fn phrase_exists_exactly_for_the_phrase_floor() {
        for action in ConfirmationAction::ALL {
            let floored = action.floor() == ConfirmationStrictness::ConfirmWithReauthAndPhrase;
            assert_eq!(
                floored,
                action.phrase().is_some(),
                "{}: floor and phrase disagree",
                action.as_str()
            );
            if let Some(phrase) = action.phrase() {
                assert_eq!(
                    phrase.trim(),
                    phrase,
                    "{}: phrase has padding",
                    action.as_str()
                );
                assert!(!phrase.is_empty(), "{}: empty phrase", action.as_str());
            }
        }
    }

    /// Anti-uniformity. If every action were floored at the top, operators would learn to type
    /// through phrases and the phrase would stop meaning anything where it matters. This is a real
    /// property of the tiering, so it is asserted rather than left to review.
    #[test]
    fn floors_are_not_uniform() {
        let mut histogram: BTreeMap<ConfirmationStrictness, usize> = BTreeMap::new();
        for action in ConfirmationAction::ALL {
            *histogram.entry(action.floor()).or_default() += 1;
        }
        assert!(
            histogram.len() >= 3,
            "floors collapsed onto {} level(s): {histogram:?}",
            histogram.len()
        );
        let phrase = histogram
            .get(&ConfirmationStrictness::ConfirmWithReauthAndPhrase)
            .copied()
            .unwrap_or(0);
        assert!(
            phrase * 3 < ConfirmationAction::ALL.len(),
            "{phrase} of {} actions demand a typed phrase — over-confirming devalues the phrase \
             exactly where it matters",
            ConfirmationAction::ALL.len()
        );
        // No action is floored `Off`: `Off` is what an action's ABSENCE from the registry means, so
        // a variant resolving to it would be an action that exists only to do nothing.
        assert!(
            !histogram.contains_key(&ConfirmationStrictness::Off),
            "an action is floored Off; remove the variant instead"
        );
    }

    /// The floor can only be raised, never lowered — the property the whole design rests on.
    #[test]
    fn a_configured_entry_can_never_lower_a_floor() {
        let settings = AuthSettings::default();
        for action in ConfirmationAction::ALL {
            assert!(
                effective_strictness(&settings, *action) >= action.floor(),
                "{} resolved below its floor",
                action.as_str()
            );
        }
    }

    #[test]
    fn strictness_is_ordered_low_to_high() {
        use ConfirmationStrictness::{Confirm, ConfirmWithReauth, ConfirmWithReauthAndPhrase, Off};
        assert!(Off < Confirm);
        assert!(Confirm < ConfirmWithReauth);
        assert!(ConfirmWithReauth < ConfirmWithReauthAndPhrase);
    }

    /// The reasons are the deliverable for a non-guarded verdict. An empty or placeholder one would
    /// let a route pass the completeness test while recording nothing.
    #[test]
    fn every_recorded_reason_is_substantive() {
        for (path, guard) in ROUTE_GUARD {
            let reason = match guard {
                RouteGuard::Actions(actions) => {
                    assert!(!actions.is_empty(), "{path}: Actions(&[]) guards nothing");
                    continue;
                }
                RouteGuard::PreExistingGate(why) | RouteGuard::NotGuarded(why) => *why,
            };
            assert!(
                reason.len() >= 30,
                "{path}: the recorded reason is too thin to review: {reason:?}"
            );
            assert!(
                reason.ends_with('.') || reason.ends_with('`'),
                "{path}: reason should read as a sentence: {reason:?}"
            );
        }
    }

    /// The new endpoint must itself be classified, or it would be the one route in the app that
    /// escaped the fail-closed map.
    #[test]
    fn the_policy_endpoint_is_classified_and_not_self_guarded() {
        let entry = ROUTE_CLASSIFICATION
            .iter()
            .find(|(path, _)| *path == "/v1/confirmation-policy");
        let (_, class) = entry.expect("/v1/confirmation-policy must be in ROUTE_CLASSIFICATION");
        assert_eq!(*class, RouteClass::Session, "it is UI-shaping metadata");
        assert!(matches!(
            guard_for_route("/v1/confirmation-policy"),
            Some(RouteGuard::NotGuarded(_))
        ));
    }
}
