//! # chancela-api
//!
//! The HTTP layer for **Chancela**. This crate is a library: it builds an [`axum::Router`]
//! over shared in-memory state and exposes it via [`router`]. The `chancela-server` binary
//! wraps this router with a Tokio runtime and a listener; tests drive it directly with
//! `tower`'s `oneshot`.
//!
//! The API is deliberately thin (ARC-02): handlers translate JSON to and from the
//! `chancela-core` domain types (via the DTOs in [`dto`], never serializing core types
//! directly) and record mutations in a `chancela-ledger` hash chain. There is no persistence
//! yet — state lives in `Arc<RwLock<..>>` and resets on restart.
//!
//! ## Endpoints (v1)
//!
//! - `GET  /health` — liveness plus the crate version.
//! - `POST|GET /v1/entities`, `GET /v1/entities/{id}` — entity CRUD (§2.3).
//! - `POST|GET /v1/books`, `GET /v1/books/{id}`, `POST /v1/books/{id}/close`,
//!   `GET /v1/books/{id}/acts` — book open/list/close and the acts-in-a-book feed (§2.4).
//! - `POST /v1/acts`, `GET|PATCH /v1/acts/{id}`, `POST /v1/acts/{id}/advance`,
//!   `POST /v1/acts/{id}/human-verification`, `GET /v1/acts/{id}/compliance`,
//!   `POST /v1/acts/{id}/seal`,
//!   `POST /v1/acts/{id}/archive` — the ata lifecycle, compliance gate, and seal (§2.5).
//! - `GET /v1/acts/{id}/document/working-copy[?format=markdown|txt|html|rtf|odt]` — deterministic
//!   non-evidentiary text working copies.
//! - `GET /v1/acts/{id}/document/office` — deterministic non-evidentiary DOCX working copy.
//! - `POST /v1/documents/import/validate` — read-only structural import validation report.
//! - `POST|GET /v1/documents/import[ed]`, `GET /v1/documents/imported/{id}[/bytes]`,
//!   `PATCH /v1/documents/imported/{id}/review` — validated non-canonical imported document
//!   evidence and operator review metadata.
//! - `POST|GET /v1/documents/generated/{id}/dispatch-evidence` — operator-recorded,
//!   metadata-only dispatch evidence for generated absent-owner communications.
//! - `POST /v1/signature/pdf/validate` — read-only local technical PDF/PAdES evidence validation.
//! - `POST /v1/signature/asic/inspect` — read-only local technical ASiC/CAdES profile inspection.
//! - `GET /v1/signature/provider-credentials/status` — read-only provider credential storage
//!   metadata; secrets, ciphertext, raw keys, and live provider calls are never returned.
//! - `POST /v1/acts/{id}/signature/archive-timestamp/append` — caller-supplied local
//!   `/DocTimeStamp` technical evidence append; no production/legal B-LTA claim.
//! - `GET /v1/ledger/events`, `GET /v1/ledger/verify` — the audit feed and chain probe (§2.6).
//! - `GET /v1/ledger/archive/document` — bounded ledger archive export (PDF/A, TXT, JSON, CSV, HTML).
//! - `GET /v1/books/{id}/archive/local-dglab-interchange-manifest` — read-only local DGLAB
//!   interchange manifest scaffold derived from the internal preservation manifest; no official
//!   DGLAB/legal-archive certification claim.
//! - `GET /v1/sync/handoff-preflight` — read-only local sync/handoff preflight readiness report
//!   composed from local evidence only; no active sync, connector, provider, or certification claim.
//! - `GET /v1/dashboard` — WFL-40 counts and recent events (§2.7).
//! - `GET|PUT /v1/settings` — the typed, versioned application settings document (§2.8).
//! - `GET /v1/platform/services`, `POST /v1/platform/services/{id}/actions/{action}` —
//!   read-only API/MCP service status plus settings-backed desired-state controls.
//! - `POST /v1/registry/lookup`, `GET /v1/registry/lookup`,
//!   `GET|POST /v1/entities/{id}/registry`,
//!   `POST /v1/entities/{id}/registry/import`, `POST /v1/entities/import-from-registry` —
//!   certidão permanente consultation/import and backend-owned auto-update planning (§2.7,
//!   LEG-20/21/22).
//! - `GET|POST /v1/privacy/users/{id}/dsr-requests`, `PATCH
//!   /v1/privacy/dsr-requests/{id}`, `POST /v1/privacy/dsr-requests/{id}/complete` — GDPR/DSR
//!   request tracking with JSON sidecar durability in data-dir mode and ledger-audited lifecycle
//!   transitions.
//! - `GET|POST /v1/privacy/processors`, `PATCH /v1/privacy/processors/{id}`,
//!   `GET /v1/privacy/dpia-template`,
//!   `GET|POST /v1/privacy/dpias`, `PATCH /v1/privacy/dpias/{id}`,
//!   `GET|POST /v1/privacy/breach-playbooks`, `PATCH /v1/privacy/breach-playbooks/{id}`,
//!   `GET|POST /v1/privacy/transfer-controls`, `PATCH /v1/privacy/transfer-controls/{id}` —
//!   a static local/offline DPIA guidance pack plus bounded privacy control registers with JSON
//!   sidecar durability in data-dir mode and ledger-audited create/update transitions.
//! - `GET|POST /v1/privacy/retention-policies`, `PATCH /v1/privacy/retention-policies/{id}`,
//!   `POST /v1/privacy/retention-policies/dry-run`,
//!   `GET /v1/privacy/retention-due-candidates`,
//!   `POST /v1/privacy/retention-due-candidates/{candidate_id}/resolution`,
//!   `GET /v1/privacy/retention-candidate-resolutions`,
//!   `GET /v1/privacy/retention-executions`,
//!   `POST /v1/privacy/retention-executions/{id}/review-closure` — bounded retention policy
//!   register, non-destructive applicability reporting, recorded execution-request evidence, and
//!   review-only execution closure.
//!
//! ## Serving the web UI
//!
//! [`router`] wires the API only. [`app`] additionally mounts the built web shell so the
//! whole application is reachable from one origin: pass the `apps/web/dist` directory and it
//! is served at `/` with a single-page-app fallback (any unknown, non-API path returns
//! `index.html`, so client-side routes like `/livros` deep-link correctly). API routes keep
//! priority over the static tree. Pass `None` to run API-only with a friendly landing page.

mod actor;
mod acts;
mod apikeys;
mod archive_package;
mod arquivo;
mod asic_signature_validation;
mod asic_signing;
mod attestation;
mod authz;
mod backup;
mod backup_recovery;
mod batch_signing;
mod books;
mod bundles;
mod cache;
mod cae;
mod chronology;
// wp16 P0: Postgres-advisory-lock leader election / step-down / failover handoff (active-passive HA).
// Compiled in every build; inert unless the durable backend is an electing one (Postgres).
mod cluster;
// wp16 P1: follower change-feed (LISTEN/NOTIFY + seq-poll) with fail-closed incremental delta apply.
// Compiled in every build; the DB-touching feed is Postgres-gated, the pure delta core is always on.
mod cluster_feed;
// wp16 P2: write routing on a follower — 307 redirect to the leader (default) or opt-in reverse proxy.
// Compiled in every build; inert on the single-node SQLite / in-memory build (always its own leader).
mod cluster_route;
// wp16 P3a: cluster-shared session identity + GLOBAL sign-in rate-limits + cross-node cache/session
// invalidation. Compiled in every build; every backend defaults to a local no-op so single-node is
// byte-identical. Redis-backed (cluster-wide, fail-closed) only with the `redis` feature + REDIS_URL.
mod cluster_shared_state;
// wp16 P4: leader self-fence watchdog — a deadline-bounded periodic re-verify of lock+epoch that
// proactively steps a partitioned/wedged leader down (fail-closed) without waiting for the next write.
// Compiled in every build; inert unless the durable backend is an electing one (Postgres).
mod cluster_watchdog;
// wp16 P4: consolidated chaos / failover / split-brain / freshness / redirect / session-coherence
// resilience suite (test-only; live multi-node scenarios `#[ignore]` requiring DATABASE_URL).
#[cfg(test)]
mod cluster_chaos_tests;
#[allow(dead_code)]
mod credential_resolve;
mod dashboard;
mod data;
mod data_status;
mod database;
mod delegations;
mod documents;
mod dto;
mod email;
mod entities;
mod error;
mod external_signing;
mod external_validator_evidence;
mod followups;
mod hex;
mod law;
mod ledger;
mod ledger_events_page;
mod ledger_filter;
mod ltv;
mod notifications;
mod observability;
mod paper_import;
mod password_policy;
mod pdf_signature_validation;
mod platform_logs;
mod platform_ops;
mod privacy;
mod provider_credentials;
mod provider_credentials_write;
mod recovery;
mod registry;
mod roles;
mod scap;
mod secretstore;
mod secretstore_persist;
mod session;
mod settings;
// wp16 P3b: backend-conditional storage seam for the five non-ledger file sidecars (users/roles/
// delegations/settings/provider-credentials). File-backed on SQLite (single-node byte-identical),
// DB-backed on Postgres so all nodes share them.
mod sidecar_store;
mod signature;
mod signature_pkcs12_stored;
mod sync_handoff;
mod trust;
mod users;
mod xades_signature;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post, put};
use chancela_cae::{CaeCatalog, CaeSource, CaeSourceChain};
use chancela_cmd::ScmdTransport;
use chancela_core::external_signing::{ExternalSignatureEnvelope, ExternalSignatureEnvelopeId};
use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_csc::{CscConfig, CscTransport};
use chancela_ledger::{Event, Ledger, LedgerError};
use chancela_registry::{RegistryExtract, RegistryTransport};
use chancela_signing::{SignerProvider, SigningError, TrustPolicy};
use chancela_store::{
    PendingCmdSession, Store, StoreError, StoreKeyOpsPlan, StoredDocument, StoredFollowUp,
    StoredSignedDocument, Tx,
};
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::services::{ServeDir, ServeFile};

pub use actor::{CurrentActor, CurrentAttestor};
pub use attestation::VerifierSeed;
pub use authz::{
    Authorizer, authorizer, require_permission, require_permission_with, scope_of_act,
    scope_of_book, scope_of_entity,
};
pub use backup_recovery::{BackupRecoveryDrillManifestEvidence, BackupRecoveryDrillReceipt};
pub use database::{
    AppStateInitError, DATABASE_URL_ENV, DATABASE_URL_FILE_ENV, DB_BACKEND_ENV, DB_KEY_ENV,
    DB_KEY_FILE_ENV, DB_KEY_SOURCE_ENV, DatabaseBackendConfigError, DatabaseEncryptionConfig,
    DatabaseEncryptionConfigError, DatabaseEncryptionKeySource,
};
pub use delegations::{DelegationId, StoredDelegation};
pub use error::ApiError;
pub use law::{LawEntry, LawEntryView, LawStore, StoredLawInfo};
pub use paper_import::PaperBookOcrCommandConfig;
pub use platform_logs::{PlatformLogEntry, PlatformLogRing, PlatformLogsResponse};
pub use roles::{
    count_owner_admins, effective_permissions_for, effective_permissions_for_actor,
    last_owner_guard_ok, resolve_principal_id,
};
// Signature-provider credential model + encrypted sidecar (t77 S2). Re-exported so the credential
// API/assembly slices (S3/S4) can name these and so the crypto core's consumers are reachable from
// the crate root (the crate-private `CredentialSecretStore` itself stays internal).
pub use privacy::provision_subject_dek;
pub use secretstore::{CredentialKeySource, ProtectionLevel, SecretEnvelope, SecretStoreError};
pub use secretstore_persist::{
    CmdCredentialFields, CredentialEntry, CredentialFieldSet, CredentialMode,
    CredentialRecordStatus, CscCredentialFields, DecryptedCredentialEntry,
    DecryptedCredentialRecord, EncryptedCredentialRecord, EntryMetadata, EntrySelectors,
    Pkcs12CredentialFields, ProviderCredentialError, ProviderCredentialStore, ScapCredentialFields,
    StoredCredentialField,
};
pub use settings::{
    AiSettings, AppearanceSettings, CaeSourceEntry, CatalogSettings, CmdEnvSetting,
    DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS, DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES,
    DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES, DocumentSettings, Locale, OnboardingSettings,
    OrganizationSettings, PlatformAuditEvent, PlatformControlOutcomeKind, PlatformLogLevel,
    PlatformLoggingSettings, PlatformServiceAction, PlatformServiceControlSettings,
    PlatformServiceDesiredState, PlatformServiceLastAction, PlatformSettings,
    RegistryAutoUpdateCadence, RegistryAutoUpdateEntityDefaults, RegistryAutoUpdateSettings,
    RegistryAutoUpdateWeekday, Settings, SignatureFamily, SigningCmdSettings, SigningSettings,
    ThemeMode,
};
#[cfg(debug_assertions)]
pub use trust::{LocalTrustUrlTestAllowance, allow_local_trust_url_for_tests};
pub use users::{User, UserId};

#[cfg(feature = "e2e")]
#[derive(serde::Deserialize)]
struct E2eSessionSeed {
    token: String,
    user_id: uuid::Uuid,
}

#[cfg(feature = "e2e")]
pub async fn seed_e2e_sessions_from_data_dir(state: &AppState) {
    let Some(data_dir) = state.data_dir() else {
        return;
    };
    let path = data_dir.join(".chancela-e2e-session-seed.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let seed: E2eSessionSeed = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("invalid e2e session seed {}: {e}", path.display()));
    let user_id = users::UserId(seed.user_id);
    {
        let users = state.users.read().await;
        assert!(
            users.get(&user_id).is_some_and(|u| u.active),
            "e2e session seed references an absent or inactive user: {user_id}"
        );
    }
    state.sessions.write().await.insert(
        seed.token,
        session::SessionEntry {
            user_id,
            unlocked_key: None,
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::seconds(actor::SESSION_TTL_SECS),
        },
    );
    std::fs::remove_file(&path)
        .unwrap_or_else(|e| panic!("remove consumed e2e session seed {}: {e}", path.display()));
}

#[derive(Default)]
pub struct ExportCleanupPreviewStore {
    pub(crate) records: HashMap<String, data_status::ExportCleanupPreviewRecord>,
}

/// Environment variable naming a data directory for on-disk persistence. When unset,
/// [`AppState::from_env`] falls back to walking up for an existing `chancela-data/` directory,
/// and finally to pure in-memory state.
pub const DATA_DIR_ENV: &str = "CHANCELA_DATA_DIR";

/// Shared application state: in-memory maps, plus optional data-dir/store-backed durability.
///
/// Every field is `Arc<RwLock<..>>` so the state is cheap to clone into each handler and safe
/// to mutate concurrently. Cloning an [`AppState`] shares the same underlying maps and ledger.
/// Handlers that take several locks acquire them in the fixed order **entities → books → acts
/// → follow_ups → registry_extracts → registry_auto_updates → users → dsr_requests → processor_records →
/// dpia_records → breach_playbooks → transfer_controls → retention_policies →
/// retention_execution_records → retention_candidate_resolutions → ledger** to avoid deadlock. The `cae` and `sessions` locks
/// are independent, short-lived locks not part of that chain (a handler acquires and releases one
/// before touching the ordered locks, or after — never interleaved with them).
#[derive(Clone, Default)]
pub struct AppState {
    /// All known entities, keyed by their [`EntityId`].
    pub entities: Arc<RwLock<HashMap<EntityId, Entity>>>,
    /// All books (livros de atas), keyed by their [`BookId`].
    pub books: Arc<RwLock<HashMap<BookId, Book>>>,
    /// All acts (atas), keyed by their [`ActId`].
    pub acts: Arc<RwLock<HashMap<ActId, Act>>>,
    /// First-class act-scoped follow-up/task rows. These are persisted outside [`Act`] JSON so sealed
    /// acts stay immutable while post-deliberation work remains trackable.
    pub follow_ups: Arc<RwLock<HashMap<String, StoredFollowUp>>>,
    /// The append-only audit ledger backing every mutation (DAT-10/11).
    pub ledger: Arc<RwLock<Ledger>>,
    /// The current application settings document (contract §2.8). Defaults until a `PUT`.
    pub settings: Arc<RwLock<settings::Settings>>,
    /// Structured platform log tail. This is API-owned and bounded; it is backed by
    /// `platform-logs.json` when a data dir is configured, and in-memory otherwise. It is not a
    /// historical stdout/stderr tail or an MCP process-log collector.
    pub platform_logs: Arc<RwLock<PlatformLogRing>>,
    /// Where `platform-logs.json` is persisted, or `None` for pure in-memory state.
    pub platform_logs_path: Option<Arc<PathBuf>>,
    /// Where `settings.json` is persisted, or `None` for pure in-memory state. Shared (and so
    /// cheap to clone) via `Arc`; set only by [`AppState::with_data_dir`]/[`AppState::from_env`].
    pub persist_path: Option<Arc<PathBuf>>,
    /// Injected certidão permanente transport; `None` ⇒ handlers build an
    /// `HttpRegistryTransport` from the environment (contract §2.7). Boxed behind `Option` so
    /// `Default` stays derivable (mirrors `persist_path`); tests inject a mock here.
    pub registry: Option<Arc<dyn RegistryTransport>>,
    /// Registry extracts imported per entity, with provenance (LEG-22). In-memory like the
    /// rest of the scaffold state.
    pub registry_extracts: Arc<RwLock<HashMap<EntityId, RegistryExtract>>>,
    /// Backend-owned commercial-registry auto-update state/evidence per entity. Metadata-only:
    /// no full access codes and no frontend-supplied registry payloads are stored here.
    pub registry_auto_updates: Arc<RwLock<HashMap<EntityId, registry::RegistryAutoUpdateState>>>,
    /// The active CAE catalog (contract §2.7). `Default` is the embedded both-revision dataset;
    /// [`AppState::with_data_dir`] prefers a valid `cae-catalog.json` cache, and
    /// `POST /v1/cae/refresh` swaps it in place.
    pub cae: Arc<RwLock<CaeCatalog>>,
    /// Legacy injected CAE dataset source for `POST /v1/cae/refresh` (single-envelope back-compat
    /// seam): when set, the refresh runs the original [`chancela_cae::refresh`] path unchanged.
    /// `None` in production, where the refresh builds an ordered chain from settings + environment.
    /// Mirrors `registry`; some tests inject a source here.
    pub cae_source: Option<Arc<dyn CaeSource>>,
    /// Test/DI seam (§cae-v2): when set, `POST /v1/cae/refresh` builds its source chain from this
    /// factory instead of from settings/environment, so tests drive the multi-source
    /// [`chancela_cae::obtain_from_chain`] pipeline over in-memory `Bytes`/`File` sources without a
    /// network. Called fresh per request (so `?source` pinning can consume it). `None` in production.
    #[allow(clippy::type_complexity)]
    pub cae_chain_factory: Option<Arc<dyn Fn() -> CaeSourceChain + Send + Sync>>,
    /// Test/DI seam (§cae-v2 no-config default): the chain `POST /v1/cae/refresh` runs when *nothing*
    /// is configured (no `cae_sources`, `cae_official_source` off, no `cae_update_url`/`CHANCELA_CAE_URL`,
    /// no `?source` pin) — the "no URL ⇒ obtain from the official gov artifacts" fallback. `None` in
    /// production, where it is [`chancela_cae::default_official_chain`] (the digest-pinned Diário da
    /// República diploma pair); tests inject a fixture DR pair here to exercise the substitution
    /// without a network. Called fresh per request. Mirrors `cae_chain_factory`.
    #[allow(clippy::type_complexity)]
    pub cae_default_chain_factory: Option<Arc<dyn Fn() -> CaeSourceChain + Send + Sync>>,
    /// Test/DI seam: when set, `GET /v1/cae/updates` points its [`chancela_cae::SmiSource`] at this
    /// base URL instead of the official INE SMI host, so the real `fetch_catalog` decode+parse path
    /// runs against an in-process fixture server without hitting the network. `None` in production
    /// (mirrors `law_pdf_base_override`).
    pub smi_base_override: Option<Arc<String>>,
    /// Named user profiles for actor attribution (contract §2.8), keyed by [`UserId`]. `Default`
    /// empty; `with_data_dir`/`from_env` load `users.json`.
    pub users: Arc<RwLock<HashMap<UserId, User>>>,
    /// First-class privacy/DSR request lifecycle records, keyed by request id. File-backed states
    /// load and write these through `privacy-dsr-requests.json`; each create/complete transition is
    /// still chained into the ledger.
    pub dsr_requests: Arc<RwLock<HashMap<privacy::DsrRequestId, privacy::DsrRequest>>>,
    /// Where `privacy-dsr-requests.json` is persisted, or `None` for in-memory request tracking.
    pub dsr_requests_path: Option<Arc<PathBuf>>,
    /// GDPR processor register records. File-backed states load and write these through
    /// `privacy-processors.json`; create and update transitions are also chained into the ledger.
    pub processor_records:
        Arc<RwLock<HashMap<privacy::ProcessorRecordId, privacy::ProcessorRecord>>>,
    /// DPIA register records. File-backed states load and write these through `privacy-dpias.json`;
    /// create and update transitions are also chained into the ledger.
    pub dpia_records: Arc<RwLock<HashMap<privacy::DpiaRecordId, privacy::DpiaRecord>>>,
    /// Breach-response playbook register records. File-backed states load and write these through
    /// `privacy-breach-playbooks.json`; create and update transitions are ledger-audited.
    pub breach_playbooks:
        Arc<RwLock<HashMap<privacy::BreachPlaybookId, privacy::BreachPlaybookRecord>>>,
    /// Transfer-control register records. File-backed states load and write these through
    /// `privacy-transfer-controls.json`; create and update transitions are ledger-audited.
    pub transfer_controls:
        Arc<RwLock<HashMap<privacy::TransferControlId, privacy::TransferControlRecord>>>,
    /// Retention policy register records. File-backed states load and write these through
    /// `retention-policies.json`; create and update transitions are also chained into the ledger.
    pub retention_policies:
        Arc<RwLock<HashMap<privacy::RetentionPolicyId, privacy::RetentionPolicyRecord>>>,
    /// Retention execution request evidence. File-backed states load and write these through
    /// `privacy-retention-executions.json`; records are non-destructive and ledger-audited.
    pub retention_execution_records:
        Arc<RwLock<HashMap<String, privacy::RetentionExecutionRecord>>>,
    /// Evidence-only due-candidate disposition records. File-backed states load and write these
    /// through `privacy-retention-candidate-resolutions.json`; they never perform disposal.
    pub retention_candidate_resolutions:
        Arc<RwLock<HashMap<String, privacy::RetentionCandidateResolutionRecord>>>,
    /// Non-destructive backup recovery drill/custody receipts. File-backed states load and write
    /// these through `backup-recovery-drills.json`; the receipt route calls restore preflight only.
    pub backup_recovery_drill_receipts: Arc<RwLock<Vec<BackupRecoveryDrillReceipt>>>,
    /// Per-actor notification triage for dashboard-derived notification ids. File-backed states load
    /// and write this through `notification-triage.json`; the dashboard generation itself is unchanged.
    pub notification_triage: Arc<RwLock<notifications::NotificationTriageTable>>,
    /// Where `privacy-processors.json` is persisted, or `None` for in-memory registers.
    pub processor_records_path: Option<Arc<PathBuf>>,
    /// Where `privacy-dpias.json` is persisted, or `None` for in-memory registers.
    pub dpia_records_path: Option<Arc<PathBuf>>,
    /// Where `privacy-breach-playbooks.json` is persisted, or `None` for in-memory registers.
    pub breach_playbooks_path: Option<Arc<PathBuf>>,
    /// Where `privacy-transfer-controls.json` is persisted, or `None` for in-memory registers.
    pub transfer_controls_path: Option<Arc<PathBuf>>,
    /// Where `retention-policies.json` is persisted, or `None` for in-memory registers.
    pub retention_policies_path: Option<Arc<PathBuf>>,
    /// Where `privacy-retention-executions.json` is persisted, or `None` for in-memory evidence.
    pub retention_execution_records_path: Option<Arc<PathBuf>>,
    /// Where `privacy-retention-candidate-resolutions.json` is persisted, or `None` for in-memory evidence.
    pub retention_candidate_resolutions_path: Option<Arc<PathBuf>>,
    /// Where `backup-recovery-drills.json` is persisted, or `None` for in-memory receipts.
    pub backup_recovery_drill_receipts_path: Option<Arc<PathBuf>>,
    /// Where `notification-triage.json` is persisted, or `None` for in-memory triage.
    pub notification_triage_path: Option<Arc<PathBuf>>,
    /// Where `users.json` is persisted, or `None` for in-memory profiles. Mirrors `persist_path`.
    pub users_path: Option<Arc<PathBuf>>,
    /// App-level seed material for hardened password/recovery verifiers. File-backed states load or
    /// lazily save it as a seed config sidecar; API/ledger payloads carry only user views and never
    /// this material.
    pub verifier_seed: Arc<RwLock<VerifierSeed>>,
    /// The scoped RBAC role catalog (t64): the seeded defaults + any custom roles. `Default` empty;
    /// [`AppState::with_data_dir`] loads `roles.json` and **ensures the seeded defaults are present**
    /// (Owner forced canonical/locked). Mirrors `users`.
    pub roles: Arc<RwLock<chancela_authz::RoleCatalog>>,
    /// Where `roles.json` is persisted, or `None` for in-memory. Mirrors `users_path`.
    pub roles_path: Option<Arc<PathBuf>>,
    /// The scoped delegation table (t64): active **and** revoked delegations, keyed by
    /// [`DelegationId`]. `Default` empty; [`AppState::with_data_dir`] loads `delegations.json`.
    pub delegations: Arc<RwLock<HashMap<DelegationId, delegations::StoredDelegation>>>,
    /// Where `delegations.json` is persisted, or `None` for in-memory. Mirrors `users_path`.
    pub delegations_path: Option<Arc<PathBuf>>,
    /// In-memory session tokens → the [`SessionEntry`](session::SessionEntry) they open: the
    /// user, plus (when the user signed in with a password and holds an attestation key) the
    /// decrypted signing key held for the life of the session. Reset on restart; the unlocked key
    /// never persists and never leaves the process (plan t29 §4.4).
    pub sessions: Arc<RwLock<HashMap<String, session::SessionEntry>>>,
    /// Short-lived server-bound previews for destructive retained-export cleanup. In-memory only:
    /// previews bind the token to the canonical data directory, request policy, and server-selected
    /// candidate manifest, and reset on restart.
    pub export_cleanup_previews: Arc<RwLock<ExportCleanupPreviewStore>>,
    /// In-memory audit-attestation sidecar (plan t29 §2/§4.4): ledger `seq` → the per-event
    /// signature produced by the signed-in user's unlocked key. Kept out of the `chancela-ledger`
    /// crate and, like the in-memory ledger, **resets on restart** (a persisted attestation would
    /// orphan against a reused `seq`). Bound to the chain by the event `hash` it signs.
    pub attestations: Arc<RwLock<HashMap<u64, attestation::Attestation>>>,
    /// Per-user sign-in backoff (plan t29 §4.5): a naive in-memory speed-bump against repeated
    /// wrong-password attempts. Resets on restart; not a hardened anti-brute-force.
    pub signin_backoff: Arc<RwLock<HashMap<UserId, session::Backoff>>>,
    /// Cross-user secret/reset backoff (t52): the speed-bump on the credential-reset endpoints
    /// (`set_secret`/`remove_secret`/`attestation-key`/`recovery`), keyed by
    /// **`(requester, target-from-request)`** so a failed attempt against a *non-existent* target
    /// accrues and throttles IDENTICALLY to one against a real target (no enumeration oracle), while
    /// an attacker hammering a victim's id cannot lock out that victim's own self-service (a
    /// different key, never throttled). Mirrors `signin_backoff`: in-memory, resets on restart, not a
    /// hardened anti-brute-force. See `users::authorize_secret_op_throttled`.
    pub secret_backoff: Arc<RwLock<HashMap<users::SecretBackoffKey, session::Backoff>>>,
    /// The law archive's directory (`<data_dir>/laws`), or `None` for in-memory (no persistence).
    /// Mirrors `users_path`; set only by [`AppState::with_data_dir`]/[`AppState::from_env`].
    pub laws_dir: Option<Arc<PathBuf>>,
    /// The law-archive store state (per-diploma stored PDF metadata). `Default` empty;
    /// `with_data_dir`/`from_env` load `laws/manifest-state.json`.
    pub law_store: Arc<RwLock<law::LawStore>>,
    /// Test/DI seam: when set, `POST /v1/law/{id}/fetch` downloads from `<base>/<id>.pdf` instead
    /// of the manifest's pinned `pdf_url`, so tests exercise the real download path against an
    /// in-process fixture server. `None` in production (mirrors `registry`/`cae_source`).
    pub law_pdf_base_override: Option<Arc<String>>,
    /// Opt-in local OCR command for preserved paper-book imports. `None` by default; when configured
    /// from environment or injected by tests, `POST /v1/books/paper-import/{id}/ocr/run` executes the
    /// command directly (no shell) against a temporary copy of the preserved package bytes and stores
    /// bounded stdout as a non-authoritative OCR draft.
    pub paper_book_ocr_command: Option<Arc<paper_import::PaperBookOcrCommandConfig>>,
    /// The durable system of record (t30): the SQLite store backing `entities`/`books`/`acts`/
    /// `registry_extracts` and the ledger's `events` table. `None` = pure in-memory (the current
    /// behaviour, byte-identical). Set only by [`AppState::with_data_dir`]/[`AppState::from_env`];
    /// every mutation write-through goes through [`AppState::persist_write_through`].
    pub store: Option<Store>,
    /// wp16 P3b — whether the five non-ledger sidecars (users/roles/delegations/settings/
    /// provider-credentials) are DB-backed (shared across cluster nodes) rather than file-backed.
    /// `true` **only** for the Postgres backend; `false` (the [`Default`]) keeps the byte-identical
    /// file behaviour on SQLite/embedded single-node. Set once at startup from the resolved backend;
    /// [`crate::sidecar_store`] and the follower change-feed read it to pick file vs DB per sidecar.
    pub sidecars_db_backed: bool,
    /// The live document read model (t48 / DOC-01): generated documents (PDF/A-2u bytes +
    /// metadata) keyed by the owning [`ActId`]. Book instruments (termos) key on their book id
    /// cast into an `ActId`. Mirrors `acts`/`books`: an in-memory read model backed by the durable
    /// `documents` table; the GET endpoints fall back to the store on a miss (e.g. after a restart,
    /// before the map is repopulated). `Default` empty.
    pub documents: Arc<RwLock<HashMap<ActId, StoredDocument>>>,
    /// The boot-time chain-verification outcome recorded by [`AppState::with_data_dir`] when the
    /// durable ledger was rehydrated (§D-boot): `Some(Ok(len))` for an intact chain, `Some(Err(..))`
    /// for a broken one (surfaced on `/health` + the startup banner), `None` in-memory. Shared via
    /// `Arc` so cloning the state stays cheap.
    pub chain_status: Option<Arc<Result<u64, LedgerError>>>,
    /// The **degraded read-only signal** (t54 §3.1). `true` when the ledger's integrity report is
    /// unhealthy (a broken chain) — set at boot from the rehydrated [`IntegrityReport`], and
    /// recomputed after every recovery op (restore / re-anchor / factory reset). While set, the
    /// [`degraded_gate`] middleware fails **loud** with `503` on ordinary mutations (create / patch /
    /// advance / seal / open / close / start-over / import-into-live), leaving reads, the integrity
    /// report, and the recovery/reset/export/quarantine-import endpoints open so the operator can see
    /// and repair. `Default` is healthy (`false`); pure in-memory state never enters degraded.
    pub degraded: Arc<RwLock<bool>>,
    /// The live SIGNED-document read model (t57-S3): the qualified signed PDF variant + metadata per
    /// act, keyed by [`ActId`]. Mirrors `documents`: an in-memory read model backed by the durable
    /// `signed_documents` table, with the read endpoints falling back to the store on a miss.
    pub signed_documents: Arc<RwLock<HashMap<ActId, StoredSignedDocument>>>,
    /// Runtime-supplied external-validator technical metadata JSON attachments. These are validated
    /// at indexing time and matched only by observed canonical/signed PDF SHA-256. Optional raw
    /// technical report bytes are preserved only when their declared digest and size match; invalid,
    /// overclaiming, duplicate-path, or non-JSON entries are ignored.
    pub external_validator_report_metadata: Arc<RwLock<Vec<Vec<u8>>>>,
    /// Where external-validator technical metadata sidecars are persisted, or `None` for pure
    /// in-memory metadata.
    pub external_validator_report_metadata_dir: Option<Arc<PathBuf>>,
    /// In-flight two-phase Chave Móvel Digital signing sessions (t57-S3), keyed by session id. The
    /// non-secret resumable handle between `initiate` and `confirm`; **never holds a PIN or OTP**.
    /// Backed by the durable `pending_cmd_sessions` table (rehydrated on boot), so a session survives
    /// a restart.
    pub pending_signatures: Arc<RwLock<HashMap<String, PendingCmdSession>>>,
    /// External signer invitation tracking records, keyed by invite id. This is an envelope
    /// workflow only: records retain a token hash and redacted hint, never the plaintext token, and
    /// do not represent a completed legal signature.
    pub external_signer_invites:
        Arc<RwLock<HashMap<uuid::Uuid, signature::ExternalSignerInviteRecord>>>,
    /// Core external-signing envelope records, keyed by envelope id. These are workflow/evidence
    /// envelopes only: they record ordered signer slots, statuses, and evidence locators/digests;
    /// they do not assert legal effect or qualified-signature status.
    pub external_signing_envelopes:
        Arc<RwLock<HashMap<ExternalSignatureEnvelopeId, ExternalSignatureEnvelope>>>,
    /// Where `external-signing-envelopes.json` is persisted, or `None` for in-memory envelopes.
    pub external_signing_envelopes_path: Option<Arc<PathBuf>>,
    /// Test/DI seam (t57-S3): an injected SCMD transport. `None` in production, where the signing
    /// handlers build a real `chancela_cmd::HttpScmdTransport` from the resolved [`CmdConfig`] and run
    /// it off the async runtime. Tests inject a `MockScmdTransport`-backed transport here so the
    /// initiate/confirm round-trip runs offline (no live SCMD). Must be `Send + Sync` for the shared
    /// state; the mock used in tests wraps its recorder so it satisfies that.
    pub cmd_transport: Option<Arc<dyn ScmdTransport + Send + Sync>>,
    /// Test/DI seam (t57-S3): an injected trusted-list policy factory (SIG-11/23). `None` in
    /// production, where the qualified path builds a `TslTrustPolicy` over the settings `tsl_url`
    /// (network-gated, run during the actual sign). Tests inject a `StaticTrustPolicy` factory to
    /// drive the gate offline (granted / withdrawn) without fetching the live TSL.
    ///
    /// **Reused by the Cartão de Cidadão (CC) path too (t58-e2):** the CC qualified signature runs
    /// the same trusted-list gate over the same factory, so both qualified methods agree on how
    /// trust is resolved in tests and production.
    #[allow(clippy::type_complexity)]
    pub cmd_trust_policy: Option<Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync>>,
    /// Whether this API process is **co-located** with a Cartão de Cidadão reader (t58 CC-B).
    /// Resolved once at construction from the `CHANCELA_LOCAL_SIGNING` signal the desktop shell sets
    /// on the embedded-server process (t58-e3); a remote `chancela-server` never sets it, so this
    /// stays `false` and the CC signing endpoint 409s there (the card is on the client's machine,
    /// unreachable by a remote server's PKCS#11). `Default` is `false`; tests set it directly.
    pub local_signing: bool,
    /// Test/DI seam (t58-e2): an injected Cartão de Cidadão signer-provider factory. `None` in
    /// production, where the co-located desktop handler opens a real `Pkcs11Token` and wraps it as a
    /// `SmartcardProvider` inside `spawn_blocking`. Tests inject a key-backed provider so the CC sign
    /// round-trip runs offline (no reader / PKCS#11 / hardware). Invoked inside `spawn_blocking`
    /// (PKCS#11/PC/SC is blocking + the middleware blocks on PIN entry at the reader); a card/reader
    /// failure surfaces as [`chancela_signing::SigningError::Provider`]. The produced provider never
    /// crosses a thread boundary (built and consumed inside the blocking task), so it need not be
    /// `Send`; only the factory is.
    #[allow(clippy::type_complexity)]
    pub cc_provider:
        Option<Arc<dyn Fn() -> Result<Box<dyn SignerProvider>, SigningError> + Send + Sync>>,
    /// Configured Cloud Signature Consortium (CSC) remote-signing providers (t59-s3): one
    /// non-secret [`CscConfig`] per external QTSP (Multicert / DigitalSign / …). **Loaded from the
    /// ENVIRONMENT, never the web-asserted `/v1/settings` document** (drift-safe: adding a CSC
    /// provider does not change any web-asserted settings fixture). Empty by default → only Chave
    /// Móvel Digital is offered. The per-provider OAuth secrets live in
    /// `CHANCELA_CSC_<PROVIDER>_*` env vars (never here); this holds only the non-secret selectors
    /// (base URL, id, authorization model, sandbox flag) surfaced by `GET /v1/signature/providers`.
    /// Populated by [`signature::load_csc_providers_from_env`] at construction.
    pub csc_providers: Arc<Vec<CscConfig>>,
    /// Test/DI seam (t59-s3): an injected CSC transport factory. `None` in production, where the
    /// generic remote-signing handlers build a real `chancela_csc::HttpCscTransport` per provider
    /// and run it off the async runtime (`spawn_blocking`). Tests inject a factory returning a
    /// `MockCscTransport` so the generic initiate/confirm round-trip runs offline (no live QTSP).
    /// Mirrors [`Self::cmd_transport`]. Called fresh per request with the resolved provider config.
    #[allow(clippy::type_complexity)]
    pub csc_transport:
        Option<Arc<dyn Fn(&CscConfig) -> Box<dyn CscTransport + Send> + Send + Sync>>,
    /// API-key registry for MCP/integration bearer authentication, keyed by the key's non-secret
    /// prefix. `with_data_dir` persists this to `apikeys.json`; pure in-memory states may still have
    /// tests/embedders inject `chancela-apikey` records directly.
    pub api_keys: Arc<RwLock<apikeys::ApiKeyRegistry>>,
    /// Where `apikeys.json` is persisted, or `None` for pure in-memory API keys.
    pub api_keys_path: Option<Arc<PathBuf>>,
    /// Per-key token-bucket state for bearer requests. Reset on restart; policy lives on the key.
    pub api_key_rate_limits: Arc<RwLock<apikeys::ApiKeyRateLimitBuckets>>,
    /// Whether the durable SQLite store was opened with a configured SQLCipher key. False for
    /// plaintext store mode and for pure in-memory state. The key itself is never stored here.
    pub database_encryption_configured: bool,
    /// Non-secret source classification for the configured database encryption key. `None` means no
    /// database key was configured; this never contains key material.
    pub database_encryption_key_source: Option<DatabaseEncryptionKeySource>,
    /// Signature-provider credentials encrypted at rest (t77): the loaded
    /// `provider-credentials.enc.json` sidecar plus a lazily-resolved handle to the internally-derived
    /// credential key (S1/S2). Reads of an empty/absent sidecar are fine; storing a secret fails
    /// closed when no key source is available or (in strict mode) the protection level is not
    /// confidential. `Default` is an in-memory, no-key-source store that refuses every write. Held
    /// behind an `Arc` so cloning the state shares the one set of interior locks.
    pub provider_credentials: Arc<ProviderCredentialStore>,
    /// wp14 Phase 4 — the in-process [`Ledger::verify`](chancela_ledger::Ledger::verify) memo (the
    /// real single-node cache win). Caches the `O(n)` chain-verify verdict keyed by the ledger head
    /// hash + length, so the dashboard / integrity hot path is `O(1)` over an unchanged chain; a new
    /// append changes the head, so it self-invalidates. Shared across clones (moka is internally
    /// `Arc`); verify semantics are unchanged — this is a transparent memo. See [`cache`].
    pub verify_cache: cache::VerifyMemo,
    /// wp14 Phase 4 — the OPTIONAL cache-aside backend (default [`cache::NullCache`], a no-op). An
    /// off-by-default Redis backend (`redis` feature + `REDIS_URL`) caches a couple of rarely-mutated
    /// catalog projections; it is **fail-open** and inert when absent, so the app is byte-identical
    /// without it. Honest scope: single-node reads are RAM-served, so this is primarily a shared
    /// cache for a future multi-instance deployment — not a single-node speed-up. See [`cache`].
    pub cache: cache::SharedCache,
    /// wp16 P3a — the cluster-shared auth state: the shared session identity store, the global
    /// sign-in/rate-limit counter, and the cross-node invalidation bus. **Every backend defaults to a
    /// local no-op**, so single-node behaviour is byte-identical: the shared session store defers to
    /// the node-local [`sessions`](Self::sessions) map and the global limiter defers to the node-local
    /// [`signin_backoff`](Self::signin_backoff). With the `redis` feature + `REDIS_URL`, sessions
    /// become cluster-wide (FAIL-CLOSED on a Redis outage), sign-in limits become global
    /// (fail-closed to the per-node floor), and a session-revoke / role-change is broadcast so other
    /// nodes evict their caches. See [`cluster_shared_state`].
    pub cluster_shared: cluster_shared_state::SharedClusterState,
    /// wp25-sec — per-client-IP HTTP rate-limit policy. `Default` is **disabled** so the
    /// test/embedding constructors ([`AppState::default`], [`AppState::with_data_dir`]) stay inert;
    /// the running server enables it with sane defaults from the environment in
    /// [`AppState::try_from_env`]. Single-node, in-memory (see [`Self::rate_limit_buckets`]).
    pub rate_limit: RateLimitConfig,
    /// wp25-sec — per-client-IP token buckets backing [`rate_limit`](Self::rate_limit). In-memory,
    /// reset on restart, bounded by the number of distinct recent client IPs. Cluster-wide limiting
    /// would need a shared store (Redis) — a documented follow-up.
    pub rate_limit_buckets: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    /// wp25-sec — the absolute session-lifetime cap: the maximum wall-clock age a session may reach
    /// regardless of the 24h idle/sliding renewal. `Default` is 7 days; the running server overrides
    /// it from `CHANCELA_SESSION_MAX_LIFETIME` in [`AppState::try_from_env`].
    pub session_max_lifetime: SessionMaxLifetime,
    /// wp25-sec — per-token session issued-at timestamps backing the absolute-lifetime cap. Recorded
    /// on first sight of a token (recovered from the pre-slide expiry on the minting node) and
    /// consulted by [`actor::resolve_session_actor`]. In-memory, reset on restart.
    pub session_issued_at: Arc<RwLock<HashMap<String, time::OffsetDateTime>>>,
}

impl AppState {
    /// Build state whose settings and JSON sidecars are read from — and written back to —
    /// `data_dir`.
    ///
    /// A missing or unreadable file yields the default settings (the directory is created lazily
    /// on the first successful `PUT`); a present-but-malformed file also falls back to defaults
    /// with a warning, so a bad file never blocks startup. Domain aggregates and the ledger are
    /// rehydrated from the durable store when it opens successfully.
    pub fn with_data_dir(data_dir: impl Into<PathBuf>) -> Self {
        Self::build_with_data_dir(data_dir.into(), DatabaseEncryptionConfig::plaintext())
            .expect("plaintext data-dir startup must not fail closed")
    }

    /// Build state from `data_dir`, applying an explicit database encryption config. Invalid or
    /// unavailable encryption fails closed instead of falling back to a misleading plaintext or
    /// in-memory store.
    pub fn try_with_data_dir(
        data_dir: impl Into<PathBuf>,
        database_encryption: DatabaseEncryptionConfig,
    ) -> Result<Self, AppStateInitError> {
        Self::build_with_data_dir(data_dir.into(), database_encryption)
    }

    fn build_with_data_dir(
        dir: PathBuf,
        database_encryption: DatabaseEncryptionConfig,
    ) -> Result<Self, AppStateInitError> {
        if database_encryption.is_configured() {
            let key_ops = Store::key_ops_status(&dir, &database_encryption.store_open_options())
                .map_err(|source| AppStateInitError::StoreOpen {
                    data_dir: dir.clone(),
                    source,
                })?;
            if key_ops.plan == StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration {
                return Err(AppStateInitError::StoreOpen {
                    data_dir: dir.clone(),
                    source: StoreError::PlaintextEncryptionMigrationUnsupported {
                        db_file: key_ops.database_file.display().to_string(),
                    },
                });
            }
            ensure_sqlcipher_feature_available()?;
        }
        let settings_path = dir.join(settings::SETTINGS_FILE);
        let loaded = settings::load_settings(&settings_path).unwrap_or_default();
        let platform_logs_path = dir.join(platform_logs::PLATFORM_LOGS_FILE);
        let loaded_platform_logs =
            platform_logs::load_platform_logs(&platform_logs_path).unwrap_or_default();
        let users_path = dir.join(users::USERS_FILE);
        let mut loaded_users = users::load_users(&users_path).unwrap_or_default();
        let verifier_seed_path = dir.join(attestation::VERIFIER_SEED_FILE);
        let verifier_seed = attestation::VerifierSeed::load_or_generate(verifier_seed_path.clone());

        // Scoped RBAC stores (t64): the role catalog + the delegation table, mirroring `users.json`.
        // The catalog seeds the four defaults if absent (Owner forced canonical/locked); the users
        // are brought forward by the one-time, idempotent, anti-lockout role migration. Each is
        // rewritten to disk exactly once, only when the load actually changed it.
        let roles_path = dir.join(roles::ROLES_FILE);
        let mut roles_catalog = roles::load_roles(&roles_path).unwrap_or_default();
        if roles::ensure_seeded_defaults(&mut roles_catalog) {
            if let Err(e) = roles::write_roles_atomic(&roles_path, &roles_catalog) {
                eprintln!("warning: failed to seed {} ({e})", roles_path.display());
            }
        }
        if roles::migrate_roles(&mut loaded_users) {
            if let Err(e) = users::write_users_atomic(&users_path, &loaded_users) {
                eprintln!(
                    "warning: failed to persist the role migration to {} ({e})",
                    users_path.display()
                );
            }
        }
        let delegations_path = dir.join(delegations::DELEGATIONS_FILE);
        let loaded_delegations =
            delegations::load_delegations(&delegations_path).unwrap_or_default();
        let dsr_requests_path = dir.join(privacy::DSR_REQUESTS_FILE);
        let loaded_dsr_requests =
            privacy::load_dsr_requests(&dsr_requests_path).unwrap_or_default();
        let processor_records_path = dir.join(privacy::PROCESSORS_FILE);
        let loaded_processor_records =
            privacy::load_processor_records(&processor_records_path).unwrap_or_default();
        let dpia_records_path = dir.join(privacy::DPIAS_FILE);
        let loaded_dpia_records =
            privacy::load_dpia_records(&dpia_records_path).unwrap_or_default();
        let breach_playbooks_path = dir.join(privacy::BREACH_PLAYBOOKS_FILE);
        let loaded_breach_playbooks =
            privacy::load_breach_playbooks(&breach_playbooks_path).unwrap_or_default();
        let transfer_controls_path = dir.join(privacy::TRANSFER_CONTROLS_FILE);
        let loaded_transfer_controls =
            privacy::load_transfer_controls(&transfer_controls_path).unwrap_or_default();
        let retention_policies_path = dir.join(privacy::RETENTION_POLICIES_FILE);
        let loaded_retention_policies =
            privacy::load_retention_policies(&retention_policies_path).unwrap_or_default();
        let retention_execution_records_path = dir.join(privacy::RETENTION_EXECUTIONS_FILE);
        let loaded_retention_execution_records =
            privacy::load_retention_execution_records(&retention_execution_records_path)
                .unwrap_or_default();
        let retention_candidate_resolutions_path =
            dir.join(privacy::RETENTION_CANDIDATE_RESOLUTIONS_FILE);
        let loaded_retention_candidate_resolutions =
            privacy::load_retention_candidate_resolution_records(
                &retention_candidate_resolutions_path,
            )
            .unwrap_or_default();
        let backup_recovery_drill_receipts_path =
            dir.join(backup_recovery::BACKUP_RECOVERY_DRILLS_FILE);
        let loaded_backup_recovery_drill_receipts =
            backup_recovery::load_backup_recovery_drill_receipts(
                &backup_recovery_drill_receipts_path,
            )
            .unwrap_or_default();
        let notification_triage_path = dir.join(notifications::NOTIFICATION_TRIAGE_FILE);
        let loaded_notification_triage =
            notifications::load_notification_triage(&notification_triage_path).unwrap_or_default();
        let api_keys_path = dir.join(apikeys::API_KEYS_FILE);
        let loaded_api_keys = apikeys::load_api_keys(&api_keys_path).unwrap_or_default();
        let external_signing_envelopes_path =
            dir.join(external_signing::EXTERNAL_SIGNING_ENVELOPES_FILE);
        let loaded_external_signing_envelopes =
            external_signing::load_envelopes(&external_signing_envelopes_path).unwrap_or_default();
        let external_validator_report_metadata_dir =
            dir.join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR);
        let loaded_external_validator_report_metadata =
            external_validator_evidence::load_external_validator_report_metadata(
                &external_validator_report_metadata_dir,
            );
        // Prefer a valid, newer `cae-catalog.json` cache over the embedded catalog (never errors).
        let catalog = chancela_cae::load_catalog(Some(&dir));
        // Law archive: the `laws/` subdir plus its state file (missing/malformed → empty archive).
        let laws_dir = dir.join(law::LAWS_DIR);
        let law_store = law::load_law_store(&laws_dir);
        let mut state = AppState {
            settings: Arc::new(RwLock::new(loaded)),
            platform_logs: Arc::new(RwLock::new(loaded_platform_logs)),
            platform_logs_path: Some(Arc::new(platform_logs_path)),
            persist_path: Some(Arc::new(settings_path)),
            users: Arc::new(RwLock::new(loaded_users)),
            users_path: Some(Arc::new(users_path)),
            verifier_seed: Arc::new(RwLock::new(verifier_seed)),
            roles: Arc::new(RwLock::new(roles_catalog)),
            roles_path: Some(Arc::new(roles_path)),
            delegations: Arc::new(RwLock::new(loaded_delegations)),
            delegations_path: Some(Arc::new(delegations_path)),
            dsr_requests: Arc::new(RwLock::new(loaded_dsr_requests)),
            dsr_requests_path: Some(Arc::new(dsr_requests_path)),
            processor_records: Arc::new(RwLock::new(loaded_processor_records)),
            processor_records_path: Some(Arc::new(processor_records_path)),
            dpia_records: Arc::new(RwLock::new(loaded_dpia_records)),
            dpia_records_path: Some(Arc::new(dpia_records_path)),
            breach_playbooks: Arc::new(RwLock::new(loaded_breach_playbooks)),
            breach_playbooks_path: Some(Arc::new(breach_playbooks_path)),
            transfer_controls: Arc::new(RwLock::new(loaded_transfer_controls)),
            transfer_controls_path: Some(Arc::new(transfer_controls_path)),
            retention_policies: Arc::new(RwLock::new(loaded_retention_policies)),
            retention_policies_path: Some(Arc::new(retention_policies_path)),
            retention_execution_records: Arc::new(RwLock::new(loaded_retention_execution_records)),
            retention_execution_records_path: Some(Arc::new(retention_execution_records_path)),
            retention_candidate_resolutions: Arc::new(RwLock::new(
                loaded_retention_candidate_resolutions,
            )),
            retention_candidate_resolutions_path: Some(Arc::new(
                retention_candidate_resolutions_path,
            )),
            backup_recovery_drill_receipts: Arc::new(RwLock::new(
                loaded_backup_recovery_drill_receipts,
            )),
            backup_recovery_drill_receipts_path: Some(Arc::new(
                backup_recovery_drill_receipts_path,
            )),
            notification_triage: Arc::new(RwLock::new(loaded_notification_triage)),
            notification_triage_path: Some(Arc::new(notification_triage_path)),
            api_keys: Arc::new(RwLock::new(loaded_api_keys)),
            api_keys_path: Some(Arc::new(api_keys_path)),
            external_signing_envelopes: Arc::new(RwLock::new(loaded_external_signing_envelopes)),
            external_signing_envelopes_path: Some(Arc::new(external_signing_envelopes_path)),
            external_validator_report_metadata: Arc::new(RwLock::new(
                loaded_external_validator_report_metadata,
            )),
            external_validator_report_metadata_dir: Some(Arc::new(
                external_validator_report_metadata_dir,
            )),
            cae: Arc::new(RwLock::new(catalog)),
            laws_dir: Some(Arc::new(laws_dir)),
            law_store: Arc::new(RwLock::new(law_store)),
            ..AppState::default()
        };

        // Durable system of record (t30): open the SQLite store and rehydrate the domain
        // aggregates + the hash-chained ledger from it. A store that fails to open or load falls
        // back to pure in-memory (`store` stays `None`) with a loud warning — durability is never
        // allowed to block startup (plan §D-boot); a broken but readable chain still boots and is
        // surfaced via `chain_status` (banner + `/health`).
        let encrypted_store = database_encryption.is_configured();
        let encryption_key_source = database_encryption.key_source();
        // wp14 Phase 2: pick the durable backend from CHANCELA_DB_BACKEND / DATABASE_URL. SQLite (the
        // default) resolves to today's data-dir + optional SQLCipher-key open unchanged; Postgres
        // (only when built with the `postgres` feature) requires a DATABASE_URL and, like an encrypted
        // store, must fail startup closed rather than silently fall back to ephemeral in-memory.
        let resolved_backend = database::resolve_backend_selection(&dir, &database_encryption)?;
        let require_durable_store = encrypted_store || resolved_backend.requires_durability;
        // wp16 P3b: the five non-ledger sidecars are DB-backed only on Postgres (shared across nodes);
        // SQLite/embedded keeps the byte-identical file path. Computed before the selection is moved
        // into `open_backend`.
        #[cfg(feature = "postgres")]
        let sidecars_db_backed = matches!(
            resolved_backend.selection,
            chancela_store::StoreBackendSelection::Postgres { .. }
        );
        #[cfg(not(feature = "postgres"))]
        let sidecars_db_backed = false;
        state.sidecars_db_backed = sidecars_db_backed;
        match Store::open_backend(resolved_backend.selection) {
            Ok(store) => match store.load() {
                Ok(loaded) => {
                    // Fail-loud gate (t54 §3.1): a broken boot chain enters DEGRADED read-only mode
                    // instead of silently booting as if healthy. Reads + recovery stay open; ordinary
                    // mutations return 503 until a restore / re-anchor / factory reset repairs it.
                    let healthy = loaded.integrity.healthy;
                    if let Err(e) = &loaded.chain_status {
                        eprintln!(
                            "chancela-store: ledger chain integrity check FAILED on boot ({e}) — \
                             entering DEGRADED read-only mode: reads and the recovery endpoints \
                             (restore / re-anchor / factory reset) stay open so the operator can \
                             inspect and repair; ordinary mutations are blocked with 503"
                        );
                    }
                    state.entities = Arc::new(RwLock::new(loaded.entities));
                    state.books = Arc::new(RwLock::new(loaded.books));
                    state.acts = Arc::new(RwLock::new(loaded.acts));
                    state.follow_ups = Arc::new(RwLock::new(loaded.follow_ups));
                    state.registry_extracts = Arc::new(RwLock::new(loaded.registry_extracts));
                    state.ledger = Arc::new(RwLock::new(loaded.ledger));
                    state.chain_status = Some(Arc::new(loaded.chain_status));
                    state.degraded = Arc::new(RwLock::new(!healthy));
                    // Rehydrate the qualified-signing read models (t57-S3): the signed variants and
                    // any in-flight pending CMD sessions, so a session survives a restart and the
                    // signed-PDF/status reads serve from memory. A read failure is non-fatal (the
                    // endpoints fall back to the store on a miss).
                    if let Ok(signed) = store.all_signed_documents() {
                        state.signed_documents = Arc::new(RwLock::new(signed));
                    }
                    if let Ok(pending) = store.all_pending_cmd_sessions() {
                        state.pending_signatures = Arc::new(RwLock::new(pending));
                    }
                    state.database_encryption_configured = encrypted_store;
                    state.database_encryption_key_source = encryption_key_source;
                    state.store = Some(store);
                }
                Err(e) if require_durable_store => {
                    return Err(AppStateInitError::StoreLoad {
                        data_dir: dir.clone(),
                        source: e,
                    });
                }
                Err(e) => {
                    eprintln!(
                        "chancela-store: failed to load durable state from {} ({e}) — running \
                         in-memory (the domain will NOT persist across restart)",
                        dir.display()
                    );
                }
            },
            Err(e) if require_durable_store => {
                return Err(AppStateInitError::StoreOpen {
                    data_dir: dir.clone(),
                    source: e,
                });
            }
            Err(e) => {
                eprintln!(
                    "chancela-store: failed to open the durable store at {} ({e}) — running \
                     in-memory (the domain will NOT persist across restart)",
                    dir.display()
                );
            }
        }

        // wp16 P3b: on Postgres the five non-ledger sidecars live in the DB (shared across nodes), so
        // make the DB tables authoritative — load users/roles/delegations/settings from the store
        // (replacing the file-derived defaults) and seed/migrate the role catalog back into the DB.
        // A store error here fails startup closed (Postgres already requires durability). No-op on
        // SQLite (`sidecars_db_backed == false`), keeping single-node byte-identical.
        if sidecars_db_backed {
            if let Some(store) = state.store.clone() {
                sidecar_store::hydrate_from_store(&mut state, &store).map_err(|source| {
                    AppStateInitError::StoreLoad {
                        data_dir: dir.clone(),
                        source,
                    }
                })?;
            }
        }

        // Resolve the CC co-location signal (t58-e2 / CC-B) from the environment the desktop shell
        // set before it spawned this embedded server (t58-e3). Absent (a remote server) ⇒ `false`.
        state.local_signing = signature::local_signing_from_env();
        // Resolve the configured CSC remote-signing providers from the environment (t59-s3): the
        // provider LIST + non-secret selectors come from `CHANCELA_CSC_*` env vars, NOT the
        // web-asserted settings document (drift-safe). Empty when none are configured.
        state.csc_providers = Arc::new(signature::load_csc_providers_from_env());
        state.paper_book_ocr_command =
            paper_import::PaperBookOcrCommandConfig::from_env().map(Arc::new);
        // wp14 Phase 4: resolve the OPTIONAL cache-aside backend from the environment (Redis when the
        // `redis` feature is built AND REDIS_URL/REDIS_URL_FILE is set; otherwise the no-op NullCache).
        // The in-process verify memo is separate and always on.
        state.cache = cache::SharedCache::from_env();
        // wp16 P3a: resolve the cluster-shared session store + global rate-limiter + invalidation bus
        // (Redis-backed only with the `redis` feature AND REDIS_URL/REDIS_URL_FILE set; otherwise every
        // backend stays a local no-op and single-node behaviour is byte-identical).
        state.cluster_shared = cluster_shared_state::SharedClusterState::from_env();
        // Signature-provider credential store (t77 S2): read the encrypted sidecar now (no key file
        // is created at boot — resolution is deferred to the first store), fail-closed on a missing
        // key source or a corrupt sidecar. Strict mode defaults off; the `credential_storage_strict`
        // settings selector that also feeds it arrives in S4, so only the env override applies here.
        let credential_strict = secretstore::strict_from_env(false);
        // wp16 P3b: on Postgres, the encrypted credential *blobs* live in the `provider_credentials`
        // DB table (shared across nodes) instead of `provider-credentials.enc.json`. The wp13 crypto
        // envelope + root-key resolution are unchanged — only the ciphertext storage moves; the root
        // key still comes from `CHANCELA_CREDENTIAL_KEY_FILE` / the data-dir sealed root. SQLite keeps
        // the file sidecar unchanged.
        state.provider_credentials = Arc::new(match (sidecars_db_backed, state.store.clone()) {
            (true, Some(store)) => {
                ProviderCredentialStore::load_db_backed(store, &dir, credential_strict)
            }
            _ => ProviderCredentialStore::load(&dir, credential_strict),
        });
        Ok(state)
    }

    /// Durable write-through (t30 §D2): persist the last `event_count` events just appended to
    /// `ledger`, together with any changed store-owned aggregates (via `upserts`), in one SQLite
    /// transaction. A **no-op** when the state is in-memory (`store` is `None`) — the current
    /// behaviour, byte-identical.
    ///
    /// Call this while holding the ledger write lock, immediately after `ledger.append(..)`, so the
    /// store write happens under the ledger lock and no `seq` can interleave. On a store failure the
    /// just-appended events are rolled back out of the in-memory `ledger` (rebuilt without them, so
    /// memory matches the untouched durable chain) and a `500` error is returned; the caller must
    /// then **not** commit its aggregate change to the in-memory maps. This keeps memory and disk
    /// from ever diverging (the plan's ruling).
    fn persist_write_through(
        &self,
        ledger: &mut Ledger,
        event_count: usize,
        upserts: impl FnOnce(&Tx<'_>) -> Result<(), StoreError>,
    ) -> Result<(), ApiError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        // wp16 P0 leadership gate: only the cluster writer-leader may append. A follower — or a
        // leader that silently lost its advisory lock / had its `leader_epoch` fenced (§7.3) — fails
        // CLOSED here so at most one writer ever extends the chain. Roll the just-appended in-memory
        // events back out so memory never diverges from the untouched durable chain, then return a
        // `503` "not leader". SQLite (single-node) is always its own leader, so this is a no-op there.
        if let Err(e) = store.cluster_assert_writable() {
            let len = ledger.len();
            let kept: Vec<Event> = ledger.events()[..len - event_count].to_vec();
            *ledger = Ledger::try_from_events(kept).0;
            return Err(Self::map_store_write_error(
                "cluster write gate refused the append",
                e,
            ));
        }
        let len = ledger.len();
        // The events just appended are the tail of the chain; persist them plus the changed
        // aggregates atomically (one commits-or-rolls-back transaction).
        let events: Vec<Event> = ledger.events()[len - event_count..].to_vec();
        if let Err(e) = store.persist(|tx| {
            for event in &events {
                tx.append_event(event)?;
            }
            upserts(tx)
        }) {
            // Roll the in-memory ledger back to match the (unchanged) durable chain on disk.
            let kept: Vec<Event> = ledger.events()[..len - event_count].to_vec();
            *ledger = Ledger::try_from_events(kept).0;
            return Err(Self::map_store_write_error(
                "failed to persist to the durable store",
                e,
            ));
        }
        // wp16 P1: the durable append committed — signal followers so the covered feed can advance
        // near-real-time (plan §2.2). Best-effort by design: a missed NOTIFY (leader crash between
        // commit and signal, no listener) is retried by the seq-poll backstop once Postgres can be
        // queried, so a failure here must never fail the write. No-op on SQLite (single-node).
        if let Err(e) = store.cluster_notify_append((len as i64) - 1) {
            eprintln!("cluster: NOTIFY on append failed ({e}); followers will retry via seq-poll");
        }
        Ok(())
    }

    /// Map durable-write failures to the API contract. In a Postgres cluster, `NotLeader` is a
    /// temporary write-service condition (`503`); other store failures are internal faults.
    pub(crate) fn map_store_write_error(context: &str, e: StoreError) -> ApiError {
        match e {
            StoreError::NotLeader => Self::not_leader_error(),
            other => ApiError::Internal(format!("{context}: {other}")),
        }
    }

    pub(crate) fn not_leader_error() -> ApiError {
        ApiError::Unavailable(
            "este nó não é o líder de escrita do cluster (failover em curso); tente novamente"
                .to_owned(),
        )
    }

    /// Roll the last `count` just-appended events back out of the in-memory `ledger`, rebuilding
    /// the chain without them. Used when an in-memory step **after** an append fails **before** the
    /// durable commit (t48: document generation during a seal / book open), so the in-memory chain
    /// stays identical to the untouched store and no aggregate change is committed. Mirrors the
    /// rollback [`persist_write_through`] performs on a store failure.
    pub(crate) fn rollback_ledger_events(ledger: &mut Ledger, count: usize) {
        let len = ledger.len();
        let kept: Vec<Event> = ledger.events()[..len - count].to_vec();
        *ledger = Ledger::try_from_events(kept).0;
    }

    /// Attest the most recently appended ledger event with the request's unlocked key, if it
    /// carries one (plan t29 §4.4). Best-effort enrichment: a signing failure is logged and
    /// skipped, never blocking the mutation. Call **after** [`persist_write_through`] has
    /// committed (so a rolled-back event is not attested); the tail event is the one just
    /// appended. The attestation sidecar is an independent lock, acquired last.
    async fn attest_latest(&self, attestor: &CurrentAttestor, ledger: &Ledger) {
        let Some((username, key)) = attestor.signer() else {
            return;
        };
        let Some(event) = ledger.events().last() else {
            return;
        };
        match attestation::sign_event(key, username, event) {
            Some(att) => {
                self.attestations.write().await.insert(att.event_seq, att);
            }
            None => eprintln!(
                "attestation: failed to sign event seq {} for {username}; continuing",
                event.seq
            ),
        }
    }

    /// The data directory backing on-disk persistence, or `None` for in-memory state. Derived
    /// from `persist_path` (the settings file's parent) so the CAE refresh writes its cache into
    /// the same directory `with_data_dir` seeded the catalog from.
    fn data_dir(&self) -> Option<PathBuf> {
        self.persist_path
            .as_ref()
            .and_then(|p| p.parent().map(PathBuf::from))
    }

    /// The whole-instance sidecar files bundled alongside the SQLite snapshot in a backup / export
    /// archive and removed on a factory reset (t54 §2.11): `settings.json`, the password-verifier
    /// seed config, user/RBAC/privacy/API sidecars, the CAE cache, and the `laws/` archive. Mirrors
    /// [`backup::create_backup`]'s list.
    /// Empty when in-memory.
    pub(crate) fn instance_sidecars(&self) -> Vec<PathBuf> {
        match self.data_dir() {
            Some(dir) => vec![
                dir.join(crate::settings::SETTINGS_FILE),
                dir.join(crate::platform_logs::PLATFORM_LOGS_FILE),
                dir.join(crate::attestation::VERIFIER_SEED_FILE),
                dir.join(crate::users::USERS_FILE),
                dir.join(crate::roles::ROLES_FILE),
                dir.join(crate::delegations::DELEGATIONS_FILE),
                dir.join(crate::privacy::DSR_REQUESTS_FILE),
                dir.join(crate::privacy::PROCESSORS_FILE),
                dir.join(crate::privacy::DPIAS_FILE),
                dir.join(crate::privacy::BREACH_PLAYBOOKS_FILE),
                dir.join(crate::privacy::TRANSFER_CONTROLS_FILE),
                dir.join(crate::privacy::RETENTION_POLICIES_FILE),
                dir.join(crate::privacy::RETENTION_EXECUTIONS_FILE),
                dir.join(crate::privacy::RETENTION_CANDIDATE_RESOLUTIONS_FILE),
                dir.join(crate::backup_recovery::BACKUP_RECOVERY_DRILLS_FILE),
                dir.join(crate::notifications::NOTIFICATION_TRIAGE_FILE),
                dir.join(crate::apikeys::API_KEYS_FILE),
                dir.join(crate::external_signing::EXTERNAL_SIGNING_ENVELOPES_FILE),
                dir.join(
                    crate::external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR,
                ),
                dir.join(chancela_cae::CACHE_FILE),
                dir.join(crate::law::LAWS_DIR),
            ],
            None => Vec::new(),
        }
    }

    /// Reload the durable DB read-models and file-backed instance sidecars after a whole-store
    /// restore so the running API reflects the swapped-in files. A no-op when in-memory. Does NOT
    /// touch the ledger — the restore path already replaced it in lock-step.
    pub(crate) async fn reload_domain_memory(&self) -> Result<(), ApiError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let loaded = store
            .load()
            .map_err(|e| ApiError::Internal(format!("reload after restore failed: {e}")))?;
        *self.entities.write().await = loaded.entities;
        *self.books.write().await = loaded.books;
        *self.acts.write().await = loaded.acts;
        *self.follow_ups.write().await = loaded.follow_ups;
        *self.registry_extracts.write().await = loaded.registry_extracts;
        self.registry_auto_updates.write().await.clear();
        self.documents.write().await.clear();
        self.external_signer_invites.write().await.clear();
        self.external_signing_envelopes.write().await.clear();
        if let Ok(signed) = store.all_signed_documents() {
            *self.signed_documents.write().await = signed;
        }
        if let Ok(pending) = store.all_pending_cmd_sessions() {
            *self.pending_signatures.write().await = pending;
        }
        if let Some(dir) = self.data_dir() {
            *self.settings.write().await =
                settings::load_settings(&dir.join(settings::SETTINGS_FILE)).unwrap_or_default();
            *self.platform_logs.write().await =
                platform_logs::load_platform_logs(&dir.join(platform_logs::PLATFORM_LOGS_FILE))
                    .unwrap_or_default();
            *self.users.write().await =
                users::load_users(&dir.join(users::USERS_FILE)).unwrap_or_default();
            *self.verifier_seed.write().await = attestation::VerifierSeed::load_or_generate(
                dir.join(attestation::VERIFIER_SEED_FILE),
            );

            let mut role_catalog =
                roles::load_roles(&dir.join(roles::ROLES_FILE)).unwrap_or_default();
            roles::ensure_seeded_defaults(&mut role_catalog);
            *self.roles.write().await = role_catalog;
            *self.delegations.write().await =
                delegations::load_delegations(&dir.join(delegations::DELEGATIONS_FILE))
                    .unwrap_or_default();
            *self.dsr_requests.write().await =
                privacy::load_dsr_requests(&dir.join(privacy::DSR_REQUESTS_FILE))
                    .unwrap_or_default();
            *self.processor_records.write().await =
                privacy::load_processor_records(&dir.join(privacy::PROCESSORS_FILE))
                    .unwrap_or_default();
            *self.dpia_records.write().await =
                privacy::load_dpia_records(&dir.join(privacy::DPIAS_FILE)).unwrap_or_default();
            *self.breach_playbooks.write().await =
                privacy::load_breach_playbooks(&dir.join(privacy::BREACH_PLAYBOOKS_FILE))
                    .unwrap_or_default();
            *self.transfer_controls.write().await =
                privacy::load_transfer_controls(&dir.join(privacy::TRANSFER_CONTROLS_FILE))
                    .unwrap_or_default();
            *self.retention_policies.write().await =
                privacy::load_retention_policies(&dir.join(privacy::RETENTION_POLICIES_FILE))
                    .unwrap_or_default();
            *self.retention_execution_records.write().await =
                privacy::load_retention_execution_records(
                    &dir.join(privacy::RETENTION_EXECUTIONS_FILE),
                )
                .unwrap_or_default();
            *self.retention_candidate_resolutions.write().await =
                privacy::load_retention_candidate_resolution_records(
                    &dir.join(privacy::RETENTION_CANDIDATE_RESOLUTIONS_FILE),
                )
                .unwrap_or_default();
            *self.backup_recovery_drill_receipts.write().await =
                backup_recovery::load_backup_recovery_drill_receipts(
                    &dir.join(backup_recovery::BACKUP_RECOVERY_DRILLS_FILE),
                )
                .unwrap_or_default();
            *self.notification_triage.write().await = notifications::load_notification_triage(
                &dir.join(notifications::NOTIFICATION_TRIAGE_FILE),
            )
            .unwrap_or_default();
            *self.api_keys.write().await =
                apikeys::load_api_keys(&dir.join(apikeys::API_KEYS_FILE)).unwrap_or_default();
            *self.external_signing_envelopes.write().await = external_signing::load_envelopes(
                &dir.join(external_signing::EXTERNAL_SIGNING_ENVELOPES_FILE),
            )
            .unwrap_or_default();
            *self.external_validator_report_metadata.write().await =
                external_validator_evidence::load_external_validator_report_metadata(
                    &dir.join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR),
                );
            self.api_key_rate_limits.write().await.clear();
            self.rate_limit_buckets.write().await.clear();
            self.sessions.write().await.clear();
            self.session_issued_at.write().await.clear();
            self.attestations.write().await.clear();
            *self.cae.write().await = chancela_cae::load_catalog(Some(&dir));
            *self.law_store.write().await = law::load_law_store(&dir.join(law::LAWS_DIR));
        }
        Ok(())
    }

    /// Clear the in-memory domain read-models (entities / books / acts / registry extracts /
    /// documents) to match a `BackendDomain` wipe or a whole-instance start-over (the ledger is
    /// preserved / re-seeded by the store, never touched here).
    pub(crate) async fn clear_domain_memory(&self) {
        self.entities.write().await.clear();
        self.books.write().await.clear();
        self.acts.write().await.clear();
        self.follow_ups.write().await.clear();
        self.registry_extracts.write().await.clear();
        self.registry_auto_updates.write().await.clear();
        self.documents.write().await.clear();
        self.signed_documents.write().await.clear();
        self.pending_signatures.write().await.clear();
        self.external_signer_invites.write().await.clear();
        self.external_signing_envelopes.write().await.clear();
    }

    /// Clear ALL in-memory state to a blank first-run instance, to match a `BackendFactory` reset
    /// (which also blanked the ledger + removed the sidecar files on disk): the domain read-models,
    /// the user profiles, every live session + unlocked key, the attestation sidecar, and the
    /// settings document (reset to defaults). The acting session is invalidated by design.
    pub(crate) async fn clear_all_memory(&self) {
        self.clear_domain_memory().await;
        self.users.write().await.clear();
        self.dsr_requests.write().await.clear();
        self.processor_records.write().await.clear();
        self.dpia_records.write().await.clear();
        self.retention_policies.write().await.clear();
        self.retention_execution_records.write().await.clear();
        self.retention_candidate_resolutions.write().await.clear();
        self.backup_recovery_drill_receipts.write().await.clear();
        self.notification_triage.write().await.clear();
        self.sessions.write().await.clear();
        self.session_issued_at.write().await.clear();
        self.attestations.write().await.clear();
        self.api_keys.write().await.clear();
        self.external_signing_envelopes.write().await.clear();
        self.external_validator_report_metadata
            .write()
            .await
            .clear();
        self.api_key_rate_limits.write().await.clear();
        self.rate_limit_buckets.write().await.clear();
        self.platform_logs.write().await.clear();
        // A blank first-run instance has the seeded default roles and no delegations (t64), matching
        // what a subsequent load of the wiped data dir would reseed.
        *self.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        self.delegations.write().await.clear();
        *self.verifier_seed.write().await = attestation::VerifierSeed::default();
        *self.settings.write().await = settings::Settings::default();
    }

    /// Resolve on-disk persistence from the environment, mirroring how `chancela-server` finds
    /// the web build: honour `CHANCELA_DATA_DIR` first, else walk up from the current directory
    /// for an existing `chancela-data/` directory, else run purely in memory.
    ///
    /// This is the one call a binary swaps in for [`AppState::default`] to gain persistence.
    pub fn from_env() -> Self {
        Self::try_from_env()
            .unwrap_or_else(|e| panic!("invalid Chancela startup configuration: {e}"))
    }

    /// Build state from process environment, including optional database encryption settings.
    ///
    /// `CHANCELA_DB_KEY` and `CHANCELA_DB_KEY_FILE` are fail-closed: invalid, ambiguous, empty, or
    /// unsupported encrypted-store configuration returns an error instead of silently running
    /// plaintext or in-memory.
    pub fn try_from_env() -> Result<Self, AppStateInitError> {
        let database_encryption = DatabaseEncryptionConfig::from_env()?;
        let mut state = match Self::resolve_data_dir() {
            Some(dir) => Self::try_with_data_dir(dir, database_encryption)?,
            // Pure in-memory (no data dir): seed the RBAC catalog so the bootstrap first user's
            // Owner\@Global assignment resolves to real authority. Without this a fresh in-memory
            // instance would hold an Owner assignment against an EMPTY catalog (fail-closed →
            // no permissions anywhere), locking the operator out of their own instance (t64-E3).
            None => {
                if database_encryption.is_configured() {
                    return Err(AppStateInitError::DatabaseEncryptionRequiresDataDir);
                }
                let base = Self::default();
                let seeded = Arc::new(RwLock::new(chancela_authz::RoleCatalog::seeded_defaults()));
                AppState {
                    roles: seeded,
                    // Honour the CC co-location signal even in the pure in-memory desktop dev path.
                    local_signing: signature::local_signing_from_env(),
                    // Resolve CSC providers from the environment (t59-s3) even in-memory.
                    csc_providers: Arc::new(signature::load_csc_providers_from_env()),
                    paper_book_ocr_command: paper_import::PaperBookOcrCommandConfig::from_env()
                        .map(Arc::new),
                    ..base
                }
            }
        };
        // wp25-sec — security-hardening posture resolved from the environment for the *running*
        // server only, so the test/embedding constructors (`default`/`with_data_dir`) stay inert:
        // the per-IP rate limiter is ON by default here, and the absolute session cap is applied.
        state.rate_limit = rate_limit_config_from_env();
        state.session_max_lifetime = session_max_lifetime_from_env();
        Ok(state)
    }

    /// The data directory `from_env` would use, or `None` for in-memory. Exposed so a binary can
    /// report the resolved path in its startup banner.
    pub fn resolve_data_dir() -> Option<PathBuf> {
        if let Ok(raw) = std::env::var(DATA_DIR_ENV) {
            if !raw.trim().is_empty() {
                return Some(PathBuf::from(raw));
            }
        }
        let start = std::env::current_dir().ok()?;
        for base in start.ancestors() {
            let candidate = base.join("chancela-data");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(feature = "sqlcipher")]
fn ensure_sqlcipher_feature_available() -> Result<(), AppStateInitError> {
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
fn ensure_sqlcipher_feature_available() -> Result<(), AppStateInitError> {
    Err(AppStateInitError::SqlcipherFeatureUnavailable)
}

/// Build the API router over the supplied [`AppState`].
///
/// The returned router carries `/health`, the observability probes (`/metrics`, `/livez`, `/readyz`),
/// the canonical `/v1/*` endpoints, and the integration alias `/api/*`. Use [`app`] to also serve the
/// web UI. The router is fully wired and can be served by a listener or exercised in tests via
/// `tower::ServiceExt::oneshot`.
pub fn router(state: AppState) -> Router {
    // wp25 observability: install the process-wide Prometheus recorder once (idempotent) so the
    // per-request metrics middleware records into a live recorder from the first request.
    observability::install_recorder();
    let api = Router::new()
        .route("/health", get(health))
        // wp25 observability probes. `/metrics` = Prometheus exposition; `/livez` = cheap liveness
        // (always 200 while the process runs); `/readyz` = narrow degraded-mode readiness (503 in
        // degraded read-only mode, not a full dependency probe). All three are unauthenticated like
        // `/health` (classified `Exempt` in `authz::ROUTE_CLASSIFICATION`); scrape `/metrics` only on
        // the internal network / behind an allowlist. The outer router also exposes these under the
        // `/api/*` integration alias.
        .route("/metrics", get(observability::metrics_endpoint))
        .route("/livez", get(observability::livez))
        .route("/readyz", get(observability::readyz))
        .route(
            "/v1/entities",
            get(entities::list_entities).post(entities::create_entity),
        )
        .route(
            "/v1/entities/{id}",
            get(entities::get_entity).patch(entities::patch_entity),
        )
        .route(
            "/v1/entities/import-from-registry",
            post(registry::import_from_registry),
        )
        .route(
            "/v1/entities/{id}/registry",
            get(registry::get_entity_registry).post(registry::request_registry_auto_update),
        )
        .route(
            "/v1/entities/{id}/registry/import",
            post(registry::import_into_entity),
        )
        .route(
            "/v1/entities/{id}/chronology",
            get(chronology::get_entity_chronology),
        )
        .route(
            "/v1/registry/lookup",
            get(registry::registry_auto_update_due_plan).post(registry::registry_lookup),
        )
        .route("/v1/books", get(books::list_books).post(books::create_book))
        .route("/v1/books/{id}", get(books::get_book))
        .route("/v1/books/{id}/close", post(books::close_book))
        .route("/v1/books/{id}/acts", get(books::list_book_acts))
        .route(
            "/v1/books/paper-import/validate",
            post(paper_import::validate_paper_book_import),
        )
        .route(
            "/v1/books/paper-import",
            get(paper_import::list_paper_book_imports).post(
                post(paper_import::preserve_paper_book_import).layer(DefaultBodyLimit::max(
                    paper_import::PAPER_BOOK_IMPORT_ENVELOPE_BYTES,
                )),
            ),
        )
        .route(
            "/v1/books/paper-import/{id}",
            get(paper_import::get_paper_book_import),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr/enqueue",
            post(paper_import::enqueue_paper_book_import_ocr),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-status",
            patch(paper_import::update_paper_book_import_ocr_status),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr/run",
            post(paper_import::run_paper_book_import_ocr),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-drafts",
            get(paper_import::list_paper_book_import_ocr_drafts)
                .post(paper_import::create_paper_book_import_ocr_draft),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/review",
            patch(paper_import::review_paper_book_import_ocr_draft),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft",
            post(paper_import::create_act_draft_from_accepted_paper_book_ocr_draft),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier",
            post(paper_import::create_paper_book_ocr_conversion_dossier),
        )
        .route(
            "/v1/books/paper-import/{id}/conversion-dossiers",
            get(paper_import::list_paper_book_ocr_conversion_dossiers),
        )
        .route(
            "/v1/books/paper-import/{id}/ocr-canonical-rehearsal",
            get(paper_import::get_paper_book_ocr_canonical_rehearsal),
        )
        .route(
            "/v1/books/paper-import/{id}/bytes",
            get(paper_import::get_paper_book_import_bytes),
        )
        .route(
            "/v1/books/{id}/legal-hold",
            get(books::get_legal_hold)
                .put(books::set_legal_hold)
                .delete(books::clear_legal_hold),
        )
        .route(
            "/v1/books/{id}/archive/package",
            get(archive_package::export_book_archive_package),
        )
        .route(
            "/v1/books/{id}/archive/local-dglab-interchange-manifest",
            get(archive_package::get_book_local_dglab_interchange_manifest),
        )
        .route(
            "/v1/books/{id}/archive/disposal",
            get(archive_package::get_book_disposal_status)
                .post(archive_package::simulate_book_disposal),
        )
        .route("/v1/acts", post(acts::draft_act))
        .route("/v1/acts/{id}", get(acts::get_act).patch(acts::patch_act))
        .route("/v1/acts/{id}/advance", post(acts::advance_act))
        .route(
            "/v1/acts/{id}/human-verification",
            post(acts::verify_ai_human_review),
        )
        .route("/v1/acts/{id}/compliance", get(acts::get_compliance))
        .route("/v1/acts/{id}/seal", post(acts::seal_act_handler))
        .route("/v1/acts/{id}/archive", post(acts::archive_act))
        .route(
            "/v1/acts/{id}/follow-ups",
            get(followups::list_follow_ups).post(followups::create_follow_up),
        )
        .route("/v1/follow-ups/{id}", patch(followups::patch_follow_up))
        .route(
            "/v1/follow-ups/{id}/complete",
            post(followups::complete_follow_up),
        )
        .route(
            "/v1/acts/{id}/convening/dispatch",
            post(acts::convening_dispatch),
        )
        .route(
            "/v1/acts/{id}/document/preview",
            get(documents::preview_document),
        )
        .route(
            "/v1/acts/{id}/document/generate",
            post(documents::generate_document),
        )
        .route(
            "/v1/acts/{act_id}/documents/generated",
            get(documents::list_generated_documents_for_act),
        )
        .route(
            "/v1/documents/generated/{document_id}",
            get(documents::get_generated_document_pdf),
        )
        .route(
            "/v1/documents/generated/{document_id}/dispatch-evidence",
            get(documents::get_generated_document_dispatch_evidence)
                .post(documents::record_generated_document_dispatch_evidence),
        )
        .route(
            "/v1/acts/{id}/document/working-copy",
            get(documents::export_working_copy),
        )
        .route(
            "/v1/acts/{id}/document/office",
            get(documents::export_office_document),
        )
        .route("/v1/acts/{id}/document", get(documents::get_document_pdf))
        .route(
            "/v1/acts/{id}/document/bundle",
            get(documents::get_document_bundle),
        )
        .route(
            "/v1/documents/import",
            post(documents::import_document).layer(DefaultBodyLimit::max(
                documents::DOCUMENT_IMPORT_VALIDATION_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/documents/imported",
            get(documents::list_imported_documents),
        )
        .route(
            "/v1/documents/imported/{id}",
            get(documents::get_imported_document),
        )
        .route(
            "/v1/documents/imported/{id}/review",
            patch(documents::review_imported_document),
        )
        .route(
            "/v1/documents/imported/{id}/bytes",
            get(documents::get_imported_document_bytes),
        )
        .route(
            "/v1/documents/import/validate",
            post(documents::validate_document_import).layer(DefaultBodyLimit::max(
                documents::DOCUMENT_IMPORT_VALIDATION_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/external-validator-reports",
            get(external_validator_evidence::list_external_validator_report_metadata).post(
                post(external_validator_evidence::create_external_validator_report_metadata).layer(
                    DefaultBodyLimit::max(
                        external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_UPLOAD_MAX_BYTES,
                    ),
                ),
            ),
        )
        .route(
            "/v1/external-validator-reports/{case_id}/{validator_family}",
            get(external_validator_evidence::download_external_validator_report_metadata),
        )
        .route(
            "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report",
            get(external_validator_evidence::download_external_validator_raw_report_bytes),
        )
        .route(
            "/v1/signature/pdf/validate",
            post(pdf_signature_validation::validate_pdf_signature).layer(DefaultBodyLimit::max(
                pdf_signature_validation::PDF_SIGNATURE_VALIDATION_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/signature/asic/inspect",
            post(asic_signature_validation::inspect_asic_signature).layer(DefaultBodyLimit::max(
                asic_signature_validation::ASIC_SIGNATURE_INSPECTION_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/signature/xades/sign",
            post(xades_signature::sign_xades).layer(DefaultBodyLimit::max(
                xades_signature::XADES_REQUEST_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/signature/xades/validate",
            post(xades_signature::validate_xades_document).layer(DefaultBodyLimit::max(
                xades_signature::XADES_REQUEST_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/signature/asic/sign",
            post(asic_signing::sign_asic).layer(DefaultBodyLimit::max(
                asic_signing::ASIC_SIGN_ENVELOPE_BYTES,
            )),
        )
        .route("/v1/scap/providers", post(scap::list_providers))
        .route("/v1/scap/attributes", post(scap::fetch_attributes))
        .route(
            "/v1/scap/sign",
            post(scap::sign_with_attribute)
                .layer(DefaultBodyLimit::max(scap::SCAP_SIGN_ENVELOPE_BYTES)),
        )
        .route(
            "/v1/acts/{id}/signature/cmd/initiate",
            post(signature::initiate_cmd_signature),
        )
        .route(
            "/v1/acts/{id}/signature/cmd/confirm",
            post(signature::confirm_cmd_signature),
        )
        .route(
            "/v1/acts/{id}/signature/cc/sign",
            post(signature::sign_cc_signature),
        )
        .route(
            "/v1/signature/cc/batch-sign",
            post(batch_signing::sign_cc_batch),
        )
        .route(
            "/v1/acts/{id}/signature/dss/attach",
            post(signature::attach_dss_evidence)
                .layer(DefaultBodyLimit::max(signature::DSS_ATTACH_ENVELOPE_BYTES)),
        )
        .route(
            "/v1/acts/{id}/signature/dss/collect-revocation",
            post(signature::collect_revocation_evidence)
                .layer(DefaultBodyLimit::max(signature::DSS_ATTACH_ENVELOPE_BYTES)),
        )
        .route(
            "/v1/acts/{id}/signature/archive-timestamp/append",
            post(signature::append_archive_timestamp).layer(DefaultBodyLimit::max(
                signature::ARCHIVE_TIMESTAMP_APPEND_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/acts/{id}/signature/ltv/execute",
            post(ltv::execute_ltv).layer(DefaultBodyLimit::max(ltv::LTV_REQUEST_ENVELOPE_BYTES)),
        )
        .route(
            "/v1/acts/{id}/signature/ltv/renew",
            post(ltv::renew_ltv).layer(DefaultBodyLimit::max(ltv::LTV_REQUEST_ENVELOPE_BYTES)),
        )
        .route(
            "/v1/acts/{id}/signature/remote/{provider}/initiate",
            post(signature::initiate_remote_signature),
        )
        .route(
            "/v1/signature/remote/{provider}/batch-initiate",
            post(signature::initiate_remote_batch_signature),
        )
        .route(
            "/v1/acts/{id}/signature/remote/{provider}/confirm",
            post(signature::confirm_remote_signature),
        )
        .route(
            "/v1/acts/{id}/signature/official/import",
            post(signature::import_official_signature).layer(DefaultBodyLimit::max(
                signature::OFFICIAL_SIGNATURE_IMPORT_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/acts/{id}/signature/local/pkcs12/sign",
            post(signature::sign_local_pkcs12_signature).layer(DefaultBodyLimit::max(
                signature::LOCAL_PKCS12_SIGN_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/acts/{id}/signature/local/pkcs12/sign-stored",
            post(signature_pkcs12_stored::sign_local_pkcs12_stored_signature),
        )
        .route(
            "/v1/acts/{id}/signature/external-invites",
            get(signature::list_external_signer_invites)
                .post(signature::create_external_signer_invite),
        )
        .route(
            "/v1/acts/{id}/signature/external-invites/{invite_id}/revoke",
            post(signature::revoke_external_signer_invite),
        )
        .route(
            "/v1/acts/{id}/external-signing/envelopes",
            get(external_signing::list_envelopes_for_act).post(external_signing::create_envelope),
        )
        .route(
            "/v1/external-signing/envelopes/{id}",
            get(external_signing::get_envelope).patch(external_signing::patch_envelope),
        )
        .route(
            "/v1/signature/external-invites/lookup",
            post(signature::lookup_external_signer_invite),
        )
        .route(
            "/v1/signature/external-invites/document/working-copy",
            post(signature::download_external_signer_invite_working_copy),
        )
        .route(
            "/v1/signature/external-invites/respond",
            post(signature::respond_external_signer_invite).layer(DefaultBodyLimit::max(
                signature::OFFICIAL_SIGNATURE_IMPORT_ENVELOPE_BYTES,
            )),
        )
        .route(
            "/v1/signature/providers",
            get(signature::list_signature_providers),
        )
        .route(
            "/v1/signature/provider-credentials/status",
            get(provider_credentials::provider_credential_status),
        )
        .route(
            "/v1/signature/provider-credentials",
            get(provider_credentials_write::list_provider_credentials),
        )
        .route(
            "/v1/signature/provider-credentials/{mode}/{provider_id}/entries",
            post(provider_credentials_write::create_entry),
        )
        .route(
            "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/reorder",
            post(provider_credentials_write::reorder_entries),
        )
        .route(
            "/v1/signature/provider-credentials/{mode}/{provider_id}/entries/{entry_id}",
            patch(provider_credentials_write::update_entry)
                .delete(provider_credentials_write::delete_entry),
        )
        .route(
            "/v1/acts/{id}/signature",
            get(signature::get_signature_status),
        )
        .route(
            "/v1/acts/{id}/document/signed",
            get(signature::get_signed_document_pdf),
        )
        .route(
            "/v1/templates",
            get(documents::list_templates).post(documents::create_template),
        )
        .route(
            "/v1/templates/{id}",
            put(documents::replace_template).delete(documents::delete_template),
        )
        .route("/v1/templates/{id}/export", get(documents::export_template))
        .route("/v1/templates/import", post(documents::import_template))
        .route("/v1/ledger/events", get(ledger::list_ledger_events))
        .route(
            "/v1/ledger/events/page",
            get(ledger::list_ledger_events_page),
        )
        .route(
            "/v1/ledger/archive/document",
            get(arquivo::export_archive_document),
        )
        .route("/v1/ledger/verify", get(ledger::verify_ledger))
        .route("/v1/ledger/integrity", get(recovery::get_integrity))
        .route(
            "/v1/ledger/recovery/reanchor",
            post(recovery::reanchor_ledger),
        )
        .route("/v1/ledger/recovery/restore", post(recovery::restore_store))
        .route(
            "/v1/ledger/recovery/restore/preflight",
            post(recovery::restore_store_preflight),
        )
        .route(
            "/v1/backup/recovery-drills",
            get(backup_recovery::list_backup_recovery_drills)
                .post(backup_recovery::create_backup_recovery_drill),
        )
        .route(
            "/v1/sync/handoff-preflight",
            get(sync_handoff::get_sync_handoff_preflight),
        )
        .route("/v1/books/{id}/export", post(bundles::export_book))
        .route(
            "/v1/books/import/preflight",
            post(bundles::preflight_import_book)
                .layer(DefaultBodyLimit::max(bundles::BOOK_IMPORT_BUNDLE_MAX_BYTES)),
        )
        .route(
            "/v1/books/import",
            post(bundles::import_book)
                .layer(DefaultBodyLimit::max(bundles::BOOK_IMPORT_BUNDLE_MAX_BYTES)),
        )
        .route("/v1/books/{id}/start-over", post(bundles::start_over_book))
        .route("/v1/data/reset", post(data::reset_data))
        .route("/v1/data/status", get(data_status::get_data_status))
        .route("/v1/data/cleanup", post(data_status::cleanup_data))
        .route(
            "/v1/data/key-rotation",
            post(data_status::execute_data_key_rotation),
        )
        .route(
            "/v1/data/key-rotation/preflight",
            post(data_status::preflight_data_key_rotation),
        )
        .route("/v1/data/start-over", post(data::start_over_instance))
        .route("/v1/dashboard", get(dashboard::dashboard))
        .route(
            "/v1/notifications/triage",
            get(notifications::list_notification_triage),
        )
        .route(
            "/v1/notifications/triage/{id}",
            patch(notifications::patch_notification_triage),
        )
        .route("/v1/backup", post(backup::create_backup))
        .route(
            "/v1/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .route("/v1/platform/services", get(platform_ops::list_services))
        .route("/v1/platform/logs", get(platform_logs::list_logs))
        .route(
            "/v1/platform/logs/forwarded",
            post(platform_logs::ingest_forwarded_log),
        )
        .route(
            "/v1/platform/services/{id}/actions/{action}",
            post(platform_ops::control_service),
        )
        .route("/v1/cae", get(cae::list_cae))
        .route("/v1/cae/refresh", post(cae::refresh_cae))
        .route("/v1/cae/updates", get(cae::cae_updates))
        .route("/v1/cae/sections", get(cae::list_sections))
        .route("/v1/cae/{code}", get(cae::get_cae))
        .route("/v1/cae/{code}/children", get(cae::list_children))
        .route("/v1/trust/status", get(trust::trust_status))
        .route("/v1/trust/refresh", post(trust::refresh_trust_tsl))
        .route("/v1/trust/catalog", get(trust::trust_catalog))
        .route("/v1/trust/tsa", get(trust::trust_tsa))
        .route("/v1/trust/providers/{id}", get(trust::trust_provider))
        .route("/v1/trust/services/{id}", get(trust::trust_service))
        .route("/v1/law", get(law::list_law))
        .route(
            "/v1/law/citations/resolve",
            post(law::resolve_law_citations),
        )
        .route("/v1/law/corpus", get(law::list_law_corpus))
        .route("/v1/law/corpus/search", get(law::search_law_corpus))
        .route("/v1/law/corpus/{diploma}", get(law::get_law_diploma))
        .route(
            "/v1/law/corpus/{diploma}/{article}",
            get(law::get_law_article),
        )
        .route("/v1/law/{id}/fetch", post(law::fetch_law))
        .route(
            "/v1/law/{id}/pdf",
            get(law::get_law_pdf).delete(law::delete_law_pdf),
        )
        .route("/v1/users", get(users::list_users).post(users::create_user))
        .route(
            "/v1/users/{id}",
            get(users::get_user).patch(users::patch_user),
        )
        .route(
            "/v1/users/{id}/secret",
            post(users::set_secret).delete(users::remove_secret),
        )
        .route(
            "/v1/users/{id}/attestation-key",
            post(users::generate_attestation_key).delete(users::remove_attestation_key),
        )
        .route("/v1/users/{id}/recovery", post(users::issue_recovery))
        .route("/v1/privacy/users/{id}/export", get(privacy::export_user))
        .route(
            "/v1/privacy/users/{id}/dsr-requests",
            get(privacy::list_dsr_requests_for_user).post(privacy::create_dsr_request),
        )
        .route(
            "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/complete",
            post(privacy::complete_user_dsr_request),
        )
        .route(
            "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/preflight",
            post(privacy::erasure_preflight),
        )
        .route(
            "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/approve",
            post(privacy::erasure_approve),
        )
        .route(
            "/v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/execute",
            post(privacy::erasure_execute),
        )
        .route(
            "/v1/privacy/dsr-requests/{id}",
            patch(privacy::patch_dsr_request),
        )
        .route(
            "/v1/privacy/dsr-requests/{id}/complete",
            post(privacy::complete_dsr_request),
        )
        .route(
            "/v1/privacy/processors",
            get(privacy::list_processor_records).post(privacy::create_processor_record),
        )
        .route(
            "/v1/privacy/processors/{id}",
            patch(privacy::patch_processor_record),
        )
        .route("/v1/privacy/dpia-template", get(privacy::get_dpia_template))
        .route(
            "/v1/privacy/dpias",
            get(privacy::list_dpia_records).post(privacy::create_dpia_record),
        )
        .route("/v1/privacy/dpias/{id}", patch(privacy::patch_dpia_record))
        .route(
            "/v1/privacy/breach-playbooks",
            get(privacy::list_breach_playbooks).post(privacy::create_breach_playbook),
        )
        .route(
            "/v1/privacy/breach-playbooks/{id}",
            patch(privacy::patch_breach_playbook),
        )
        .route(
            "/v1/privacy/transfer-controls",
            get(privacy::list_transfer_controls).post(privacy::create_transfer_control),
        )
        .route(
            "/v1/privacy/transfer-controls/{id}",
            patch(privacy::patch_transfer_control),
        )
        .route(
            "/v1/privacy/retention-policies",
            get(privacy::list_retention_policies).post(privacy::create_retention_policy),
        )
        .route(
            "/v1/privacy/retention-policies/dry-run",
            post(privacy::retention_policy_dry_run),
        )
        .route(
            "/v1/privacy/retention-due-candidates",
            get(privacy::list_retention_due_candidates),
        )
        .route(
            "/v1/privacy/retention-due-candidates/{candidate_id}/resolution",
            post(privacy::record_retention_candidate_resolution),
        )
        .route(
            "/v1/privacy/retention-candidate-resolutions",
            get(privacy::list_retention_candidate_resolution_records),
        )
        .route(
            "/v1/privacy/retention-executions",
            get(privacy::list_retention_execution_records),
        )
        .route(
            "/v1/privacy/retention-executions/{id}/review-closure",
            post(privacy::close_retention_execution_review),
        )
        .route(
            "/v1/privacy/retention-policies/{id}",
            patch(privacy::patch_retention_policy),
        )
        .route(
            "/v1/api-keys",
            get(apikeys::list_api_keys).post(apikeys::create_api_key),
        )
        .route("/v1/api-keys/{id}", delete(apikeys::revoke_api_key))
        .route("/v1/api-keys/{id}/rotate", post(apikeys::rotate_api_key))
        .route(
            "/v1/ledger/attestations/{seq}",
            get(ledger::get_attestation),
        )
        // RBAC management (t64-E4): role CRUD, the permission catalog, scoped role assignment, and
        // scoped delegation. Mutations are gated + invariant-enforced server-side (see the handlers).
        .route("/v1/roles", get(roles::list_roles).post(roles::create_role))
        .route(
            "/v1/roles/{id}",
            patch(roles::patch_role).delete(roles::delete_role),
        )
        .route(
            "/v1/roles/{id}/seeded-drift-reconciliation",
            get(roles::seeded_role_reconciliation_proposal)
                .post(roles::apply_seeded_role_reconciliation),
        )
        .route("/v1/permissions", get(roles::list_permissions))
        .route(
            "/v1/users/{id}/roles",
            post(roles::assign_role).delete(roles::unassign_role),
        )
        .route(
            "/v1/delegations",
            get(delegations::list_delegations).post(delegations::grant_delegation),
        )
        .route(
            "/v1/delegations/{id}",
            delete(delegations::revoke_delegation),
        )
        .route("/v1/session/roster", get(session::session_roster))
        .route("/v1/session/password-policy", get(session::password_policy))
        .route("/v1/session/permissions", get(session::session_permissions))
        .route(
            "/v1/session",
            get(session::get_session)
                .post(session::create_session)
                .delete(session::delete_session),
        )
        // Own the entire `/v1` and `/health` namespaces: any unmatched path under them is a
        // JSON 404, never a fall-through. The same route table is mounted under `/api`, so these
        // catch-alls also own `/api/v1` for integration clients. Registered as low-priority
        // catch-alls (matchit ranks the specific routes above them), so a stale binary or a typo'd
        // path can never reach the SPA fallback in [`app`] and hand the web client `index.html`
        // where it expects JSON (the "Unexpected token '<'" failure). Non-API paths keep the SPA
        // fallback.
        .route("/v1", any(unknown_api_route))
        .route("/v1/{*rest}", any(unknown_api_route))
        .route("/health/{*rest}", any(unknown_api_route))
        // Credential ambiguity guard (MCP/API): a request may authenticate with either the web
        // session header or a bearer API key, never both. This sits at router level so manual
        // session-resolution endpoints are covered too.
        .layer(middleware::from_fn(reject_mixed_credentials))
        // Degraded read-only gate (t54 §3.1): block ordinary mutations with 503 when the chain is
        // broken, leaving reads + the recovery/reset/export/quarantine-import endpoints open. Layered
        // BELOW `security_headers` (added after) so a 503 still carries the security headers.
        .layer(middleware::from_fn_with_state(state.clone(), degraded_gate))
        // wp16 P2 write routing: a mutating request that lands on a cluster FOLLOWER is 307-redirected
        // (default) or reverse-proxied (opt-in) to the current leader; leader-unknown → 503+Retry-After.
        // Layered above `degraded_gate` so a follower routes to the leader before the local read-only
        // gate, and BELOW `security_headers` (added after) so the 307/503 still carries them. Inert on
        // the single-node SQLite / in-memory build (no election → always its own leader).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            cluster_route::write_redirect_gate,
        ))
        // Security response headers (t41 M2) — now including HSTS (wp25-sec).
        .layer(middleware::from_fn(security_headers))
        // wp25-sec — per-client-IP HTTP rate limiter. Placed just below `observe` (so a rejected
        // `429` is still traced + metered) and above the credential/degraded/cluster gates and the
        // handlers. The health/readiness/metrics probes are exempt. Inert unless enabled (ON for the
        // running server via `AppState::try_from_env`; OFF for the test/embedding constructors).
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        // wp25 observability — OUTERMOST layer: correlation id (`x-request-id`) + tracing span +
        // HTTP metrics (count / latency / in-flight) for every request. Added last so it wraps the
        // whole stack (a 503 from the gates below is still traced, metered, and carries the id). It
        // runs after routing, so `MatchedPath` is present for bounded-cardinality trace/metric labels
        // and raw URL paths with ids/secrets are never logged.
        .layer(middleware::from_fn(observability::observe))
        .with_state(state);

    Router::new()
        .merge(api.clone())
        .route("/api", any(unknown_api_route))
        .route("/api/", any(unknown_api_route))
        .nest("/api", api)
}

async fn reject_mixed_credentials(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let has_session = request
        .headers()
        .get(actor::SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|v| !v.is_empty());
    let bearer = apikeys::read_bearer_api_key(request.headers());
    match bearer {
        Ok(Some(_)) if has_session => {
            ApiError::Unauthorized("use sessão ou chave API, não ambas".to_owned()).into_response()
        }
        Err(e) if has_session => e.into_response(),
        _ => next.run(request).await,
    }
}

/// Whether a request is exempt from the degraded (read-only) mutation gate (t54 §3.1).
///
/// Reads (`GET`/`HEAD`/`OPTIONS`) are always allowed. Among mutations, only the **recovery** plane
/// stays reachable in a broken-chain instance — a restore / re-anchor / factory reset is the
/// legitimate last-resort repair, an export lets the operator archive first, key-rotation preflight
/// is read-only evidence gathering, a quarantine-import is isolated and never merged into a live
/// chain, and the session endpoints must work so the operator can authenticate to run any of these.
/// Every other mutation is blocked with `503` while degraded.
fn degraded_gate_exempt(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    path == "/v1/ledger/recovery/reanchor"
        || path == "/v1/ledger/recovery/restore"
        || path == "/v1/ledger/recovery/restore/preflight"
        || path == "/v1/backup/recovery-drills"
        || path == "/v1/data/reset"
        || path == "/v1/data/start-over"
        || path == "/v1/data/key-rotation/preflight"
        || path == "/v1/books/import/preflight"
        || path == "/v1/books/import"
        || path == "/v1/books/paper-import/validate"
        || path.starts_with("/v1/session")
        || (path.starts_with("/v1/books/") && path.ends_with("/export"))
        || (path.starts_with("/v1/books/") && path.ends_with("/archive/disposal"))
}

/// Middleware enforcing the degraded read-only gate. When [`AppState::degraded`] is set, an ordinary
/// mutation (not [`degraded_gate_exempt`]) is refused with a **loud** honest-PT `503` naming the
/// read-only mode; reads and the recovery/reset endpoints pass through unchanged.
async fn degraded_gate(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !degraded_gate_exempt(request.method(), request.uri().path()) && *state.degraded.read().await
    {
        let body = serde_json::json!({
            "error": "sistema em modo só-leitura: a cadeia de integridade está quebrada. \
                      Restaure a partir de uma cópia de segurança, faça a re-ancoragem, ou uma \
                      reposição de fábrica antes de continuar a escrever.",
            "read_only": true,
            "integrity": "broken",
        });
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
    }
    next.run(request).await
}

/// Recompute the degraded (read-only) signal from a ledger's live integrity report and store it on
/// `state` (t54 §3.1). Called after a recovery op (restore / re-anchor / factory reset) so a repaired
/// chain lifts the gate — and a still-broken one keeps it. Runs a full `integrity_report()`; it is
/// only invoked on the rare recovery paths, never on the hot mutation path.
pub(crate) async fn refresh_degraded(state: &AppState, ledger: &Ledger) {
    let healthy = ledger.integrity_report().healthy;
    *state.degraded.write().await = !healthy;
}

/// Route a user-driven ledger append through the validating [`Ledger::try_append`] (t54 deliverable
/// #6): an append that would break a chain (wrong genesis kind, or onto a broken tail) is rejected
/// **before** the ledger is mutated, so nothing is persisted and the surrounding transaction is safe
/// to abort. Replaces the infallible `append` on the api's domain mutation paths.
pub(crate) fn try_append_event(
    ledger: &mut Ledger,
    actor: &str,
    scope: &str,
    kind: &str,
    justification: Option<&str>,
    payload: &[u8],
) -> Result<(), ApiError> {
    ledger
        .try_append(actor, scope, kind, justification, payload)
        .map(|_| ())
        .map_err(|e| ApiError::Conflict(format!("appending {kind} would break a chain: {e}")))
}

/// Middleware that sets security response headers on every response (t41 M2).
async fn security_headers(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(
        axum::http::HeaderName::from_static("referrer-policy"),
        "no-referrer".parse().unwrap(),
    );
    headers.insert(
        axum::http::HeaderName::from_static("content-security-policy"),
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
         script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    // Strict-Transport-Security (wp25-sec). HSTS only takes effect over HTTPS — TLS is terminated at
    // the reverse proxy in front of the server, and browsers ignore this header on plain HTTP — so
    // emitting it unconditionally is safe and lets a TLS-fronted deployment pin HTTPS with no
    // per-request configuration. The value (max-age / includeSubDomains / preload) is resolved once
    // from the environment; see [`hsts_header_value`].
    headers.insert(
        axum::http::HeaderName::from_static("strict-transport-security"),
        axum::http::HeaderValue::from_static(hsts_header_value()),
    );
    response
}

// ── wp25-sec: security-hardening configuration + middleware ──────────────────────────────────────

/// Env var overriding the absolute session lifetime cap, in whole seconds. Default 7 days; a
/// non-positive value disables the cap (sessions then rely on the 24h idle/sliding expiry alone).
pub const SESSION_MAX_LIFETIME_ENV: &str = "CHANCELA_SESSION_MAX_LIFETIME";
/// Default absolute session lifetime cap: 7 days.
pub const DEFAULT_SESSION_MAX_LIFETIME_SECS: i64 = 7 * 24 * 60 * 60;

/// Env var setting the HSTS `max-age` (seconds). Default [`DEFAULT_HSTS_MAX_AGE_SECS`].
pub const HSTS_MAX_AGE_ENV: &str = "CHANCELA_HSTS_MAX_AGE";
/// Env var toggling the HSTS `includeSubDomains` directive. Default on.
pub const HSTS_INCLUDE_SUBDOMAINS_ENV: &str = "CHANCELA_HSTS_INCLUDE_SUBDOMAINS";
/// Env var toggling the HSTS `preload` directive. Default off (opt in only once the domain is
/// actually submitted to the browser preload list).
pub const HSTS_PRELOAD_ENV: &str = "CHANCELA_HSTS_PRELOAD";
/// Default HSTS `max-age`: two years, the common preload-eligible baseline.
pub const DEFAULT_HSTS_MAX_AGE_SECS: u64 = 63_072_000;

/// Env var toggling the per-IP HTTP rate limiter. Default ON for the running server.
pub const RATE_LIMIT_ENABLED_ENV: &str = "CHANCELA_RATE_LIMIT_ENABLED";
/// Env var setting the sustained per-IP request rate (requests per second).
pub const RATE_LIMIT_PER_SECOND_ENV: &str = "CHANCELA_RATE_LIMIT_PER_SECOND";
/// Env var setting the per-IP burst allowance (bucket capacity).
pub const RATE_LIMIT_BURST_ENV: &str = "CHANCELA_RATE_LIMIT_BURST";
/// Env var enabling trust of `X-Forwarded-For` / `X-Real-IP` for the client IP. Default OFF
/// (spoofable unless the server sits behind a trusted reverse proxy).
pub const RATE_LIMIT_TRUST_FORWARDED_ENV: &str = "CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR";
const DEFAULT_RATE_LIMIT_PER_SECOND: f64 = 50.0;
const DEFAULT_RATE_LIMIT_BURST: f64 = 100.0;

/// Parse a boolean-ish env var (`1/true/yes/on` vs `0/false/no/off`), falling back to `default`
/// when unset or unrecognised.
fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

/// The absolute session lifetime cap resolved from the environment (default 7 days).
fn session_max_lifetime_from_env() -> SessionMaxLifetime {
    match std::env::var(SESSION_MAX_LIFETIME_ENV) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(secs) => SessionMaxLifetime(secs),
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    "{SESSION_MAX_LIFETIME_ENV} is not an integer number of seconds; using default"
                );
                SessionMaxLifetime::default()
            }
        },
        Err(_) => SessionMaxLifetime::default(),
    }
}

/// The `Strict-Transport-Security` header value, resolved once from the environment.
///
/// `max-age` defaults to two years; `includeSubDomains` is on by default; `preload` is off by
/// default. Setting `CHANCELA_HSTS_MAX_AGE=0` emits `max-age=0`, which tells browsers to forget the
/// policy. Cached in a `OnceLock` so it is computed once and the header can be a `&'static str`.
fn hsts_header_value() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            let max_age = std::env::var(HSTS_MAX_AGE_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(DEFAULT_HSTS_MAX_AGE_SECS);
            let mut value = format!("max-age={max_age}");
            if env_flag(HSTS_INCLUDE_SUBDOMAINS_ENV, true) {
                value.push_str("; includeSubDomains");
            }
            if env_flag(HSTS_PRELOAD_ENV, false) {
                value.push_str("; preload");
            }
            value
        })
        .as_str()
}

/// Absolute upper bound on how long a single session may live regardless of sliding renewals
/// (wp25-sec). `Default` is [`DEFAULT_SESSION_MAX_LIFETIME_SECS`] (7 days); the running server
/// overrides it from [`SESSION_MAX_LIFETIME_ENV`] in [`AppState::try_from_env`].
#[derive(Clone, Copy, Debug)]
pub struct SessionMaxLifetime(pub i64);

impl Default for SessionMaxLifetime {
    fn default() -> Self {
        Self(DEFAULT_SESSION_MAX_LIFETIME_SECS)
    }
}

/// Per-client-IP HTTP rate-limit policy (wp25-sec). `Default` is **disabled** (test/embedding
/// posture); the running server enables it with sane defaults via [`AppState::try_from_env`].
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Whether limiting is active at all.
    pub enabled: bool,
    /// Sustained refill rate, in requests per second per IP.
    pub per_second: f64,
    /// Burst capacity (bucket size) per IP.
    pub burst: f64,
    /// Whether to trust `X-Forwarded-For` / `X-Real-IP` for the client IP. OFF by default: only a
    /// deployment actually behind a trusted reverse proxy should enable it, since these headers are
    /// client-spoofable when the server is directly reachable.
    pub trust_forwarded_for: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            per_second: DEFAULT_RATE_LIMIT_PER_SECOND,
            burst: DEFAULT_RATE_LIMIT_BURST,
            trust_forwarded_for: false,
        }
    }
}

/// The rate-limit policy resolved from the environment for the running server (limiter ON unless
/// `CHANCELA_RATE_LIMIT_ENABLED` says otherwise).
fn rate_limit_config_from_env() -> RateLimitConfig {
    let defaults = RateLimitConfig::default();
    RateLimitConfig {
        enabled: env_flag(RATE_LIMIT_ENABLED_ENV, true),
        per_second: std::env::var(RATE_LIMIT_PER_SECOND_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .unwrap_or(defaults.per_second),
        burst: std::env::var(RATE_LIMIT_BURST_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 1.0)
            .unwrap_or(defaults.burst),
        trust_forwarded_for: env_flag(RATE_LIMIT_TRUST_FORWARDED_ENV, false),
    }
}

/// A single client IP's token bucket (wp25-sec): refills at `per_second`, capped at `burst`.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last_refill: now,
        }
    }

    fn refill(&mut self, per_second: f64, burst: f64, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * per_second).min(burst);
            self.last_refill = now;
        }
    }

    /// Consume one token; returns `true` if the request is allowed.
    fn try_take(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whole seconds until at least one token is available again (for `Retry-After`).
    fn retry_after_secs(&self, per_second: f64) -> u64 {
        if per_second <= 0.0 {
            return 1;
        }
        let deficit = (1.0 - self.tokens).max(0.0);
        ((deficit / per_second).ceil() as u64).max(1)
    }
}

/// Paths always exempt from rate limiting: the liveness/readiness/metrics probes (and their `/api`
/// aliases) must answer even under load so an orchestrator never kills a busy-but-healthy node.
fn rate_limit_exempt(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/livez"
            | "/readyz"
            | "/metrics"
            | "/api/health"
            | "/api/livez"
            | "/api/readyz"
            | "/api/metrics"
    )
}

/// Resolve the client IP for rate limiting. When `trust_forwarded_for` is set (deployment behind a
/// trusted reverse proxy), prefer `X-Real-IP` then the left-most `X-Forwarded-For` entry; otherwise
/// use the TCP peer address ([`ConnectInfo`], populated by the server's
/// `into_make_service_with_connect_info`). Falls back to the unspecified address (one shared bucket)
/// when no source is available — e.g. in-process tests without connect info.
fn rate_limit_client_ip(
    request: &axum::http::Request<axum::body::Body>,
    trust_forwarded_for: bool,
) -> IpAddr {
    if trust_forwarded_for {
        if let Some(ip) = forwarded_client_ip(request.headers()) {
            return ip;
        }
    }
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Extract a client IP from the proxy forwarding headers (`X-Real-IP`, then the left-most
/// `X-Forwarded-For` entry). Only consulted when the proxy is explicitly trusted.
fn forwarded_client_ip(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?;
    forwarded.split(',').next()?.trim().parse::<IpAddr>().ok()
}

/// Per-client-IP HTTP rate-limit middleware (wp25-sec). Exempts the health/readiness/metrics probes;
/// otherwise debits the client IP's token bucket and returns `429 Too Many Requests` with a
/// `Retry-After` header once the IP outruns its configured rate + burst. In-memory + single-node;
/// cluster-wide limiting would need a shared store (Redis) — a documented follow-up.
async fn rate_limit(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let config = state.rate_limit.clone();
    if !config.enabled || rate_limit_exempt(request.uri().path()) {
        return next.run(request).await;
    }
    let ip = rate_limit_client_ip(&request, config.trust_forwarded_for);
    let retry_after = {
        let now = Instant::now();
        let mut buckets = state.rate_limit_buckets.write().await;
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(config.burst, now));
        bucket.refill(config.per_second, config.burst, now);
        if bucket.try_take() {
            None
        } else {
            Some(bucket.retry_after_secs(config.per_second))
        }
    };
    match retry_after {
        None => next.run(request).await,
        Some(secs) => too_many_requests(secs),
    }
}

/// Build the `429 Too Many Requests` response with a `Retry-After` (delta-seconds).
fn too_many_requests(retry_after_secs: u64) -> Response {
    let body = serde_json::json!({
        "error": "demasiados pedidos: limite de taxa excedido; tente novamente dentro de instantes",
        "rate_limited": true,
    });
    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(retry_after_secs.max(1)),
    );
    response
}

/// Fallback for any unmatched path under an API namespace (`/v1`, `/v1/*`, `/api/v1/*`,
/// `/health/*`).
///
/// Returns `404 {"error": "unknown API route: <method> <path>"}` so a client that reached a
/// route the running binary does not serve — e.g. a UI newer than a stale server — gets a
/// diagnosable JSON error instead of the single-page-app shell (see [`app`]).
async fn unknown_api_route(
    method: axum::http::Method,
    OriginalUri(original_uri): OriginalUri,
) -> Response {
    let body = serde_json::json!({
        "error": format!("unknown API route: {} {}", method, original_uri.path()),
    });
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}

/// Build the full application router: the [`router`] API plus, optionally, the web UI.
///
/// The API routes always take priority. When `web_dist` is `Some(dir)`, everything else is
/// served from that directory as a single-page app — files resolve to their contents and any
/// unmatched, non-API path falls back to `index.html` so client-side routing works. When it
/// is `None`, the server runs API-only and unmatched paths get a short landing message
/// explaining how to build the UI (see [`landing`]).
pub fn app(state: AppState, web_dist: Option<PathBuf>) -> Router {
    // wp16 P0: mount the cluster leader-election supervisor (promotion poll + heartbeat + step-down).
    // Inert unless the durable backend is an electing one (Postgres); the default SQLite / in-memory
    // build spawns nothing. Spawned here (inside the server's tokio runtime) so the bounded advisory
    // lock polling loop is active when the Postgres backend is selected.
    cluster::spawn_cluster_supervisor(state.clone());
    // wp16 P1: mount the follower change-feed (LISTEN/NOTIFY + seq-poll → fail-closed incremental
    // delta apply). Inert unless the backend is an electing one (Postgres); no-op on SQLite/in-memory.
    cluster_feed::spawn_cluster_feed(state.clone());
    // wp16 P3a: subscribe to the cross-node session/role invalidation channel so a revoke / role
    // change on another node evicts this node's local session copy + permission-shaped caches. Inert
    // unless a Redis invalidation bus is active (redis feature + REDIS_URL); single-node spawns nothing.
    cluster_shared_state::spawn_invalidation_listener(state.clone());
    // wp16 P4: mount the leader self-fence watchdog (deadline-bounded periodic lock+epoch re-verify →
    // proactive fail-closed step-down of a partitioned / wedged leader). Inert unless the backend is an
    // electing one (Postgres); no-op on SQLite / in-memory.
    cluster_watchdog::spawn_leader_watchdog(state.clone());
    let api = router(state);
    let app = match web_dist {
        Some(dir) => {
            // ServeDir handles real files; its own fallback returns index.html for anything
            // it can't find, which is exactly SPA deep-link behaviour.
            let serve = ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")));
            api.fallback_service(serve)
        }
        None => api.fallback(landing),
    };
    app.layer(middleware::from_fn(security_headers))
}

/// API-only fallback served at `/` (and any unmatched path) when no web build is present.
///
/// Plain text so it reads cleanly in a browser and in `curl`; it points the operator at the
/// one command needed to get the UI, and lists the live API endpoints so the server is still
/// self-describing without a UI.
async fn landing() -> Response {
    let body = concat!(
        "Chancela API is running (web UI not built).\n",
        "\n",
        "To serve the web interface, build it once:\n",
        "    npm run build --workspace apps/web\n",
        "then restart the server.\n",
        "\n",
        "Available API endpoints:\n",
        "    GET  /health\n",
        "    GET  /v1/entities\n",
        "    POST /v1/entities\n",
        "    GET  /v1/entities/{id}\n",
        "    GET  /v1/books\n",
        "    POST /v1/books\n",
        "    GET  /v1/acts/{id}\n",
        "    POST /v1/acts\n",
        "    GET  /v1/ledger/events\n",
        "    GET  /v1/ledger/verify\n",
        "    GET  /v1/dashboard\n",
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Body of `GET /health`. The `persistent`/`ledger_*`/`store_schema_version` fields are additive
/// (t30 §3.3): older clients and the web version-check tolerate the extra keys.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    /// Whether the server is backed by the durable on-disk store (t30). `false` = in-memory.
    persistent: bool,
    /// Number of events currently in the ledger.
    ledger_length: u64,
    /// The boot-time chain-verification outcome: `true`/`false` when persistent (the durable chain
    /// was verified as it loaded), `null` in-memory (nothing was loaded to verify). Gives the web a
    /// signal for a future "chain verified / BROKEN — restore" banner.
    ledger_verified: Option<bool>,
    /// The store schema version, present only when persistent.
    #[serde(skip_serializing_if = "Option::is_none")]
    store_schema_version: Option<i64>,
    /// The live integrity signal (t54 §3.1): `"broken"` when the instance is in degraded read-only
    /// mode (a broken chain — mutations are gated with `503`), else `"ok"`. The web reads this to
    /// raise the server-driven degraded banner.
    integrity: &'static str,
    /// Whether the instance is in degraded read-only mode (mirrors `integrity == "broken"`).
    degraded: bool,
    /// wp16 P1 — cluster role + covered-feed lag, present only on an electing (Postgres) cluster
    /// node. The nested payload names its narrow read-model scope; it is not an all-sidecar
    /// read-freshness or production HA certificate. Absent on single-node deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<cluster_feed::ClusterReplicaLag>,
}

/// Liveness probe; also reports the running crate version (used by the Docker healthcheck) and,
/// additively, the durability/ledger signal (t30 §3.3).
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let persistent = state.store.is_some();
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let store_schema_version = persistent.then_some(chancela_store::schema::SCHEMA_VERSION);
    let degraded = *state.degraded.read().await;
    let cluster = state.cluster_read_lag().await;
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        persistent,
        ledger_length,
        ledger_verified,
        store_schema_version,
        integrity: if degraded { "broken" } else { "ok" },
        degraded,
        cluster,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{HeaderMap, Request, StatusCode};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt; // for `oneshot`
    use uuid::Uuid;
    use zeroize::Zeroizing;

    const DEFAULT_TEST_PASSWORD: &str = "Teste-Forte7!X";
    const PROVIDER_CREDENTIAL_STATUS_URI: &str = "/v1/signature/provider-credentials/status";

    /// Send one request through a fresh router and return (status, parsed JSON body).
    /// Does NOT auto-seed a session — used by [`send`] and [`auth_token`] internally, and by
    /// tests that check auth rejection (401 without a session).
    async fn send_raw(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        let response = router(state).oneshot(req).await.expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("body is JSON")
        };
        (status, value)
    }

    async fn send_status(state: AppState, req: Request<Body>) -> StatusCode {
        router(state)
            .oneshot(req)
            .await
            .expect("router responds")
            .status()
    }

    /// Like [`send_raw`] but auto-seeds a session token for requests that don't carry one (t41:
    /// all mutation endpoints now require auth). For GET requests the extra header is harmless;
    /// for mutations it satisfies the fallible `CurrentActor` extractor. Tests that specifically
    /// check auth rejection (401 without a session) use [`send_raw`] directly.
    async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        if req.headers().get("x-chancela-session").is_none() {
            let token = auth_token(&state).await;
            send_raw(state, with_session(req, &token)).await
        } else {
            send_raw(state, req).await
        }
    }

    /// Auto-seeding variant kept for potential future use.
    #[allow(dead_code)]
    async fn send_mut(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
        send(state, req).await
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn body_json(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn post_json(uri: &str, body: Value) -> Request<Body> {
        body_json("POST", uri, body)
    }

    fn template_body(id: &str, heading: &str) -> Value {
        json!({
            "id": id,
            "family": "CommercialCompany",
            "stage": "Ata",
            "channels": ["Physical"],
            "signature_policy": "QualifiedPreferred",
            "rule_pack_id": "csc-art63/v2",
            "locale": "pt-PT",
            "blocks": [
                { "kind": "Heading", "level": 1, "template": heading },
                {
                    "kind": "Paragraph",
                    "template": "Reunida a assembleia em {{ meeting_date | long_date }}."
                }
            ]
        })
    }

    fn seal_body() -> Value {
        seal_body_with_reference("Arquivo A / Pasta 2026 / Ata teste")
    }

    fn seal_body_with_reference(storage_reference: &str) -> Value {
        json!({
            "manual_signature_original_reference": {
                "storage_reference": storage_reference
            }
        })
    }

    fn seal_body_acknowledging_warnings() -> Value {
        let mut body = seal_body();
        body["acknowledge_warnings"] = json!(true);
        body
    }

    fn seal_body_with_template_id(template_id: &str) -> Value {
        let mut body = seal_body();
        body["template_id"] = json!(template_id);
        body
    }

    fn cleanup_preview_token(body: &Value) -> String {
        body["preview_token"]
            .as_str()
            .expect("cleanup preview_token")
            .to_owned()
    }

    fn set_file_modified(path: &std::path::Path, modified: std::time::SystemTime) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open file to set modified timestamp");
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .expect("set test file modified timestamp");
    }

    fn patch_json(uri: &str, body: Value) -> Request<Body> {
        body_json("PATCH", uri, body)
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn sha256_hex_test(bytes: &[u8]) -> String {
        crate::hex::hex(&<[u8; 32]>::from(Sha256::digest(bytes)))
    }

    fn external_validator_metadata_bytes(
        case_id: &str,
        family: &str,
        document_sha256: &str,
    ) -> Vec<u8> {
        json!({
            "schema": "chancela-external-validator-report-evidence/v1",
            "evidence_kind": "external_validator_report_metadata",
            "legal_validity_claimed": false,
            "evidence_scope": {
                "kind": "external_validator_report",
                "technical_only": true,
                "legal_validity_assessment": "not_assessed",
                "claim": "technical_validator_evidence_only"
            },
            "case_id": case_id,
            "source_sidecar": {
                "schema": "chancela-external-validator-sidecar/v1",
                "path": format!("cases/{case_id}/expected/{family}.json")
            },
            "validator": {
                "family": family,
                "name": "Fixture validator",
                "version": "1.0",
                "run_status": "recorded",
                "run_at": "2026-07-10T00:00:00Z",
                "operator": "operator@example.test",
                "environment": "test",
                "command": "validator --fixture"
            },
            "document": {
                "path": format!("cases/{case_id}/input/{case_id}.pdf"),
                "sha256": document_sha256,
                "bytes": 1
            },
            "report": {
                "path": format!("cases/{case_id}/reports/{family}.json"),
                "sidecar_path": format!("../reports/{family}.json"),
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "bytes": 2,
                "content_type": "application/json",
                "source_filename": format!("{family}.json"),
                "captured_at": "2026-07-10T00:00:00Z",
                "preserved_at": "2026-07-10T00:00:00Z",
                "preserved_by": "operator@example.test",
                "preservation_action": "copied_to_corpus"
            },
            "transcription": {
                "status": "raw_report_only",
                "summary": "Raw report metadata preserved.",
                "findings_available": false
            },
            "archive_attachment": {
                "role": "technical_external_validator_report_metadata",
                "content_type": "application/json",
                "suggested_path": format!("evidence/external-validators/{case_id}-{family}.json")
            },
            "evidence_indexing": {
                "status_scope": "technical_metadata_only",
                "archive_package": {
                    "index_path": "evidence/index.json",
                    "indexed_path_prefix": "evidence/external-validators/",
                    "indexed_path_pattern": "evidence/external-validators/{case_id}-{validator_family}.json"
                },
                "document_bundle": {
                    "index_json_pointer": "/validation_report/evidence_index/external_validator_reports",
                    "archive_path_prefix": "evidence/external-validators/",
                    "archive_path_pattern": "evidence/external-validators/{case_id}-{validator_family}.json"
                }
            }
        })
        .to_string()
        .into_bytes()
    }

    fn external_validator_metadata_with_raw_report_bytes(
        case_id: &str,
        family: &str,
        document_sha256: &str,
    ) -> (Vec<u8>, Vec<u8>, String) {
        let raw_report =
            br#"{"report_kind":"external_validator_raw_report","status":"technical"}"#.to_vec();
        let raw_report_sha256 = sha256_hex_test(&raw_report);
        let mut metadata: Value = serde_json::from_slice(&external_validator_metadata_bytes(
            case_id,
            family,
            document_sha256,
        ))
        .expect("fixture JSON");
        metadata["raw_report"] = json!({
            "content_type": "application/json",
            "sha256": raw_report_sha256,
            "bytes": raw_report.len(),
            "source_filename": format!("{family}-raw.json"),
            "suggested_path": format!(
                "evidence/external-validators/{case_id}-{family}-raw-report.json"
            ),
            "content_base64": B64.encode(&raw_report)
        });
        (
            metadata.to_string().into_bytes(),
            raw_report,
            raw_report_sha256,
        )
    }

    fn post_external_validator_metadata(bytes: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/external-validator-reports")
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .expect("request builds")
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_accepts_and_lists_redacted_summary() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata = external_validator_metadata_bytes("api-valid", "eu-dss", &document_sha256);
        let metadata_sha256 = sha256_hex_test(&metadata);

        let (status, created) =
            send(state.clone(), post_external_validator_metadata(metadata)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["storage"], "in_memory");
        assert_eq!(
            created["status"],
            "external_validator_report_metadata_attached"
        );
        assert_eq!(created["report"]["case_id"], "api-valid");
        assert_eq!(created["report"]["validator_family"], "eu-dss");
        assert_eq!(
            created["report"]["path"],
            "evidence/external-validators/api-valid-eu-dss.json"
        );
        assert_eq!(created["report"]["sha256"], metadata_sha256);

        let (status, listed) = send(state, get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["storage"], "in_memory");
        assert_eq!(
            listed["status"],
            "external_validator_report_metadata_attached"
        );
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["malformed_count"], 0);
        assert_eq!(listed["duplicate_suggested_path_count"], 0);
        let report = &listed["reports"][0];
        assert_eq!(report["case_id"], "api-valid");
        assert_eq!(report["validator_family"], "eu-dss");
        assert_eq!(report["content_type"], "application/json");
        assert!(report.get("bytes").is_none(), "raw bytes are not listed");
        let listed_text = listed.to_string();
        assert!(!listed_text.contains("operator@example.test"));
        assert!(!listed_text.contains("validator --fixture"));
        assert!(!listed_text.contains("raw_report_only"));
    }

    #[tokio::test]
    async fn external_validator_report_metadata_in_memory_state_remains_ephemeral() {
        let first = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-memory-only", "eu-dss", &document_sha256);

        let (status, body) = send(
            first.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["storage"], "in_memory");
        assert!(first.external_validator_report_metadata_dir.is_none());
        assert_eq!(
            *first.external_validator_report_metadata.read().await,
            vec![metadata]
        );

        let fresh = AppState::default();
        let (status, listed) = send(fresh, get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["storage"], "in_memory");
        assert_eq!(listed["count"], 0);
        assert_eq!(listed["malformed_count"], 0);
    }

    #[tokio::test]
    async fn external_validator_report_metadata_persists_and_reloads_from_data_dir() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata = external_validator_metadata_bytes("api-durable", "eu-dss", &document_sha256);

        let (status, created) = send(
            first.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["storage"], "data_dir");

        let sidecar = tmp
            .dir
            .join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR)
            .join("api-durable-eu-dss.json");
        assert_eq!(
            std::fs::read(&sidecar).expect("external-validator sidecar"),
            metadata
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, listed) = send(restarted.clone(), get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["storage"], "data_dir");
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["malformed_count"], 0);
        assert_eq!(
            listed["reports"][0]["path"],
            "evidence/external-validators/api-durable-eu-dss.json"
        );

        let (status, content_type, downloaded) = send_bytes(
            restarted.clone(),
            get("/v1/external-validator-reports/api-durable/eu-dss"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "application/json");
        assert_eq!(downloaded, metadata);

        let raw_entries = restarted.external_validator_report_metadata.read().await;
        let attachments = external_validator_evidence::matching_attachments(
            &raw_entries,
            vec![document_sha256.clone()],
        );
        assert_eq!(attachments.len(), 1);
        assert_eq!(
            attachments[0].archive_path,
            "evidence/external-validators/api-durable-eu-dss.json"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_accepts_verified_raw_report_attachment() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let document_sha256 = sha256_hex_test(b"document bytes");
        let (metadata, raw_report, raw_report_sha256) =
            external_validator_metadata_with_raw_report_bytes(
                "api-raw",
                "eu-dss",
                &document_sha256,
            );

        let (status, created) = send(
            first.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["storage"], "data_dir");
        assert_eq!(
            created["report"]["raw_report"]["preservation_status"],
            "raw_report_attached"
        );
        assert_eq!(
            created["report"]["raw_report"]["path"],
            "evidence/external-validators/api-raw-eu-dss-raw-report.json"
        );
        assert_eq!(created["report"]["raw_report"]["sha256"], raw_report_sha256);
        assert_eq!(
            created["report"]["raw_report"]["size_bytes"],
            raw_report.len()
        );
        assert!(
            !created.to_string().contains("content_base64"),
            "listing response must not expose embedded raw report bytes"
        );

        let sidecar = tmp
            .dir
            .join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR)
            .join("api-raw-eu-dss.json");
        assert_eq!(
            std::fs::read(&sidecar).expect("external-validator sidecar"),
            metadata
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, listed) = send(restarted.clone(), get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["count"], 1);
        assert_eq!(
            listed["reports"][0]["raw_report"]["preservation_status"],
            "raw_report_attached"
        );
        assert_eq!(
            listed["reports"][0]["raw_report"]["path"],
            "evidence/external-validators/api-raw-eu-dss-raw-report.json"
        );
        assert!(
            !listed.to_string().contains("content_base64"),
            "list response must not expose embedded raw report bytes"
        );

        let raw_entries = restarted.external_validator_report_metadata.read().await;
        let attachments =
            external_validator_evidence::matching_attachments(&raw_entries, vec![document_sha256]);
        assert_eq!(attachments.len(), 1);
        let raw = attachments[0]
            .raw_report
            .as_ref()
            .expect("raw report summary");
        assert_eq!(raw.bytes.as_deref(), Some(raw_report.as_slice()));
        assert_eq!(raw.sha256, raw_report_sha256);
    }

    #[tokio::test]
    async fn external_validator_raw_report_downloads_retained_bytes_after_reload() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let document_sha256 = sha256_hex_test(b"document bytes");
        let (metadata, raw_report, _raw_report_sha256) =
            external_validator_metadata_with_raw_report_bytes(
                "api-raw-download",
                "eu-dss",
                &document_sha256,
            );

        let (status, created) = send(
            first.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert!(
            !created.to_string().contains("content_base64"),
            "create response must not expose embedded raw report bytes"
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, listed) = send(restarted.clone(), get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["count"], 1);
        assert!(
            !listed.to_string().contains("content_base64"),
            "list response must not expose embedded raw report bytes"
        );

        let token = auth_token(&restarted).await;
        let (status, headers, downloaded) = send_raw_bytes(
            restarted,
            with_session(
                get("/v1/external-validator-reports/api-raw-download/eu-dss/raw-report"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            headers
                .get("content-disposition")
                .and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"api-raw-download-eu-dss-raw-report.json\"")
        );
        assert_eq!(downloaded, raw_report);
        assert!(!contains_subslice(&downloaded, b"content_base64"));
    }

    #[tokio::test]
    async fn external_validator_raw_report_download_requires_settings_read() {
        use chancela_authz::{GUEST_ROLE_ID, LEITOR_ROLE_ID, RoleAssignment, Scope};

        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let (metadata, raw_report, _raw_report_sha256) =
            external_validator_metadata_with_raw_report_bytes(
                "api-raw-authz",
                "eu-dss",
                &document_sha256,
            );

        let (status, body) = send(state.clone(), post_external_validator_metadata(metadata)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let reader_id = seed_user(
            &state,
            "reader.raw-external-validator",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let reader_token = seed_session(&state, &reader_id.to_string()).await;
        let raw_uri = "/v1/external-validator-reports/api-raw-authz/eu-dss/raw-report";
        let (status, _headers, downloaded) =
            send_raw_bytes(state.clone(), with_session(get(raw_uri), &reader_token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(downloaded, raw_report);

        let guest_id = seed_user(
            &state,
            "guest.raw-external-validator",
            vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        )
        .await;
        let guest_token = seed_session(&state, &guest_id.to_string()).await;
        let (status, _headers, denied) =
            send_raw_bytes(state.clone(), with_session(get(raw_uri), &guest_token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_ne!(denied, raw_report);

        let (status, _headers, denied) = send_raw_bytes(state, get(raw_uri)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(denied, raw_report);
    }

    #[tokio::test]
    async fn provider_credential_status_requires_settings_read() {
        use chancela_authz::{GUEST_ROLE_ID, LEITOR_ROLE_ID, RoleAssignment, RoleCatalog, Scope};

        let state = AppState::default();
        *state.roles.write().await = RoleCatalog::seeded_defaults();

        let (status, _) = send_raw(state.clone(), get(PROVIDER_CREDENTIAL_STATUS_URI)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let guest_id = seed_user(
            &state,
            "guest.provider-credential-status",
            vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        )
        .await;
        let guest_token = seed_session(&state, &guest_id.to_string()).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(get(PROVIDER_CREDENTIAL_STATUS_URI), &guest_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let reader_id = seed_user(
            &state,
            "reader.provider-credential-status",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let reader_token = seed_session(&state, &reader_id.to_string()).await;
        let (status, body) = send_raw(
            state,
            with_session(get(PROVIDER_CREDENTIAL_STATUS_URI), &reader_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn provider_credential_status_reports_empty_store_without_key_material() {
        let state = AppState::default();
        let (status, body) = send(state, get(PROVIDER_CREDENTIAL_STATUS_URI)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["report_kind"], "provider_credential_storage_status");
        assert_eq!(body["read_only"], true);
        assert_eq!(body["live_provider_calls"], false);
        assert_eq!(body["production_or_legal_use_claimed"], false);
        assert_eq!(body["redaction"]["plaintext_secrets_returned"], false);
        assert_eq!(body["redaction"]["ciphertext_returned"], false);
        assert_eq!(body["redaction"]["raw_key_material_returned"], false);
        assert_eq!(body["storage"]["sidecar_status"], "available");
        assert_eq!(body["storage"]["crypto_status"], "unavailable_fail_closed");
        assert_eq!(body["storage"]["strict"], false);
        assert_eq!(body["storage"]["key_failure"], "missing_key_source");
        assert!(body["records"].as_array().expect("records").is_empty());
    }

    #[tokio::test]
    async fn provider_credential_status_redacts_populated_store() {
        let tmp = TempDir::new();
        let state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                &tmp.dir,
                b"provider-status-test-db-key-012345",
                false,
            )),
            ..AppState::default()
        };
        state
            .provider_credentials
            .put(
                CredentialMode::CscQtsp,
                "encosto-qtsp",
                CscCredentialFields {
                    client_id: Some(Zeroizing::new("client-id-hidden-1234".to_owned())),
                    client_secret: Some(Zeroizing::new("super-secret-hidden-9876".to_owned())),
                    access_token: Some(Zeroizing::new("access-token-hidden-5555".to_owned())),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted credentials");

        let (status, body) = send(state, get(PROVIDER_CREDENTIAL_STATUS_URI)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["storage"]["sidecar_status"], "available");
        assert_eq!(body["storage"]["crypto_status"], "available");
        assert_eq!(body["storage"]["protection_level"], "confidential");
        assert!(body["storage"]["key_source_class"].is_string());

        let records = body["records"].as_array().expect("records");
        assert_eq!(records.len(), 1, "{body}");
        let record = &records[0];
        assert_eq!(record["mode"], "csc");
        assert_eq!(record["provider_id"], serde_json::Value::Null);
        assert_eq!(record["provider_id_redacted"], true);
        assert_eq!(record["key_version"], 1);

        let fields = record["fields"].as_array().expect("fields");
        assert_eq!(fields.len(), 3, "{body}");
        let rendered = body.to_string();
        assert!(!rendered.contains("client-id-hidden"));
        assert!(!rendered.contains("super-secret-hidden"));
        assert!(!rendered.contains("access-token-hidden"));
        assert!(!rendered.contains("encosto-qtsp"));
        assert!(!rendered.contains("1234"));
        assert!(!rendered.contains("9876"));
        assert!(!rendered.contains("5555"));
        for field in fields {
            assert_eq!(field["configured"], true);
            assert_eq!(field["plaintext_redacted"], true);
            assert_eq!(field["ciphertext_redacted"], true);
            assert_eq!(field["raw_value_returned"], false);
            assert!(field["field_name"].is_string());
            assert_eq!(field["last4"], serde_json::Value::Null);
        }
    }

    #[tokio::test]
    async fn provider_credential_status_reports_strict_no_key_fail_closed() {
        let state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::in_memory_with_strict(true)),
            ..AppState::default()
        };

        let (status, body) = send(state, get(PROVIDER_CREDENTIAL_STATUS_URI)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["storage"]["strict"], true);
        assert_eq!(body["storage"]["sidecar_status"], "available");
        assert_eq!(body["storage"]["crypto_status"], "unavailable_fail_closed");
        assert_eq!(body["storage"]["key_failure"], "missing_key_source");
        assert!(body["records"].as_array().expect("records").is_empty());
    }

    #[tokio::test]
    async fn provider_credential_status_reports_corrupt_sidecar_without_raw_details() {
        let tmp = TempDir::new();
        std::fs::write(
            tmp.dir.join(secretstore_persist::CREDENTIAL_SIDECAR_FILE),
            b"{ not valid credential sidecar json ",
        )
        .expect("write corrupt sidecar");
        let state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                &tmp.dir,
                b"provider-status-test-db-key-012345",
                false,
            )),
            ..AppState::default()
        };

        let (status, body) = send(state, get(PROVIDER_CREDENTIAL_STATUS_URI)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["storage"]["sidecar_status"], "fail_closed");
        assert_eq!(body["storage"]["sidecar_failure"], "corrupt_sidecar");
        assert!(body["records"].as_array().expect("records").is_empty());
        let rendered = body.to_string();
        assert!(!rendered.contains("not valid credential sidecar json"));
        assert!(!rendered.contains(&tmp.dir.to_string_lossy().to_string()));
        assert_eq!(body["redaction"]["plaintext_secrets_returned"], false);
        assert_eq!(body["redaction"]["ciphertext_returned"], false);
        assert_eq!(body["redaction"]["raw_key_material_returned"], false);
    }

    #[tokio::test]
    async fn external_validator_raw_report_manifest_only_returns_404() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-raw-manifest-only", "eu-dss", &document_sha256);

        let (status, created) =
            send(state.clone(), post_external_validator_metadata(metadata)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(
            created["report"]["raw_report"]["preservation_status"],
            "raw_report_manifest_only"
        );

        let (status, body) = send(
            state,
            get("/v1/external-validator-reports/api-raw-manifest-only/eu-dss/raw-report"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"], "resource not found");
        assert!(!body.to_string().contains("content_base64"));
        assert!(
            !body
                .to_string()
                .contains("technical_validator_evidence_only")
        );
    }

    #[tokio::test]
    async fn external_validator_raw_report_download_fail_closed_cases() {
        let state = AppState::default();
        let (status, body) = send(
            state,
            get("/v1/external-validator-reports/api.unsafe/eu-dss/raw-report"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let tmp = TempDir::new();
        let sidecar_dir = tmp
            .dir
            .join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR);
        std::fs::create_dir_all(&sidecar_dir).expect("sidecar dir");
        std::fs::write(
            sidecar_dir.join("api-raw-malformed-eu-dss.json"),
            b"{not valid json",
        )
        .expect("malformed sidecar");
        let malformed_state = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(
            malformed_state,
            get("/v1/external-validator-reports/api-raw-malformed/eu-dss/raw-report"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("technical metadata sidecar"),
            "{body}"
        );
        assert!(!body.to_string().contains("not valid json"));

        let duplicate_state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let (metadata, _raw_report, _raw_report_sha256) =
            external_validator_metadata_with_raw_report_bytes(
                "api-raw-duplicate",
                "eu-dss",
                &document_sha256,
            );
        {
            let mut raw_entries = duplicate_state
                .external_validator_report_metadata
                .write()
                .await;
            raw_entries.push(metadata.clone());
            raw_entries.push(metadata);
        }
        let (status, body) = send(
            duplicate_state,
            get("/v1/external-validator-reports/api-raw-duplicate/eu-dss/raw-report"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"].as_str().expect("error").contains("ambiguous"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_rejects_legal_overclaim() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let mut value: Value = serde_json::from_slice(&external_validator_metadata_bytes(
            "api-legal",
            "adobe",
            &document_sha256,
        ))
        .expect("fixture JSON");
        value["legal_validity_claimed"] = json!(true);

        let (status, body) = send(
            state,
            post_external_validator_metadata(value.to_string().into_bytes()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("external-validator metadata"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_rejects_raw_report_digest_mismatch() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let (metadata, _raw_report, _raw_sha256) =
            external_validator_metadata_with_raw_report_bytes(
                "api-raw-mismatch",
                "eu-dss",
                &document_sha256,
            );
        let mut value: Value = serde_json::from_slice(&metadata).expect("fixture JSON");
        value["raw_report"]["sha256"] =
            json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        let (status, body) = send(
            state,
            post_external_validator_metadata(value.to_string().into_bytes()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("external-validator metadata"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_rejects_malformed_and_non_json() {
        let state = AppState::default();
        let (status, body) = send(
            state.clone(),
            post_external_validator_metadata(b"{not json".to_vec()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let req = Request::builder()
            .method("POST")
            .uri("/v1/external-validator-reports")
            .header("content-type", "text/plain")
            .body(Body::from("not json"))
            .expect("request builds");
        let (status, body) = send(state, req).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("application/json"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_malformed_sidecars_are_counted_not_trusted() {
        let tmp = TempDir::new();
        let sidecar_dir = tmp
            .dir
            .join(external_validator_evidence::EXTERNAL_VALIDATOR_REPORT_METADATA_DIR);
        std::fs::create_dir_all(&sidecar_dir).expect("sidecar dir");
        std::fs::write(
            sidecar_dir.join("api-malformed-eu-dss.json"),
            b"{not valid json",
        )
        .expect("malformed sidecar");

        let state = AppState::with_data_dir(tmp.dir.clone());
        let (status, listed) = send(state.clone(), get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["storage"], "data_dir");
        assert_eq!(listed["count"], 0);
        assert_eq!(listed["malformed_count"], 1);
        assert_eq!(listed["duplicate_suggested_path_count"], 0);
        assert_eq!(listed["reports"], json!([]));
        assert!(
            !listed.to_string().contains("not valid json"),
            "raw malformed bytes must not be listed"
        );

        let (status, body) = send(
            state.clone(),
            get("/v1/external-validator-reports/api-malformed/eu-dss"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("technical metadata sidecar"),
            "{body}"
        );
        assert!(
            !body.to_string().contains("not valid json"),
            "malformed raw bytes must not be returned"
        );

        let raw_entries = state.external_validator_report_metadata.read().await;
        let attachments = external_validator_evidence::matching_attachments(
            &raw_entries,
            vec![sha256_hex_test(b"document bytes")],
        );
        assert!(attachments.is_empty());
    }

    #[tokio::test]
    async fn external_validator_report_metadata_duplicate_identity_is_not_downloadable() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-download-duplicate", "eu-dss", &document_sha256);
        {
            let mut raw_entries = state.external_validator_report_metadata.write().await;
            raw_entries.push(metadata.clone());
            raw_entries.push(metadata);
        }

        let (status, listed) = send(state.clone(), get("/v1/external-validator-reports")).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["count"], 0);
        assert_eq!(listed["duplicate_suggested_path_count"], 1);

        let (status, body) = send(
            state,
            get("/v1/external-validator-reports/api-download-duplicate/eu-dss"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"].as_str().expect("error").contains("ambiguous"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_download_allows_settings_read() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};

        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-read-download", "eu-dss", &document_sha256);

        let (status, body) = send(
            state.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let reader_id = seed_user(
            &state,
            "reader.external-validator",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let reader_token = seed_session(&state, &reader_id.to_string()).await;

        let (status, content_type, downloaded) = send_bytes(
            state,
            with_session(
                get("/v1/external-validator-reports/api-read-download/eu-dss"),
                &reader_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "application/json");
        assert_eq!(downloaded, metadata);
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_rejects_duplicate_suggested_path() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-duplicate", "eu-dss", &document_sha256);

        let (status, body) = send(
            state.clone(),
            post_external_validator_metadata(metadata.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (status, body) = send(state, post_external_validator_metadata(metadata)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("duplicate external-validator suggested_path"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_rejects_duplicate_suggested_path_after_restart() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let document_sha256 = sha256_hex_test(b"document bytes");
        let metadata =
            external_validator_metadata_bytes("api-restart-duplicate", "eu-dss", &document_sha256);

        let (status, body) = send(first, post_external_validator_metadata(metadata.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(restarted, post_external_validator_metadata(metadata)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("duplicate external-validator suggested_path"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn external_validator_report_metadata_api_rejects_unsafe_path_and_bad_sha256() {
        let state = AppState::default();
        let document_sha256 = sha256_hex_test(b"document bytes");
        let mut traversal: Value = serde_json::from_slice(&external_validator_metadata_bytes(
            "api-traversal",
            "eu-dss",
            &document_sha256,
        ))
        .expect("fixture JSON");
        traversal["archive_attachment"]["suggested_path"] =
            json!("evidence/external-validators/../api-traversal-eu-dss.json");
        let (status, body) = send(
            state.clone(),
            post_external_validator_metadata(traversal.to_string().into_bytes()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let mut bad_sha: Value = serde_json::from_slice(&external_validator_metadata_bytes(
            "api-bad-sha",
            "eu-dss",
            &document_sha256,
        ))
        .expect("fixture JSON");
        bad_sha["document"]["sha256"] = json!("NOT-A-SHA256");
        let (status, body) = send(
            state,
            post_external_validator_metadata(bad_sha.to_string().into_bytes()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }

    fn data_status_filesystem_concern<'a>(body: &'a Value, id: &str) -> &'a Value {
        body["usage"]["filesystem"]
            .as_array()
            .expect("filesystem usage array")
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("missing filesystem usage concern {id} in {body}"))
    }

    /// A request builder carrying an `X-Chancela-Session` token.
    fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
        req.headers_mut().insert(
            "x-chancela-session",
            token.parse().expect("valid header value"),
        );
        req
    }

    fn with_bearer(mut req: Request<Body>, key: &str) -> Request<Body> {
        req.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("valid header value"),
        );
        req
    }

    /// Seed a test user + session directly into the state (bypassing the API) and return the
    /// token (t41: all mutation endpoints require auth). This avoids creating `user.created`
    /// ledger events and extra users in lists — the test's own mutations are the only ones
    /// recorded. The user has non-empty test credential material, but the session is seeded
    /// directly because these tests are not exercising sign-in.
    async fn auth_token(state: &AppState) -> String {
        use crate::users::{User, UserId};
        use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
        use time::format_description::well_known::Rfc3339;
        // RBAC (t64-E3): every gated endpoint resolves the acting user's scoped permissions against
        // the role catalog. A pure in-memory `AppState::default()` has an EMPTY catalog, so seed the
        // defaults and make the test actor **Owner\@Global** — the bootstrap-first-user identity every
        // in-crate test implicitly acts as (an admin operating its own instance). Idempotent.
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: "test.actor".to_owned(),
            display_name: "Test Actor".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some("direct-session-test-password-hash".to_owned()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    /// A fresh in-memory state with the RBAC catalog seeded — the in-memory equivalent of a real
    /// first-run install (mirrors [`AppState::from_env`]'s in-memory seeding). Used by the tests that
    /// bootstrap the first user through the API and then act AS that Owner: without a seeded catalog
    /// the bootstrap Owner\@Global assignment would resolve against an empty catalog and grant nothing
    /// (fail-closed), which is precisely the in-memory lockout `from_env` now prevents (t64-E3).
    async fn fresh_state() -> AppState {
        let state = AppState::default();
        *state.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();
        state
    }

    /// Create an entity and an open book for it; returns (state, entity_id, book_id).
    async fn entity_and_open_book(kind: &str) -> (AppState, String, String) {
        entity_and_open_book_in_state(AppState::default(), kind).await
    }

    async fn entity_and_open_book_in_state(
        state: AppState,
        kind: &str,
    ) -> (AppState, String, String) {
        let token = auth_token(&state).await;
        let (status, entity) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Lisboa",
                        "kind": kind,
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/books",
                    json!({
                        "entity_id": entity_id,
                        "kind": "AssembleiaGeral",
                        "purpose": "livro de atas da assembleia geral",
                        "opening_date": "2026-01-15",
                        "required_signatories": ["Administrador"],
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(book["state"], "Open");
        let book_id = book["id"].as_str().expect("book id").to_owned();
        (state, entity_id, book_id)
    }

    #[tokio::test]
    async fn health_returns_ok_and_version() {
        let (status, body) = send(AppState::default(), get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn create_then_get_entity_round_trips() {
        let state = AppState::default();
        let create = post_json(
            "/v1/entities",
            json!({
                "name": "Encosto Estratégico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima",
            }),
        );
        let (status, created) = send(state.clone(), create).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["name"], "Encosto Estratégico, S.A.");
        assert_eq!(created["family"], "CommercialCompany");
        let id = created["id"].as_str().expect("id is a string").to_owned();

        let (status, fetched) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched, created);

        let (status, list) = send(state, get("/v1/entities")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("list is array").len(), 1);
    }

    #[tokio::test]
    async fn invalid_nipc_is_rejected_with_422() {
        let create = post_json(
            "/v1/entities",
            json!({
                "name": "Bad NIPC, Lda.",
                "nipc": "111111111",
                "seat": "Porto",
                "kind": "SociedadePorQuotas",
            }),
        );
        let (status, body) = send(AppState::default(), create).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn missing_entity_returns_404() {
        let missing = Uuid::new_v4();
        let (status, _) = send(AppState::default(), get(&format!("/v1/entities/{missing}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn entity_view_carries_nipc_validated_true_for_a_valid_nipc() {
        // A validated NIPC serializes as a bare string with an explicit `nipc_validated: true`.
        let state = AppState::default();
        let (status, created) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["nipc"], "503004642");
        assert_eq!(created["nipc_validated"], true);
        let id = created["id"].as_str().expect("id").to_owned();

        // GET and the list both expose the same stable shape.
        let (_, got) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(got["nipc"], "503004642");
        assert_eq!(got["nipc_validated"], true);
        let (_, list) = send(state, get("/v1/entities")).await;
        assert_eq!(list[0]["nipc_validated"], true);
    }

    #[tokio::test]
    async fn override_stores_an_invalid_nipc_unvalidated() {
        // With the override, a NIPC that fails validation is stored raw and flagged unvalidated
        // instead of being rejected — the foreign/legacy-entity affordance.
        let state = AppState::default();
        let (status, created) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Foreign Holding Ltd",
                    "nipc": "GB-12345",
                    "seat": "London",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // The raw identifier is preserved verbatim as a bare string, flagged unvalidated.
        assert_eq!(created["nipc"], "GB-12345");
        assert_eq!(created["nipc_validated"], false);
        let id = created["id"].as_str().expect("id").to_owned();

        // It is queryable with the same stable shape.
        let (status, got) = send(state.clone(), get(&format!("/v1/entities/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["nipc"], "GB-12345");
        assert_eq!(got["nipc_validated"], false);

        // The override is recorded on the entity.created audit event.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created_event = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created present");
        assert_eq!(
            created_event["justification"],
            "nipc validation overridden (stored unvalidated)"
        );
    }

    #[tokio::test]
    async fn override_flag_does_not_downgrade_a_valid_nipc() {
        // A NIPC that parses is always stored validated, even with the override flag set.
        let (status, created) = send(
            AppState::default(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["nipc"], "503004642");
        assert_eq!(created["nipc_validated"], true);
    }

    #[tokio::test]
    async fn invalid_nipc_without_override_is_still_422() {
        // The default path is byte-identical to before: an invalid NIPC is rejected.
        let (status, body) = send(
            AppState::default(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Bad NIPC, Lda.",
                    "nipc": "GB-12345",
                    "seat": "Porto",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": false,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn unvalidated_nipc_entity_warns_and_seals_only_when_acknowledged() {
        // The LEG-05 warning-acknowledgement path, driven over HTTP: an entity whose NIPC was
        // stored via the override raises the CSC-63/nipc-unvalidated Warning on its acts. The
        // warning does not block by itself, but sealing requires it to be acknowledged.
        let state = AppState::default();
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Foreign Holding Ltd",
                    "nipc": "GB-12345",
                    "seat": "London",
                    "kind": "SociedadeAnonima",
                    "allow_invalid_nipc": true,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({
                    "entity_id": entity_id,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro de atas da assembleia geral",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_str().expect("book id").to_owned();

        // Draft, fill mandatory contents, and advance to Signing so nothing but the NIPC warning
        // stands between the act and a seal.
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas do exercício.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // Compliance surfaces the NIPC warning but is not error-blocked: seal is allowed once the
        // warning is acknowledged. With the mesa now filled, the NIPC warning is the only finding.
        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["errors"], 0);
        assert!(comp["warnings"].as_u64().expect("warnings count") >= 1);
        assert_eq!(comp["seal_allowed"], true);
        let issues = comp["issues"].as_array().expect("issues");
        assert!(
            issues
                .iter()
                .any(|i| i["rule_id"] == "CSC-63/nipc-unvalidated" && i["severity"] == "Warning"),
            "the unvalidated-NIPC warning is present: {issues:?}"
        );

        // Sealing without acknowledging the warning is refused (409) with the warning surfaced.
        let (status, body) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let warnings = body["warnings"].as_array().expect("warnings");
        assert!(
            warnings
                .iter()
                .any(|w| w["rule_id"] == "CSC-63/nipc-unvalidated"),
            "seal refusal carries the warning: {warnings:?}"
        );

        // Acknowledging the warning seals the act.
        let (status, sealed) = send(
            state,
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                seal_body_acknowledging_warnings(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["act"]["state"], "Sealed");
        assert!(
            sealed["acknowledged_warnings"]
                .as_array()
                .expect("acknowledged")
                .iter()
                .any(|w| w["rule_id"] == "CSC-63/nipc-unvalidated"),
            "the acknowledged warning is echoed back"
        );
    }

    #[tokio::test]
    async fn full_lifecycle_happy_path() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Draft an act into the open book.
        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(act["state"], "Draft");
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // PATCH the working content — including the mesa/time/agenda now that the wire carries
        // them (t31); no ledger event is appended for this.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas do exercício.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["meeting_date"], "2026-03-30");
        assert_eq!(patched["meeting_time"], "10:00");
        assert_eq!(patched["place"], "Sede social");
        assert_eq!(patched["mesa"]["presidente"], "Ana Presidente");

        // Advance through the lifecycle to Signing.
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, advanced) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}");
            assert_eq!(advanced["state"], to);
        }

        // A fully-filled CSC v2 ata (mesa, time, agenda all set) has no findings at all, so
        // sealing is allowed with no acknowledgement. The dispatched pack is the CSC family pack.
        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["rule_pack"], "csc-art63/v2");
        assert_eq!(comp["family"], "CommercialCompany");
        assert_eq!(comp["statute_overlay"], false);
        assert_eq!(comp["errors"], 0);
        assert_eq!(comp["warnings"], 0);
        assert_eq!(comp["seal_allowed"], true);

        // Seal — no warnings to acknowledge.
        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["ata_number"], 1);
        assert_eq!(sealed["act"]["state"], "Sealed");
        assert_eq!(
            sealed["payload_digest"].as_str().expect("hex digest").len(),
            64
        );

        // The act now reads as Sealed with its ata number.
        let (status, got) = send(state.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["state"], "Sealed");
        assert_eq!(got["ata_number"], 1);

        // The ledger holds the whole chain.
        let (status, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        let kinds: Vec<&str> = events
            .as_array()
            .expect("events array")
            .iter()
            .map(|e| e["kind"].as_str().expect("kind"))
            .collect();
        assert!(kinds.contains(&"book.opened"));
        assert!(kinds.contains(&"act.drafted"));
        assert!(kinds.contains(&"act.advanced"));
        assert!(kinds.contains(&"act.sealed"));

        // The dashboard reflects the sealed ata.
        let (status, dash) = send(state.clone(), get("/v1/dashboard")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(dash["entities"], 1);
        assert_eq!(dash["books_total"], 1);
        assert_eq!(dash["books_open"], 1);
        assert_eq!(dash["acts_total"], 1);
        assert_eq!(dash["acts_sealed"], 1);
        assert_eq!(dash["ledger_valid"], true);

        // The book's acts feed lists the sealed ata.
        let (status, book_acts) = send(state, get(&format!("/v1/books/{book_id}/acts"))).await;
        assert_eq!(status, StatusCode::OK);
        let arr = book_acts.as_array().expect("acts array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["ata_number"], 1);
    }

    #[tokio::test]
    async fn ai_draft_requires_accepted_human_verification_before_signing() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({
                    "book_id": book_id,
                    "title": "Ata assistida por IA",
                    "channel": "Physical",
                    "ai_provenance": {
                        "source": "mcp",
                        "tool": "draft_act",
                        "statement_source": "operator instruction",
                        "statement_sources": [
                            {
                                "path": "/draft",
                                "source_type": "ai_suggestion",
                                "source_label": "draft_act",
                                "human_verified": true,
                                "human_verification_status": "accepted_by_human",
                                "authoritative_source_claimed": true,
                                "legal_validity_claimed": true
                            },
                            {
                                "path": "/draft/title",
                                "source_type": "caller_supplied",
                                "source_label": "arguments.title",
                                "human_verified": true,
                                "human_verification_status": "accepted_by_human",
                                "authoritative_source_claimed": true,
                                "legal_validity_claimed": true
                            }
                        ]
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(act["ai_provenance"]["source"], "mcp");
        let statement_sources = act["ai_provenance"]["statement_sources"]
            .as_array()
            .expect("statement sources returned");
        assert_eq!(statement_sources.len(), 2);
        assert!(
            statement_sources
                .iter()
                .any(|source| source["path"] == "/draft"
                    && source["source_type"] == "ai_suggestion"
                    && source["source_label"] == "draft_act"
                    && source["human_verified"] == false
                    && source["human_verification_status"] == "pending_human_verification"
                    && source["authoritative_source_claimed"] == false
                    && source["legal_validity_claimed"] == false),
            "{act}"
        );
        assert!(
            statement_sources
                .iter()
                .any(|source| source["path"] == "/draft/title"
                    && source["source_type"] == "caller_supplied"
                    && source["source_label"] == "arguments.title"
                    && source["human_verified"] == false
                    && source["human_verification_status"] == "pending_human_verification"
                    && source["authoritative_source_claimed"] == false
                    && source["legal_validity_claimed"] == false),
            "{act}"
        );
        assert_eq!(
            act["ai_provenance"]["human_verification"]["status"],
            "pending_human_verification"
        );
        let act_id = act["id"].as_str().expect("act id").to_owned();

        for to in ["Review", "Convened", "Deliberated", "TextApproved"] {
            let (status, advanced) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}");
            assert_eq!(advanced["state"], to);
        }

        let (status, blocked) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/advance"),
                json!({ "to": "Signing" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            blocked["error"]
                .as_str()
                .expect("error")
                .contains("accepted human review before Signing"),
            "{blocked}"
        );

        let (status, rejected) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/human-verification"),
                json!({ "decision": "reject", "note": "needs correction" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            rejected["ai_provenance"]["human_verification"]["status"],
            "rejected_by_human"
        );

        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/advance"),
                json!({ "to": "Signing" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, accepted) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/human-verification"),
                json!({ "decision": "accept", "note": "human reviewed only" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            accepted["ai_provenance"]["human_verification"]["status"],
            "accepted_by_human"
        );
        assert!(
            accepted["ai_provenance"]["human_verification"]["reviewed_at"]
                .as_str()
                .is_some_and(|ts| ts.ends_with('Z')),
            "{accepted}"
        );

        let (status, signed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/advance"),
                json!({ "to": "Signing" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(signed["state"], "Signing");

        let (status, events) = send(state, get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "act.ai_human_verification"),
            "{events}"
        );
    }

    /// Send a request and return (status, content-type, raw body bytes) — for the non-JSON PDF
    /// download. Auto-seeds a session like [`send`].
    async fn send_bytes(state: AppState, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
        let (status, ctype, _disposition, bytes) = send_download(state, req).await;
        (status, ctype, bytes)
    }

    async fn send_download(
        state: AppState,
        req: Request<Body>,
    ) -> (StatusCode, String, String, Vec<u8>) {
        let req = if req.headers().get("x-chancela-session").is_none() {
            let token = auth_token(&state).await;
            with_session(req, &token)
        } else {
            req
        };
        let response = router(state).oneshot(req).await.expect("router responds");
        let status = response.status();
        let ctype = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let disposition = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (status, ctype, disposition, bytes.to_vec())
    }

    #[tokio::test]
    async fn ledger_events_carry_chain_membership_and_filter_by_chain() {
        let (state, entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let company_chain = format!("company:{entity_id}");
        let book_chain = format!("book:{book_id}");

        let (status, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = events.as_array().expect("events");
        let entity_created = arr
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created event");
        assert_eq!(
            entity_created["chains"],
            json!(["global", company_chain.clone()])
        );
        let book_opened = arr
            .iter()
            .find(|e| e["kind"] == "book.opened")
            .expect("book.opened event");
        assert_eq!(
            book_opened["chains"],
            json!(["global", book_chain.clone(), company_chain])
        );

        let (status, filtered) = send(
            state.clone(),
            get(&format!("/v1/ledger/events?chain={book_chain}&limit=1000")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let filtered = filtered.as_array().expect("filtered events");
        assert!(!filtered.is_empty(), "book chain has events");
        assert!(
            filtered.iter().all(|e| e["chains"]
                .as_array()
                .expect("chains")
                .iter()
                .any(|c| c == &json!(book_chain))),
            "every returned event belongs to the requested book chain: {filtered:?}"
        );
        assert!(
            filtered.iter().all(|e| e["kind"] != "entity.created"),
            "entity genesis is not a member of the book chain: {filtered:?}"
        );

        let (status, body) = send(state, get("/v1/ledger/events?chain=not-a-chain")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("invalid chain")
        );
    }

    async fn install_test_ledger(state: &AppState, ledger: Ledger) {
        if let Some(store) = &state.store {
            let events = ledger.events().to_vec();
            store
                .persist(|tx| {
                    for event in &events {
                        tx.append_event(event)?;
                    }
                    Ok(())
                })
                .expect("test ledger persisted");
        }
        *state.ledger.write().await = ledger;
    }

    fn store_pager_fixture_ledger() -> Ledger {
        let mut ledger = Ledger::new();
        ledger.append(
            "store.actor",
            "entity:company-a",
            "entity.created",
            Some("company genesis"),
            b"company-a",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a",
            "book.opened",
            Some("book genesis"),
            b"book-a",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a/act:match-0",
            "act.sealed",
            Some("needle archive"),
            b"match-0",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a/act:match-1",
            "act.sealed",
            Some("needle archive"),
            b"match-1",
        );
        ledger.append(
            "other.actor",
            "entity:company-a/book:book-a/act:match-noise",
            "act.sealed",
            Some("needle archive"),
            b"actor-noise",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a/act:match-2",
            "act.sealed",
            Some("needle archive"),
            b"match-2",
        );
        ledger.append(
            "store.actor",
            "settings/archive",
            "settings.updated",
            Some("needle archive"),
            b"settings-noise",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a/act:match-3",
            "act.sealed",
            Some("needle archive"),
            b"match-3",
        );
        ledger.append(
            "store.actor",
            "entity:company-a/book:book-a/act:match-4",
            "act.sealed",
            Some("needle archive"),
            b"match-4",
        );
        ledger
    }

    async fn install_archive_limit_ledger(state: &AppState) {
        let mut ledger = Ledger::new();
        for i in 0..300 {
            ledger.append(
                "limit.actor",
                "archive/limit-target",
                "limit.target",
                None,
                format!("target-{i}").as_bytes(),
            );
        }
        ledger.append(
            "limit.actor",
            "archive/limit-noise",
            "limit.noise",
            None,
            b"noise",
        );
        install_test_ledger(state, ledger).await;
    }

    fn bulk_application_ledger(event_count: usize) -> Ledger {
        let mut ledger = Ledger::new();
        for i in 0..event_count {
            ledger.append(
                "bulk.actor",
                "settings",
                "settings.updated",
                None,
                format!("payload-{i}").as_bytes(),
            );
        }
        ledger
    }

    fn accented_archive_search_ledger() -> Ledger {
        let mut ledger = Ledger::new();
        ledger.append(
            "arquivo.admin",
            "settings/livros",
            "archive.note",
            Some("Aprovação dos livros em reunião ordinária"),
            b"accented-archive-note",
        );
        ledger.append(
            "arquivo.admin",
            "settings/livros",
            "archive.note",
            Some("Revisão de arquivo sem o termo pesquisado"),
            b"archive-note-noise",
        );
        ledger
    }

    fn event_seqs(value: &Value) -> Vec<u64> {
        value["events"]
            .as_array()
            .expect("events")
            .iter()
            .map(|event| event["seq"].as_u64().expect("seq"))
            .collect()
    }

    #[tokio::test]
    async fn ledger_events_page_handles_thousand_event_chain_without_duplicates() {
        let state = fresh_state().await;
        install_test_ledger(&state, bulk_application_ledger(1005)).await;

        let (status, first) = send(
            state.clone(),
            get("/v1/ledger/events/page?chain=application&limit=50"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["limit"], 50);
        assert_eq!(first["order"], "desc");
        assert_eq!(first["has_more"], true);
        let first_events = first["events"].as_array().expect("first events");
        assert_eq!(first_events.len(), 50);
        assert_eq!(first_events[0]["seq"], 1004);
        assert_eq!(first_events[49]["seq"], 955);
        assert!(
            first_events
                .windows(2)
                .all(|pair| pair[0]["seq"].as_u64() > pair[1]["seq"].as_u64()),
            "page is newest-first: {first_events:?}"
        );
        assert!(first_events[0]["hash"].as_str().expect("hash").len() == 64);
        assert!(
            first_events[0]["prev_hash"]
                .as_str()
                .expect("prev_hash")
                .len()
                == 64
        );

        let cursor = first["next_cursor"].as_u64().expect("next cursor");
        assert_eq!(cursor, 955);
        let (status, second) = send(
            state.clone(),
            get(&format!(
                "/v1/ledger/events/page?chain=application&limit=50&before_seq={cursor}&order=desc"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let second_events = second["events"].as_array().expect("second events");
        assert_eq!(second_events.len(), 50);
        assert_eq!(second_events[0]["seq"], 954);
        assert_eq!(second_events[49]["seq"], 905);
        let first_seq: std::collections::HashSet<u64> = first_events
            .iter()
            .map(|event| event["seq"].as_u64().expect("seq"))
            .collect();
        assert!(
            second_events
                .iter()
                .all(|event| !first_seq.contains(&event["seq"].as_u64().expect("seq"))),
            "second page has no duplicate seq from first page"
        );

        let (status, unsupported) = send(
            state,
            get("/v1/ledger/events/page?chain=application&order=asc"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            unsupported["error"]
                .as_str()
                .expect("error")
                .contains("only desc"),
            "{unsupported}"
        );
    }

    #[tokio::test]
    async fn ledger_events_page_search_folds_accents_like_livros_filters() {
        let state = fresh_state().await;
        install_test_ledger(&state, accented_archive_search_ledger()).await;

        let (status, page) = send(
            state,
            get("/v1/ledger/events/page?q=reuniao%20ordinaria&chain=application&limit=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let events = page["events"].as_array().expect("events");
        assert_eq!(events.len(), 1, "{page}");
        assert_eq!(
            events[0]["justification"],
            "Aprovação dos livros em reunião ordinária"
        );

        let tmp = TempDir::new();
        {
            let first = AppState::with_data_dir(tmp.dir.clone());
            install_test_ledger(&first, accented_archive_search_ledger()).await;
        }
        let restarted = AppState::with_data_dir(tmp.dir.clone());
        *restarted.ledger.write().await = Ledger::new();

        let (status, page) = send(
            restarted,
            get("/v1/ledger/events/page?q=reuniao%20ordinaria&chain=application&limit=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let events = page["events"].as_array().expect("events");
        assert_eq!(events.len(), 1, "{page}");
        assert_eq!(
            events[0]["justification"],
            "Aprovação dos livros em reunião ordinária"
        );
    }

    #[tokio::test]
    async fn ledger_events_page_persistent_thousand_event_chain_pages_after_reload_and_clear() {
        let tmp = TempDir::new();
        {
            let first = AppState::with_data_dir(tmp.dir.clone());
            install_test_ledger(&first, bulk_application_ledger(1005)).await;
        }

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        *restarted.ledger.write().await = Ledger::new();

        let (status, first) = send(
            restarted.clone(),
            get("/v1/ledger/events/page?chain=application&limit=50&order=desc"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["limit"], 50);
        assert_eq!(first["order"], "desc");
        assert_eq!(first["has_more"], true);
        let first_events = first["events"].as_array().expect("first events");
        assert_eq!(first_events.len(), 50, "first page must be bounded");
        assert_eq!(first_events[0]["seq"], 1004);
        assert_eq!(first_events[49]["seq"], 955);
        assert!(
            first_events
                .windows(2)
                .all(|pair| pair[0]["seq"].as_u64() > pair[1]["seq"].as_u64()),
            "page is newest-first: {first_events:?}"
        );

        let cursor = first["next_cursor"].as_u64().expect("next cursor");
        assert_eq!(cursor, 955);
        let (status, second) = send(
            restarted,
            get(&format!(
                "/v1/ledger/events/page?chain=application&limit=50&order=desc&before_seq={cursor}"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["has_more"], true);
        assert_eq!(second["next_cursor"], 905);
        let second_events = second["events"].as_array().expect("second events");
        assert_eq!(second_events.len(), 50);
        assert_eq!(second_events[0]["seq"], 954);
        assert_eq!(second_events[49]["seq"], 905);
        let first_seq: std::collections::HashSet<u64> = first_events
            .iter()
            .map(|event| event["seq"].as_u64().expect("seq"))
            .collect();
        assert!(
            second_events
                .iter()
                .all(|event| !first_seq.contains(&event["seq"].as_u64().expect("seq"))),
            "second page has no duplicate seq from first page"
        );
    }

    #[tokio::test]
    async fn ledger_events_page_filters_by_chain_scope_kind_actor_and_date() {
        let state = fresh_state().await;
        {
            let mut ledger = state.ledger.write().await;
            ledger.append(
                "alice",
                "settings/archive",
                "settings.updated",
                Some("approved by records officer"),
                b"settings",
            );
            ledger.append(
                "alice",
                "settings/archive",
                "settings.reviewed",
                None,
                b"settings-review",
            );
            ledger.append("bruno", "backup/archive", "backup.created", None, b"backup");
        }

        let date = {
            let ledger = state.ledger.read().await;
            ledger.events()[0]
                .timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .expect("timestamp")
                .get(..10)
                .expect("date prefix")
                .to_owned()
        };
        let uri = format!(
            "/v1/ledger/events/page?q=records&chain=application&scope=settings/archive&kind=settings.updated,backup.created&actor=alice&from={date}&to={date}&limit=10"
        );
        let (status, page) = send(state.clone(), get(&uri)).await;
        assert_eq!(status, StatusCode::OK);
        let events = page["events"].as_array().expect("events");
        assert_eq!(events.len(), 1, "{page}");
        assert_eq!(events[0]["kind"], "settings.updated");
        assert_eq!(events[0]["actor"], "alice");
        assert_eq!(events[0]["justification"], "approved by records officer");
        assert_eq!(events[0]["chains"], json!(["global", "application"]));

        let (status, empty) = send(
            state,
            get("/v1/ledger/events/page?chain=application&from=2999-01-01"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(empty["events"].as_array().expect("events").is_empty());
    }

    #[tokio::test]
    async fn ledger_events_page_uses_store_pager_after_reload_and_memory_clear() {
        let tmp = TempDir::new();
        {
            let first = AppState::with_data_dir(tmp.dir.clone());
            install_test_ledger(&first, store_pager_fixture_ledger()).await;
        }

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let uri = "/v1/ledger/events/page?q=needle&chain=book:book-a&scope=act:match&kind=act.sealed&actor=store.actor&limit=3";
        let (status, reloaded_page) = send(restarted.clone(), get(uri)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(event_seqs(&reloaded_page), vec![8, 7, 5]);
        assert_eq!(reloaded_page["has_more"], true);
        assert_eq!(reloaded_page["next_cursor"], 5);
        assert!(
            reloaded_page["events"]
                .as_array()
                .expect("events")
                .iter()
                .all(|event| {
                    event["chains"]
                        .as_array()
                        .expect("chains")
                        .iter()
                        .any(|chain| chain == "book:book-a")
                })
        );

        *restarted.ledger.write().await = Ledger::new();
        let (status, after_clear) = send(restarted.clone(), get(uri)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            event_seqs(&after_clear),
            vec![8, 7, 5],
            "store-backed route must not fall back to the cleared in-memory ledger"
        );

        let (status, older) = send(
            restarted,
            get("/v1/ledger/events/page?q=needle&chain=book:book-a&scope=act:match&kind=act.sealed&actor=store.actor&limit=3&before_seq=5"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(event_seqs(&older), vec![3, 2]);
        assert_eq!(older["has_more"], false);
        assert_eq!(older["next_cursor"], Value::Null);
    }

    #[tokio::test]
    async fn ledger_archive_document_limit_matches_paged_list_for_filtered_exports() {
        let base =
            "/v1/ledger/events/page?chain=application&scope=archive/limit-target&kind=limit.target";
        let export_base = "/v1/ledger/archive/document?chain=application&scope=archive/limit-target&kind=limit.target&format=json";
        let persistent_tmp = TempDir::new();

        for (mode, state) in [
            ("in-memory", fresh_state().await),
            (
                "store-backed",
                AppState::with_data_dir(persistent_tmp.dir.clone()),
            ),
        ] {
            install_archive_limit_ledger(&state).await;
            let (status, page) = send(state.clone(), get(&format!("{base}&limit=10"))).await;
            assert_eq!(status, StatusCode::OK, "{mode} page");
            assert_eq!(page["limit"], 10);

            for (raw_limit, expected_limit) in [("0", 1_usize), ("500", 250_usize)] {
                let (status, page) =
                    send(state.clone(), get(&format!("{base}&limit={raw_limit}"))).await;
                assert_eq!(status, StatusCode::OK, "{mode} page limit={raw_limit}");
                assert_eq!(page["limit"], expected_limit);
                let page_events = page["events"].as_array().expect("page events");
                assert_eq!(page_events.len(), expected_limit);

                let (status, ctype, _disposition, export_bytes) = send_download(
                    state.clone(),
                    get(&format!("{export_base}&limit={raw_limit}")),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{mode} export limit={raw_limit}");
                assert_eq!(ctype, "application/json");
                let export: Value = serde_json::from_slice(&export_bytes).expect("archive json");
                assert_eq!(export["event_count"], expected_limit);
                assert_eq!(export["export_scope"], "bounded_first_page");
                assert_eq!(export["page_limit"], expected_limit);
                assert_eq!(export["record_cap"], Value::Null);
                assert_eq!(export["streamed"], false);
                assert_eq!(export["streaming_mode"], "buffered");
                assert_eq!(export["order"], "desc");
                assert_eq!(export["event_order"], "seq_desc");
                assert_eq!(export["has_more"], true);
                assert!(export["next_cursor"].as_u64().is_some());
                assert!(
                    export["filters"]
                        .as_str()
                        .expect("filters")
                        .contains(&format!("limit={expected_limit}")),
                    "{mode}: {export}"
                );
                let export_events = export["events"].as_array().expect("export events");
                assert_eq!(export_events.len(), page_events.len());
                assert_eq!(
                    export_events
                        .iter()
                        .map(|event| event["seq"].as_u64().expect("export seq"))
                        .collect::<Vec<_>>(),
                    page_events
                        .iter()
                        .map(|event| event["seq"].as_u64().expect("page seq"))
                        .collect::<Vec<_>>(),
                    "{mode}: export order must match page order"
                );
                assert!(export_events.iter().all(|event| {
                    event["kind"] == "limit.target"
                        && event["scope"]
                            .as_str()
                            .expect("scope")
                            .contains("archive/limit-target")
                }));
            }

            let (status, ctype, disposition, export_bytes) = send_download(
                state.clone(),
                get(&format!("{export_base}&export_scope=all_filtered&limit=10")),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{mode} all-filtered export");
            assert_eq!(ctype, "application/json");
            assert!(
                disposition.contains("all-filtered-audit-interchange.json"),
                "{mode}: {disposition}"
            );
            let export: Value = serde_json::from_slice(&export_bytes).expect("archive json");
            assert_eq!(export["export_scope"], "all_filtered");
            assert!(
                export["export_scope_description"]
                    .as_str()
                    .expect("scope description")
                    .contains("every matching filtered ledger event"),
                "{mode}: {export}"
            );
            assert_eq!(export["event_count"], 300);
            assert_eq!(export["page_limit"], Value::Null);
            assert_eq!(export["internal_batch_limit"], 250);
            assert_eq!(export["record_cap"], Value::Null);
            assert_eq!(export["streamed"], true);
            assert_eq!(export["streaming_mode"], "streamed");
            assert_eq!(export["has_more"], false);
            assert_eq!(export["next_cursor"], Value::Null);
            assert_eq!(export["order"], "desc");
            assert_eq!(export["event_order"], "seq_desc");
            assert!(
                !export["filters"]
                    .as_str()
                    .expect("filters")
                    .contains("limit=10"),
                "{mode}: all-filtered export must not use the UI page limit as an export cap"
            );
            let all_events = export["events"].as_array().expect("all export events");
            assert_eq!(all_events.len(), 300);
            assert_eq!(all_events[0]["seq"], 299);
            assert_eq!(all_events[299]["seq"], 0);
            assert!(all_events.windows(2).all(|pair| {
                pair[0]["seq"].as_u64().expect("left seq")
                    > pair[1]["seq"].as_u64().expect("right seq")
            }));
            assert!(all_events.iter().all(|event| {
                event["kind"] == "limit.target"
                    && event["scope"]
                        .as_str()
                        .expect("scope")
                        .contains("archive/limit-target")
            }));
        }
    }

    #[tokio::test]
    async fn ledger_archive_document_streams_all_filtered_audit_interchange_formats() {
        let state = fresh_state().await;
        install_archive_limit_ledger(&state).await;
        let base = "/v1/ledger/archive/document?chain=application&scope=archive/limit-target&kind=limit.target&export_scope=all_filtered";

        let (status, ctype, disposition, txt_bytes) =
            send_download(state.clone(), get(&format!("{base}&format=txt"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctype, "text/plain; charset=utf-8");
        assert!(disposition.contains("all-filtered-audit-interchange.txt"));
        let txt = String::from_utf8(txt_bytes).expect("txt utf8");
        assert!(txt.contains("Modo de geracao: streamed"));
        assert!(txt.contains("Eventos exportados: calculado no fim do fluxo"));
        assert!(txt.contains("Total de eventos exportados: 300"));
        assert!(txt.contains("seq=299 kind=limit.target"));
        assert!(txt.contains("seq=0 kind=limit.target"));

        let (status, ctype, _disposition, csv_bytes) =
            send_download(state.clone(), get(&format!("{base}&format=csv"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctype, "text/csv; charset=utf-8");
        let csv = String::from_utf8(csv_bytes).expect("csv utf8");
        assert!(csv.contains("# streaming_mode=streamed"));
        assert!(csv.contains("# event_count=300"));
        assert!(csv.contains("299,299,limit.target"));
        assert!(csv.contains("0,0,limit.target"));

        let (status, ctype, _disposition, html_bytes) =
            send_download(state, get(&format!("{base}&format=html"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctype, "text/html; charset=utf-8");
        let html = String::from_utf8(html_bytes).expect("html utf8");
        assert!(html.contains("<dd>streamed</dd>"));
        assert!(html.contains("Eventos exportados: 300"));
        assert!(html.contains("<td>299</td>"));
        assert!(html.contains("<td>0</td>"));
    }

    #[tokio::test]
    async fn ledger_archive_document_caps_all_filtered_pdfa_without_truncating() {
        let state = fresh_state().await;
        install_test_ledger(&state, bulk_application_ledger(1001)).await;

        let (status, body) = send(
            state,
            get("/v1/ledger/archive/document?chain=application&export_scope=all_filtered&format=pdfa"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let error = body["error"].as_str().expect("error");
        assert!(error.contains("capped at 1000 records"), "{body}");
        assert!(error.contains("JSON, CSV, TXT, or HTML"), "{body}");
        assert!(error.contains("No records were truncated"), "{body}");
    }

    #[tokio::test]
    async fn ledger_archive_document_search_folds_accents_for_audit_exports() {
        let state = fresh_state().await;
        install_test_ledger(&state, accented_archive_search_ledger()).await;

        let (status, ctype, _disposition, export_bytes) = send_download(
            state,
            get("/v1/ledger/archive/document?format=json&q=aprovacao&chain=application&limit=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctype, "application/json");
        let export: Value = serde_json::from_slice(&export_bytes).expect("archive json");
        assert_eq!(export["event_count"], 1);
        assert_eq!(export["export_scope"], "bounded_first_page");
        assert_eq!(export["page_limit"], 10);
        assert!(
            export["filters"]
                .as_str()
                .expect("filters")
                .contains("pesquisa contem aprovacao"),
            "{export}"
        );
        assert_eq!(
            export["events"][0]["justification"],
            "Aprovação dos livros em reunião ordinária"
        );
    }

    #[tokio::test]
    async fn ledger_archive_document_returns_pdfa_and_rejects_bad_chain() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (status, ctype, bytes) = send_bytes(
            state.clone(),
            get(&format!(
                "/v1/ledger/archive/document?chain=book:{book_id}&scope=book:{book_id}&kind=book.opened&limit=1"
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctype, "application/pdf; profile=PDF/A-2u");
        assert!(bytes.starts_with(b"%PDF-"), "archive export is a PDF");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("<pdfaid:part>2</pdfaid:part>"));
        assert!(text.contains("<pdfaid:conformance>U</pdfaid:conformance>"));

        let (status, body) = send(
            state.clone(),
            get("/v1/ledger/archive/document?chain=not-a-chain"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("invalid chain")
        );

        let (status, body) =
            send(state.clone(), get("/v1/ledger/archive/document?order=asc")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"].as_str().expect("error").contains("only desc"),
            "{body}"
        );

        let (status, body) = send(state, get("/v1/ledger/archive/document?before_seq=10")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("first filtered page"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn ledger_archive_document_exports_audit_interchange_formats_with_filters() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let base = format!(
            "/v1/ledger/archive/document?q=book.opened&chain=book:{book_id}&scope=book:{book_id}&kind=book.opened&limit=1"
        );

        let (status, pdf_type, pdf_disposition, pdf_bytes) =
            send_download(state.clone(), get(&base)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pdf_type, "application/pdf; profile=PDF/A-2u");
        assert!(pdf_disposition.contains("arquivo-book-"));
        assert!(pdf_disposition.contains(".pdf"));
        assert!(pdf_bytes.starts_with(b"%PDF-"));

        let (status, json_type, json_disposition, json_bytes) =
            send_download(state.clone(), get(&format!("{base}&format=json"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_type, "application/json");
        assert!(json_disposition.contains("audit-interchange.json"));
        let export: Value = serde_json::from_slice(&json_bytes).expect("json export");
        assert_eq!(export["export_kind"], "audit_interchange");
        assert_eq!(export["canonical_preserved_evidence"], false);
        assert_eq!(export["event_count"], 1);
        assert_eq!(export["export_scope"], "bounded_first_page");
        assert_eq!(export["page_limit"], 1);
        assert_eq!(export["has_more"], false);
        assert_eq!(export["next_cursor"], Value::Null);
        assert_eq!(export["order"], "desc");
        assert_eq!(export["event_order"], "seq_desc");
        assert!(
            export["filters"]
                .as_str()
                .expect("filters")
                .contains("pesquisa contem book.opened"),
            "{export}"
        );
        assert!(
            export["filters"]
                .as_str()
                .expect("filters")
                .contains("order=desc"),
            "{export}"
        );
        assert_eq!(export["events"][0]["kind"], "book.opened");
        assert!(
            export["events"][0]["scope"]
                .as_str()
                .expect("scope")
                .contains(&format!("book:{book_id}"))
        );
        assert!(export["events"][0]["hash"].as_str().expect("hash").len() == 64);

        let (status, txt_type, txt_disposition, txt_bytes) =
            send_download(state.clone(), get(&format!("{base}&format=txt"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(txt_type, "text/plain; charset=utf-8");
        assert!(txt_disposition.contains("audit-interchange.txt"));
        let txt = String::from_utf8(txt_bytes).expect("txt utf8");
        assert!(txt.contains("Audit/interchange export only"));
        assert!(txt.contains("Ambito da exportacao: bounded_first_page"));
        assert!(txt.contains("Ordem: desc"));
        assert!(txt.contains("Eventos exportados: 1"));
        assert!(txt.contains("kind=book.opened"));

        let (status, csv_type, csv_disposition, csv_bytes) =
            send_download(state.clone(), get(&format!("{base}&format=csv"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(csv_type, "text/csv; charset=utf-8");
        assert!(csv_disposition.contains("audit-interchange.csv"));
        let csv = String::from_utf8(csv_bytes).expect("csv utf8");
        assert!(csv.contains("# export_scope=bounded_first_page"));
        assert!(csv.contains("# order=desc"));
        assert!(csv.contains("seq,chain_seq,kind,scope,actor,timestamp"));
        assert!(csv.contains("book.opened"));

        let (status, html_type, html_disposition, html_bytes) =
            send_download(state, get(&format!("{base}&format=html"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(html_type, "text/html; charset=utf-8");
        assert!(html_disposition.contains("audit-interchange.html"));
        let html = String::from_utf8(html_bytes).expect("html utf8");
        assert!(html.contains("Audit/interchange export only"));
        assert!(html.contains("bounded_first_page"));
        assert!(html.contains("desc (seq global decrescente)"));
        assert!(html.contains("book.opened"));
    }

    #[tokio::test]
    async fn ledger_archive_document_requires_global_ledger_read() {
        let state = fresh_state().await;
        let user = seed_user(&state, "sem.ledger", vec![]).await;
        let token = seed_session(&state, &user.to_string()).await;

        let (status, body) = send_raw(
            state,
            with_session(get("/v1/ledger/archive/document"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "RBAC denial body: {body}"
        );
    }

    /// Draft an ata into `book_id`, fill mandatory (compliance-clean) contents, and advance it to
    /// Signing; returns the act id. Mirrors `full_lifecycle_happy_path`'s fill.
    async fn draft_fill_and_advance(state: &AppState, book_id: &str) -> String {
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas do exercício.",
                }),
            ),
        )
        .await;
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        act_id
    }

    #[tokio::test]
    async fn seal_persists_manual_signature_original_reference_as_metadata_only() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, sealed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({
                    "manual_signature_original_reference": {
                        "storage_reference": "  Arquivo A / Pasta 2026 / Ata 1  ",
                        "custodian": "  Secretariado  ",
                        "note": "Original assinado manualmente; referência local apenas."
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let metadata = &sealed["act"]["seal_metadata"];
        let reference = &metadata["manual_signature_original_reference"];
        assert_eq!(
            reference["storage_reference"],
            "Arquivo A / Pasta 2026 / Ata 1"
        );
        assert_eq!(reference["custodian"], "Secretariado");
        assert_eq!(
            reference["note"],
            "Original assinado manualmente; referência local apenas."
        );
        for claim in [
            "legal_validity_claimed",
            "signature_validation_claimed",
            "qualified_signature_claimed",
            "archive_certification_claimed",
            "manual_signature_verified",
        ] {
            assert!(
                metadata.get(claim).is_none() && reference.get(claim).is_none(),
                "manual reference must not expose claim flag {claim}: {metadata}"
            );
        }

        let (status, got) = send(state.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            got["seal_metadata"]["manual_signature_original_reference"],
            *reference
        );

        let (status, body) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "title": "Tentativa de mutação pós-selo",
                    "seal_metadata": {
                        "manual_signature_original_reference": {
                            "storage_reference": "Outro arquivo"
                        }
                    }
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "sealed act patch must be rejected: {body}"
        );

        let (status, after_patch) = send(state, get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            after_patch["seal_metadata"]["manual_signature_original_reference"],
            *reference
        );
    }

    #[tokio::test]
    async fn seal_rejects_missing_manual_signature_original_reference_without_mutation() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, body) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("manual_signature_original_reference"),
            "validation error names the missing reference: {body}"
        );

        let (status, act) = send(state, get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(act["state"], "Signing");
        assert!(act["seal_metadata"].is_null());
        assert!(act["ata_number"].is_null());
    }

    #[tokio::test]
    async fn seal_rejects_invalid_manual_signature_original_reference_without_mutation() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        for (value, expected) in [
            ("   ".to_owned(), "must not be empty"),
            ("Arquivo\u{0007}A".to_owned(), "control characters"),
            ("R".repeat(513), "at most 512 characters"),
        ] {
            let (status, body) = send(
                state.clone(),
                post_json(
                    &format!("/v1/acts/{act_id}/seal"),
                    json!({
                        "manual_signature_original_reference": {
                            "storage_reference": value
                        }
                    }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            let error = body["error"].as_str().expect("error");
            assert!(
                error.contains("storage_reference") && error.contains(expected),
                "validation error names storage_reference and {expected}: {body}"
            );
        }

        let (status, act) = send(state, get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(act["state"], "Signing");
        assert!(act["seal_metadata"].is_null());
        assert!(act["ata_number"].is_null());
    }

    #[tokio::test]
    async fn seal_rejects_nested_manual_signature_original_reference_without_mutation() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, _content_type, body) = send_bytes(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({
                    "manual_signature_original_reference": {
                        "manual_signature_original_reference": {}
                    }
                }),
            ),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "nested reference must not seal: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "nested reference should be rejected by request validation before mutation: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let (status, act) = send(state, get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(act["state"], "Signing");
        assert!(act["seal_metadata"].is_null());
        assert!(act["ata_number"].is_null());
    }

    #[tokio::test]
    async fn seal_accepts_max_length_reference_and_omits_empty_optional_custody_fields() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let storage_reference = "R".repeat(512);

        let (status, sealed) = send(
            state,
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({
                    "manual_signature_original_reference": {
                        "storage_reference": storage_reference,
                        "custodian": "   ",
                        "note": ""
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let reference = &sealed["act"]["seal_metadata"]["manual_signature_original_reference"];
        assert_eq!(reference["storage_reference"].as_str().unwrap().len(), 512);
        assert!(
            reference.get("custodian").is_none(),
            "empty custodian is omitted: {reference}"
        );
        assert!(
            reference.get("note").is_none(),
            "empty note is omitted: {reference}"
        );
    }

    #[tokio::test]
    async fn guest_act_read_redacts_manual_signature_original_reference() {
        use chancela_authz::{GUEST_ROLE_ID, RoleAssignment, RoleCatalog, Scope};

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, sealed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({
                    "manual_signature_original_reference": {
                        "storage_reference": "Cofre documental 2 / Ata AG 2026",
                        "custodian": "Secretariado",
                        "note": "Original em papel; referência local apenas."
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        assert!(
            sealed["act"]["seal_metadata"]["manual_signature_original_reference"].is_object(),
            "owner response keeps manual reference: {sealed}"
        );

        *state.roles.write().await = RoleCatalog::seeded_defaults();
        let guest_id = seed_user(
            &state,
            "guest.manual-reference",
            vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        )
        .await;
        let guest_token = seed_session(&state, &guest_id.to_string()).await;

        let (status, guest_view) = send_raw(
            state,
            with_session(get(&format!("/v1/acts/{act_id}")), &guest_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{guest_view}");
        assert_eq!(
            guest_view["seal_metadata"]["rule_pack_id"], "csc-art63/v2",
            "guest still sees non-sensitive seal metadata"
        );
        assert!(
            guest_view["seal_metadata"]
                .get("manual_signature_original_reference")
                .is_none(),
            "guest response suppresses manual reference: {guest_view}"
        );
        let redacted = guest_view.to_string();
        for sensitive in [
            "manual_signature_original_reference",
            "storage_reference",
            "Cofre documental 2",
            "Secretariado",
            "Original em papel",
        ] {
            assert!(
                !redacted.contains(sensitive),
                "guest view leaked {sensitive}: {redacted}"
            );
        }
    }

    #[tokio::test]
    async fn guest_book_act_feed_redacts_manual_signature_original_reference() {
        use chancela_authz::{GUEST_ROLE_ID, RoleAssignment, RoleCatalog, Scope};

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, sealed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                json!({
                    "manual_signature_original_reference": {
                        "storage_reference": "Cofre documental 2 / Ata AG 2026",
                        "custodian": "Secretariado",
                        "note": "Original em papel; referência local apenas."
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");

        *state.roles.write().await = RoleCatalog::seeded_defaults();
        let guest_id = seed_user(
            &state,
            "guest.book-act-feed.manual-reference",
            vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        )
        .await;
        let guest_token = seed_session(&state, &guest_id.to_string()).await;

        let (status, feed) = send_raw(
            state,
            with_session(get(&format!("/v1/books/{book_id}/acts")), &guest_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{feed}");
        let act = feed
            .as_array()
            .expect("book acts feed")
            .iter()
            .find(|row| row["id"].as_str() == Some(act_id.as_str()))
            .expect("sealed act present in feed");
        assert_eq!(
            act["seal_metadata"]["rule_pack_id"], "csc-art63/v2",
            "guest still sees non-sensitive seal metadata in book feed"
        );
        assert!(
            act["seal_metadata"]
                .get("manual_signature_original_reference")
                .is_none(),
            "guest book feed suppresses manual reference: {feed}"
        );

        let redacted = feed.to_string();
        for sensitive in [
            "manual_signature_original_reference",
            "storage_reference",
            "Cofre documental 2",
            "Secretariado",
            "Original em papel",
        ] {
            assert!(
                !redacted.contains(sensitive),
                "guest book feed leaked {sensitive}: {redacted}"
            );
        }
    }

    #[tokio::test]
    async fn seal_produces_a_document_and_a_document_generated_event() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // Pre-seal the persisted PDF is 404 (no document until sealing).
        let (status, _, _) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Seal → the additive `document` block names the PDF/A digest + pinned template version.
        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let doc = &sealed["document"];
        assert_eq!(doc["template_id"], "csc-ata-ag/v1");
        assert_eq!(doc["pdf_digest"].as_str().expect("digest").len(), 64);
        assert!(doc["id"].is_string());

        // A `document.generated` event is bound into the chain.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "document.generated"),
            "a document.generated event was appended: {events}"
        );

        // The persisted PDF now downloads as application/pdf and carries the PDF header.
        let (status, ctype, bytes) =
            send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "content-type={ctype}");
        assert!(bytes.starts_with(b"%PDF-"), "bytes start with a PDF header");
    }

    #[tokio::test]
    async fn document_preview_renders_a_model_pre_seal_without_persisting() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "deliberations": "Aprovadas.",
                }),
            ),
        )
        .await;

        // Preview renders the CURRENT (draft) record live to a DocumentModel.
        let (status, model) = send(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/preview")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(model["title"], "Ata da AG anual");
        assert_eq!(model["language"], "pt-PT");
        assert!(!model["blocks"].as_array().expect("blocks").is_empty());

        // Preview does NOT persist: the PDF endpoint is still 404.
        let (status, _, _) = send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn working_copy_export_formats_are_non_evidentiary_and_read_only() {
        use std::io::Read;

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, _, _) = send_raw_bytes(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/working-copy")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "working-copy export is session-gated"
        );

        let token = auth_token(&state).await;
        let (status, sealed) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let doc = &sealed["document"];
        let doc_id = doc["id"].as_str().expect("document id");
        let digest = doc["pdf_digest"].as_str().expect("pdf digest");

        let (status, _, pdf_before) = send_bytes(
            state.clone(),
            with_session(get(&format!("/v1/acts/{act_id}/document")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, events_before) = send(
            state.clone(),
            with_session(get("/v1/ledger/events?limit=1000"), &token),
        )
        .await;

        for (query, expected_type, expected_ext, format_notice) in [
            ("", "text/markdown", ".md", "Markdown export"),
            ("?format=txt", "text/plain", ".txt", "plain-text export"),
            ("?format=html", "text/html", ".html", "HTML export"),
            ("?format=rtf", "application/rtf", ".rtf", "RTF export"),
        ] {
            let (status, headers, body) = send_raw_bytes(
                state.clone(),
                with_session(
                    get(&format!("/v1/acts/{act_id}/document/working-copy{query}")),
                    &token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "format query {query:?}");
            assert!(
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with(expected_type)),
                "working copy content-type for {query:?}: {headers:?}"
            );
            let disposition = headers
                .get("content-disposition")
                .and_then(|value| value.to_str().ok())
                .expect("content-disposition");
            assert!(
                disposition.contains("working-copy") && disposition.contains(expected_ext),
                "filename labels working copy for {query:?}: {disposition}"
            );
            let body = String::from_utf8(body).expect("working copy is utf-8");
            assert!(body.contains("WORKING COPY - NON-EVIDENTIARY"));
            assert!(body.contains(format_notice));
            assert!(body.contains("not the preserved signed original"));
            assert!(body.contains(doc_id));
            assert!(body.contains(digest));
            assert!(body.contains("Ata da AG anual"));
            assert!(body.contains("Sede social"));
            assert!(!body.starts_with("%PDF-"));
        }

        let odt_request = || {
            with_session(
                get(&format!(
                    "/v1/acts/{act_id}/document/working-copy?format=odt"
                )),
                &token,
            )
        };
        let (status, headers, first_odt) = send_raw_bytes(state.clone(), odt_request()).await;
        assert_eq!(status, StatusCode::OK, "ODT working-copy export succeeds");
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/vnd.oasis.opendocument.text")
        );
        let disposition = headers
            .get("content-disposition")
            .and_then(|value| value.to_str().ok())
            .expect("content-disposition");
        assert!(
            disposition.contains("working-copy") && disposition.contains(".odt"),
            "filename labels ODT working copy: {disposition}"
        );
        assert!(first_odt.starts_with(b"PK"), "ODT is a zip package");
        let (status, _, second_odt) = send_raw_bytes(state.clone(), odt_request()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "second ODT working-copy export succeeds"
        );
        assert_eq!(second_odt, first_odt, "ODT export bytes are deterministic");

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(first_odt)).expect("valid odt");
        assert_eq!(
            archive.by_index(0).expect("first ODT member").name(),
            "mimetype",
            "ODT mimetype is the first stored member"
        );
        let mut mimetype = String::new();
        archive
            .by_name("mimetype")
            .expect("mimetype member")
            .read_to_string(&mut mimetype)
            .expect("mimetype reads");
        assert_eq!(mimetype, "application/vnd.oasis.opendocument.text");
        let mut content_xml = String::new();
        archive
            .by_name("content.xml")
            .expect("content.xml member")
            .read_to_string(&mut content_xml)
            .expect("content.xml reads");
        assert!(content_xml.contains("WORKING COPY - NON-EVIDENTIARY"));
        assert!(content_xml.contains("not the preserved signed original"));
        assert!(content_xml.contains(doc_id));
        assert!(content_xml.contains(digest));
        assert!(content_xml.contains("Ata da AG anual"));

        let (status, _, pdf_after) = send_bytes(
            state.clone(),
            with_session(get(&format!("/v1/acts/{act_id}/document")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            pdf_after, pdf_before,
            "working-copy export must not alter preserved PDF/A bytes"
        );
        let (_, events_after) = send(
            state.clone(),
            with_session(get("/v1/ledger/events?limit=1000"), &token),
        )
        .await;
        assert_eq!(
            events_after, events_before,
            "working-copy export must not append ledger events"
        );
        let (_, verify) = send(state, with_session(get("/v1/ledger/verify"), &token)).await;
        assert_eq!(verify["valid"], true, "ledger still verifies");
    }

    #[tokio::test]
    async fn office_export_is_docx_deterministic_non_evidentiary_and_read_only() {
        use std::io::Read;

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, _, _) = send_raw_bytes(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/office")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "office export is session-gated"
        );

        let token = auth_token(&state).await;
        let (status, sealed) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let doc = &sealed["document"];
        let doc_id = doc["id"].as_str().expect("document id");
        let digest = doc["pdf_digest"].as_str().expect("pdf digest");

        let (_, events_before) = send(
            state.clone(),
            with_session(get("/v1/ledger/events?limit=1000"), &token),
        )
        .await;

        let request = || with_session(get(&format!("/v1/acts/{act_id}/document/office")), &token);
        let (status, headers, first) = send_raw_bytes(state.clone(), request()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        );
        let disposition = headers
            .get("content-disposition")
            .and_then(|value| value.to_str().ok())
            .expect("content-disposition");
        assert!(
            disposition.contains("office-working-copy") && disposition.contains(".docx"),
            "filename labels office working copy: {disposition}"
        );
        assert!(first.starts_with(b"PK"), "DOCX is a zip package");

        let (status, _, second) = send_raw_bytes(state.clone(), request()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second, first, "office export bytes are deterministic");

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(first)).expect("valid docx");
        let mut document_xml = String::new();
        archive
            .by_name("word/document.xml")
            .expect("document part")
            .read_to_string(&mut document_xml)
            .expect("document xml reads");
        assert!(document_xml.contains("WORKING COPY - NON-EVIDENTIARY"));
        assert!(document_xml.contains("not the preserved signed original"));
        assert!(document_xml.contains(doc_id));
        assert!(document_xml.contains(digest));
        assert!(document_xml.contains("Ata da AG anual"));

        let (_, events_after) = send(
            state.clone(),
            with_session(get("/v1/ledger/events?limit=1000"), &token),
        )
        .await;
        assert_eq!(
            events_after, events_before,
            "office export must not append ledger events"
        );
        let (_, verify) = send(state, with_session(get("/v1/ledger/verify"), &token)).await;
        assert_eq!(verify["valid"], true, "ledger still verifies");
    }

    #[tokio::test]
    async fn office_export_requires_a_preserved_document_and_rebuildable_model() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, _, _) = send_bytes(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/office")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "draft has no preserved document to export"
        );

        let orphan_act_id = ActId(Uuid::new_v4());
        state.documents.write().await.insert(
            orphan_act_id,
            StoredDocument {
                id: "orphan-document".to_owned(),
                act_id: orphan_act_id,
                template_id: "csc-ata-ag/v1".to_owned(),
                pdf_digest: "00".repeat(32),
                profile: crate::documents::PDFA_PROFILE.to_owned(),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                pdf_bytes: b"%PDF-1.7\n".to_vec(),
            },
        );

        let (status, body) = send(
            state,
            get(&format!("/v1/acts/{orphan_act_id}/document/office")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("editable document model"),
            "409 explains missing model: {body}"
        );
    }

    #[tokio::test]
    async fn document_import_persists_lists_reads_and_survives_restart_without_replacing_canonical()
    {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let token = auth_token(&state).await;
        let (_entity_id, book_id) = seed_entity_and_book(&state, &token).await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, sealed) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let (status, _, canonical_before) = send_bytes(
            state.clone(),
            with_session(get(&format!("/v1/acts/{act_id}/document")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let imported_pdf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n0\n%%EOF\n".to_vec();
        let body = json!({
            "act_id": act_id,
            "filename": "supporting-evidence.pdf",
            "content_type": "application/pdf",
            "content_base64": B64.encode(&imported_pdf),
            "access_code": "SECRET-SHOULD-BE-IGNORED"
        });

        let ledger_before = state.ledger.read().await.len();
        let imports_before = state
            .store
            .as_ref()
            .expect("store")
            .imported_documents(None)
            .expect("import list")
            .len();
        let (status, validation) = send(
            state.clone(),
            with_session(
                post_json("/v1/documents/import/validate", body.clone()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "validate: {validation}");
        assert_eq!(validation["can_accept_non_canonical_import"], true);
        assert_eq!(
            state.ledger.read().await.len(),
            ledger_before,
            "validate stays read-only"
        );
        assert_eq!(
            state
                .store
                .as_ref()
                .expect("store")
                .imported_documents(None)
                .expect("import list")
                .len(),
            imports_before,
            "validate must not create imported rows"
        );

        let (status, imported) = send(
            state.clone(),
            with_session(post_json("/v1/documents/import", body.clone()), &token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "import: {imported}");
        let import_id = imported["id"].as_str().expect("import id").to_owned();
        Uuid::parse_str(&import_id).expect("import id is uuid");
        assert_eq!(imported["act_id"].as_str(), Some(act_id.as_str()));
        assert_eq!(imported["filename"], "supporting-evidence.pdf");
        assert_eq!(imported["detected_content_type"], "application/pdf");
        assert_eq!(
            imported["size_bytes"].as_u64(),
            Some(imported_pdf.len() as u64)
        );
        assert_eq!(imported["non_canonical"], true);
        assert!(
            imported["legal_notice"]
                .as_str()
                .expect("notice")
                .contains("does not replace")
        );

        {
            let ledger = state.ledger.read().await;
            let event = ledger.events().last().expect("import event");
            assert_eq!(event.kind, "document.imported");
            assert!(event.scope.contains(&format!("act:{act_id}")));
            assert!(
                event
                    .scope
                    .contains(&format!("imported-document:{import_id}"))
            );
        }

        let (status, _, canonical_after) = send_bytes(
            state.clone(),
            with_session(get(&format!("/v1/acts/{act_id}/document")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            canonical_after, canonical_before,
            "import must not replace the preserved PDF/A"
        );

        let (status, list) = send(
            state.clone(),
            with_session(
                get(&format!("/v1/documents/imported?act_id={act_id}")),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list: {list}");
        assert_eq!(list.as_array().expect("list").len(), 1);
        assert_eq!(list[0]["id"].as_str(), Some(import_id.as_str()));

        let (status, read) = send(
            state.clone(),
            with_session(get(&format!("/v1/documents/imported/{import_id}")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "read: {read}");
        assert_eq!(read, imported);
        assert!(
            !serde_json::to_string(&read)
                .expect("read json")
                .contains("SECRET-SHOULD-BE-IGNORED"),
            "unknown secret fields are not reflected"
        );

        let (status, content_type, bytes) = send_bytes(
            state.clone(),
            with_session(
                get(&format!("/v1/documents/imported/{import_id}/bytes")),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "application/pdf");
        assert_eq!(bytes, imported_pdf);

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let restarted_token = auth_token(&restarted).await;
        let (status, restarted_read) = send(
            restarted.clone(),
            with_session(
                get(&format!("/v1/documents/imported/{import_id}")),
                &restarted_token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "read after restart: {restarted_read}"
        );
        assert_eq!(restarted_read["id"].as_str(), Some(import_id.as_str()));
        let (status, _, restarted_bytes) = send_bytes(
            restarted,
            with_session(
                get(&format!("/v1/documents/imported/{import_id}/bytes")),
                &restarted_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(restarted_bytes, imported_pdf);
    }

    #[tokio::test]
    async fn document_import_fails_closed_on_auth_invalid_content_and_path_names() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};

        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let owner = auth_token(&state).await;
        let pdf = b"%PDF-1.7\nstartxref\n0\n%%EOF\n".to_vec();
        let good = json!({
            "filename": "evidence.pdf",
            "content_type": "application/pdf",
            "content_base64": B64.encode(&pdf)
        });

        let (status, _) = send_raw(
            state.clone(),
            post_json("/v1/documents/import", good.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "session required");

        let leitor = seed_user(
            &state,
            "document.reader",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let leitor_token = seed_session(&state, &leitor.to_string()).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/documents/import", good.clone()),
                &leitor_token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Leitor cannot import: {body}"
        );

        let bad_name = json!({
            "filename": "../secret.pdf",
            "content_type": "application/pdf",
            "content_base64": B64.encode(&pdf)
        });
        let (status, _) = send(
            state.clone(),
            with_session(post_json("/v1/documents/import", bad_name), &owner),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let empty = json!({
            "filename": "empty.pdf",
            "content_type": "application/pdf",
            "content_base64": B64.encode(Vec::<u8>::new())
        });
        let (status, body) = send(
            state.clone(),
            with_session(post_json("/v1/documents/import", empty), &owner),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty rejected: {body}"
        );

        let not_pdf = json!({
            "filename": "note.txt",
            "content_type": "text/plain",
            "content_base64": B64.encode(b"not a pdf")
        });
        let (status, body) = send(
            state.clone(),
            with_session(post_json("/v1/documents/import", not_pdf), &owner),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "non-pdf rejected: {body}"
        );

        assert!(
            state
                .store
                .as_ref()
                .expect("store")
                .imported_documents(None)
                .expect("import list")
                .is_empty(),
            "failed imports must not persist rows"
        );
        assert!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .all(|event| event.kind != "document.imported"),
            "failed imports must not append ledger events"
        );
    }

    #[tokio::test]
    async fn templates_list_exposes_the_spine_templates() {
        let state = AppState::default();
        let (status, all) = send(state.clone(), get("/v1/templates")).await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<&str> = all
            .as_array()
            .expect("templates")
            .iter()
            .map(|t| t["id"].as_str().expect("id"))
            .collect();
        assert!(ids.contains(&"csc-ata-ag/v1"));
        assert!(ids.contains(&"csc-termo-abertura/v1"));

        // Filter by family + stage.
        let (status, ata) = send(
            state.clone(),
            get("/v1/templates?family=CommercialCompany&stage=Ata"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = ata.as_array().expect("filtered templates");
        assert!(arr.iter().all(|t| t["stage"] == "Ata"));
        assert!(
            arr.iter()
                .any(|t| t["id"] == "csc-ata-ag/v1" && t["locale"] == "pt-PT")
        );
        let spine = arr
            .iter()
            .find(|t| t["id"] == "csc-ata-ag/v1")
            .expect("csc ata spine summary");
        assert_eq!(spine["family"], "CommercialCompany");
        assert_eq!(spine["editable"], false);
        assert_eq!(spine["source"], "builtin");
        assert_eq!(spine["signature_policy"], "QualifiedPreferred");
        assert_eq!(spine["rule_pack_id"], "csc-art63/v2");
        assert_eq!(
            spine["channels"],
            serde_json::json!(["Physical", "Hybrid", "Telematic", "WrittenResolution"])
        );

        let (status, certidao) = send(
            state,
            get("/v1/templates?family=CommercialCompany&stage=Certidao"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let certidao_arr = certidao.as_array().expect("filtered certidao templates");
        assert!(
            certidao_arr.iter().any(|t| {
                t["id"] == "csc-certidao-ata/v1" && t["channels"] == serde_json::json!([])
            }),
            "non-meeting summaries keep the asset's empty channel metadata"
        );
    }

    #[tokio::test]
    async fn user_template_management_routes_accept_encoded_ids_and_emit_ledger_events() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let token = auth_token(&state).await;
        let id = "user-route-ata/v1";
        let encoded_id = "user-route-ata%2Fv1";
        let create_body = template_body(id, "Ata n.º {{ ata_number }}");

        let (status, created) = send_raw(
            state.clone(),
            with_session(post_json("/v1/templates", create_body.clone()), &token),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create: {created}");
        assert_eq!(created["id"], id);
        assert_eq!(created["editable"], true);
        assert_eq!(created["source"], "user");

        let replace_body = template_body(id, "Ata revista n.º {{ ata_number }}");
        let (status, updated) = send_raw(
            state.clone(),
            with_session(
                put_json(&format!("/v1/templates/{encoded_id}"), replace_body.clone()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "replace: {updated}");
        assert_eq!(updated["id"], id);
        assert_eq!(updated["editable"], true);
        assert_eq!(updated["source"], "user");

        let (status, verdict) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/templates/import?dry_run=true", replace_body),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "dry-run: {verdict}");
        assert_eq!(verdict["ok"], false);
        assert_eq!(verdict["error"]["code"], "conflict");

        let (status, content_type, disposition, bytes) = send_download(
            state.clone(),
            with_session(get(&format!("/v1/templates/{encoded_id}/export")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export status");
        assert_eq!(content_type, "application/json");
        assert_eq!(
            disposition,
            "attachment; filename=\"user-route-ata-v1.json\""
        );
        let exported: Value = serde_json::from_slice(&bytes).expect("export JSON");
        assert_eq!(exported["id"], id);
        assert_eq!(
            exported["blocks"][0]["template"],
            "Ata revista n.º {{ ata_number }}"
        );

        let status = send_status(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/templates/{encoded_id}"), json!({})),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let ledger = state.ledger.read().await;
        let template_events: Vec<_> = ledger
            .events()
            .iter()
            .filter(|event| event.kind.starts_with("template."))
            .collect();
        let kinds: Vec<&str> = template_events
            .iter()
            .map(|event| event.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec!["template.created", "template.updated", "template.deleted"]
        );
        assert!(template_events.iter().all(|event| event.scope == "global"));

        let created_payload = serde_json::to_vec(&json!({
            "template_id": id,
            "action": "created",
            "family": "CommercialCompany",
            "stage": "Ata",
            "locale": "pt-PT",
            "source": "user",
        }))
        .expect("created payload JSON");
        let deleted_payload = serde_json::to_vec(&json!({
            "template_id": id,
            "action": "deleted",
            "source": "user",
        }))
        .expect("deleted payload JSON");
        assert_eq!(
            template_events[0].payload_digest,
            <[u8; 32]>::from(Sha256::digest(&created_payload))
        );
        assert_eq!(
            template_events[2].payload_digest,
            <[u8; 32]>::from(Sha256::digest(&deleted_payload))
        );
    }

    #[tokio::test]
    async fn opening_a_book_produces_a_preserved_termo_document() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // A `document.generated` event for the termo is on the chain right after opening.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "document.generated"),
            "opening a book emits a document.generated event: {events}"
        );

        // The termo PDF is preserved, keyed by the book id (book instruments have no owning act).
        let (status, ctype, bytes) =
            send_bytes(state, get(&format!("/v1/acts/{book_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "content-type={ctype}");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[tokio::test]
    async fn document_bundle_populates_the_validation_report() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // The bundle is 404 until sealed.
        let (status, _) = send(
            state.clone(),
            get(&format!("/v1/acts/{act_id}/document/bundle")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;

        let (status, bundle) =
            send(state, get(&format!("/v1/acts/{act_id}/document/bundle"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bundle["document"]["template_id"], "csc-ata-ag/v1");
        assert_eq!(
            bundle["document"]["profile"],
            "application/pdf; profile=PDF/A-2u"
        );
        assert_eq!(bundle["pdf"]["media_type"], "application/pdf");
        assert!(bundle["pdf"]["byte_length"].as_u64().expect("length") > 0);
        assert!(bundle["attachments_manifest"].is_array());
        let report = &bundle["validation_report"];
        assert_eq!(report["report_kind"], "document_bundle_validation");
        assert_eq!(report["scope"], "generated_document_bundle");
        assert_eq!(report["status"], "technical_warning");
        assert_eq!(
            report["evidence_index"]["index_kind"],
            "document_bundle_evidence_index"
        );
        assert_eq!(
            report["evidence_index"]["status_scope"],
            "technical_metadata_only"
        );
        assert_eq!(report["evidence_index"]["act_id"], act_id);
        assert_eq!(
            report["evidence_index"]["document_id"],
            bundle["document"]["id"]
        );
        assert_eq!(
            report["evidence_index"]["bundle_paths"]["canonical_pdf_download"],
            format!("/v1/acts/{act_id}/document")
        );
        assert_eq!(
            report["evidence_index"]["bundle_paths"]["signed_pdf_download"],
            serde_json::Value::Null
        );
        assert_eq!(
            report["evidence_index"]["bundle_paths"]["attachments_manifest_json_pointer"],
            "/attachments_manifest"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["evidence_kind"],
            "pdf_accessibility_report"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["metadata_schema"],
            "chancela-pdf-accessibility-evidence/v1"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["bundle_report_json_pointer"],
            "/validation_report/pdf_accessibility"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["archive_path_pattern"],
            "evidence/pdf-accessibility/{document_id}.json"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["evidence_status"],
            "pdf_accessibility_report_attached"
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["pdf_ua_claimed"],
            true
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["dglab_certification_claimed"],
            false
        );
        assert_eq!(
            report["evidence_index"]["pdf_accessibility"]["legal_validity_claimed"],
            false
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["evidence_kind"],
            "external_validator_report_metadata"
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["metadata_schema"],
            "chancela-external-validator-report-evidence/v1"
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["archive_path_pattern"],
            "evidence/external-validators/{case_id}-{validator_family}.json"
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["raw_report_path_pattern"],
            "evidence/external-validators/{case_id}-{validator_family}-raw-report.{extension}"
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["bundle_attachment_status"],
            "no_external_validator_report_metadata_attached"
        );
        assert_eq!(
            report["evidence_index"]["external_validator_reports"]["attachments"],
            serde_json::json!([])
        );
        let evidence_index_text = serde_json::to_string(&report["evidence_index"])
            .expect("evidence index JSON serializes");
        assert!(
            !evidence_index_text.contains("trust-list")
                && !evidence_index_text.contains("trust_list"),
            "evidence index stays local technical metadata scoped: {report}"
        );
        assert!(
            !evidence_index_text.contains("pdfuaid")
                && !evidence_index_text.contains("DGLAB")
                && !evidence_index_text.contains("\"dglab_certification_claimed\":true")
                && !evidence_index_text.contains("\"legal_validity_claimed\":true"),
            "evidence index must not carry DGLAB or legal-validity claims: {report}"
        );
        assert_eq!(report["canonical_pdf"]["present"], true);
        assert_eq!(report["canonical_pdf"]["media_type"], "application/pdf");
        assert_eq!(
            report["pdf_accessibility"]["evidence_kind"],
            "pdf_accessibility_report"
        );
        assert_eq!(
            report["pdf_accessibility"]["evidence_status"],
            "pdf_accessibility_report_attached"
        );
        assert_eq!(report["pdf_accessibility"]["pdf_ua_claimed"], true);
        assert_eq!(
            report["pdf_accessibility"]["dglab_certification_claimed"],
            false
        );
        assert_eq!(report["pdf_accessibility"]["legal_validity_claimed"], false);
        assert_eq!(report["pdf_accessibility"]["report_version"], json!(12));
        assert_eq!(
            report["pdf_accessibility"]["accessibility_report_json"]["version"],
            json!(12)
        );
        let table_semantics =
            &report["pdf_accessibility"]["accessibility_report_json"]["tagged_structure"]["tables"];
        assert_eq!(table_semantics["header_cells_have_scope"], true);
        assert_eq!(table_semantics["table_rows_missing_header_count"], json!(0));
        assert_eq!(table_semantics["row_header_cells_have_scope_row"], true);
        assert_eq!(
            table_semantics["column_header_cells_have_scope_column"],
            true
        );
        assert_eq!(
            report["pdf_accessibility"]["accessibility_report_json"]["pdf_ua_claimed"],
            true
        );
        assert_eq!(
            report["pdf_accessibility"]["pdf_ua_blockers"]
                .as_array()
                .expect("accessibility blockers"),
            &Vec::<serde_json::Value>::new(),
            "conforming document has no remaining PDF/UA blockers: {report}"
        );
        let accessibility_text =
            serde_json::to_string(&report["pdf_accessibility"]).expect("accessibility JSON");
        assert!(
            !accessibility_text.contains("pdfuaid")
                && !accessibility_text.contains("DGLAB")
                && !accessibility_text.contains("\"dglab_certification_claimed\":true")
                && !accessibility_text.contains("\"legal_validity_claimed\":true"),
            "accessibility evidence never carries DGLAB or legal-validity claims: {report}"
        );
        assert_eq!(
            report["fixity"]["canonical_pdf_sha256"],
            bundle["document"]["pdf_digest"]
        );
        assert_eq!(
            report["fixity"]["canonical_pdf_digest_matches_metadata"],
            true
        );
        assert_eq!(
            report["bundle_document_consistency"]["act_id_matches_document"],
            true
        );
        assert_eq!(report["signed_document"]["present"], false);
        assert_eq!(report["signed_document"]["status"], "not_present");
        assert_eq!(report["non_certification"]["legal_validity_claimed"], false);
        assert_eq!(
            report["non_certification"]["qualified_signature_claimed"],
            false
        );
        assert_eq!(
            report["non_certification"]["dglab_certification_claimed"],
            false
        );
        assert!(
            report["legal_notice"]
                .as_str()
                .expect("legal notice")
                .contains("Technical bundle evidence report only"),
            "technical-only notice is explicit: {report}"
        );
        assert!(
            report["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .any(|finding| finding["code"] == "signed_document_missing"
                    && finding["severity"] == "warning"),
            "missing signed document is flagged honestly: {report}"
        );
    }

    #[tokio::test]
    async fn document_bundle_indexes_matching_external_validator_metadata() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;

        let doc = crate::documents::load_document(
            &state,
            ActId(Uuid::parse_str(&act_id).expect("act id")),
        )
        .await
        .expect("document load")
        .expect("sealed document");
        let metadata = external_validator_metadata_bytes(
            "bundle-runtime",
            "eu-dss",
            &sha256_hex_test(&doc.pdf_bytes),
        );
        let metadata_sha256 = sha256_hex_test(&metadata);
        state
            .external_validator_report_metadata
            .write()
            .await
            .push(metadata);

        let (status, bundle) =
            send(state, get(&format!("/v1/acts/{act_id}/document/bundle"))).await;
        assert_eq!(status, StatusCode::OK);
        let external_reports =
            &bundle["validation_report"]["evidence_index"]["external_validator_reports"];
        assert_eq!(
            external_reports["bundle_attachment_status"],
            "external_validator_report_metadata_attached"
        );
        assert_eq!(
            external_reports["attachments"],
            json!([{
                "case_id": "bundle-runtime",
                "validator_family": "eu-dss",
                "archive_path": "evidence/external-validators/bundle-runtime-eu-dss.json",
                "content_type": "application/json",
                "sha256": metadata_sha256,
                "raw_report": {
                    "preservation_status": "raw_report_manifest_only",
                    "content_type": "application/json",
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 2,
                    "source_filename": "eu-dss.json"
                }
            }])
        );
    }

    #[tokio::test]
    async fn document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata()
     {
        let tmp = TempDir::new();
        let (state, _entity_id, book_id) =
            entity_and_open_book_in_state(AppState::with_data_dir(tmp.dir.clone()), "Condominio")
                .await;
        let act_id = draft_condominium_absent_owner_act(&state, &book_id).await;

        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        let ata_document_id = sealed["document"]["id"].as_str().expect("ata document id");
        assert_eq!(
            sealed["document"]["template_id"],
            "condominio-ata-assembleia/v1"
        );

        let token = auth_token(&state).await;
        let (status, generated_docs) = send_raw(
            state.clone(),
            with_session(
                get(&format!("/v1/acts/{act_id}/documents/generated")),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "generated docs: {generated_docs}");
        let communication = generated_docs
            .as_array()
            .expect("generated docs array")
            .iter()
            .find(|doc| {
                doc["template_id"].as_str()
                    == Some(crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID)
            })
            .unwrap_or_else(|| panic!("absent-owner communication missing: {generated_docs}"));
        let communication_id = communication["id"]
            .as_str()
            .expect("communication document id");
        assert_ne!(communication_id, ata_document_id);

        let note = "unique bundle preservation note 2026-07-12T12:34:56Z idempotency sentinel";
        let (status, evidence) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/documents/generated/{communication_id}/dispatch-evidence"),
                    json!({
                        "actor": "operator.bundle",
                        "dispatched_at": "2026-04-01T10:00:00Z",
                        "channel": "RegisteredLetter",
                        "reference": "RR123456789PT",
                        "recipients": ["Fração B"],
                        "evidence_reference": "archive:dispatch-proof-1",
                        "operator_note": note
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "dispatch evidence: {evidence}");
        let idempotency_key = evidence["evidence"]["idempotency_key"]
            .as_str()
            .expect("dispatch evidence idempotency key");

        let (status, bundle) = send_raw(
            state,
            with_session(get(&format!("/v1/acts/{act_id}/document/bundle")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "bundle: {bundle}");
        assert_eq!(bundle["document"]["id"], ata_document_id);
        assert_eq!(
            bundle["document"]["template_id"],
            "condominio-ata-assembleia/v1"
        );
        assert_eq!(
            bundle["validation_report"]["evidence_index"]["document_id"],
            ata_document_id
        );
        assert_eq!(
            bundle["validation_report"]["evidence_index"]["bundle_paths"]["canonical_pdf_download"],
            format!("/v1/acts/{act_id}/document")
        );

        let generated_dispatch =
            bundle["validation_report"]["evidence_index"]["generated_dispatch_evidence"]
                .as_array()
                .expect("generated dispatch evidence index");
        assert_eq!(
            generated_dispatch.len(),
            1,
            "one absent-owner generated communication is indexed: {bundle}"
        );
        let entry = &generated_dispatch[0];
        assert_eq!(
            entry["evidence_kind"],
            "generated_document_dispatch_evidence_metadata"
        );
        assert_eq!(
            entry["metadata_schema"],
            "chancela-generated-document-dispatch-evidence-metadata/v1"
        );
        assert_eq!(entry["status_scope"], "technical_metadata_only");
        assert_eq!(entry["generated_document_id"], communication_id);
        assert_eq!(entry["act_id"], act_id);
        assert_eq!(
            entry["template_id"],
            crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID
        );
        assert_eq!(
            entry["generated_document_download"],
            format!("/v1/documents/generated/{communication_id}")
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["status"],
            "operator_evidence_covered"
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["completion_basis"],
            "none"
        );
        assert_eq!(
            entry["coverage"]["required_recipients"],
            json!(["Fração B"])
        );
        assert_eq!(
            entry["coverage"]["recorded_recipients"],
            json!(["Fração B"])
        );
        assert_eq!(entry["coverage"]["missing_recipients"], json!([]));
        assert_eq!(entry["coverage"]["all_required_recipients_covered"], true);
        assert_eq!(entry["sending_performed_by_chancela"], false);
        assert_eq!(entry["delivery_confirmed"], false);
        assert_eq!(entry["legal_notice_completion_claimed"], false);
        assert_eq!(entry["legal_sufficiency_claimed"], false);
        assert_eq!(entry["provider_execution_claimed"], false);
        assert_eq!(entry["registry_filing_claimed"], false);
        assert_eq!(entry["bundle_readiness_claimed"], false);
        assert_eq!(entry["dglab_certification_claimed"], false);
        assert_eq!(entry["legal_archive_acceptance_claimed"], false);
        assert_eq!(entry["proof_bytes_included"], false);
        assert_eq!(entry["operator_note_included"], false);

        let record = &entry["records"].as_array().expect("records")[0];
        assert_eq!(record["dispatched_at"], "2026-04-01T10:00:00Z");
        assert!(
            record["recorded_at"]
                .as_str()
                .is_some_and(|ts| !ts.is_empty())
        );
        assert_eq!(record["channel"], "RegisteredLetter");
        assert_eq!(record["reference"], "RR123456789PT");
        assert_eq!(record["evidence_reference"], "archive:dispatch-proof-1");
        assert_eq!(record["imported_document_id"], serde_json::Value::Null);
        assert_eq!(record["recipients"], json!(["Fração B"]));
        assert_eq!(record["bytes_included"], false);
        assert_eq!(record["operator_note_included"], false);
        assert!(
            record.get("idempotency_key").is_none(),
            "note-derived idempotency key must stay out of preservation records: {record}"
        );

        let evidence_index_text =
            serde_json::to_string(&bundle["validation_report"]["evidence_index"])
                .expect("evidence index serializes");
        assert!(
            !evidence_index_text.contains(note)
                && !evidence_index_text.contains("\"operator_note\":"),
            "operator notes stay out of preservation evidence: {evidence_index_text}"
        );
        assert!(
            !evidence_index_text.contains(idempotency_key)
                && !evidence_index_text.contains("\"idempotency_key\":")
                && !evidence_index_text.contains("\"fingerprint\":"),
            "note-derived stable identifiers stay out of preservation evidence: {evidence_index_text}"
        );
    }

    #[tokio::test]
    async fn document_bundle_indexes_generated_convening_notice_dispatch_evidence_without_replacing_ata()
     {
        let tmp = TempDir::new();
        let (state, _entity_id, book_id) = entity_and_open_book_in_state(
            AppState::with_data_dir(tmp.dir.clone()),
            "SociedadeAnonima",
        )
        .await;
        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({
                    "book_id": book_id,
                    "title": "Ata da AG anual convocada",
                    "channel": "Physical"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "draft act: {act}");
        let act_id = act["id"].as_str().expect("act id").to_owned();

        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                    "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                    "attendance_reference": "Lista de presencas",
                    "deliberations": "Aprovadas as contas do exercicio.",
                    "convening": {
                        "convener": "Ana Presidente",
                        "convener_capacity": "Administrator",
                        "dispatch_date": "2026-03-01",
                        "antecedence_days": 21,
                        "channel": "Email",
                        "evidence_reference": "doc:convocatoria-2026-03-01",
                        "recipients": [
                            { "name": "Ana Sócia", "contact": "ana@example.test", "channel": "Email", "reference": "MSG-1" },
                            { "name": "Bruno Sócio", "contact": "bruno@example.test", "channel": "Email", "reference": "MSG-2" }
                        ]
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "patch act: {patched}");
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, body) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
        }

        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal: {sealed}");
        let ata_document_id = sealed["document"]["id"].as_str().expect("ata document id");
        assert_eq!(sealed["document"]["template_id"], "csc-ata-ag/v1");

        let token = auth_token(&state).await;
        let (status, notice) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!(
                        "/v1/acts/{act_id}/document/generate?template_id=csc-convocatoria-ag/v1"
                    ),
                    json!({}),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "generated notice: {notice}");
        assert_eq!(notice["template_id"], "csc-convocatoria-ag/v1");
        assert_eq!(
            notice["dispatch_evidence_status"]["status"],
            "required_pending"
        );
        let notice_id = notice["id"].as_str().expect("notice id");
        assert_ne!(notice_id, ata_document_id);

        let note =
            "unique generated convening bundle note 2026-07-15T09:30:00Z idempotency sentinel";
        let (status, evidence) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/documents/generated/{notice_id}/dispatch-evidence"),
                    json!({
                        "actor": "operator.bundle",
                        "dispatched_at": "2026-03-01T09:00:00Z",
                        "channel": "Email",
                        "reference": "MSG-1",
                        "recipients": ["Ana Sócia", "Bruno Sócio"],
                        "evidence_reference": "archive:generated-convening-notice-dispatch",
                        "operator_note": note
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "dispatch evidence: {evidence}");
        let idempotency_key = evidence["evidence"]["idempotency_key"]
            .as_str()
            .expect("dispatch evidence idempotency key");

        let (status, bundle) = send_raw(
            state,
            with_session(get(&format!("/v1/acts/{act_id}/document/bundle")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "bundle: {bundle}");
        assert_eq!(bundle["document"]["id"], ata_document_id);
        assert_eq!(bundle["document"]["template_id"], "csc-ata-ag/v1");
        assert_eq!(
            bundle["validation_report"]["evidence_index"]["document_id"],
            ata_document_id
        );

        let generated_dispatch =
            bundle["validation_report"]["evidence_index"]["generated_dispatch_evidence"]
                .as_array()
                .expect("generated dispatch evidence index");
        assert_eq!(
            generated_dispatch.len(),
            1,
            "one generated convening notice is indexed: {bundle}"
        );
        let entry = &generated_dispatch[0];
        assert_eq!(
            entry["evidence_kind"],
            "generated_document_dispatch_evidence_metadata"
        );
        assert_eq!(
            entry["metadata_schema"],
            "chancela-generated-document-dispatch-evidence-metadata/v1"
        );
        assert_eq!(entry["status_scope"], "technical_metadata_only");
        assert_eq!(entry["generated_document_id"], notice_id);
        assert_eq!(entry["act_id"], act_id);
        assert_eq!(entry["template_id"], "csc-convocatoria-ag/v1");
        assert_eq!(
            entry["generated_document_download"],
            format!("/v1/documents/generated/{notice_id}")
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["status"],
            "operator_evidence_covered"
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(
            entry["dispatch_evidence_status"]["completion_basis"],
            "none"
        );
        assert_eq!(
            entry["coverage"]["required_recipients"],
            json!(["Ana Sócia", "Bruno Sócio"])
        );
        assert_eq!(
            entry["coverage"]["recorded_recipients"],
            json!(["Ana Sócia", "Bruno Sócio"])
        );
        assert_eq!(entry["coverage"]["missing_recipients"], json!([]));
        assert_eq!(entry["coverage"]["all_required_recipients_covered"], true);
        for flag in [
            "sending_performed_by_chancela",
            "delivery_confirmed",
            "legal_notice_completion_claimed",
            "legal_sufficiency_claimed",
            "provider_execution_claimed",
            "registry_filing_claimed",
            "bundle_readiness_claimed",
            "dglab_certification_claimed",
            "legal_archive_acceptance_claimed",
            "proof_bytes_included",
            "operator_note_included",
        ] {
            assert_eq!(entry[flag], false, "{flag} must remain false");
        }

        let record = &entry["records"].as_array().expect("records")[0];
        assert_eq!(record["dispatched_at"], "2026-03-01T09:00:00Z");
        assert_eq!(record["channel"], "Email");
        assert_eq!(record["reference"], "MSG-1");
        assert_eq!(
            record["evidence_reference"],
            "archive:generated-convening-notice-dispatch"
        );
        assert_eq!(record["recipients"], json!(["Ana Sócia", "Bruno Sócio"]));
        assert_eq!(record["bytes_included"], false);
        assert_eq!(record["operator_note_included"], false);
        assert!(
            record.get("idempotency_key").is_none(),
            "note-derived idempotency key must stay out of preservation records: {record}"
        );

        let evidence_index_text =
            serde_json::to_string(&bundle["validation_report"]["evidence_index"])
                .expect("evidence index serializes");
        assert!(
            !evidence_index_text.contains(note)
                && !evidence_index_text.contains("\"operator_note\":"),
            "operator notes stay out of preservation evidence: {evidence_index_text}"
        );
        assert!(
            !evidence_index_text.contains(idempotency_key)
                && !evidence_index_text.contains("\"idempotency_key\":")
                && !evidence_index_text.contains("\"fingerprint\":"),
            "note-derived stable identifiers stay out of preservation evidence: {evidence_index_text}"
        );
    }

    #[tokio::test]
    async fn document_bundle_validation_report_flags_signed_document_inconsistency() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let act_uuid = Uuid::parse_str(&act_id).expect("act uuid");
        let signed_pdf_bytes = b"%PDF-1.7\n1 0 obj <<>> endobj\nstartxref\n0\n%%EOF\n".to_vec();
        state.signed_documents.write().await.insert(
            ActId(act_uuid),
            StoredSignedDocument {
                act_id: ActId(act_uuid),
                document_id: Uuid::new_v4().to_string(),
                signed_pdf_digest: "00".repeat(32),
                signature_family: "local-test".to_owned(),
                evidentiary_level: "technical-only".to_owned(),
                trusted_list_status: None,
                signer_cert_subject: None,
                signing_time: time::OffsetDateTime::UNIX_EPOCH,
                signed_at: time::OffsetDateTime::UNIX_EPOCH,
                signer_cert_der: vec![1],
                timestamp_token_der: None,
                timestamp_trust_report_json: None,
                signer_capacity_evidence_json: None,
                signed_pdf_bytes,
            },
        );

        let (status, bundle) =
            send(state, get(&format!("/v1/acts/{act_id}/document/bundle"))).await;
        assert_eq!(status, StatusCode::OK);
        let report = &bundle["validation_report"];
        assert_eq!(report["status"], "technical_error");
        assert_eq!(report["signed_document"]["present"], true);
        assert_eq!(
            report["evidence_index"]["bundle_paths"]["signed_pdf_download"],
            format!("/v1/acts/{act_id}/document/signed")
        );
        assert_eq!(
            report["signed_document"]["document_id_matches_canonical"],
            false
        );
        assert_eq!(
            report["signed_document"]["signed_pdf_digest_matches_metadata"],
            false
        );
        assert_eq!(
            report["non_certification"]["qualified_signature_claimed"],
            false
        );
        let findings = report["findings"].as_array().expect("findings");
        assert!(
            findings
                .iter()
                .any(|finding| finding["code"] == "signed_document_id_mismatch"
                    && finding["severity"] == "error"),
            "signed document id mismatch is reported: {report}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["code"] == "signed_pdf_digest_mismatch"
                    && finding["severity"] == "error"),
            "signed PDF digest mismatch is reported: {report}"
        );
    }

    #[tokio::test]
    async fn closing_a_book_produces_the_termo_encerramento_document() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Close the book → the encerramento document is generated in the same commit as book.closed.
        let (status, closed) = send(
            state.clone(),
            post_json(
                &format!("/v1/books/{book_id}/close"),
                json!({
                    "reason": "BookFull",
                    "closing_date": "2026-12-31",
                    "required_signatories": ["Administrador"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "close: {closed}");
        assert_eq!(closed["state"], "Closed");

        // A book-scoped `document.generated` event exists for the encerramento (plus the abertura's).
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let book_doc_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| {
                e["kind"] == "document.generated"
                    && e["scope"].as_str().is_some_and(|s| {
                        s.contains(&format!("book:{book_id}")) && !s.contains("/act:")
                    })
            })
            .count();
        assert!(
            book_doc_events >= 2,
            "abertura + encerramento document.generated events: {events}"
        );

        // The encerramento is the latest document for the book key (a real csc-termo-encerramento).
        let (status, bundle) = send(
            state.clone(),
            get(&format!("/v1/acts/{book_id}/document/bundle")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            bundle["document"]["template_id"],
            "csc-termo-encerramento/v1"
        );

        let (_, verify) = send(state, get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true, "chain still verifies after close");
    }

    #[tokio::test]
    async fn on_demand_generate_persists_a_chosen_document_and_emits_the_event() {
        let tmp = TempDir::new();
        let (state, _entity_id, book_id) = entity_and_open_book_in_state(
            AppState::with_data_dir(tmp.dir.clone()),
            "SociedadeAnonima",
        )
        .await;
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        // Unknown template id → 404.
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=nao-existe/v9"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A certidão against an UNSEALED act is refused honestly (422).
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=csc-certidao-ata/v1"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Seal, then generate the certidão on demand — it persists + emits a document.generated event.
        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, canonical_ctype, canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            canonical_ctype.starts_with("application/pdf"),
            "ctype={canonical_ctype}"
        );
        let canonical_digest = sha256_hex_test(&canonical_ata);

        let (status, made) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=csc-certidao-ata/v1"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "generate: {made}");
        assert_eq!(made["template_id"], "csc-certidao-ata/v1");
        assert_eq!(made["act_id"], act_id);
        assert_eq!(made["pdf_digest"].as_str().expect("digest").len(), 64);
        let generated_id = made["id"].as_str().expect("generated id");
        let generated_download = made["download"].as_str().expect("download url");
        assert_eq!(
            generated_download,
            format!("/v1/documents/generated/{generated_id}")
        );
        assert_ne!(
            generated_download,
            format!("/v1/acts/{act_id}/document"),
            "on-demand document download must not point at the canonical Ata endpoint"
        );

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let doc_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "document.generated")
            .count();
        assert!(
            doc_events >= 2,
            "the sealed ata doc + the on-demand certidão doc are both on the chain: {events}"
        );

        // The chosen document is persisted and downloads by its own document id.
        let token = auth_token(&state).await;
        let (status, headers, bytes) =
            send_raw_bytes(state.clone(), with_session(get(generated_download), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/pdf");
        assert_eq!(headers.get("x-chancela-document-id").unwrap(), generated_id);
        assert_eq!(
            headers.get("x-chancela-template-id").unwrap(),
            "csc-certidao-ata/v1"
        );
        assert_eq!(
            headers.get("x-chancela-pdf-digest").unwrap(),
            made["pdf_digest"].as_str().expect("generated digest")
        );
        assert!(bytes.starts_with(b"%PDF-"));
        assert_eq!(
            sha256_hex_test(&bytes),
            made["pdf_digest"].as_str().expect("generated digest")
        );
        assert_ne!(
            sha256_hex_test(&bytes),
            canonical_digest,
            "certidão bytes must not be the sealed Ata bytes"
        );

        // The canonical Ata endpoint still serves the original sealed Ata for signing/bundles.
        let (status, ctype, still_canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
        assert_eq!(still_canonical_ata, canonical_ata);

        let (status, _) = send(
            state.clone(),
            with_session(get("/v1/documents/generated/not-a-document"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let powerless = powerless_token(&state).await;
        let (status, _) = send(state, with_session(get(generated_download), &powerless)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        assert!(state.store.is_none(), "regression must use no-store state");
        let act_id = draft_fill_and_advance(&state, &book_id).await;

        let (status, _) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, ctype, canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
        let canonical_digest = sha256_hex_test(&canonical_ata);

        let (status, made) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/document/generate?template_id=csc-certidao-ata/v1"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "generate: {made}");
        assert_eq!(made["template_id"], "csc-certidao-ata/v1");
        assert_eq!(made["act_id"], act_id);
        let generated_id = made["id"].as_str().expect("generated id");
        let generated_download = made["download"].as_str().expect("download url");
        assert_eq!(
            generated_download,
            format!("/v1/documents/generated/{generated_id}")
        );

        let token = auth_token(&state).await;
        let (status, headers, generated_bytes) =
            send_raw_bytes(state.clone(), with_session(get(generated_download), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/pdf");
        assert_eq!(headers.get("x-chancela-document-id").unwrap(), generated_id);
        assert_eq!(
            headers.get("x-chancela-template-id").unwrap(),
            "csc-certidao-ata/v1"
        );
        assert!(generated_bytes.starts_with(b"%PDF-"));
        assert_eq!(
            sha256_hex_test(&generated_bytes),
            made["pdf_digest"].as_str().expect("generated digest")
        );
        assert_ne!(
            sha256_hex_test(&generated_bytes),
            canonical_digest,
            "generated certidao must not be the sealed Ata bytes"
        );

        let (status, ctype, still_canonical_ata) =
            send_bytes(state, get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
        assert_eq!(still_canonical_ata, canonical_ata);
    }

    async fn draft_condominium_absent_owner_act(state: &AppState, book_id: &str) -> String {
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da assembleia", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Hall do prédio",
                    "agenda": [{ "number": 1, "text": "Orçamento anual" }],
                    "attendance_reference": "Folha de presenças",
                    "deliberations": "Aprovado o orçamento anual.",
                    "deliberation_items": [{
                        "agenda_number": 1,
                        "text": "Aprovado o orçamento anual.",
                        "vote": { "type": "Recorded", "em_favor": 600, "contra": 0, "abstencoes": 0 },
                        "statements": []
                    }],
                    "attendees": [
                        {
                            "name": "Fração A",
                            "quality": "CondoOwner",
                            "presence": "InPerson",
                            "weight": { "Permilage": 600 }
                        },
                        {
                            "name": "Fração B",
                            "quality": "CondoOwner",
                            "presence": "Absent",
                            "weight": { "Permilage": 400 }
                        }
                    ]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(state, &act_id).await;
        act_id
    }

    fn generated_doc<'a>(docs: &'a [StoredDocument], template_id: &str) -> &'a StoredDocument {
        docs.iter()
            .find(|doc| doc.template_id == template_id)
            .unwrap_or_else(|| panic!("{template_id} generated: {docs:?}"))
    }

    fn assert_pending_dispatch_headers(headers: &axum::http::HeaderMap) {
        assert_eq!(
            headers.get("x-chancela-dispatch-evidence-status").unwrap(),
            "required_pending"
        );
        assert_eq!(
            headers
                .get("x-chancela-dispatch-evidence-required")
                .unwrap(),
            "true"
        );
        assert_eq!(
            headers
                .get("x-chancela-dispatch-evidence-attached")
                .unwrap(),
            "false"
        );
        assert_eq!(
            headers.get("x-chancela-dispatch-completed").unwrap(),
            "false"
        );
    }

    #[tokio::test]
    async fn condominium_absent_owner_communication_auto_generates_durably_after_seal() {
        let tmp = TempDir::new();
        let (state, _entity_id, book_id) =
            entity_and_open_book_in_state(AppState::with_data_dir(tmp.dir.clone()), "Condominio")
                .await;
        let act_id = draft_condominium_absent_owner_act(&state, &book_id).await;

        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        assert_eq!(
            sealed["document"]["template_id"],
            "condominio-ata-assembleia/v1"
        );

        let (status, _, canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            sha256_hex_test(&canonical_ata),
            sealed["document"]["pdf_digest"]
                .as_str()
                .expect("ata digest")
        );

        let act_uuid = ActId(Uuid::parse_str(&act_id).expect("act uuid"));
        let docs = state
            .store
            .as_ref()
            .expect("durable store")
            .documents_for_act(act_uuid)
            .expect("documents for act");
        let communication = generated_doc(
            &docs,
            crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID,
        );
        assert_ne!(
            communication.id,
            sealed["document"]["id"].as_str().expect("ata document id")
        );
        assert_ne!(communication.pdf_digest, sha256_hex_test(&canonical_ata));

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let generated_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| {
                e["kind"] == "document.generated"
                    && e["scope"]
                        .as_str()
                        .is_some_and(|scope| scope.contains(&format!("/act:{act_id}")))
            })
            .count();
        assert_eq!(
            generated_events, 2,
            "Ata + absent-owner communication document events: {events}"
        );

        let token = auth_token(&state).await;
        let (status, headers, generated_bytes) = send_raw_bytes(
            state.clone(),
            with_session(
                get(&format!("/v1/documents/generated/{}", communication.id)),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_pending_dispatch_headers(&headers);
        assert_eq!(sha256_hex_test(&generated_bytes), communication.pdf_digest);

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, _, restarted_ata) = send_bytes(
            restarted.clone(),
            get(&format!("/v1/acts/{act_id}/document")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(restarted_ata, canonical_ata);
        let token = auth_token(&restarted).await;
        let (status, headers, restarted_generated) = send_raw_bytes(
            restarted,
            with_session(
                get(&format!("/v1/documents/generated/{}", communication.id)),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_pending_dispatch_headers(&headers);
        assert_eq!(restarted_generated, generated_bytes);
    }

    #[tokio::test]
    async fn generated_documents_for_act_discovers_absent_owner_communication_and_gates_read() {
        let tmp = TempDir::new();
        let (state, _entity_id, book_id) =
            entity_and_open_book_in_state(AppState::with_data_dir(tmp.dir.clone()), "Condominio")
                .await;
        let act_id = draft_condominium_absent_owner_act(&state, &book_id).await;

        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        let sealed_doc_id = sealed["document"]["id"]
            .as_str()
            .expect("sealed document id");
        let route = format!("/v1/acts/{act_id}/documents/generated");

        let (status, _) = send_raw(state.clone(), get(&route)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let token = auth_token(&state).await;
        let (status, docs) = send_raw(state.clone(), with_session(get(&route), &token)).await;
        assert_eq!(status, StatusCode::OK, "generated documents: {docs}");
        let rows = docs.as_array().expect("generated document list");
        assert!(
            rows.iter()
                .any(|doc| doc["id"].as_str() == Some(sealed_doc_id)),
            "canonical Ata summary is discoverable: {docs}"
        );
        let communication = rows
            .iter()
            .find(|doc| {
                doc["template_id"].as_str()
                    == Some(crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID)
            })
            .unwrap_or_else(|| panic!("absent-owner communication summary missing: {docs}"));
        let generated_id = communication["id"]
            .as_str()
            .expect("communication document id");
        assert_eq!(communication["act_id"], act_id);
        assert_eq!(
            communication["pdf_digest"].as_str().expect("digest").len(),
            64
        );
        assert_eq!(communication["profile"], crate::documents::PDFA_PROFILE);
        assert!(
            communication["created_at"]
                .as_str()
                .is_some_and(|created_at| !created_at.is_empty())
        );
        assert_eq!(
            communication["download"],
            format!("/v1/documents/generated/{generated_id}")
        );
        assert_eq!(
            communication["dispatch_evidence_status"]["status"],
            "required_pending"
        );
        assert_eq!(
            communication["dispatch_evidence_status"]["required_recipients"],
            json!(["Fração B"])
        );
        assert_eq!(
            communication["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(
            communication["dispatch_evidence_status"]["completion_basis"],
            "none"
        );

        let powerless = powerless_token(&state).await;
        let (status, _) = send_raw(state, with_session(get(&route), &powerless)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn condominium_absent_owner_communication_auto_generates_in_memory_without_replacing_ata()
    {
        let (state, _entity_id, book_id) = entity_and_open_book("Condominio").await;
        assert!(state.store.is_none(), "regression must use no-store state");
        let act_id = draft_condominium_absent_owner_act(&state, &book_id).await;

        let (status, sealed) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        assert_eq!(
            sealed["document"]["template_id"],
            "condominio-ata-assembleia/v1"
        );

        let (status, _, canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            sha256_hex_test(&canonical_ata),
            sealed["document"]["pdf_digest"]
                .as_str()
                .expect("ata digest")
        );

        let docs: Vec<StoredDocument> = state
            .documents
            .read()
            .await
            .values()
            .filter(|doc| doc.act_id.to_string() == act_id)
            .cloned()
            .collect();
        let communication = generated_doc(
            &docs,
            crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID,
        );
        assert_ne!(
            communication.id,
            sealed["document"]["id"].as_str().expect("ata document id")
        );
        assert_ne!(communication.pdf_digest, sha256_hex_test(&canonical_ata));

        let token = auth_token(&state).await;
        let (status, headers, generated_bytes) = send_raw_bytes(
            state.clone(),
            with_session(
                get(&format!("/v1/documents/generated/{}", communication.id)),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_pending_dispatch_headers(&headers);
        assert_eq!(sha256_hex_test(&generated_bytes), communication.pdf_digest);

        let (status, _, still_canonical_ata) =
            send_bytes(state.clone(), get(&format!("/v1/acts/{act_id}/document"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(still_canonical_ata, canonical_ata);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let generated_events = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| {
                e["kind"] == "document.generated"
                    && e["scope"]
                        .as_str()
                        .is_some_and(|scope| scope.contains(&format!("/act:{act_id}")))
            })
            .count();
        assert_eq!(
            generated_events, 2,
            "Ata + absent-owner communication document events: {events}"
        );
    }

    #[tokio::test]
    async fn seal_template_id_override_selects_a_subtype_and_unknown_errors() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // An unknown override id is rejected (422), never silently defaulted to the spine.
        let act_bad = draft_fill_and_advance(&state, &book_id).await;
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_bad}/seal"),
                seal_body_with_template_id("nao-existe/v9"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // The bad seal rolled back: the act is not sealed.
        let (_, act) = send(state.clone(), get(&format!("/v1/acts/{act_bad}"))).await;
        assert_ne!(
            act["state"], "Sealed",
            "a failed override seal leaves no trace"
        );

        // A valid ata subtype override generates that subtype instead of the spine.
        let act_id = draft_fill_and_advance(&state, &book_id).await;
        let (status, sealed) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/seal"),
                seal_body_with_template_id("csc-ata-aprovacao-contas/v1"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "override seal: {sealed}");
        assert_eq!(
            sealed["document"]["template_id"],
            "csc-ata-aprovacao-contas/v1"
        );
    }

    #[tokio::test]
    async fn draft_in_non_open_book_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Close the book so it is no longer open.
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/books/{book_id}/close"),
                json!({
                    "reason": "BookFull",
                    "closing_date": "2026-12-31",
                    "required_signatories": ["Administrador"],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Drafting into a closed book is refused.
        let (status, body) = send(
            state,
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Tardio", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn seal_with_missing_contents_is_422_with_issues() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        // Draft an empty act and push it to Signing without filling the mandatory contents.
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Vazia", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        let (status, body) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let issues = body["issues"].as_array().expect("issues array");
        assert!(!issues.is_empty());
        assert!(issues.iter().all(|i| i["severity"] == "Error"));
    }

    #[tokio::test]
    async fn seal_when_not_signing_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Rascunho", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Sealing a Draft act (never advanced to Signing) is refused with a conflict.
        let (status, body) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn close_non_open_book_is_409() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let close = || {
            post_json(
                &format!("/v1/books/{book_id}/close"),
                json!({
                    "reason": "BookFull",
                    "closing_date": "2026-12-31",
                    "required_signatories": ["Administrador"],
                }),
            )
        };
        let (status, _) = send(state.clone(), close()).await;
        assert_eq!(status, StatusCode::OK);

        // Closing an already-closed book is refused.
        let (status, body) = send(state, close()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn book_create_rejects_bad_date_with_422() {
        let state = AppState::default();
        let (_, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        let entity_id = entity["id"].as_str().unwrap().to_owned();

        let (status, body) = send(
            state,
            post_json(
                "/v1/books",
                json!({
                    "entity_id": entity_id,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro",
                    "opening_date": "not-a-date",
                    "required_signatories": [],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn book_on_missing_entity_is_404() {
        let missing = Uuid::new_v4();
        let (status, _) = send(
            AppState::default(),
            post_json(
                "/v1/books",
                json!({
                    "entity_id": missing,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro",
                    "opening_date": "2026-01-15",
                    "required_signatories": [],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A throwaway `apps/web/dist`-shaped directory with an `index.html`, cleaned up on drop.
    struct TempWeb {
        dir: PathBuf,
    }

    impl TempWeb {
        fn new(index_html: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("chancela-web-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp web dir created");
            std::fs::write(dir.join("index.html"), index_html).expect("index.html written");
            Self { dir }
        }
    }

    impl Drop for TempWeb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Drive one request through the full [`app`] router and return (status, body text).
    async fn send_text(router: Router, req: Request<Body>) -> (StatusCode, String) {
        let response = router.oneshot(req).await.expect("router responds");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn send_text_with_headers(
        router: Router,
        req: Request<Body>,
    ) -> (StatusCode, HeaderMap, String) {
        let response = router.oneshot(req).await.expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    // --- wp25 observability: probes + correlation id -------------------------------------------

    #[tokio::test]
    async fn livez_probe_is_cheap_200_with_a_request_id() {
        let (status, headers, body) =
            send_text_with_headers(router(AppState::default()), get("/livez")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
        // The outermost observability layer stamps a correlation id on every response.
        let id = headers
            .get("x-request-id")
            .expect("x-request-id echoed on every response");
        assert!(!id.is_empty(), "request id must be non-empty");
    }

    #[tokio::test]
    async fn readyz_is_ready_when_not_degraded() {
        let (status, _headers, body) =
            send_text_with_headers(router(AppState::default()), get("/readyz")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ready");
    }

    #[tokio::test]
    async fn readyz_is_503_in_degraded_read_only_mode() {
        let state = AppState::default();
        *state.degraded.write().await = true;

        let (status, _headers, body) = send_text_with_headers(router(state), get("/readyz")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            body.contains("degraded read-only mode"),
            "readyz should name the narrow degraded-mode blocker, got {body:?}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_text() {
        let (status, headers, body) =
            send_text_with_headers(router(AppState::default()), get("/metrics")).await;
        assert_eq!(status, StatusCode::OK);
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/plain"),
            "Prometheus exposition is text/plain, got {content_type:?}"
        );
        // App gauges are refreshed from live state on every scrape, so they are present even before
        // any HTTP counter has been flushed — a deterministic marker that the recorder is wired.
        assert!(
            body.contains("chancela_ledger_length"),
            "metrics body should carry the app gauges, got:\n{body}"
        );
    }

    #[tokio::test]
    async fn inbound_request_id_is_honoured_and_echoed() {
        let req = Request::builder()
            .uri("/health")
            .header("x-request-id", "trace-abc-123")
            .body(Body::empty())
            .expect("request builds");
        let (status, headers, _body) =
            send_text_with_headers(router(AppState::default()), req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("x-request-id").and_then(|v| v.to_str().ok()),
            Some("trace-abc-123"),
            "a sane inbound x-request-id is adopted and echoed back verbatim"
        );
    }

    #[tokio::test]
    async fn bad_inbound_request_id_is_rejected_and_replaced() {
        let empty_req = Request::builder()
            .uri("/health")
            .header("x-request-id", "")
            .body(Body::empty())
            .expect("request builds");
        let (status, headers, _body) =
            send_text_with_headers(router(AppState::default()), empty_req).await;
        assert_eq!(status, StatusCode::OK);
        let replacement = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("replacement request id");
        assert_ne!(replacement, "");
        assert!(
            Uuid::parse_str(replacement).is_ok(),
            "bad inbound request id should be replaced with a minted UUID, got {replacement:?}"
        );

        let long_id = "a".repeat(201);
        let long_req = Request::builder()
            .uri("/health")
            .header("x-request-id", &long_id)
            .body(Body::empty())
            .expect("request builds");
        let (status, headers, _body) =
            send_text_with_headers(router(AppState::default()), long_req).await;
        assert_eq!(status, StatusCode::OK);
        let replacement = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("replacement request id");
        assert_ne!(replacement, long_id);
        assert!(
            Uuid::parse_str(replacement).is_ok(),
            "overlong inbound request id should be replaced with a minted UUID, got {replacement:?}"
        );
    }

    #[tokio::test]
    async fn observability_probes_are_available_under_api_alias() {
        let (status, _headers, body) =
            send_text_with_headers(router(AppState::default()), get("/api/livez")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");

        let (status, _headers, body) =
            send_text_with_headers(router(AppState::default()), get("/api/readyz")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ready");

        let (status, headers, body) =
            send_text_with_headers(router(AppState::default()), get("/api/metrics")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .starts_with("text/plain"),
            "/api/metrics should render Prometheus text"
        );
        assert!(
            body.contains("chancela_ledger_length"),
            "/api/metrics should expose the same app gauges as /metrics"
        );
    }

    #[tokio::test]
    async fn metrics_use_matched_route_labels_not_raw_paths() {
        let state = AppState::default();
        let secret_id = format!("secret-{}", Uuid::new_v4());
        let raw_path = format!("/v1/entities/{secret_id}");

        let (_status, _headers, _body) =
            send_text_with_headers(router(state.clone()), get(&raw_path)).await;
        let (status, _headers, metrics) =
            send_text_with_headers(router(state), get("/metrics")).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            metrics.contains("path=\"/v1/entities/{id}\""),
            "metrics should label the dynamic request by route template, got:\n{metrics}"
        );
        assert!(
            !metrics.contains(&secret_id),
            "metrics must not contain raw path ids or secrets, got:\n{metrics}"
        );
    }

    fn assert_security_headers(headers: &HeaderMap) {
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .expect("content-security-policy header");
        assert!(csp.contains("default-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        // wp25-sec: HSTS is emitted on every response (safe even over plain HTTP — browsers ignore
        // it there; it pins HTTPS once the TLS-terminating reverse proxy is in front).
        let hsts = headers
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .expect("strict-transport-security header");
        assert!(hsts.contains("max-age="), "{hsts}");
        assert!(hsts.contains("includeSubDomains"), "{hsts}");
    }

    #[tokio::test]
    async fn hsts_header_present_on_api_responses() {
        let (_status, headers, _body) =
            send_text_with_headers(router(AppState::default()), get("/health")).await;
        let hsts = headers
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .expect("strict-transport-security header on API responses");
        assert!(hsts.starts_with("max-age="), "{hsts}");
        assert!(hsts.contains("includeSubDomains"), "{hsts}");
    }

    #[tokio::test]
    async fn rate_limiter_returns_429_with_retry_after_after_burst() {
        // Tight policy (burst of 2, negligible refill) so the third request from one IP is limited.
        // Trust the forwarded IP so the in-process test can key requests by header (no ConnectInfo).
        let state = AppState {
            rate_limit: RateLimitConfig {
                enabled: true,
                per_second: 0.001,
                burst: 2.0,
                trust_forwarded_for: true,
            },
            ..AppState::default()
        };

        let request = |ip: &str| {
            Request::builder()
                .uri("/v1/entities")
                .header("x-real-ip", ip)
                .body(Body::empty())
                .expect("request builds")
        };

        // First two requests pass the limiter (they then 401 at the auth layer — not our concern).
        for _ in 0..2 {
            let status = router(state.clone())
                .oneshot(request("203.0.113.7"))
                .await
                .expect("router responds")
                .status();
            assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        }

        // The third is rate-limited with a Retry-After.
        let response = router(state.clone())
            .oneshot(request("203.0.113.7"))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            response.headers().get("retry-after").is_some(),
            "429 carries a Retry-After header"
        );

        // A different client IP is unaffected (per-IP buckets).
        let status = router(state.clone())
            .oneshot(request("198.51.100.9"))
            .await
            .expect("router responds")
            .status();
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn rate_limiter_exempts_liveness_probe() {
        let state = AppState {
            rate_limit: RateLimitConfig {
                enabled: true,
                per_second: 0.001,
                burst: 1.0,
                trust_forwarded_for: true,
            },
            ..AppState::default()
        };
        // Far more requests than the burst; /livez is exempt so none is ever limited.
        for _ in 0..5 {
            let response = router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri("/livez")
                        .header("x-real-ip", "203.0.113.7")
                        .body(Body::empty())
                        .expect("request builds"),
                )
                .await
                .expect("router responds");
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn session_past_absolute_lifetime_cap_is_rejected() {
        // A 1-hour absolute cap so a session issued two hours ago is over-age.
        let state = AppState {
            session_max_lifetime: SessionMaxLifetime(60 * 60),
            ..AppState::default()
        };
        let uid = seed_user(&state, "amelia.marques", vec![]).await;
        let token = seed_session(&state, &uid.to_string()).await;
        // Pin the issued-at well beyond the cap (the sliding 24h expiry stays fresh).
        state.session_issued_at.write().await.insert(
            token.clone(),
            time::OffsetDateTime::now_utc() - time::Duration::hours(2),
        );

        // The session is rejected (401) — not a 403 (which would mean the session was accepted but
        // the user lacked permission).
        let (status, _) = send_raw(state.clone(), with_session(get("/v1/entities"), &token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // The over-age session was evicted.
        assert!(!state.sessions.read().await.contains_key(&token));
    }

    #[tokio::test]
    async fn runtime_security_state_cleared_on_data_dir_reload() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        state
            .session_issued_at
            .write()
            .await
            .insert("stale-session".to_owned(), time::OffsetDateTime::now_utc());
        state.rate_limit_buckets.write().await.insert(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            TokenBucket::new(1.0, std::time::Instant::now()),
        );

        state
            .reload_domain_memory()
            .await
            .expect("data-dir reload succeeds");

        assert!(
            state.session_issued_at.read().await.is_empty(),
            "session issued-at cap tracker is cleared on reload"
        );
        assert!(
            state.rate_limit_buckets.read().await.is_empty(),
            "per-IP rate-limit buckets are cleared on reload"
        );
    }

    #[tokio::test]
    async fn runtime_security_state_cleared_on_factory_memory_clear() {
        let state = AppState::default();
        state
            .session_issued_at
            .write()
            .await
            .insert("stale-session".to_owned(), time::OffsetDateTime::now_utc());
        state.rate_limit_buckets.write().await.insert(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            TokenBucket::new(1.0, std::time::Instant::now()),
        );

        state.clear_all_memory().await;

        assert!(
            state.session_issued_at.read().await.is_empty(),
            "session issued-at cap tracker is cleared on factory reset"
        );
        assert!(
            state.rate_limit_buckets.read().await.is_empty(),
            "per-IP rate-limit buckets are cleared on factory reset"
        );
    }

    #[tokio::test]
    async fn current_attestor_rejects_session_past_absolute_lifetime_cap() {
        let state = AppState {
            session_max_lifetime: SessionMaxLifetime(60 * 60),
            ..AppState::default()
        };
        let uid = seed_user(&state, "attestor.cap", vec![]).await;
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: Some(
                    p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("valid test key"),
                ),
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        state
            .session_issued_at
            .write()
            .await
            .insert(token.clone(), now - time::Duration::hours(2));

        let (mut parts, _) = with_session(get("/v1/entities"), &token).into_parts();
        let attestor =
            <CurrentAttestor as axum::extract::FromRequestParts<AppState>>::from_request_parts(
                &mut parts, &state,
            )
            .await
            .expect("attestor extractor is infallible");

        assert!(
            attestor.signer().is_none(),
            "over-age sessions must not expose an unlocked signing key"
        );
        assert!(
            !state.sessions.read().await.contains_key(&token),
            "over-age session is evicted"
        );
        assert!(
            !state.session_issued_at.read().await.contains_key(&token),
            "over-age issued-at tracker is evicted"
        );
    }

    #[tokio::test]
    async fn web_dist_serves_index_at_root() {
        let web = TempWeb::new("<!doctype html><title>Chancela</title>");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<title>Chancela</title>"), "got: {body}");
    }

    #[tokio::test]
    async fn unknown_route_falls_back_to_index_html() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        // A client-side route with no matching file must return the SPA shell, not 404.
        let (status, body) = send_text(app, get("/livros")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "SPA-SHELL-MARKER");
    }

    #[tokio::test]
    async fn security_headers_apply_to_static_spa_fallback_and_assets() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        std::fs::write(web.dir.join("app.js"), "window.__chancela = true;").expect("asset");

        let spa_app = app(AppState::default(), Some(web.dir.clone()));
        let (status, headers, body) = send_text_with_headers(spa_app, get("/livros")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "SPA-SHELL-MARKER");
        assert_security_headers(&headers);

        let asset_app = app(AppState::default(), Some(web.dir.clone()));
        let (status, headers, body) = send_text_with_headers(asset_app, get("/app.js")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "window.__chancela = true;");
        assert_security_headers(&headers);
    }

    #[tokio::test]
    async fn unknown_v1_route_is_json_404_not_spa_shell() {
        // The regression under test: with a web build mounted, an unknown /v1 path (a typo, or a
        // route a stale binary predates) must return a JSON 404 — never the SPA `index.html`,
        // which the web client would try to `JSON.parse` ("Unexpected token '<'").
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/v1/definitely-not-a-route")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("SPA-SHELL-MARKER"),
            "must not be the SPA shell: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(
            value["error"],
            "unknown API route: GET /v1/definitely-not-a-route"
        );
    }

    #[tokio::test]
    async fn unknown_health_subpath_is_json_404_not_spa_shell() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/health/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("SPA-SHELL-MARKER"),
            "must not be the SPA shell: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert!(
            value["error"]
                .as_str()
                .expect("error string")
                .starts_with("unknown API route:"),
        );
    }

    #[tokio::test]
    async fn unknown_v1_route_is_json_404_in_api_only_mode() {
        // Even without a web build, an unknown /v1 path is a JSON 404, not the plain-text landing.
        let app = app(AppState::default(), None);
        let (status, body) = send_text(app, get("/v1/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            !body.contains("web UI not built"),
            "must not be the landing page: {body}"
        );
        let value: Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(value["error"], "unknown API route: GET /v1/nope");
    }

    #[tokio::test]
    async fn known_v1_route_still_wins_over_the_catch_all() {
        // The catch-all is low priority: a real endpoint keeps serving its own response.
        let state = AppState::default();
        let token = auth_token(&state).await; // RBAC (t64-E3): the gated list needs a session.
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(state, Some(web.dir.clone()));
        let (status, body) = send_text(app, with_session(get("/v1/entities"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "[]", "the entities list, not a 404 or the SPA shell");
    }

    #[tokio::test]
    async fn api_routes_keep_priority_over_static_tree() {
        let web = TempWeb::new("SPA-SHELL-MARKER");
        let app = app(AppState::default(), Some(web.dir.clone()));
        let (status, body) = send_text(app, get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        // Must be the JSON health body, never the SPA shell.
        assert!(body.contains("\"status\":\"ok\""), "got: {body}");
    }

    #[tokio::test]
    async fn api_only_mode_serves_helpful_landing() {
        let app = app(AppState::default(), None);
        let (status, body) = send_text(app, get("/")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("web UI not built"), "got: {body}");
        assert!(body.contains("npm run build"), "got: {body}");
    }

    #[tokio::test]
    async fn ledger_verify_reports_valid_chain_after_creates() {
        let state = AppState::default();

        // Empty ledger verifies with length 0.
        let (status, body) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true);
        assert_eq!(body["length"], 0);

        // Two creates append two events; the chain still verifies.
        for nipc in ["503004642", "500000000"] {
            let create = post_json(
                "/v1/entities",
                json!({
                    "name": "Entity",
                    "nipc": nipc,
                    "seat": "Lisboa",
                    "kind": "Cooperativa",
                }),
            );
            let (status, _) = send(state.clone(), create).await;
            assert_eq!(status, StatusCode::CREATED);
        }

        let (status, body) = send(state, get("/v1/ledger/verify")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true);
        assert_eq!(body["length"], 2);
    }

    // --- Settings (§2.8) -----------------------------------------------------------------

    fn put_json(uri: &str, body: Value) -> Request<Body> {
        body_json("PUT", uri, body)
    }

    /// A complete, non-default settings document used to prove PUT round-trips every section.
    fn sample_settings() -> Value {
        json!({
            "schema_version": 1,
            "organization": { "name": "Encosto Estratégico, S.A.", "default_actor": "amelia.marques" },
            "documents": { "locale": "en-US", "numbering_scheme_default": "LooseLeaf" },
            "catalog": {
                "cae_update_url": "https://catalog.example.pt/cae.json",
                "cae_sources": [
                    { "url": "https://espelho.example.pt/cae.json", "format": "Envelope", "digest": null },
                    { "url": "https://files.example.pt/cae.pdf", "format": "Pdf",
                      "digest": "0000000000000000000000000000000000000000000000000000000000000000" }
                ],
                "cae_official_source": true,
                "preferred_official_source": "Ine"
            },
            "signing": {
                "preferred_family": "ChaveMovelDigital",
                "tsa_url": "https://tsa.example.pt/tsr",
                "tsl_url": "https://tsl.example.pt/tsl.xml",
                "tsl_sources": [
                    {
                        "id": "pt-gns",
                        "name": "Portugal GNS Trusted List",
                        "enabled": true,
                        "url": "https://tsl.example.pt/tsl.xml",
                        "path": null,
                        "country": "PT",
                        "scheme": "eidas",
                        "digest": null,
                        "timeout_seconds": 20,
                        "max_bytes": 26214400,
                        "refresh": { "enabled": true, "cadence": { "kind": "daily", "hour_utc": 3 } }
                    },
                    {
                        "id": "eu-lotl",
                        "name": "EU List of Trusted Lists",
                        "enabled": false,
                        "url": "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
                        "path": null,
                        "country": "EU",
                        "scheme": "lotl",
                        "digest": "0000000000000000000000000000000000000000000000000000000000000000",
                        "timeout_seconds": 30,
                        "max_bytes": 26214400,
                        "refresh": { "enabled": false, "cadence": { "kind": "manual" } }
                    }
                ],
                "tsa_providers": [
                    {
                        "id": "pt-cc",
                        "name": "Portugal Cartao de Cidadao TSA",
                        "enabled": true,
                        "url": "https://tsa.example.pt/tsr",
                        "path": null,
                        "default": true,
                        "policy": null,
                        "digest": "sha256",
                        "timeout_seconds": 20,
                        "max_bytes": 1048576
                    },
                    {
                        "id": "lab-rfc3161",
                        "name": "Lab RFC 3161 TSA",
                        "enabled": false,
                        "url": "https://tsa-lab.example.pt/tsr",
                        "path": null,
                        "default": false,
                        "policy": "1.2.3.4.5",
                        "digest": "sha256",
                        "timeout_seconds": 30,
                        "max_bytes": 1048576
                    }
                ],
                "require_qualified_for_seal": true,
                "cmd": {
                    "env": "prod",
                    "application_id": "AMA-APP-0001",
                    "ama_cert_configured": true
                },
                "providers": [
                    {
                        "id": "cmd",
                        "mode": "CMD",
                        "label": "Chave Móvel Digital (CMD/SCMD)",
                        "configured": true,
                        "production_blocked": false,
                        "local_only": false,
                        "note": "Configured for AMA production. PIN/OTP are never stored."
                    },
                    {
                        "id": "cc",
                        "mode": "CC",
                        "label": "Cartão de Cidadão",
                        "configured": false,
                        "production_blocked": false,
                        "local_only": true,
                        "note": "Requires a co-located desktop process and card reader; no PIN is stored."
                    },
                    {
                        "id": "csc_qtsp",
                        "mode": "CSC_QTSP",
                        "label": "CSC/QTSP remote provider",
                        "configured": false,
                        "production_blocked": true,
                        "local_only": false,
                        "note": "No CSC/QTSP provider is configured in protected storage or environment."
                    },
                    {
                        "id": "soft_pkcs12",
                        "mode": "LOCAL_PKCS12",
                        "label": "Local soft certificate (PKCS#12/PFX)",
                        "configured": false,
                        "production_blocked": true,
                        "local_only": true,
                        "note": "Local-only test/operator material; private key and passphrase are never captured in settings."
                    }
                ]
            },
            "registry_auto_update": {
                "enabled": true,
                "cadence": { "kind": "interval_hours", "hours": 12 },
                "stale_threshold_hours": 168,
                "min_backoff_minutes": 30,
                "max_backoff_minutes": 240,
                "max_attempts_per_run": 5,
                "entity_defaults": {
                    "enabled": true,
                    "enabled_profiles": ["SociedadePorQuotas"]
                }
            },
            "ai": { "enabled": true },
            "platform": {
                "logging": {
                    "global": "warn",
                    "app": "debug",
                    "api": "info",
                    "mcp": "error",
                    "service_overrides": {
                        "app": "off",
                        "api": "trace",
                        "mcp_stdio": "debug"
                    }
                },
                "api_server": {
                    "enabled": true,
                    "desired_state": "running",
                    "last_action": null
                },
                "mcp_stdio_server": {
                    "enabled": true,
                    "desired_state": "running",
                    "last_action": null
                },
                "audit": []
            },
            "appearance": { "theme": "dark", "leather_texture": false, "texture_intensity": 25, "button_texture": false },
            "ui": {
                "registered_entity_columns": ["Name", "Nipc", "Type", "LastActivity", "Actions"]
            },
            "workflow": {
                "reminders": {
                    "enabled": true,
                    "dashboard_limit": 5,
                    "due_soon_days": 45,
                    "attendance_lookahead_days": 45,
                    "sources": {
                        "profile_calendar": true,
                        "act_follow_ups": true,
                        "attendance_hygiene": true,
                        "privacy_control_reviews": true
                    }
                }
            },
            "data_management": {
                "retained_export_cleanup": {
                    "minimum_age_days": 30,
                    "keep_latest": 5
                },
                "backup_recovery": {
                    "max_drill_age_days": 90,
                    "target_rpo_minutes": 1440,
                    "target_rto_minutes": 240
                }
            },
            "onboarding": { "completed": false, "completed_at": null }
        })
    }

    #[tokio::test]
    async fn settings_get_returns_defaults() {
        let (status, body) = send(AppState::default(), get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["organization"]["name"], Value::Null);
        assert_eq!(body["organization"]["default_actor"], "api");
        assert_eq!(body["documents"]["locale"], "pt-PT");
        assert_eq!(body["documents"]["numbering_scheme_default"], "Sequential");
        // The CAE update URL is unset by default (no official feed to ride); the ordered source
        // chain is empty and the official DR obtain is off (§cae-v2).
        assert_eq!(body["catalog"]["cae_update_url"], Value::Null);
        assert_eq!(body["catalog"]["cae_sources"], json!([]));
        assert_eq!(body["catalog"]["cae_official_source"], false);
        // t57 Slice 1: the default preferred family is now Chave Móvel Digital (the family wired
        // end-to-end), not Cartão de Cidadão.
        assert_eq!(body["signing"]["preferred_family"], "ChaveMovelDigital");
        // CMD config surface defaults: preprod env, no ApplicationId, AMA cert not configured.
        assert_eq!(body["signing"]["cmd"]["env"], "preprod");
        assert_eq!(body["signing"]["cmd"]["application_id"], Value::Null);
        assert_eq!(body["signing"]["cmd"]["ama_cert_configured"], false);
        assert_eq!(body["signing"]["providers"][0]["mode"], "CMD");
        assert_eq!(body["signing"]["providers"][0]["production_blocked"], true);
        assert_eq!(body["signing"]["providers"][1]["mode"], "CC");
        assert_eq!(body["signing"]["providers"][1]["local_only"], true);
        assert_eq!(body["signing"]["providers"][2]["mode"], "CSC_QTSP");
        assert_eq!(body["signing"]["providers"][3]["mode"], "LOCAL_PKCS12");
        // Trust-service URLs now default to the official Portuguese endpoints (not null).
        assert_eq!(
            body["signing"]["tsa_url"],
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert_eq!(
            body["signing"]["tsl_url"],
            "https://www.gns.gov.pt/media/TSLPT.xml"
        );
        assert_eq!(body["signing"]["tsl_sources"][0]["id"], "pt-gns");
        assert_eq!(body["signing"]["tsl_sources"][0]["enabled"], true);
        assert_eq!(
            body["signing"]["tsl_sources"][0]["url"],
            "https://www.gns.gov.pt/media/TSLPT.xml"
        );
        assert_eq!(body["signing"]["tsl_sources"][1]["id"], "eu-lotl");
        assert_eq!(body["signing"]["tsl_sources"][1]["enabled"], false);
        assert_eq!(
            body["signing"]["tsl_sources"][1]["url"],
            "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
        );
        assert_eq!(body["signing"]["tsa_providers"][0]["id"], "pt-cc");
        assert_eq!(body["signing"]["tsa_providers"][0]["enabled"], true);
        assert_eq!(body["signing"]["tsa_providers"][0]["default"], true);
        assert_eq!(
            body["signing"]["tsa_providers"][0]["url"],
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert_eq!(body["signing"]["require_qualified_for_seal"], false);
        assert_eq!(body["ai"]["enabled"], false);
        assert_eq!(body["platform"]["logging"]["global"], "info");
        assert_eq!(body["platform"]["logging"]["app"], "info");
        assert_eq!(body["platform"]["logging"]["api"], "info");
        assert_eq!(body["platform"]["logging"]["mcp"], "info");
        assert_eq!(body["platform"]["logging"]["service_overrides"], json!({}));
        assert_eq!(body["platform"]["api_server"]["enabled"], true);
        assert_eq!(body["platform"]["api_server"]["desired_state"], "running");
        assert_eq!(body["platform"]["api_server"]["last_action"], Value::Null);
        assert_eq!(body["platform"]["mcp_stdio_server"]["enabled"], false);
        assert_eq!(
            body["platform"]["mcp_stdio_server"]["desired_state"],
            "stopped"
        );
        assert_eq!(
            body["platform"]["mcp_stdio_server"]["last_action"],
            Value::Null
        );
        assert_eq!(body["platform"]["audit"], json!([]));
        assert_eq!(
            body["data_management"]["retained_export_cleanup"]["minimum_age_days"],
            30
        );
        assert_eq!(
            body["data_management"]["retained_export_cleanup"]["keep_latest"],
            5
        );
        assert_eq!(body["appearance"]["theme"], "system");
        assert_eq!(body["appearance"]["leather_texture"], true);
        assert_eq!(body["appearance"]["texture_intensity"], 60);
        assert_eq!(body["appearance"]["button_texture"], true);
    }

    #[tokio::test]
    async fn settings_provider_metadata_counts_stored_csc_credentials_without_secret_status_leaks()
    {
        let tmp = TempDir::new();
        let mut state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                &tmp.dir,
                b"settings-provider-credential-db-key",
                false,
            )),
            ..AppState::default()
        };
        state.csc_providers = Arc::new(vec![CscConfig {
            provider_id: "encosto-qtsp".to_owned(),
            display_name: "Encosto QTSP".to_owned(),
            base_url: "https://sandbox.encosto.example/csc/v2".to_owned(),
            authorization: chancela_csc::CscAuthorization::Service,
            sandbox: false,
            credential_id: None,
            scope: chancela_csc::DEFAULT_SCOPE.to_owned(),
        }]);
        state
            .provider_credentials
            .put(
                CredentialMode::CscQtsp,
                "encosto-qtsp",
                CscCredentialFields {
                    client_id: Some(Zeroizing::new("client-id-hidden-abcd".to_owned())),
                    client_secret: Some(Zeroizing::new("client-secret-hidden-wxyz".to_owned())),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted CSC credentials");

        let (status, body) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let provider = body["signing"]["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .find(|provider| provider["id"] == "encosto-qtsp")
            .expect("CSC provider metadata");
        assert_eq!(provider["configured"], true, "{body}");
        assert_eq!(provider["production_blocked"], false, "{body}");
        assert!(
            provider["note"]
                .as_str()
                .expect("note")
                .contains("protected storage"),
            "{body}"
        );

        let rendered = body.to_string();
        for forbidden in [
            "client-id-hidden-abcd",
            "client-secret-hidden-wxyz",
            "abcd",
            "wxyz",
            "last4",
            "ciphertext",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "settings metadata leaked {forbidden}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn settings_provider_metadata_counts_stored_cmd_credentials_without_secret_status_leaks()
    {
        let tmp = TempDir::new();
        let state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                &tmp.dir,
                b"settings-cmd-credential-db-key",
                false,
            )),
            ..AppState::default()
        };
        state.settings.write().await.signing.cmd.application_id = None;
        state
            .provider_credentials
            .put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(Zeroizing::new(
                        "stored-cmd-application-hidden-abcd".to_owned(),
                    )),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted CMD credentials");

        let (status, body) = send(state.clone(), get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["signing"]["cmd"]["application_id"], Value::Null);
        let settings_cmd = body["signing"]["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .find(|provider| provider["id"] == "cmd")
            .expect("CMD provider metadata");
        assert_eq!(settings_cmd["configured"], true, "{body}");

        let (status, providers) = send(state, get("/v1/signature/providers")).await;
        assert_eq!(status, StatusCode::OK, "{providers}");
        let picker_cmd = providers
            .as_array()
            .expect("provider picker")
            .iter()
            .find(|provider| provider["id"] == "cmd")
            .expect("CMD picker metadata");
        assert_eq!(picker_cmd["configured"], settings_cmd["configured"]);

        let rendered = body.to_string();
        for forbidden in [
            "stored-cmd-application-hidden-abcd",
            "abcd",
            "last4",
            "ciphertext",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "settings metadata leaked {forbidden}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn settings_provider_metadata_treats_blank_stored_csc_secret_as_unconfigured() {
        let tmp = TempDir::new();
        let mut state = AppState {
            provider_credentials: Arc::new(ProviderCredentialStore::load_with_db_key(
                &tmp.dir,
                b"settings-blank-csc-credential-key",
                false,
            )),
            ..AppState::default()
        };
        state.csc_providers = Arc::new(vec![CscConfig {
            provider_id: "encosto-qtsp".to_owned(),
            display_name: "Encosto QTSP".to_owned(),
            base_url: "https://sandbox.encosto.example/csc/v2".to_owned(),
            authorization: chancela_csc::CscAuthorization::Service,
            sandbox: false,
            credential_id: None,
            scope: chancela_csc::DEFAULT_SCOPE.to_owned(),
        }]);
        state
            .provider_credentials
            .put(
                CredentialMode::CscQtsp,
                "encosto-qtsp",
                CscCredentialFields {
                    client_id: Some(Zeroizing::new("client-id-hidden-abcd".to_owned())),
                    client_secret: Some(Zeroizing::new("   ".to_owned())),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted CSC credentials");

        let (status, body) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let provider = body["signing"]["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .find(|provider| provider["id"] == "encosto-qtsp")
            .expect("CSC provider metadata");
        assert_eq!(provider["configured"], false, "{body}");
        assert_eq!(provider["production_blocked"], true, "{body}");

        let rendered = body.to_string();
        for forbidden in ["client-id-hidden-abcd", "abcd", "last4", "ciphertext"] {
            assert!(
                !rendered.contains(forbidden),
                "settings metadata leaked {forbidden}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn settings_put_round_trips_and_get_reflects() {
        let state = AppState::default();
        let (status, stored) =
            send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        // PUT echoes the stored document.
        assert_eq!(stored, sample_settings());

        // A subsequent GET reflects the stored document exactly.
        let (status, got) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, sample_settings());
    }

    #[tokio::test]
    async fn dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed() {
        use chancela_authz::{GUEST_ROLE_ID, LEITOR_ROLE_ID, RoleAssignment, Scope};

        let state = fresh_state().await;
        let owner_token = auth_token(&state).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                put_json(
                    "/v1/settings",
                    json!({ "organization": { "name": "Dashboard Audit" } }),
                ),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, owner_dashboard) = send_raw(
            state.clone(),
            with_session(get("/v1/dashboard"), &owner_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{owner_dashboard}");
        let owner_events = owner_dashboard["recent_events"]
            .as_array()
            .expect("owner recent_events");
        let owner_event = owner_events
            .iter()
            .find(|event| event["kind"] == "settings.updated")
            .expect("owner sees the settings.updated ledger event");
        assert_eq!(owner_event["actor"], "test.actor");
        assert_eq!(owner_event["justification"], "settings updated");
        assert_eq!(owner_event["scope"], "settings");

        let reader_id = seed_user(
            &state,
            "reader.dashboard-events",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let reader_token = seed_session(&state, &reader_id.to_string()).await;
        let (status, reader_dashboard) = send_raw(
            state.clone(),
            with_session(get("/v1/dashboard"), &reader_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reader_dashboard}");
        assert!(
            reader_dashboard["recent_events"]
                .as_array()
                .expect("reader recent_events")
                .iter()
                .any(|event| event["kind"] == "settings.updated"),
            "authorized non-guest reader should still see recent ledger events: {reader_dashboard}"
        );

        let guest_id = seed_user(
            &state,
            "guest.dashboard-events",
            vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        )
        .await;
        let guest_token = seed_session(&state, &guest_id.to_string()).await;
        let (status, ledger_body) = send_raw(
            state.clone(),
            with_session(get("/v1/ledger/events"), &guest_token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{ledger_body}");

        let (status, guest_dashboard) =
            send_raw(state, with_session(get("/v1/dashboard"), &guest_token)).await;
        assert_eq!(status, StatusCode::OK, "{guest_dashboard}");
        assert_eq!(guest_dashboard["recent_events"], json!([]));

        let guest_body = serde_json::to_string(&guest_dashboard).expect("guest body serializes");
        for field in [
            "actor",
            "justification",
            "scope",
            "payload_digest",
            "prev_hash",
            "hash",
        ] {
            let value = owner_event[field].as_str().expect(field);
            assert!(
                !guest_body.contains(value),
                "guest dashboard leaked {field}={value}: {guest_body}"
            );
        }
    }

    #[tokio::test]
    async fn dashboard_backup_recovery_freshness_advisory_is_recovery_authority_gated() {
        use chancela_authz::{LEITOR_ROLE_ID, Permission, Role, RoleAssignment, RoleId, Scope};

        let state = fresh_state().await;
        let backup_reviewer = RoleId(Uuid::from_u128(0xBACA));
        state.roles.write().await.insert(Role {
            id: backup_reviewer,
            name: "Dashboard backup reviewer".to_owned(),
            permission_set: [Permission::ActRead, Permission::DataBackup]
                .into_iter()
                .collect(),
            protected: false,
        });

        let backup_actor = seed_user(
            &state,
            "dashboard.backup.reviewer",
            vec![RoleAssignment::new(backup_reviewer, Scope::Global)],
        )
        .await;
        let backup_token = seed_session(&state, &backup_actor.to_string()).await;
        let (status, backup_dashboard) = send_raw(
            state.clone(),
            with_session(get("/v1/dashboard"), &backup_token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{backup_dashboard}");
        let backup_alert = backup_dashboard["alerts"]
            .as_array()
            .expect("backup dashboard alerts")
            .iter()
            .find(|alert| alert["code"] == "backup.recovery.freshness_advisory")
            .expect("backup-authorized dashboard includes freshness advisory");
        assert_eq!(backup_alert["label"], "Advisory");
        assert_eq!(backup_alert["params"]["freshness_status"], "no_receipt");
        assert_eq!(backup_alert["params"]["policy_max_drill_age_days"], "90");
        assert_eq!(backup_alert["params"]["latest_receipt_at"], "not_recorded");
        assert_eq!(
            backup_alert["params"]["latest_receipt_preflight_ready"],
            "false"
        );
        assert_eq!(
            backup_alert["params"]["latest_receipt_isolated_restore_verified"],
            "false"
        );
        assert!(backup_alert["params"].get("latest_receipt_id").is_none());
        assert!(backup_alert["params"].get("archive").is_none());
        assert_eq!(backup_alert["action"]["route"], "/configuracoes?sec=dados");

        let reader = seed_user(
            &state,
            "dashboard.reader.no.backup",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let reader_token = seed_session(&state, &reader.to_string()).await;
        let (status, reader_dashboard) =
            send_raw(state, with_session(get("/v1/dashboard"), &reader_token)).await;
        assert_eq!(status, StatusCode::OK, "{reader_dashboard}");
        assert!(
            reader_dashboard["alerts"]
                .as_array()
                .expect("reader dashboard alerts")
                .iter()
                .all(|alert| alert["code"] != "backup.recovery.freshness_advisory"),
            "plain dashboard readers must not receive backup recovery freshness state: {reader_dashboard}"
        );
    }

    #[tokio::test]
    async fn settings_partial_document_fills_defaults() {
        // Only one nested field is supplied; every other field must default cleanly.
        let (status, stored) = send(
            AppState::default(),
            put_json(
                "/v1/settings",
                json!({ "organization": { "name": "Solo" } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["schema_version"], 1);
        assert_eq!(stored["organization"]["name"], "Solo");
        assert_eq!(stored["organization"]["default_actor"], "api");
        assert_eq!(stored["documents"]["locale"], "pt-PT");
        assert_eq!(stored["ai"]["enabled"], false);
        assert_eq!(stored["platform"]["logging"]["api"], "info");
        assert_eq!(stored["platform"]["api_server"]["desired_state"], "running");
        assert_eq!(
            stored["platform"]["mcp_stdio_server"]["desired_state"],
            "stopped"
        );
        assert_eq!(stored["appearance"]["texture_intensity"], 60);
        // Omitted trust URLs and button_texture inherit the official/textured defaults.
        assert_eq!(
            stored["signing"]["tsa_url"],
            "http://ts.cartaodecidadao.pt/tsa/server"
        );
        assert_eq!(
            stored["signing"]["tsl_url"],
            "https://www.gns.gov.pt/media/TSLPT.xml"
        );
        assert_eq!(stored["signing"]["tsl_sources"][0]["id"], "pt-gns");
        assert_eq!(stored["signing"]["tsa_providers"][0]["id"], "pt-cc");
        assert_eq!(stored["appearance"]["button_texture"], true);
    }

    #[tokio::test]
    async fn settings_stored_null_tsa_url_is_preserved() {
        // An operator who explicitly cleared the URL (stored `null`) keeps `null` — their
        // recorded choice wins over the new official default (null-vs-default policy).
        let mut doc = sample_settings();
        doc["signing"]["tsa_url"] = Value::Null;
        let (status, stored) = send(AppState::default(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["signing"]["tsa_url"], Value::Null);
        // A sibling field left explicit is untouched.
        assert_eq!(
            stored["signing"]["tsl_url"],
            "https://tsl.example.pt/tsl.xml"
        );
    }

    #[test]
    fn settings_old_document_inherits_new_defaults_and_preserves_null() {
        // An older settings.json that predates these fields: it omits ai, button_texture and
        // tsa_url entirely, and stores tsl_url as an explicit null.
        let old = json!({
            "schema_version": 1,
            "organization": { "name": "Legado", "default_actor": "api" },
            "documents": { "locale": "en-US", "numbering_scheme_default": "Sequential" },
            "signing": { "preferred_family": "CartaoCidadao", "tsl_url": null },
            "appearance": { "theme": "system", "leather_texture": true, "texture_intensity": 60 }
        });
        let parsed: Settings = serde_json::from_value(old).expect("old document deserializes");
        // Omitted field inherits the new official default...
        assert_eq!(
            parsed.signing.tsa_url.as_deref(),
            Some("http://ts.cartaodecidadao.pt/tsa/server")
        );
        // ...while an explicit stored null is preserved as None (operator's choice wins).
        assert_eq!(parsed.signing.tsl_url, None);
        // Omitted additive appearance flag inherits its default (textured buttons on).
        assert!(parsed.appearance.button_texture);
        // Omitted tenant AI/MCP controls default off.
        assert!(!parsed.ai.enabled);
        // Omitted platform operations/logging controls inherit safe defaults.
        assert_eq!(parsed.platform.logging.global, PlatformLogLevel::Info);
        assert_eq!(
            parsed.platform.api_server.desired_state,
            PlatformServiceDesiredState::Running
        );
        assert!(!parsed.platform.mcp_stdio_server.enabled);
        // Omitted registry auto-update policy defaults fail-closed.
        assert!(!parsed.registry_auto_update.enabled);
        assert!(!parsed.registry_auto_update.entity_defaults.enabled);
        assert_eq!(parsed.signing.tsl_sources[0].id, "pt-gns");
        assert_eq!(parsed.signing.tsa_providers[0].id, "pt-cc");
        assert!(parsed.signing.tsa_providers[0].r#default);
    }

    #[tokio::test]
    async fn settings_put_invalid_intensity_is_422() {
        let mut bad = sample_settings();
        bad["appearance"]["texture_intensity"] = json!(150);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_locale_is_422() {
        let mut bad = sample_settings();
        // `fr-FR` is now a supported locale; use a tag outside the 14-locale set.
        bad["documents"]["locale"] = json!("zz-ZZ");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_tsa_url_is_422() {
        let mut bad = sample_settings();
        bad["signing"]["tsa_url"] = json!("ftp://tsa.example.pt");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_rejects_private_loopback_metadata_tsl_tsa_urls() {
        let mut loopback_tsl = sample_settings();
        loopback_tsl["signing"]["tsl_sources"][0]["url"] = json!("http://127.0.0.1:9/tsl.xml");
        let (status, body) =
            send(AppState::default(), put_json("/v1/settings", loopback_tsl)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body["error"].as_str().expect("error");
        assert!(err.contains("signing.tsl_sources[0].url"), "{err}");
        assert!(err.contains("unsafe outbound URL"), "{err}");

        let mut reserved_tsl = sample_settings();
        reserved_tsl["signing"]["tsl_sources"][0]["url"] = json!("http://0.1.2.3/tsl.xml");
        let (status, body) =
            send(AppState::default(), put_json("/v1/settings", reserved_tsl)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body["error"].as_str().expect("error");
        assert!(err.contains("signing.tsl_sources[0].url"), "{err}");
        assert!(err.contains("unsafe outbound URL"), "{err}");
        assert!(err.contains("disallowed address"), "{err}");

        let mut private_tsa = sample_settings();
        private_tsa["signing"]["tsa_providers"][0]["url"] = json!("http://10.0.0.5/tsa");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", private_tsa)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body["error"].as_str().expect("error");
        assert!(err.contains("signing.tsa_providers[0].url"), "{err}");
        assert!(err.contains("unsafe outbound URL"), "{err}");

        let mut reserved_tsa = sample_settings();
        reserved_tsa["signing"]["tsa_providers"][0]["url"] = json!("http://0.1.2.3/tsa");
        let (status, body) =
            send(AppState::default(), put_json("/v1/settings", reserved_tsa)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body["error"].as_str().expect("error");
        assert!(err.contains("signing.tsa_providers[0].url"), "{err}");
        assert!(err.contains("unsafe outbound URL"), "{err}");
        assert!(err.contains("disallowed address"), "{err}");
    }

    #[tokio::test]
    async fn settings_put_allows_public_https_tsl_tsa_urls() {
        let mut doc = sample_settings();
        doc["signing"]["tsl_sources"][0]["url"] = json!("https://93.184.216.34/tsl.xml");
        doc["signing"]["tsa_providers"][0]["url"] = json!("https://93.184.216.34/tsa");

        let (status, stored) = send(AppState::default(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK, "{stored}");
        assert_eq!(
            stored["signing"]["tsl_sources"][0]["url"],
            "https://93.184.216.34/tsl.xml"
        );
        assert_eq!(
            stored["signing"]["tsa_providers"][0]["url"],
            "https://93.184.216.34/tsa"
        );
    }

    #[tokio::test]
    async fn settings_put_invalid_trust_source_provider_config_is_422() {
        let mut duplicate_tsl = sample_settings();
        duplicate_tsl["signing"]["tsl_sources"][1]["id"] = json!("pt-gns");
        let (status, body) =
            send(AppState::default(), put_json("/v1/settings", duplicate_tsl)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("duplicates")
        );

        let mut missing_tsl_location = sample_settings();
        missing_tsl_location["signing"]["tsl_sources"][0]["url"] = Value::Null;
        missing_tsl_location["signing"]["tsl_sources"][0]["path"] = Value::Null;
        let (status, body) = send(
            AppState::default(),
            put_json("/v1/settings", missing_tsl_location),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("either url or path")
        );

        let mut oversized_tsl = sample_settings();
        oversized_tsl["signing"]["tsl_sources"][0]["max_bytes"] = json!(200 * 1024 * 1024u64);
        let (status, body) =
            send(AppState::default(), put_json("/v1/settings", oversized_tsl)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].as_str().expect("error").contains("max_bytes"));

        let mut no_default_tsa = sample_settings();
        no_default_tsa["signing"]["tsa_providers"][0]["default"] = json!(false);
        let (status, body) = send(
            AppState::default(),
            put_json("/v1/settings", no_default_tsa),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("exactly one enabled default")
        );
    }

    #[tokio::test]
    async fn settings_put_invalid_cae_update_url_is_422() {
        let mut bad = sample_settings();
        bad["catalog"]["cae_update_url"] = json!("not-a-url");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_registry_auto_update_values_are_422() {
        let mut bad_cadence = sample_settings();
        bad_cadence["registry_auto_update"]["cadence"] =
            json!({ "kind": "interval_hours", "hours": 0 });
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad_cadence)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("registry_auto_update.cadence.hours")
        );

        let mut bad_backoff = sample_settings();
        bad_backoff["registry_auto_update"]["min_backoff_minutes"] = json!(60);
        bad_backoff["registry_auto_update"]["max_backoff_minutes"] = json!(30);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad_backoff)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("min_backoff_minutes")
        );
    }

    #[tokio::test]
    async fn settings_put_invalid_platform_log_level_is_422() {
        let mut bad = sample_settings();
        bad["platform"]["logging"]["api"] = json!("verbose");
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_invalid_platform_service_ids_are_422() {
        let mut unknown = sample_settings();
        unknown["platform"]["logging"]["service_overrides"] = json!({ "mystery": "info" });
        let (status, body) = send(AppState::default(), put_json("/v1/settings", unknown)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("unknown platform service id")
        );

        let mut blank = sample_settings();
        blank["platform"]["logging"]["service_overrides"] = json!({ "": "info" });
        let (status, body) = send(AppState::default(), put_json("/v1/settings", blank)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("must not be blank")
        );
    }

    #[tokio::test]
    async fn settings_put_bad_cae_source_entry_is_422() {
        // A cae_sources entry with a non-http(s) URL is rejected.
        let mut bad = sample_settings();
        bad["catalog"]["cae_sources"] =
            json!([{ "url": "ftp://espelho.example/cae.json", "format": "Auto" }]);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad.clone())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());

        // A malformed digest pin (not 64-char sha256 hex) is also rejected.
        bad["catalog"]["cae_sources"] = json!([{ "url": "https://espelho.example/cae.json", "format": "Auto", "digest": "xyz" }]);
        let (status, body) = send(AppState::default(), put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_catalog_v2_round_trips() {
        // The whole §catalog-v2 block (update URL + ordered sources with format/digest + official
        // toggle) round-trips through PUT/GET unchanged.
        let state = AppState::default();
        let (status, stored) =
            send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["catalog"]["cae_official_source"], true);
        assert_eq!(
            stored["catalog"]["cae_sources"][0]["url"],
            "https://espelho.example.pt/cae.json"
        );
        assert_eq!(stored["catalog"]["cae_sources"][0]["format"], "Envelope");
        assert_eq!(stored["catalog"]["cae_sources"][1]["format"], "Pdf");
        let (status, got) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["catalog"], sample_settings()["catalog"]);
    }

    #[tokio::test]
    async fn settings_preferred_official_source_defaults_to_ine_and_round_trips() {
        // Default (omitted) → Ine (user directive t37: "default is ine").
        let state = AppState::default();
        let (status, defaults) = send(state, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(defaults["catalog"]["preferred_official_source"], "Ine");

        // A non-default value round-trips.
        let state = AppState::default();
        let mut doc = sample_settings();
        doc["catalog"]["preferred_official_source"] = json!("DiarioRepublica");
        let (status, stored) = send(state.clone(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored["catalog"]["preferred_official_source"],
            "DiarioRepublica"
        );

        // An unknown value is rejected by deserialization → 422.
        let mut bad = sample_settings();
        bad["catalog"]["preferred_official_source"] = json!("Eurostat");
        let (status, body) = send(state, put_json("/v1/settings", bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn settings_put_appends_ledger_event_with_default_actor() {
        let state = AppState::default();
        let (status, _) = send(state.clone(), put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);

        let (status, events) = send(state, get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = events.as_array().expect("events array");
        let updated = arr
            .iter()
            .find(|e| e["kind"] == "settings.updated")
            .expect("settings.updated event present");
        // t41: with a session, the actor is the session username ("test.actor"),
        // not the document's organization.default_actor.
        assert_eq!(updated["actor"], "test.actor");
        assert_eq!(updated["scope"], "settings");
        assert_eq!(updated["justification"], "settings updated");
    }

    #[tokio::test]
    async fn settings_put_actor_query_overrides_default_actor() {
        let state = AppState::default();
        let (status, _) = send(
            state.clone(),
            put_json("/v1/settings?actor=auditor", sample_settings()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let arr = events.as_array().expect("events array");
        let updated = arr
            .iter()
            .find(|e| e["kind"] == "settings.updated")
            .expect("settings.updated event present");
        // t41: with a session, the actor is the session username ("test.actor"),
        // which takes precedence over the ?actor= query param.
        assert_eq!(updated["actor"], "test.actor");
    }

    /// A throwaway data directory (unique under the OS temp dir), cleaned up on drop.
    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("chancela-data-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp data dir created");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn settings_file_persistence_round_trip() {
        let tmp = TempDir::new();

        // A file-backed state starts at defaults and has no settings.json yet.
        let first = AppState::with_data_dir(tmp.dir.clone());
        let settings_file = tmp.dir.join("settings.json");
        assert!(!settings_file.exists(), "no file before the first PUT");

        // PUT persists the document to disk.
        let (status, _) = send(first, put_json("/v1/settings", sample_settings())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(settings_file.is_file(), "settings.json written on PUT");

        // A fresh state over the same directory loads the persisted document at startup.
        let second = AppState::with_data_dir(tmp.dir.clone());
        let (status, got) = send(second, get("/v1/settings")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got, sample_settings());
    }

    async fn seed_platform_log(
        state: &AppState,
        service_id: &str,
        level: PlatformLogLevel,
        target: &str,
        message: &str,
        context: Option<Value>,
    ) {
        platform_logs::record_platform_log(
            state,
            platform_logs::PlatformLogInput {
                service_id,
                level,
                target,
                message,
                context,
            },
        )
        .await
        .expect("platform log seed");
    }

    async fn platform_logs_api_key(
        state: &AppState,
        permission: chancela_authz::Permission,
    ) -> String {
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/api-keys",
                json!({
                    "name": format!("platform-log-{permission}"),
                    "grant": {
                        "kind": "permissions",
                        "permissions": [permission.as_str()],
                        "scope": { "kind": "global" }
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "API key created: {body}");
        body["secret"].as_str().expect("secret").to_owned()
    }

    fn valid_forwarded_platform_log_body() -> Value {
        json!({
            "service_id": "api",
            "level": "info",
            "target": "platform.forwarded.test",
            "message": "forwarded structured event",
            "context": {
                "pid": 4242,
                "supervisor": "test-harness"
            }
        })
    }

    const FORWARDED_LOG_TEST_ROUTE: &str = "/v1/platform/logs/forwarded";
    const MALFORMED_FORWARDED_LOG_BODY: &str = r#"{"service_id":"api","level":"info","target":"platform.forwarded.malformed","message":"raw malformed forwarded body","context":{"token":"secret-material"}"#;

    fn post_malformed_forwarded_platform_log() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(FORWARDED_LOG_TEST_ROUTE)
            .header("content-type", "application/json")
            .body(Body::from(MALFORMED_FORWARDED_LOG_BODY))
            .expect("request builds")
    }

    fn assert_no_malformed_forwarded_raw_material(dump: &str, label: &str) {
        for needle in [
            MALFORMED_FORWARDED_LOG_BODY,
            "raw malformed forwarded body",
            "platform.forwarded.malformed",
            "secret-material",
            "token",
            "EOF",
        ] {
            assert!(
                !dump.contains(needle),
                "{label} must not expose raw malformed JSON material or parser detail: {dump}"
            );
        }
    }

    fn audit_payload_digest<T: serde::Serialize>(payload: &T) -> String {
        crate::hex::hex(&chancela_ledger::digest(
            &serde_json::to_vec(payload).expect("audit payload serializes"),
        ))
    }

    #[derive(serde::Serialize)]
    struct ExpectedForwardedPlatformLogAcceptedAuditPayload<'a> {
        log_id: &'a str,
        log_seq: u64,
        log_timestamp: &'a str,
        service_id: &'a str,
        level: PlatformLogLevel,
        target: &'a str,
        message_len_bytes: usize,
        message_sha256: String,
        context_key_count: usize,
        context_serialized_size_bytes: usize,
    }

    #[derive(serde::Serialize)]
    struct ExpectedForwardedPlatformLogRouteOutcomeAuditPayload<'a> {
        route: &'a str,
        outcome: &'a str,
    }

    #[derive(serde::Serialize)]
    struct ExpectedForwardedPlatformLogRejectedAuditPayload<'a> {
        route: &'a str,
        outcome: &'a str,
        reason_code: &'a str,
    }

    #[derive(serde::Serialize)]
    struct ExpectedForwardedPlatformLogSuppressedAuditPayload<'a> {
        route: &'a str,
        outcome: &'a str,
        reason_code: &'a str,
        service_id: &'a str,
        level: PlatformLogLevel,
        target: &'a str,
        message_len_bytes: usize,
        message_sha256: String,
        context_key_count: usize,
        context_serialized_size_bytes: usize,
    }

    fn forwarded_log_audit_digest(log: &Value) -> String {
        let message = log["message"].as_str().expect("log message");
        let context = log.get("context").filter(|value| !value.is_null());
        let payload = ExpectedForwardedPlatformLogAcceptedAuditPayload {
            log_id: log["id"].as_str().expect("log id"),
            log_seq: log["seq"].as_u64().expect("log seq"),
            log_timestamp: log["timestamp"].as_str().expect("log timestamp"),
            service_id: log["service_id"].as_str().expect("log service_id"),
            level: PlatformLogLevel::Info,
            target: log["target"].as_str().expect("log target"),
            message_len_bytes: message.len(),
            message_sha256: sha256_hex_test(message.as_bytes()),
            context_key_count: context.map(context_key_count_test).unwrap_or(0),
            context_serialized_size_bytes: context
                .map(|value| serde_json::to_vec(value).expect("context serializes").len())
                .unwrap_or(0),
        };
        audit_payload_digest(&payload)
    }

    fn forwarded_log_denied_audit_digest() -> String {
        audit_payload_digest(&ExpectedForwardedPlatformLogRouteOutcomeAuditPayload {
            route: FORWARDED_LOG_TEST_ROUTE,
            outcome: "rbac_denied",
        })
    }

    fn forwarded_log_rejected_audit_digest(reason_code: &str) -> String {
        audit_payload_digest(&ExpectedForwardedPlatformLogRejectedAuditPayload {
            route: FORWARDED_LOG_TEST_ROUTE,
            outcome: "rejected",
            reason_code,
        })
    }

    fn forwarded_log_suppressed_audit_digest(body: &Value) -> String {
        let message = body["message"].as_str().expect("forwarded message");
        let context = body.get("context").filter(|value| !value.is_null());
        let payload = ExpectedForwardedPlatformLogSuppressedAuditPayload {
            route: FORWARDED_LOG_TEST_ROUTE,
            outcome: "suppressed",
            reason_code: "threshold_suppressed",
            service_id: body["service_id"].as_str().expect("service id"),
            level: PlatformLogLevel::Error,
            target: body["target"].as_str().expect("target"),
            message_len_bytes: message.len(),
            message_sha256: sha256_hex_test(message.as_bytes()),
            context_key_count: context.map(context_key_count_test).unwrap_or(0),
            context_serialized_size_bytes: context
                .map(|value| serde_json::to_vec(value).expect("context serializes").len())
                .unwrap_or(0),
        };
        audit_payload_digest(&payload)
    }

    fn context_key_count_test(value: &Value) -> usize {
        match value {
            Value::Object(map) => {
                map.len() + map.values().map(context_key_count_test).sum::<usize>()
            }
            Value::Array(items) => items.iter().map(context_key_count_test).sum(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
        }
    }

    #[tokio::test]
    async fn platform_logs_forwarded_post_with_write_api_key_appears_in_tail() {
        let state = AppState::default();
        let key =
            platform_logs_api_key(&state, chancela_authz::Permission::PlatformLogsWrite).await;

        let (status, body) = send_raw(
            state.clone(),
            with_bearer(
                post_json(
                    "/v1/platform/logs/forwarded",
                    valid_forwarded_platform_log_body(),
                ),
                &key,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "forwarded response: {body}");
        assert_eq!(body["accepted"], true);

        let (status, tail) = send(
            state.clone(),
            get("/v1/platform/logs?service_id=api&tail=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "tail response: {tail}");
        let logs = tail["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["service_id"], "api");
        assert_eq!(logs[0]["level"], "info");
        assert_eq!(logs[0]["target"], "platform.forwarded.test");
        assert_eq!(logs[0]["message"], "forwarded structured event");
        assert_eq!(
            logs[0]["context"],
            json!({ "pid": 4242, "supervisor": "test-harness" })
        );

        let (status, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK, "ledger response: {events}");
        let forwarded_events = events
            .as_array()
            .expect("ledger events")
            .iter()
            .filter(|event| {
                event["kind"]
                    .as_str()
                    .is_some_and(|kind| kind.starts_with("platform.log.forwarded."))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            forwarded_events.len(),
            1,
            "retained forwarded log should append exactly one forwarded audit event: {events}"
        );
        let event = events
            .as_array()
            .expect("ledger events")
            .iter()
            .find(|event| event["kind"] == "platform.log.forwarded.accepted")
            .expect("forwarded accepted audit event");
        assert_eq!(event["scope"], "platform");
        assert_eq!(event["justification"], "forwarded platform log accepted");
        assert_eq!(
            event["payload_digest"],
            forwarded_log_audit_digest(&logs[0])
        );
        let event_dump = event.to_string();
        assert!(
            !event_dump.contains("forwarded structured event")
                && !event_dump.contains("test-harness")
                && !event_dump.contains("supervisor"),
            "ledger event must not expose raw message or context: {event}"
        );

        let (status, verify) = send(state, get("/v1/ledger/verify")).await;
        assert_eq!(status, StatusCode::OK, "verify response: {verify}");
        assert_eq!(verify["valid"], true);
    }

    #[tokio::test]
    async fn platform_logs_forwarded_missing_bearer_writes_nothing() {
        let state = AppState::default();
        let ledger_len_before = state.ledger.read().await.len();

        let (status, _) = send_raw(
            state.clone(),
            post_json(
                "/v1/platform/logs/forwarded",
                valid_forwarded_platform_log_body(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before,
            "missing bearer must not append ledger events"
        );
        let (status, tail) = send(state.clone(), get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));
    }

    #[tokio::test]
    async fn platform_logs_forwarded_malformed_json_with_owner_auth_audits_sanitized_rejection_without_tail_or_sidecar()
     {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let token = auth_token(&state).await;
        let ledger_len_before = state.ledger.read().await.len();

        let (status, err) = send_raw(
            state.clone(),
            with_session(post_malformed_forwarded_platform_log(), &token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
        assert_eq!(
            err["error"],
            "forwarded platform log request body is malformed JSON"
        );
        assert_no_malformed_forwarded_raw_material(&err.to_string(), "malformed JSON response");

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before + 1,
            "authenticated malformed JSON should append one sanitized rejected audit event"
        );
        let (status, tail) = send(state.clone(), get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));
        assert!(
            !tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE).exists(),
            "rejected malformed forwarded log must not create platform log sidecar"
        );

        let (status, events) = send(state, get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK, "ledger response: {events}");
        let forwarded_events = events
            .as_array()
            .expect("ledger events")
            .iter()
            .filter(|event| {
                event["kind"]
                    .as_str()
                    .is_some_and(|kind| kind.starts_with("platform.log.forwarded."))
            })
            .collect::<Vec<_>>();
        assert_eq!(forwarded_events.len(), 1, "{events}");
        let event = forwarded_events[0];
        assert_eq!(event["kind"], "platform.log.forwarded.rejected");
        assert_eq!(event["scope"], "platform");
        assert_eq!(event["justification"], "forwarded platform log rejected");
        assert_eq!(
            event["payload_digest"],
            forwarded_log_rejected_audit_digest("malformed_json")
        );
        assert_no_malformed_forwarded_raw_material(&event.to_string(), "malformed JSON audit");
    }

    #[tokio::test]
    async fn platform_logs_forwarded_malformed_json_missing_or_invalid_bearer_writes_no_audit() {
        let state = AppState::default();
        let ledger_len_before = state.ledger.read().await.len();

        let cases = vec![
            ("missing bearer", post_malformed_forwarded_platform_log()),
            (
                "invalid bearer",
                with_bearer(post_malformed_forwarded_platform_log(), "not-a-real-key"),
            ),
        ];
        for (label, req) in cases {
            let (status, err) = send_raw(state.clone(), req).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}: {err}");
            assert_no_malformed_forwarded_raw_material(
                &err.to_string(),
                &format!("{label} response"),
            );
        }

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before,
            "missing or invalid bearer must not append malformed JSON audit events"
        );
        let (status, tail) = send(state, get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));
    }

    #[tokio::test]
    async fn platform_logs_forwarded_malformed_json_authenticated_rbac_denied_gets_only_route_outcome_audit()
     {
        let state = AppState::default();
        let read_key =
            platform_logs_api_key(&state, chancela_authz::Permission::SettingsRead).await;
        let ledger_len_before = state.ledger.read().await.len();

        let (status, err) = send_raw(
            state.clone(),
            with_bearer(post_malformed_forwarded_platform_log(), &read_key),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert_no_malformed_forwarded_raw_material(&err.to_string(), "RBAC denial response");

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before + 1,
            "authenticated RBAC denial should append one sanitized audit event"
        );
        let (status, tail) = send(state.clone(), get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));

        let (status, events) = send(state, get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK, "ledger response: {events}");
        let forwarded_events = events
            .as_array()
            .expect("ledger events")
            .iter()
            .filter(|event| {
                event["kind"]
                    .as_str()
                    .is_some_and(|kind| kind.starts_with("platform.log.forwarded."))
            })
            .collect::<Vec<_>>();
        assert_eq!(forwarded_events.len(), 1, "{events}");
        let event = forwarded_events[0];
        assert_eq!(event["kind"], "platform.log.forwarded.denied");
        assert_eq!(event["scope"], "platform");
        assert_eq!(event["justification"], "forwarded platform log denied");
        assert_eq!(event["payload_digest"], forwarded_log_denied_audit_digest());
        assert_no_malformed_forwarded_raw_material(&event.to_string(), "RBAC denial audit");
    }

    #[tokio::test]
    async fn platform_logs_forwarded_authenticated_rbac_denied_gets_route_outcome_audit() {
        let state = AppState::default();
        let read_key =
            platform_logs_api_key(&state, chancela_authz::Permission::SettingsRead).await;
        let ledger_len_before = state.ledger.read().await.len();

        let (status, _) = send_raw(
            state.clone(),
            with_bearer(
                post_json(
                    "/v1/platform/logs/forwarded",
                    valid_forwarded_platform_log_body(),
                ),
                &read_key,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before + 1,
            "authenticated RBAC denial should append one sanitized audit event"
        );
        let (status, tail) = send(state.clone(), get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));

        let (status, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK, "ledger response: {events}");
        let event = events
            .as_array()
            .expect("ledger events")
            .iter()
            .find(|event| event["kind"] == "platform.log.forwarded.denied")
            .expect("forwarded denied audit event");
        assert_eq!(event["scope"], "platform");
        assert_eq!(event["justification"], "forwarded platform log denied");
        assert_eq!(event["payload_digest"], forwarded_log_denied_audit_digest());
        let event_dump = event.to_string();
        assert!(
            !event_dump.contains("forwarded structured event")
                && !event_dump.contains("test-harness")
                && !event_dump.contains("supervisor"),
            "denied audit must not expose forwarded payload: {event}"
        );
    }

    #[tokio::test]
    async fn platform_logs_forwarded_global_and_service_off_suppress_without_sidecar() {
        for label in ["global off", "service override off"] {
            let tmp = TempDir::new();
            let state = AppState::with_data_dir(tmp.dir.clone());
            {
                let mut settings = state.settings.write().await;
                match label {
                    "global off" => {
                        settings.platform.logging.global = PlatformLogLevel::Off;
                        settings.platform.logging.api = PlatformLogLevel::Trace;
                        settings
                            .platform
                            .logging
                            .service_overrides
                            .insert("api".to_owned(), PlatformLogLevel::Trace);
                    }
                    "service override off" => {
                        settings.platform.logging.global = PlatformLogLevel::Trace;
                        settings.platform.logging.api = PlatformLogLevel::Trace;
                        settings
                            .platform
                            .logging
                            .service_overrides
                            .insert("api".to_owned(), PlatformLogLevel::Off);
                    }
                    _ => unreachable!("known platform log suppression scenario"),
                }
            }
            let key =
                platform_logs_api_key(&state, chancela_authz::Permission::PlatformLogsWrite).await;
            let ledger_len_before = state.ledger.read().await.len();
            let forwarded = json!({
                "service_id": "api",
                "level": "error",
                "target": "platform.forwarded.suppressed",
                "message": format!("suppressed by {label}")
            });

            let (status, body) = send_raw(
                state.clone(),
                with_bearer(
                    post_json("/v1/platform/logs/forwarded", forwarded.clone()),
                    &key,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{label}: {body}");

            assert_eq!(
                state.ledger.read().await.len(),
                ledger_len_before + 1,
                "{label}: suppressed forwarded log should append one audit event"
            );
            let (status, tail) = send(
                state.clone(),
                get("/v1/platform/logs?service_id=api&tail=10"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{label}: {tail}");
            assert_eq!(tail["logs"], json!([]), "{label}");
            assert!(
                !tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE).exists(),
                "{label}: suppressed forwarded log should not create platform log sidecar"
            );

            let (status, events) = send(state, get("/v1/ledger/events?limit=1000")).await;
            assert_eq!(status, StatusCode::OK, "{label}: {events}");
            let event = events
                .as_array()
                .expect("ledger events")
                .iter()
                .find(|event| event["kind"] == "platform.log.forwarded.suppressed")
                .expect("forwarded suppressed audit event");
            assert_eq!(event["scope"], "platform", "{label}");
            assert_eq!(
                event["justification"], "forwarded platform log suppressed",
                "{label}"
            );
            assert_eq!(
                event["payload_digest"],
                forwarded_log_suppressed_audit_digest(&forwarded),
                "{label}"
            );
            let event_dump = event.to_string();
            assert!(
                !event_dump.contains("suppressed by")
                    && !event_dump.contains("platform.forwarded.suppressed"),
                "{label}: suppressed audit must not expose raw message or target: {event}"
            );
        }
    }

    #[tokio::test]
    async fn platform_logs_forwarded_data_dir_post_persists_and_reloads() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let key =
            platform_logs_api_key(&state, chancela_authz::Permission::PlatformLogsWrite).await;

        let (status, body) = send_raw(
            state,
            with_bearer(
                post_json(
                    "/v1/platform/logs/forwarded",
                    json!({
                        "service_id": "mcp_stdio",
                        "level": "warn",
                        "target": "platform.forwarded.durable",
                        "message": "durable forwarded event",
                        "context": { "attempt": 1 }
                    }),
                ),
                &key,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "forwarded response: {body}");
        assert!(
            tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE).is_file(),
            "platform log sidecar written by POST"
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, tail) = send(
            restarted,
            get("/v1/platform/logs?service_id=mcp_stdio&level=warn&tail=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "tail response: {tail}");
        let logs = tail["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["message"], "durable forwarded event");
        assert_eq!(logs[0]["context"], json!({ "attempt": 1 }));
    }

    #[tokio::test]
    async fn platform_logs_forwarded_rejects_invalid_structured_payloads() {
        let state = AppState::default();
        let key =
            platform_logs_api_key(&state, chancela_authz::Permission::PlatformLogsWrite).await;
        let ledger_len_before = state.ledger.read().await.len();
        let cases = vec![
            ("stream field", "unsupported_field", {
                let mut body = valid_forwarded_platform_log_body();
                body["stdout"] = json!("raw stdout must not be accepted");
                body["stderr"] = json!("raw stderr must not be accepted");
                body
            }),
            ("secret-like context key", "unsupported_context_key", {
                let mut body = valid_forwarded_platform_log_body();
                body["context"] = json!({ "api_key": "redacted" });
                body
            }),
        ];

        for (label, _reason_code, body) in &cases {
            let (status, err) = send_raw(
                state.clone(),
                with_bearer(post_json("/v1/platform/logs/forwarded", body.clone()), &key),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {err}");
            let err_dump = err.to_string();
            assert!(
                !err_dump.contains("raw stdout must not be accepted")
                    && !err_dump.contains("raw stderr must not be accepted")
                    && !err_dump.contains("api_key")
                    && !err_dump.contains("redacted"),
                "{label}: error response must not echo raw payload material: {err}"
            );
        }

        assert_eq!(
            state.ledger.read().await.len(),
            ledger_len_before + cases.len(),
            "invalid forwarded logs should append one sanitized rejected event each"
        );
        let (status, tail) = send(state.clone(), get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tail["logs"], json!([]));

        let (status, events) = send(state, get("/v1/ledger/events?limit=1000")).await;
        assert_eq!(status, StatusCode::OK, "ledger response: {events}");
        let rejected_events = events
            .as_array()
            .expect("ledger events")
            .iter()
            .filter(|event| event["kind"] == "platform.log.forwarded.rejected")
            .collect::<Vec<_>>();
        assert_eq!(rejected_events.len(), cases.len(), "{events}");
        for event in rejected_events {
            assert_eq!(event["scope"], "platform");
            assert_eq!(event["justification"], "forwarded platform log rejected");
            let digest = event["payload_digest"].as_str().expect("payload digest");
            assert!(
                cases.iter().any(|(_, reason_code, _)| digest
                    == forwarded_log_rejected_audit_digest(reason_code)),
                "unexpected rejected audit payload digest: {event}"
            );
            let event_dump = event.to_string();
            assert!(
                !event_dump.contains("raw stdout must not be accepted")
                    && !event_dump.contains("raw stderr must not be accepted")
                    && !event_dump.contains("api_key")
                    && !event_dump.contains("redacted"),
                "rejected audit must not expose raw payload material: {event}"
            );
        }
    }

    #[tokio::test]
    async fn platform_logs_default_empty_tail_is_honest() {
        let state = AppState::default();
        let (status, body) = send(state, get("/v1/platform/logs")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logs"], json!([]));
        assert_eq!(body["tail"], platform_logs::PLATFORM_LOG_DEFAULT_TAIL);
        assert_eq!(body["order"], "chronological");
        assert_eq!(
            body["retention"],
            json!({
                "retention_limit": platform_logs::PLATFORM_LOG_RETENTION_LIMIT,
                "retained_count": 0,
                "oldest_seq": null,
                "newest_seq": null,
                "dropped_before_seq": null,
                "durable": false,
                "basis": "memory",
                "source": "process_memory"
            })
        );
        assert!(
            body["limitations"]
                .as_array()
                .expect("limitations")
                .iter()
                .any(|item| item
                    .as_str()
                    .expect("limitation text")
                    .contains("in-memory API-owned structured log ring"))
        );
    }

    #[tokio::test]
    async fn platform_logs_seeded_filter_by_service_level_and_tail() {
        let state = AppState::default();
        seed_platform_log(
            &state,
            "mcp_stdio",
            PlatformLogLevel::Info,
            "platform.test",
            "mcp info",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Warn,
            "platform.test",
            "api warn one",
            Some(json!({ "slot": 1 })),
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Warn,
            "platform.test",
            "api warn two",
            Some(json!({ "slot": 2 })),
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Error,
            "platform.test",
            "api error",
            None,
        )
        .await;

        let (status, body) = send(
            state.clone(),
            get("/v1/platform/logs?service_id=api&level=warn&tail=1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let logs = body["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["service_id"], "api");
        assert_eq!(logs[0]["level"], "warn");
        assert_eq!(logs[0]["message"], "api warn two");
        assert_eq!(logs[0]["context"], json!({ "slot": 2 }));

        let (status, body) = send(state, get("/v1/platform/logs?service_id=api&tail=2")).await;
        assert_eq!(status, StatusCode::OK);
        let messages = body["logs"]
            .as_array()
            .expect("logs array")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect::<Vec<_>>();
        assert_eq!(messages, vec!["api warn two", "api error"]);
    }

    #[tokio::test]
    async fn platform_logs_invalid_query_is_422() {
        let state = AppState::default();
        let invalid_uris = vec![
            "/v1/platform/logs?service_id=web".to_owned(),
            "/v1/platform/logs?level=verbose".to_owned(),
            "/v1/platform/logs?level=off".to_owned(),
            "/v1/platform/logs?tail=abc".to_owned(),
            format!(
                "/v1/platform/logs?tail={}",
                platform_logs::PLATFORM_LOG_MAX_TAIL + 1
            ),
        ];
        for uri in invalid_uris {
            let (status, body) = send(state.clone(), get(&uri)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}: {body}");
        }
    }

    #[tokio::test]
    async fn platform_logs_persist_and_reload_from_data_dir() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        seed_platform_log(
            &first,
            "api",
            PlatformLogLevel::Info,
            "platform.test",
            "durable api event",
            Some(json!({ "phase": "first" })),
        )
        .await;

        let log_file = tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE);
        assert!(log_file.is_file(), "platform log sidecar written");

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(
            restarted,
            get("/v1/platform/logs?service_id=api&level=info&tail=10"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let logs = body["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["message"], "durable api event");
        assert_eq!(logs[0]["context"], json!({ "phase": "first" }));
        assert_eq!(
            body["retention"]["retention_limit"],
            platform_logs::PLATFORM_LOG_RETENTION_LIMIT
        );
        assert_eq!(body["retention"]["retained_count"], 1);
        assert_eq!(body["retention"]["oldest_seq"], 1);
        assert_eq!(body["retention"]["newest_seq"], 1);
        assert_eq!(body["retention"]["dropped_before_seq"], Value::Null);
        assert_eq!(body["retention"]["durable"], true);
        assert_eq!(body["retention"]["basis"], "data_dir");
        assert_eq!(
            body["retention"]["source"],
            platform_logs::PLATFORM_LOGS_FILE
        );
        assert!(
            body["limitations"]
                .as_array()
                .expect("limitations")
                .iter()
                .any(|item| item
                    .as_str()
                    .expect("limitation text")
                    .contains("data-dir-backed"))
        );
    }

    #[tokio::test]
    async fn platform_logs_data_dir_retention_is_bounded() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        for idx in 0..platform_logs::PLATFORM_LOG_RETENTION_LIMIT + 3 {
            seed_platform_log(
                &state,
                "api",
                PlatformLogLevel::Info,
                "platform.retention",
                &format!("retained event {idx}"),
                None,
            )
            .await;
        }

        let on_disk: Value = serde_json::from_slice(
            &std::fs::read(tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE)).expect("log sidecar"),
        )
        .expect("platform log sidecar json");
        let entries = on_disk["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), platform_logs::PLATFORM_LOG_RETENTION_LIMIT);
        assert_eq!(entries[0]["seq"], 4);
        assert_eq!(
            entries.last().expect("last retained entry")["seq"]
                .as_u64()
                .expect("last seq"),
            (platform_logs::PLATFORM_LOG_RETENTION_LIMIT + 3) as u64
        );
        assert_eq!(
            on_disk["next_seq"].as_u64().expect("next seq"),
            (platform_logs::PLATFORM_LOG_RETENTION_LIMIT + 4) as u64
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(restarted, get("/v1/platform/logs?tail=1")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["logs"][0]["message"],
            format!(
                "retained event {}",
                platform_logs::PLATFORM_LOG_RETENTION_LIMIT + 2
            )
        );
        assert_eq!(
            body["retention"]["retention_limit"],
            platform_logs::PLATFORM_LOG_RETENTION_LIMIT
        );
        assert_eq!(
            body["retention"]["retained_count"],
            platform_logs::PLATFORM_LOG_RETENTION_LIMIT
        );
        assert_eq!(body["retention"]["oldest_seq"], 4);
        assert_eq!(
            body["retention"]["newest_seq"],
            (platform_logs::PLATFORM_LOG_RETENTION_LIMIT + 3) as u64
        );
        assert_eq!(body["retention"]["dropped_before_seq"], 3);
        assert_eq!(body["retention"]["durable"], true);
        assert_eq!(body["retention"]["basis"], "data_dir");
        assert_eq!(
            body["retention"]["source"],
            platform_logs::PLATFORM_LOGS_FILE
        );
    }

    #[tokio::test]
    async fn platform_logs_malformed_data_dir_sidecar_reads_empty() {
        let tmp = TempDir::new();
        std::fs::write(
            tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE),
            b"{not valid json",
        )
        .expect("write malformed platform log sidecar");

        let state = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(state, get("/v1/platform/logs")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logs"], json!([]));
    }

    #[tokio::test]
    async fn platform_logs_respect_global_floor_and_area_thresholds() {
        let state = AppState::default();
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Warn;
            settings.platform.logging.app = PlatformLogLevel::Debug;
            settings.platform.logging.api = PlatformLogLevel::Info;
            settings.platform.logging.mcp = PlatformLogLevel::Error;
            settings.platform.logging.service_overrides.clear();
        }

        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Info,
            "platform.threshold",
            "api info suppressed by global floor",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Warn,
            "platform.threshold",
            "api warn recorded",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "mcp_stdio",
            PlatformLogLevel::Warn,
            "platform.threshold",
            "mcp warn suppressed by area threshold",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "mcp_stdio",
            PlatformLogLevel::Error,
            "platform.threshold",
            "mcp error recorded",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "app",
            PlatformLogLevel::Debug,
            "platform.threshold",
            "app debug suppressed by global floor",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "app",
            PlatformLogLevel::Warn,
            "platform.threshold",
            "app warn recorded",
            None,
        )
        .await;

        let (status, body) = send(state, get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        let messages = body["logs"]
            .as_array()
            .expect("logs array")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect::<Vec<_>>();
        assert_eq!(
            messages,
            vec![
                "api warn recorded",
                "mcp error recorded",
                "app warn recorded"
            ]
        );
    }

    #[tokio::test]
    async fn platform_logs_service_override_can_lower_threshold_or_turn_service_off() {
        let state = AppState::default();
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Error;
            settings.platform.logging.api = PlatformLogLevel::Error;
            settings
                .platform
                .logging
                .service_overrides
                .insert("api".to_owned(), PlatformLogLevel::Debug);
        }

        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Debug,
            "platform.threshold",
            "api debug recorded by service override",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Trace,
            "platform.threshold",
            "api trace suppressed by service override",
            None,
        )
        .await;
        state
            .settings
            .write()
            .await
            .platform
            .logging
            .service_overrides
            .insert("api".to_owned(), PlatformLogLevel::Off);
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Error,
            "platform.threshold",
            "api error suppressed by service override off",
            None,
        )
        .await;

        let (status, body) = send(state, get("/v1/platform/logs?service_id=api&tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        let messages = body["logs"]
            .as_array()
            .expect("logs array")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect::<Vec<_>>();
        assert_eq!(messages, vec!["api debug recorded by service override"]);
    }

    #[tokio::test]
    async fn platform_logs_service_override_bypasses_global_floor_when_global_is_not_off() {
        let state = AppState::default();
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Warn;
            settings.platform.logging.api = PlatformLogLevel::Debug;
            settings
                .platform
                .logging
                .service_overrides
                .insert("api".to_owned(), PlatformLogLevel::Debug);
        }

        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Debug,
            "platform.threshold",
            "api debug recorded by service override",
            None,
        )
        .await;
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Warn,
            "platform.threshold",
            "api warn recorded above service override",
            None,
        )
        .await;

        let (status, body) = send(state, get("/v1/platform/logs?service_id=api&tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        let messages = body["logs"]
            .as_array()
            .expect("logs array")
            .iter()
            .map(|entry| entry["message"].as_str().expect("message"))
            .collect::<Vec<_>>();
        assert_eq!(
            messages,
            vec![
                "api debug recorded by service override",
                "api warn recorded above service override"
            ]
        );
    }

    #[tokio::test]
    async fn platform_logs_global_off_suppresses_service_override_and_sidecar() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Off;
            settings.platform.logging.api = PlatformLogLevel::Trace;
            settings
                .platform
                .logging
                .service_overrides
                .insert("api".to_owned(), PlatformLogLevel::Trace);
        }

        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Error,
            "platform.threshold",
            "api error suppressed by global off",
            None,
        )
        .await;

        let (status, body) = send(state, get("/v1/platform/logs?service_id=api&tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logs"], json!([]));
        assert!(
            !tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE).exists(),
            "global off should suppress sidecar creation even with a service override"
        );
    }

    #[tokio::test]
    async fn platform_logs_apply_persisted_thresholds_to_api_owned_endpoint_logs() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(
            first,
            put_json(
                "/v1/settings",
                json!({
                    "platform": {
                        "logging": {
                            "global": "warn",
                            "app": "info",
                            "api": "info",
                            "mcp": "info",
                            "service_overrides": {}
                        }
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "settings response: {body}");

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(restarted.clone(), get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK, "services response: {body}");
        let (status, body) = send(restarted, get("/v1/platform/logs?tail=10")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logs"], json!([]));
        assert!(
            !tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE).exists(),
            "suppressed API-owned log should not create a platform log sidecar"
        );
    }

    #[tokio::test]
    async fn platform_action_logs_do_not_echo_secret_request_fields() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let secret = "NeverLog-Platform-Secret-123";
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/platform/services/mcp_stdio/actions/start",
                json!({
                    "api_key": secret,
                    "password": secret,
                    "token": secret
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "control response: {body}");

        let (status, logs) = send(
            state,
            get("/v1/platform/logs?service_id=mcp_stdio&level=info&tail=5"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !logs.to_string().contains(secret),
            "platform log response must not echo secret fields: {logs}"
        );

        let on_disk = std::fs::read_to_string(tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE))
            .expect("platform log sidecar");
        assert!(
            !on_disk.contains(secret),
            "platform log sidecar must not echo secret fields"
        );
    }

    #[tokio::test]
    async fn platform_services_status_exposes_api_and_mcp_records() {
        let state = AppState::default();
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Trace;
            settings.platform.logging.api = PlatformLogLevel::Trace;
            settings
                .platform
                .logging
                .service_overrides
                .insert("api".to_owned(), PlatformLogLevel::Debug);
        }

        let (status, body) = send(state.clone(), get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK);
        let services = body["services"].as_array().expect("services array");
        assert_eq!(services.len(), 2);

        let api = services
            .iter()
            .find(|service| service["id"] == "api")
            .expect("api service");
        assert_eq!(api["kind"], "api");
        assert_eq!(api["configured"], true);
        assert_eq!(api["enabled"], true);
        assert_eq!(api["desired_state"], "running");
        assert_eq!(api["actual_runtime_status"], "running");
        assert_eq!(api["logging_level"], "debug");
        assert!(
            api["limitations"]
                .as_array()
                .expect("api limitations")
                .len()
                >= 2
        );
        assert!(
            api["controllable_actions"]
                .as_array()
                .expect("api actions")
                .iter()
                .any(|action| {
                    action["action"] == "restart"
                        && action["supported"] == false
                        && action["outcome"] == "restart_required"
                })
        );

        let mcp = services
            .iter()
            .find(|service| service["id"] == "mcp_stdio")
            .expect("mcp stdio service");
        assert_eq!(mcp["kind"], "mcp");
        assert_eq!(mcp["enabled"], false);
        assert_eq!(mcp["desired_state"], "stopped");
        assert_eq!(mcp["actual_runtime_status"], "unknown");
        assert_eq!(mcp["logging_level"], "info");
        assert!(
            mcp["controllable_actions"]
                .as_array()
                .expect("mcp actions")
                .iter()
                .all(|action| action["supported"] == false)
        );
        assert!(
            mcp["limitations"]
                .as_array()
                .expect("mcp limitations")
                .iter()
                .any(|item| item
                    .as_str()
                    .expect("limitation text")
                    .contains("cannot observe or spawn"))
        );

        let (status, logs) = send(state, get("/v1/platform/logs?service_id=api&tail=1")).await;
        assert_eq!(status, StatusCode::OK);
        let logs = logs["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["target"], "platform.services");
        assert_eq!(logs[0]["message"], "Platform service status read");
        assert_eq!(logs[0]["context"], json!({ "service_count": 2 }));
    }

    #[tokio::test]
    async fn platform_services_status_reports_effective_logging_thresholds() {
        let state = AppState::default();
        {
            let mut settings = state.settings.write().await;
            settings.platform.logging.global = PlatformLogLevel::Warn;
            settings.platform.logging.api = PlatformLogLevel::Debug;
            settings
                .platform
                .logging
                .service_overrides
                .insert("api".to_owned(), PlatformLogLevel::Debug);
            settings.platform.logging.mcp = PlatformLogLevel::Off;
        }

        let (status, body) = send(state, get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK);
        let services = body["services"].as_array().expect("services array");
        let api = services
            .iter()
            .find(|service| service["id"] == "api")
            .expect("api service");
        let mcp = services
            .iter()
            .find(|service| service["id"] == "mcp_stdio")
            .expect("mcp stdio service");
        assert_eq!(api["logging_level"], "debug");
        assert_eq!(mcp["logging_level"], "off");
    }

    #[tokio::test]
    async fn platform_api_restart_records_unsupported_result_and_audit() {
        let state = AppState::default();
        let (status, body) = send(
            state.clone(),
            post_json("/v1/platform/services/api/actions/restart", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "control response: {body}");
        assert_eq!(body["action"], "restart");
        assert_eq!(body["result"]["kind"], "restart_required");
        assert_eq!(body["result"]["supported"], false);
        assert_eq!(body["result"]["applied_to_settings"], true);
        assert_eq!(body["result"]["desired_state"], "running");
        assert_eq!(body["result"]["actual_runtime_status"], "running");
        assert_eq!(body["service"]["last_action"]["action"], "restart");
        assert_eq!(
            body["service"]["last_action"]["outcome"],
            "restart_required"
        );

        let settings = state.settings.read().await.clone();
        assert_eq!(
            settings.platform.api_server.desired_state,
            PlatformServiceDesiredState::Running
        );
        let last = settings
            .platform
            .api_server
            .last_action
            .expect("last api action");
        assert_eq!(last.action, PlatformServiceAction::Restart);
        assert_eq!(last.outcome, PlatformControlOutcomeKind::RestartRequired);
        assert_eq!(settings.platform.audit.len(), 1);
        assert_eq!(settings.platform.audit[0].service_id, "api");

        let (status, logs) = send(
            state.clone(),
            get("/v1/platform/logs?service_id=api&level=info&tail=5"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let logs = logs["logs"].as_array().expect("logs array");
        let entry = logs
            .iter()
            .find(|entry| entry["target"] == "platform.service.control")
            .expect("control log entry");
        assert_eq!(
            entry["message"],
            "Platform service control desired state recorded"
        );
        assert_eq!(entry["context"]["action"], "restart");
        assert_eq!(entry["context"]["outcome"], "restart_required");
        assert_eq!(entry["context"]["applied_to_settings"], true);

        let (status, events) = send(state, get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = events.as_array().expect("events array");
        let event = arr
            .iter()
            .find(|event| event["kind"] == "platform.service.control")
            .expect("platform control event");
        assert_eq!(event["scope"], "platform");
        assert_eq!(event["justification"], "platform service control requested");
    }

    #[tokio::test]
    async fn platform_api_stop_records_unsupported_desired_state_but_runtime_stays_running() {
        let state = AppState::default();
        let (status, body) = send(
            state.clone(),
            post_json("/v1/platform/services/api/actions/stop", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "control response: {body}");
        assert_eq!(body["action"], "stop");
        assert_eq!(body["result"]["kind"], "unsupported");
        assert_eq!(body["result"]["supported"], false);
        assert_eq!(body["result"]["applied_to_settings"], true);
        assert_eq!(body["result"]["desired_state"], "stopped");
        assert_eq!(body["result"]["actual_runtime_status"], "running");
        assert_eq!(body["service"]["enabled"], false);
        assert_eq!(body["service"]["desired_state"], "stopped");
        assert_eq!(body["service"]["actual_runtime_status"], "running");

        let settings = state.settings.read().await.clone();
        assert_eq!(
            settings.platform.api_server.desired_state,
            PlatformServiceDesiredState::Stopped
        );
        assert!(!settings.platform.api_server.enabled);
        assert_eq!(
            settings
                .platform
                .api_server
                .last_action
                .expect("last api action")
                .outcome,
            PlatformControlOutcomeKind::Unsupported
        );

        let (status, status_body) = send(state, get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK);
        let api = status_body["services"]
            .as_array()
            .expect("services array")
            .iter()
            .find(|service| service["id"] == "api")
            .expect("api service");
        assert_eq!(api["desired_state"], "stopped");
        assert_eq!(api["actual_runtime_status"], "running");
    }

    #[tokio::test]
    async fn platform_mcp_start_records_supervisor_required_result() {
        let state = AppState::default();
        let (status, body) = send(
            state.clone(),
            post_json("/v1/platform/services/mcp_stdio/actions/start", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "control response: {body}");
        assert_eq!(body["action"], "start");
        assert_eq!(body["result"]["kind"], "supervisor_required");
        assert_eq!(body["result"]["supported"], false);
        assert_eq!(body["result"]["desired_state"], "running");
        assert_eq!(body["result"]["actual_runtime_status"], "unknown");
        assert_eq!(body["service"]["enabled"], true);
        assert_eq!(body["service"]["desired_state"], "running");
        assert_eq!(
            body["service"]["last_action"]["outcome"],
            "supervisor_required"
        );

        let (status, status_body) = send(state.clone(), get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK);
        let mcp = status_body["services"]
            .as_array()
            .expect("services array")
            .iter()
            .find(|service| service["id"] == "mcp_stdio")
            .expect("mcp stdio service");
        assert_eq!(mcp["enabled"], true);
        assert_eq!(mcp["desired_state"], "running");

        let settings = state.settings.read().await.clone();
        assert_eq!(
            settings.platform.mcp_stdio_server.desired_state,
            PlatformServiceDesiredState::Running
        );
        assert_eq!(settings.platform.audit[0].service_id, "mcp_stdio");
    }

    #[tokio::test]
    async fn platform_desired_state_and_audit_persist_through_data_dir_reload() {
        let tmp = TempDir::new();
        let first = AppState::with_data_dir(tmp.dir.clone());
        let (status, body) = send(
            first,
            post_json("/v1/platform/services/mcp_stdio/actions/start", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "control response: {body}");

        let settings_file = tmp.dir.join("settings.json");
        let persisted: Settings =
            serde_json::from_slice(&std::fs::read(&settings_file).expect("settings sidecar"))
                .expect("valid persisted settings");
        assert_eq!(
            persisted.platform.mcp_stdio_server.desired_state,
            PlatformServiceDesiredState::Running
        );
        assert_eq!(persisted.platform.audit.len(), 1);
        assert_eq!(persisted.platform.audit[0].service_id, "mcp_stdio");
        assert_eq!(
            persisted.platform.audit[0].outcome,
            PlatformControlOutcomeKind::SupervisorRequired
        );

        let restarted = AppState::with_data_dir(tmp.dir.clone());
        {
            let settings = restarted.settings.read().await;
            assert_eq!(
                settings.platform.mcp_stdio_server.desired_state,
                PlatformServiceDesiredState::Running
            );
            assert_eq!(settings.platform.audit.len(), 1);
        }

        let (status, status_body) = send(restarted.clone(), get("/v1/platform/services")).await;
        assert_eq!(status, StatusCode::OK);
        let mcp = status_body["services"]
            .as_array()
            .expect("services array")
            .iter()
            .find(|service| service["id"] == "mcp_stdio")
            .expect("mcp stdio service");
        assert_eq!(mcp["enabled"], true);
        assert_eq!(mcp["desired_state"], "running");
        assert_eq!(mcp["actual_runtime_status"], "unknown");
        assert_eq!(mcp["last_action"]["outcome"], "supervisor_required");

        let (status, events) = send(restarted, get("/v1/ledger/events")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            events
                .as_array()
                .expect("events array")
                .iter()
                .any(|event| event["kind"] == "platform.service.control"
                    && event["scope"] == "platform"),
            "platform control ledger event should persist through reload: {events}"
        );
    }

    // --- Scoped RBAC stores + migration + bootstrap + resolution seam (t64-E2) ------------

    /// Insert an active user with the given role assignments directly into the state (bypassing the
    /// API + migration), returning its id. For the store/seam tests below.
    async fn seed_user(
        state: &AppState,
        username: &str,
        assignments: Vec<chancela_authz::RoleAssignment>,
    ) -> crate::users::UserId {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret(DEFAULT_TEST_PASSWORD).unwrap()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: assignments,
        };
        state.users.write().await.insert(uid, user);
        uid
    }

    #[tokio::test]
    async fn legacy_users_json_migrates_on_load_and_is_idempotent() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        // A pre-t64 users.json: two users, with NO `role_assignments` field at all (back-compat).
        let legacy = json!([
            { "id": "00000000-0000-0000-0000-000000000001", "username": "amelia.marques",
              "display_name": "Amélia Marques", "created_at": "2026-01-01T00:00:00Z", "active": true },
            { "id": "00000000-0000-0000-0000-000000000002", "username": "bruno.dias",
              "display_name": "Bruno Dias", "created_at": "2026-02-01T00:00:00Z", "active": true }
        ]);
        std::fs::write(
            tmp.dir.join("users.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let state = AppState::with_data_dir(tmp.dir.clone());
        {
            let users = state.users.read().await;
            let amelia = users
                .values()
                .find(|u| u.username == "amelia.marques")
                .unwrap();
            let bruno = users.values().find(|u| u.username == "bruno.dias").unwrap();
            // Earliest user ⇒ Owner@Global; the rest ⇒ Gestor@Global (no lockout, one Owner).
            assert_eq!(
                amelia.role_assignments,
                vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)]
            );
            assert_eq!(
                bruno.role_assignments,
                vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)]
            );
        }
        // Rewritten to disk (now carries role_assignments), and roles.json was seeded.
        let on_disk = std::fs::read_to_string(tmp.dir.join("users.json")).unwrap();
        assert!(on_disk.contains("role_assignments"));
        assert!(tmp.dir.join("roles.json").is_file());

        // Idempotent: a second load rewrites nothing (already-migrated ⇒ no-op).
        let before = std::fs::read(tmp.dir.join("users.json")).unwrap();
        let _second = AppState::with_data_dir(tmp.dir.clone());
        let after = std::fs::read(tmp.dir.join("users.json")).unwrap();
        assert_eq!(before, after, "second load is a no-op");
    }

    #[tokio::test]
    async fn bootstrap_first_user_owner_second_user_gestor() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        // Fresh install, zero users: the bootstrap create needs no session.
        let (status, first) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": DEFAULT_TEST_PASSWORD,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let first_id = first["id"].as_str().unwrap().to_owned();

        // Sign in as the first user to get a session, then create a second user.
        let (status, sess) = send_raw(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": first_id, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().unwrap().to_owned();

        let (status, _second) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/users",
                    json!({ "username": "bruno.dias", "password": DEFAULT_TEST_PASSWORD }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let users = state.users.read().await;
        let amelia = users
            .values()
            .find(|u| u.username == "amelia.marques")
            .unwrap();
        let bruno = users.values().find(|u| u.username == "bruno.dias").unwrap();
        assert_eq!(
            amelia.role_assignments,
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            "the first user is Owner"
        );
        assert_eq!(
            bruno.role_assignments,
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
            "subsequent users are Gestor"
        );
    }

    #[tokio::test]
    async fn principal_resolution_yields_correct_effective_permissions() {
        use chancela_authz::{
            GESTOR_ROLE_ID, NoBooks, OWNER_ROLE_ID, Permission, RoleAssignment, Scope,
            has_permission,
        };
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let now = time::OffsetDateTime::now_utc();

        let owner_id = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let gestor_id = seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
        )
        .await;

        let owner_eff = crate::roles::effective_permissions_for(&state, owner_id, now).await;
        assert!(has_permission(
            &owner_eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
        assert!(has_permission(
            &owner_eff,
            Permission::RoleManage,
            Scope::Global,
            &NoBooks
        ));

        let gestor_eff = crate::roles::effective_permissions_for(&state, gestor_id, now).await;
        assert!(has_permission(
            &gestor_eff,
            Permission::BookOpen,
            Scope::Global,
            &NoBooks
        ));
        // Gestor lacks the destructive + meta verbs.
        assert!(!has_permission(
            &gestor_eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
        assert!(!has_permission(
            &gestor_eff,
            Permission::RoleManage,
            Scope::Global,
            &NoBooks
        ));

        // Unknown principal ⇒ empty authority (fail-closed).
        let ghost = crate::users::UserId(Uuid::new_v4());
        assert!(
            crate::roles::effective_permissions_for(&state, ghost, now)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn delegation_contributes_to_effective_permissions() {
        use chancela_authz::{
            Delegation, GESTOR_ROLE_ID, LEITOR_ROLE_ID, NoBooks, Permission, RoleAssignment, Scope,
            has_permission,
        };
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let now = time::OffsetDateTime::UNIX_EPOCH;

        let grantor_id = seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
        )
        .await;
        // A Leitor (read-only) who receives a delegated act.advance.
        let leitor_id = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let did = crate::delegations::DelegationId(Uuid::from_u128(1));
        {
            let mut table = state.delegations.write().await;
            table.insert(
                did,
                crate::delegations::StoredDelegation::new(
                    did,
                    now.format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    Delegation::new(
                        chancela_authz::UserId(grantor_id.0),
                        chancela_authz::UserId(leitor_id.0),
                        Permission::ActAdvance,
                        Scope::Global,
                    ),
                ),
            );
        }

        let eff = crate::roles::effective_permissions_for(&state, leitor_id, now).await;
        // Base read stays; the delegated act.advance is present; a non-granted verb is not.
        assert!(has_permission(
            &eff,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
        assert!(has_permission(
            &eff,
            Permission::ActAdvance,
            Scope::Global,
            &NoBooks
        ));
        assert!(!has_permission(
            &eff,
            Permission::DataWipe,
            Scope::Global,
            &NoBooks
        ));
    }

    #[tokio::test]
    async fn last_owner_guard_tracks_admin_owner_count() {
        use chancela_authz::{GESTOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(GESTOR_ROLE_ID, Scope::Global)],
        )
        .await;
        // One Owner ⇒ removing it is unsafe (guard false).
        assert_eq!(crate::roles::count_owner_admins(&state).await, 1);
        assert!(!crate::roles::last_owner_guard_ok(&state).await);

        // A second Owner ⇒ safe to remove one.
        seed_user(
            &state,
            "carla.nunes",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        assert_eq!(crate::roles::count_owner_admins(&state).await, 2);
        assert!(crate::roles::last_owner_guard_ok(&state).await);
    }

    #[tokio::test]
    async fn roles_and_delegations_persist_through_state() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        // Add a custom role + a delegation, persist both, reload from disk.
        let custom_id = chancela_authz::RoleId(Uuid::from_u128(0xABCD));
        {
            let mut roles = state.roles.write().await;
            roles.insert(chancela_authz::Role {
                id: custom_id,
                name: "Auditor".to_owned(),
                permission_set: [chancela_authz::Permission::LedgerRead]
                    .into_iter()
                    .collect(),
                protected: false,
            });
        }
        crate::roles::persist_roles(&state).await.unwrap();

        let did = crate::delegations::DelegationId(Uuid::from_u128(1));
        {
            let mut table = state.delegations.write().await;
            table.insert(
                did,
                crate::delegations::StoredDelegation::new(
                    did,
                    time::OffsetDateTime::UNIX_EPOCH
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap(),
                    chancela_authz::Delegation::new(
                        chancela_authz::UserId(Uuid::from_u128(1)),
                        chancela_authz::UserId(Uuid::from_u128(2)),
                        chancela_authz::Permission::ActAdvance,
                        chancela_authz::Scope::Global,
                    ),
                ),
            );
        }
        crate::delegations::persist_delegations(&state)
            .await
            .unwrap();

        let reloaded = AppState::with_data_dir(tmp.dir.clone());
        assert!(reloaded.roles.read().await.get(custom_id).is_some());
        assert_eq!(reloaded.delegations.read().await.len(), 1);
    }

    // --- CAE library (§2.7) --------------------------------------------------------------

    // `with_session` is defined near the top of the test module (before `entity_and_open_book`).

    #[tokio::test]
    async fn cae_lookup_returns_entry_with_hierarchy() {
        let (status, view) = send(AppState::default(), get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["code"], "68110");
        assert_eq!(view["designation"], "Compra e venda de bens imobiliários.");
        assert_eq!(view["level"], "Subclasse");
        assert_eq!(view["revision"], "Rev4");
        let hierarchy = view["hierarchy"].as_array().expect("hierarchy array");
        // secção → divisão → grupo → classe → subclasse.
        assert_eq!(hierarchy.len(), 5);
        assert_eq!(hierarchy[0]["level"], "Seccao");
        assert_eq!(hierarchy[4]["code"], "68110");
    }

    #[tokio::test]
    async fn cae_lookup_respects_a_revision_pin() {
        // 68100 exists only in Rev.3; pinning Rev.4 misses (404), Rev.3 hits.
        let (status, _) = send(AppState::default(), get("/v1/cae/68100?revision=Rev4")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, view) = send(AppState::default(), get("/v1/cae/68100?revision=Rev3")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["revision"], "Rev3");
    }

    #[tokio::test]
    async fn cae_lookup_unknown_code_is_404() {
        let (status, _) = send(AppState::default(), get("/v1/cae/99999")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cae_search_returns_matching_nodes_without_hierarchy() {
        // Accent-folded search: "imobili" matches "imobiliários" in both revisions.
        let (status, hits) = send(AppState::default(), get("/v1/cae?search=imobili&limit=5")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = hits.as_array().expect("hits array");
        assert!(!arr.is_empty(), "at least one match");
        assert!(arr.len() <= 5, "limit respected");
        // The list form omits the hierarchy field entirely.
        assert!(arr[0].get("hierarchy").is_none());
        assert!(arr[0]["designation"].as_str().unwrap().contains("imobili"));
    }

    #[tokio::test]
    async fn cae_no_search_returns_catalog_metadata() {
        let (status, meta) = send(AppState::default(), get("/v1/cae")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(meta["origin"], "Embedded");
        assert_eq!(meta["schema_version"], 1);
        // Official Rev.4 totals (the structural-integrity gate).
        assert_eq!(meta["counts"]["rev4"]["seccao"], 22);
        assert_eq!(meta["counts"]["rev4"]["subclasse"], 915);
        assert!(meta["digest"].as_str().expect("digest").len() == 64);
    }

    /// A tiny but structurally-valid dataset that supersedes the embedded catalog (distinct
    /// digest, far-future `generated_at`), for the refresh path.
    fn superseding_dataset() -> Value {
        json!({
            "schema_version": 1,
            "generated_at": "2099-01-01T00:00:00Z",
            "source_note": "test refresh dataset",
            "rev3": [],
            "rev4": [
                { "code": "A", "designation": "Secção de teste", "level": "Seccao",
                  "revision": "Rev4", "parent": null },
                { "code": "01", "designation": "Divisão de teste", "level": "Divisao",
                  "revision": "Rev4", "parent": "A" }
            ]
        })
    }

    /// A data-dir-backed state with an injected CAE source, so the refresh writes a cache the
    /// second attempt can compare against (the no-op path only holds once a cache exists).
    fn state_with_cae_source(dir: PathBuf, dataset: Value) -> AppState {
        let bytes = serde_json::to_vec(&dataset).expect("dataset serializes");
        let mut state = AppState::with_data_dir(dir);
        state.cae_source = Some(Arc::new(chancela_cae::BytesCaeSource::new(bytes)));
        state
    }

    #[tokio::test]
    async fn cae_refresh_swaps_catalog_and_appends_event() {
        let tmp = TempDir::new();
        let state = state_with_cae_source(tmp.dir.clone(), superseding_dataset());

        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], true);
        // The fetched dataset is labelled a Cache origin, and the cache file was written.
        assert_eq!(report["metadata"]["origin"], "Cache");
        assert!(tmp.dir.join("cae-catalog.json").is_file());

        // The live catalog now serves the refreshed data (the tiny test dataset).
        let (status, view) = send(state.clone(), get("/v1/cae/A")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["designation"], "Secção de teste");

        // A `cae.updated` event was appended.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let updated = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "cae.updated")
            .expect("cae.updated event present");
        assert_eq!(updated["scope"], "cae");
        assert_eq!(updated["actor"], "test.actor"); // t41: session actor

        // A second refresh of the same dataset is a no-op: it no longer supersedes the cache.
        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], false);
    }

    #[tokio::test]
    async fn cae_refresh_on_a_bad_source_is_502() {
        // A source returning non-dataset bytes → CaeError::Parse → 502.
        let state = AppState {
            cae_source: Some(Arc::new(chancela_cae::BytesCaeSource::new(
                b"not a dataset".to_vec(),
            ))),
            ..AppState::default()
        };
        let (status, body) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["error"].is_string());
    }

    // --- CAE multi-source chain refresh (§cae-v2) -----------------------------------------

    /// A data-dir-backed state whose refresh chain is driven by an injected factory (in-memory
    /// sources), so the multi-source pipeline is exercised without a network. Rebuilds the chain per
    /// call so `?source` pinning + repeat refreshes work.
    fn state_with_cae_chain(
        dir: PathBuf,
        factory: impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync + 'static,
    ) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.cae_chain_factory = Some(Arc::new(factory));
        state
    }

    /// A **complete both-revision** envelope dataset built from the vendored embedded revision
    /// arrays, with code `68110`'s Rev.4 designation tagged by `marker` so it (a) differs in digest
    /// from the embedded catalog (thus supersedes) while keeping the exact official per-level counts
    /// the chain's fidelity gate demands, and (b) is identifiable after a refresh. Unlike the legacy
    /// `refresh` path, the chain runs the full-count fidelity gate, so a tiny fixture cannot win.
    fn full_fidelity_envelope(marker: &str) -> Value {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data");
        let read = |name: &str| -> Vec<Value> {
            serde_json::from_slice(&std::fs::read(dir.join(name)).expect("vendored array readable"))
                .expect("vendored array parses")
        };
        let rev3 = read("cae_rev3.json");
        let mut rev4 = read("cae_rev4.json");
        for node in &mut rev4 {
            if node["code"] == "68110" {
                let d = node["designation"].as_str().unwrap_or_default().to_owned();
                node["designation"] = json!(format!("{d} [{marker}]"));
            }
        }
        json!({
            "schema_version": 1,
            "generated_at": "2099-01-01T00:00:00Z",
            "source_note": "test full-fidelity mirror",
            "rev3": rev3,
            "rev4": rev4,
        })
    }

    /// A one-entry `MirrorArtifactSource` chain over the given envelope-JSON `Value`.
    fn bytes_mirror_chain(
        dataset: Value,
    ) -> impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync {
        use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
        let bytes = serde_json::to_vec(&dataset).expect("dataset serializes");
        move || {
            CaeSourceChain::new(vec![ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                bytes.clone(),
                CaeSourceFormat::Envelope,
            ))])
        }
    }

    #[tokio::test]
    async fn cae_chain_refresh_supersedes_records_mirror_provenance_and_no_ops() {
        let tmp = TempDir::new();
        let state = state_with_cae_chain(
            tmp.dir.clone(),
            bytes_mirror_chain(full_fidelity_envelope("mirror")),
        );

        // A superseding mirror wins: catalog swapped, provenance recorded (Mirror), cache written,
        // cae.updated appended, and it cleared the full-count fidelity gate.
        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["metadata"]["origin"], "Cache");
        assert_eq!(report["metadata"]["provenance"]["source_kind"], "Mirror");
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
        assert_eq!(report["source"], "<bytes>");
        assert_eq!(report["failures"].as_array().expect("failures").len(), 0);
        assert!(tmp.dir.join("cae-catalog.json").is_file());

        // The live catalog serves the tagged designation from the mirror.
        let (status, view) = send(state.clone(), get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            view["designation"]
                .as_str()
                .expect("designation")
                .contains("[mirror]")
        );

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "cae.updated" && e["scope"] == "cae"),
            "cae.updated appended"
        );

        // Repeat: the same dataset no longer supersedes the written cache → up to date, no event.
        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["updated"], false);
        assert_eq!(report["source"], Value::Null);
    }

    #[tokio::test]
    async fn cae_chain_first_superseding_source_wins() {
        use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
        // Two superseding mirrors, each a complete dataset tagged distinctly; the FIRST in order wins
        // and its data lands (the second is never obtained).
        let tmp = TempDir::new();
        let b1 = serde_json::to_vec(&full_fidelity_envelope("FIRST")).unwrap();
        let b2 = serde_json::to_vec(&full_fidelity_envelope("SECOND")).unwrap();
        let state = state_with_cae_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![
                ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                    b1.clone(),
                    CaeSourceFormat::Envelope,
                )),
                ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                    b2.clone(),
                    CaeSourceFormat::Envelope,
                )),
            ])
        });

        let (status, report) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        let (status, view) = send(state, get("/v1/cae/68110")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            view["designation"]
                .as_str()
                .expect("designation")
                .contains("[FIRST]"),
            "the first source won: {}",
            view["designation"]
        );
    }

    #[tokio::test]
    async fn cae_chain_all_sources_fail_is_502_with_failures() {
        // A single mirror returning non-dataset bytes fails every gate → 502, catalog untouched, the
        // per-source failure surfaced.
        let tmp = TempDir::new();
        let state = state_with_cae_chain(tmp.dir.clone(), || {
            use chancela_cae::{CaeSourceChain, CaeSourceFormat, ChainEntry, MirrorArtifactSource};
            CaeSourceChain::new(vec![ChainEntry::Mirror(MirrorArtifactSource::from_bytes(
                b"not a dataset".to_vec(),
                CaeSourceFormat::Auto,
            ))])
        });
        let (status, body) = send(state.clone(), post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");
        assert!(body["error"].is_string());
        assert_eq!(body["failures"].as_array().expect("failures").len(), 1);
        // The catalog is unchanged (still the embedded dataset).
        let (_, meta) = send(state, get("/v1/cae")).await;
        assert_eq!(meta["origin"], "Embedded");
    }

    #[tokio::test]
    async fn cae_refresh_pinned_source_with_no_match_is_settings_aware_422() {
        // The one case that still refuses: a `?source` pin matching nothing configured (a default is
        // impossible for a pin, e.g. `?source=mirror` with no mirrors) → friendly 422 pointing at
        // Configurações (the message the web/e2e error surface keys on). No network is touched — the
        // pin short-circuits before any chain runs. (Plain no-config refresh now runs the official
        // default chain instead; see `cae_refresh_with_no_config_runs_the_official_default_chain`.)
        let (status, body) = send(
            AppState::default(),
            post_json("/v1/cae/refresh?source=mirror", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error string")
                .contains("Configurações")
        );
    }

    /// A data-dir-backed state whose *no-config default* chain (run when nothing at all is
    /// configured) is driven by an injected factory, so the "no URL ⇒ official gov artifacts"
    /// substitution is exercised without a network. Nothing else is configured, so the refresh
    /// reaches the default path. Mirrors `state_with_cae_chain`.
    fn state_with_cae_default_chain(
        dir: PathBuf,
        factory: impl Fn() -> chancela_cae::CaeSourceChain + Send + Sync + 'static,
    ) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.cae_default_chain_factory = Some(Arc::new(factory));
        state
    }

    #[tokio::test]
    async fn cae_refresh_with_no_config_runs_the_official_default_chain() {
        use chancela_cae::{CaeSourceChain, ChainEntry, DrPdfSource};
        // Nothing configured (no cae_source, no cae_sources, cae_official_source off, no
        // cae_update_url, no ?source pin) → instead of the old 422, the refresh runs the built-in
        // official Diário da República pair. The default is injected here as the vendored diploma
        // PDFs (via the no-config-default seam) so the substitution is proven end-to-end offline.
        let cae_data =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data/source");
        let (rev4, rev3) = (cae_data.join("rev4.pdf"), cae_data.join("rev3.pdf"));
        let tmp = TempDir::new();
        let state = state_with_cae_default_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![ChainEntry::Official(DrPdfSource::from_files(
                &rev4, &rev3,
            ))])
        });

        let (status, report) = send(state, post_json("/v1/cae/refresh", json!({}))).await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["source"], "Diário da República (fonte oficial)");
        assert_eq!(
            report["metadata"]["provenance"]["source_kind"],
            "DiarioRepublica"
        );
        // The obtained catalog reproduces the official structural counts (full-count fidelity gate).
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
    }

    #[tokio::test]
    async fn cae_refresh_source_official_over_injected_dr_pdf_pair() {
        use chancela_cae::{CaeSourceChain, ChainEntry, DrPdfSource};
        // `?source=official` runs the official DR pair; injected here as `DrPdfSource::from_files`
        // over the vendored diploma PDFs, so the in-app lopdf parser produces a complete dataset that
        // supersedes the embedded catalog with DiarioRepublica provenance.
        let cae_data =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chancela-cae/data/source");
        let (rev4, rev3) = (cae_data.join("rev4.pdf"), cae_data.join("rev3.pdf"));
        let tmp = TempDir::new();
        let state = state_with_cae_chain(tmp.dir.clone(), move || {
            CaeSourceChain::new(vec![ChainEntry::Official(DrPdfSource::from_files(
                &rev4, &rev3,
            ))])
        });

        let (status, report) = send(
            state,
            post_json("/v1/cae/refresh?source=official", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "refresh: {report}");
        assert_eq!(report["updated"], true);
        assert_eq!(report["source"], "Diário da República (fonte oficial)");
        assert_eq!(
            report["metadata"]["provenance"]["source_kind"],
            "DiarioRepublica"
        );
        // The obtained catalog reproduces the official structural counts.
        assert_eq!(report["metadata"]["counts"]["rev4"]["subclasse"], 915);
    }

    // --- CAE update signal: GET /v1/cae/updates (§cae-v2) ---------------------------------

    /// The checked-in INE SMI version-catalog fixture (UTF-16LE + BOM, a trimmed real capture),
    /// reused from `chancela-cae` so the `/v1/cae/updates` decode+parse path runs on the real shape.
    const SMI_FIXTURE: &[u8] =
        include_bytes!("../../chancela-cae/fixtures/smi_version_catalog.csv");

    /// Spawn a tiny in-process HTTP server that returns `body` for the SMI version-export path, and
    /// return its base URL. The state's `smi_base_override` points `GET /v1/cae/updates` here, so the
    /// real `SmiSource::fetch_catalog` transport + UTF-16 decode runs without hitting the network.
    async fn spawn_smi_fixture(body: &'static [u8]) -> String {
        let app = axum::Router::new().route(
            "/Versao/Exportacao",
            axum::routing::get(move || async move { body }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture binds");
        let addr = listener.local_addr().expect("fixture addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cae_updates_reports_the_current_smi_cae_versions() {
        // The mock SMI transport serves the real UTF-16 fixture; /updates decodes it and reports the
        // two current official CAE versions INE publishes, plus a checked_at stamp.
        let base = spawn_smi_fixture(SMI_FIXTURE).await;
        let state = AppState {
            smi_base_override: Some(Arc::new(base)),
            ..AppState::default()
        };

        let (status, body) = send(state, get("/v1/cae/updates")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["rev4"]["version"], "V05497");
        assert_eq!(
            body["rev4"]["designation"],
            "Classificação portuguesa das atividades económicas, revisão 4"
        );
        assert_eq!(body["rev3"]["version"], "V00554");
        assert!(
            !body["checked_at"]
                .as_str()
                .expect("checked_at string")
                .is_empty(),
            "checked_at is stamped"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cae_updates_on_a_non_smi_response_is_502() {
        // A transport that answers with a non-SMI body → parse error → 502 (SMI unusable as a signal).
        let base = spawn_smi_fixture(b"not an SMI version export\r\n").await;
        let state = AppState {
            smi_base_override: Some(Arc::new(base)),
            ..AppState::default()
        };
        let (status, body) = send(state, get("/v1/cae/updates")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");
        assert!(body["error"].is_string());
    }

    // --- CAE tree browse: sections + children (§cae-v2) -----------------------------------

    #[tokio::test]
    async fn cae_sections_lists_the_top_level_of_a_revision() {
        // Rev.4 has 22 secções, Rev.3 has 21; every entry is a Seccao node.
        let (status, rev4) = send(AppState::default(), get("/v1/cae/sections?revision=Rev4")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = rev4.as_array().expect("sections array");
        assert_eq!(arr.len(), 22);
        assert!(
            arr.iter()
                .all(|n| n["level"] == "Seccao" && n["revision"] == "Rev4")
        );

        let (_, rev3) = send(AppState::default(), get("/v1/cae/sections?revision=Rev3")).await;
        assert_eq!(rev3.as_array().expect("sections array").len(), 21);

        // No revision defaults to Rev.4.
        let (_, default) = send(AppState::default(), get("/v1/cae/sections")).await;
        assert_eq!(default.as_array().expect("sections").len(), 22);
    }

    #[tokio::test]
    async fn cae_children_drills_down_and_404s_unknown_codes() {
        // A secção drills down to its divisões (all Divisao-level).
        let (status, kids) =
            send(AppState::default(), get("/v1/cae/L/children?revision=Rev4")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = kids.as_array().expect("children array");
        assert!(!arr.is_empty() && arr.iter().all(|n| n["level"] == "Divisao"));

        // A divisão drills down to its grupos: 68 → 681.
        let (status, kids) = send(
            AppState::default(),
            get("/v1/cae/68/children?revision=Rev4"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = kids.as_array().expect("children array");
        assert!(
            arr.iter()
                .any(|n| n["code"] == "681" && n["level"] == "Grupo"),
            "681 is a child of 68: {arr:?}"
        );

        // A known leaf (subclasse) legitimately has no children → empty array, 200.
        let (status, leaf) = send(AppState::default(), get("/v1/cae/68110/children")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(leaf.as_array().expect("empty").len(), 0);

        // An unknown code is a 404.
        let (status, _) = send(AppState::default(), get("/v1/cae/ZZ/children")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // --- Law archive (spec/09 AI-20..22) --------------------------------------------------

    /// A minimal but structurally-recognisable PDF body for the fixture server.
    const PDF_BODY: &[u8] = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n";

    /// Spawn a tiny in-process HTTP server that returns `body` for any `/{id}` path, and return its
    /// base URL. Used so the real `reqwest` download path (size cap + `%PDF` check) is exercised
    /// without hitting the network — the state's `law_pdf_base_override` points the fetch here.
    async fn spawn_pdf_fixture(body: &'static [u8]) -> String {
        let app =
            axum::Router::new().route("/{id}", axum::routing::get(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture binds");
        let addr = listener.local_addr().expect("fixture addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// A data-dir-backed state whose law fetches are redirected to the fixture `base` URL.
    fn law_state(dir: PathBuf, base: String) -> AppState {
        let mut state = AppState::with_data_dir(dir);
        state.law_pdf_base_override = Some(Arc::new(base));
        state
    }

    fn delete(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    /// Send one request and return (status, headers, raw body bytes) — for the non-JSON PDF stream.
    async fn send_raw_bytes(
        state: AppState,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = router(state).oneshot(req).await.expect("router responds");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects")
            .to_vec();
        (status, headers, bytes)
    }

    #[tokio::test]
    async fn law_manifest_lists_curated_entries() {
        let (status, body) = send(AppState::default(), get("/v1/law")).await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().expect("law array");
        assert_eq!(arr.len(), 9, "the curated statutory table");

        let csc = arr.iter().find(|e| e["id"] == "csc").expect("csc entry");
        assert_eq!(csc["ref"], "Decreto-Lei n.º 262/86, de 2 de setembro");
        assert_eq!(
            csc["official_url"],
            "https://data.dre.pt/eli/dec-lei/262/1986/p/cons/20260101"
        );
        assert!(csc["pdf_url"].is_null(), "csc has no pinned PDF");
        assert_eq!(csc["articles"][0], "Artigo 63.º");

        // The two CAE diplomas carry the pinned Diário da República PDF URLs (PROVENANCE.md).
        let cae4 = arr
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .expect("dl-9-2025");
        assert_eq!(
            cae4["pdf_url"],
            "https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf"
        );
        let cae3 = arr
            .iter()
            .find(|e| e["id"] == "dl-381-2007")
            .expect("dl-381-2007");
        assert_eq!(
            cae3["pdf_url"],
            "https://files.dre.pt/1s/2007/11/21900/0844008464.pdf"
        );

        // In memory nothing is archived.
        assert!(arr.iter().all(|e| e["stored"] == false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_fetch_stores_pdf_and_appends_event() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);

        let (status, body) = send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["stored"], true);
        assert_eq!(
            body["stored_digest"].as_str().expect("digest").len(),
            64,
            "sha256 hex"
        );
        assert!(body["stored_bytes"].as_u64().expect("bytes") > 0);
        assert!(body["retrieved_at"].is_string());

        // The bytes and the state file are on disk.
        assert!(tmp.dir.join("laws").join("dl-9-2025.pdf").is_file());
        assert!(tmp.dir.join("laws").join("manifest-state.json").is_file());

        // A `law.fetched` event was appended, scoped to `law`.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let ev = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "law.fetched")
            .expect("law.fetched event present");
        assert_eq!(ev["scope"], "law");

        // The manifest now reports the entry as stored.
        let (_, list) = send(state, get("/v1/law")).await;
        let e = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .unwrap();
        assert_eq!(e["stored"], true);
    }

    #[tokio::test]
    async fn law_fetch_without_pinned_pdf_is_409() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        // `csc` has pdf_url = null → nothing trustworthy to archive.
        let (status, body) = send(state, post_json("/v1/law/csc/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_fetch_non_pdf_body_is_502() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(b"<html>not a pdf</html>").await;
        let state = law_state(tmp.dir.clone(), base);
        let (status, body) = send(state, post_json("/v1/law/dl-9-2025/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn law_fetch_without_data_dir_is_422() {
        let (status, body) = send(
            AppState::default(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("CHANCELA_DATA_DIR")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_serve_stored_pdf_returns_bytes_and_headers() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);
        // RBAC (t64-E3): serving/reading an archived PDF is `law.read`; carry an Owner session.
        let token = auth_token(&state).await;

        // Not yet fetched → serving is a 404.
        let (status, _, _) = send_raw_bytes(
            state.clone(),
            with_session(get("/v1/law/dl-9-2025/pdf"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, headers, bytes) =
            send_raw_bytes(state, with_session(get("/v1/law/dl-9-2025/pdf"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "application/pdf");
        assert!(
            headers
                .get("content-disposition")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("inline")
        );
        assert!(bytes.starts_with(b"%PDF"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_delete_removes_pdf_and_appends_event() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let state = law_state(tmp.dir.clone(), base);
        let token = auth_token(&state).await; // RBAC (t64-E3): the pdf read is `law.read`.
        send(
            state.clone(),
            post_json("/v1/law/dl-9-2025/fetch", json!({})),
        )
        .await;

        let (status, body) = send(state.clone(), delete("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["stored"], false);
        assert!(!tmp.dir.join("laws").join("dl-9-2025.pdf").exists());

        // Serving is now a 404, and a `law.removed` event was appended.
        let (status, _, _) = send_raw_bytes(
            state.clone(),
            with_session(get("/v1/law/dl-9-2025/pdf"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "law.removed")
        );

        // Deleting again (nothing stored) is a 404.
        let (status, _) = send(state, delete("/v1/law/dl-9-2025/pdf")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn law_archive_state_reloads_after_restart() {
        let tmp = TempDir::new();
        let base = spawn_pdf_fixture(PDF_BODY).await;
        let first = law_state(tmp.dir.clone(), base);
        let (status, _) = send(first, post_json("/v1/law/dl-9-2025/fetch", json!({}))).await;
        assert_eq!(status, StatusCode::OK);

        // A fresh state over the same data dir reloads `manifest-state.json`.
        let second = AppState::with_data_dir(tmp.dir.clone());
        let (_, list) = send(second, get("/v1/law")).await;
        let e = list
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["id"] == "dl-9-2025")
            .unwrap();
        assert_eq!(e["stored"], true);
        assert_eq!(e["stored_digest"].as_str().unwrap().len(), 64);
    }

    // --- Law corpus reader: GET /v1/law/corpus[...] + search (t55-E2) ---------------------

    /// Seed an ACTIVE user with **no** role assignments (zero authority) plus a session, returning
    /// its token — for asserting an authenticated-but-unauthorised `403` on the gated reads.
    async fn powerless_token(state: &AppState) -> String {
        use crate::users::{User, UserId};
        use time::format_description::well_known::Rfc3339;
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = chancela_authz::RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let user = User {
            id: uid,
            username: "no.perms".to_owned(),
            display_name: "No Perms".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some("direct-session-test-password-hash".to_owned()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![],
        };
        state.users.write().await.insert(uid, user);
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    #[tokio::test]
    async fn law_corpus_lists_diplomas_with_authenticity_counts() {
        let (status, body) = send(AppState::default(), get("/v1/law/corpus")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        // Corpus-level provenance/integrity metadata.
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["origin"], "Embedded");
        assert_eq!(
            body["digest"].as_str().expect("digest").len(),
            64,
            "sha256 hex"
        );
        // The committed corpus (wp22): 9 diplomas, 193 articles across three honest authenticity
        // tiers — 153 human-`Verified` + 39 `automated_review` (vendored + auto-reviewed, NOT
        // human-approved) + 1 `Pending` (no vendored text).
        assert_eq!(body["counts"]["diplomas"], 9);
        assert_eq!(body["counts"]["articles"], 193);
        assert_eq!(body["counts"]["verified"], 153);
        assert_eq!(body["counts"]["automated_review"], 39);
        assert_eq!(body["counts"]["pending"], 1);

        let diplomas = body["diplomas"].as_array().expect("diplomas array");
        assert_eq!(diplomas.len(), 9);

        // eIDAS is fully Verified (EU-regulation text vendored from EUR-Lex).
        let eidas = diplomas
            .iter()
            .find(|d| d["id"] == "eidas-910-2014")
            .expect("eidas diploma");
        assert_eq!(eidas["kind"], "RegulamentoUe");
        assert_eq!(eidas["article_count"], 52);
        assert_eq!(eidas["verified_count"], 52);
        assert_eq!(eidas["automated_review_count"], 0);
        assert_eq!(eidas["pending_count"], 0);

        // CSC is now fully automated-review (wp22): its 15 articles carry vendored, auto-reviewed
        // statutory text — NOT human-`Verified`, and not `Pending` placeholders either. The per-
        // diploma counts keep the tier distinct instead of lumping it into pending.
        let csc = diplomas
            .iter()
            .find(|d| d["id"] == "csc")
            .expect("csc diploma");
        assert_eq!(csc["verified_count"], 0);
        assert_eq!(csc["automated_review_count"], 15);
        assert_eq!(csc["pending_count"], 0);
    }

    #[tokio::test]
    async fn law_corpus_diploma_returns_full_verbatim_articles() {
        let (status, body) = send(AppState::default(), get("/v1/law/corpus/eidas-910-2014")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        // The flattened summary header travels with the detail.
        assert_eq!(body["id"], "eidas-910-2014");
        assert_eq!(body["article_count"], 52);

        let articles = body["articles"].as_array().expect("articles");
        assert_eq!(articles.len(), 52);

        let art1 = &articles[0];
        assert_eq!(art1["number"], "1");
        assert_eq!(art1["label"], "Artigo 1.º");
        assert_eq!(art1["heading"], "Objeto");
        assert_eq!(art1["verified"], true);
        assert_eq!(art1["verification"], "Verified");
        // Full verbatim body, not an extract, with complete citation metadata.
        assert!(
            art1["body"]
                .as_str()
                .expect("body")
                .contains("mercado interno"),
            "verbatim body present"
        );
        assert_eq!(art1["source"]["complete"], true);
        assert!(art1["source"]["url"].is_string());
        assert!(art1["source"]["dr_reference"].is_string());
    }

    #[tokio::test]
    async fn law_corpus_pending_article_never_leaks_a_body() {
        // dl-76-a-2006 is a mixed diploma (wp22): article 1 is automated-review authentic text,
        // article 2 is still a Pending placeholder. The invariant under test: a Pending article
        // renders the loud marker and never a raw body, while an automated-review article carries
        // real vendored text yet is NOT human-`Verified` (no marker, complete source).
        let (status, body) = send(AppState::default(), get("/v1/law/corpus/dl-76-a-2006")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let articles = body["articles"].as_array().expect("articles");

        let pending = articles
            .iter()
            .find(|a| a["number"] == "2")
            .expect("pending article 2");
        assert_eq!(pending["verified"], false);
        assert_eq!(pending["verification"], "Pending");
        assert_eq!(pending["body"], chancela_law::UNVERIFIED_MARKER);
        assert_eq!(pending["source"]["complete"], false);

        let automated = articles
            .iter()
            .find(|a| a["number"] == "1")
            .expect("automated-review article 1");
        // Automated-review is authentic text: it is NOT the loud marker and its source is complete,
        // but `verified` stays false — it is not human-legally-approved.
        assert_eq!(automated["verified"], false);
        assert_eq!(automated["verification"], "automated_review");
        assert_ne!(automated["body"], chancela_law::UNVERIFIED_MARKER);
        assert!(!automated["body"].as_str().expect("body").trim().is_empty());
        assert_eq!(automated["source"]["complete"], true);
        assert_eq!(automated["source"]["review_method"], "automated-capture");
        assert!(
            automated["source"]["review_note"]
                .as_str()
                .expect("review_note")
                .contains("NÃO aprovado juridicamente"),
            "automated-review source carries the human-approval caveat"
        );
    }

    #[tokio::test]
    async fn law_corpus_single_article_carries_citation() {
        let (status, body) =
            send(AppState::default(), get("/v1/law/corpus/eidas-910-2014/1")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["number"], "1");
        assert_eq!(body["label"], "Artigo 1.º");
        assert_eq!(body["verified"], true);
        assert!(!body["body"].as_str().expect("body").is_empty());
        assert!(body["source"]["dr_reference"].is_string());
        assert_eq!(body["source"]["complete"], true);
    }

    #[tokio::test]
    async fn law_citation_resolver_preserves_verified_and_pending_state() {
        let (status, body) = send(
            AppState::default(),
            post_json(
                "/v1/law/citations/resolve",
                json!({
                    "references": [
                        { "diploma_id": "eidas-910-2014", "article": "1" },
                        { "diploma_id": "csc", "article": "63" }
                    ]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["count"], 2);
        assert!(
            body["legal_notice"]
                .as_str()
                .expect("notice")
                .contains("não substituem"),
            "non-authoritative notice is explicit"
        );

        let citations = body["citations"].as_array().expect("citations");
        assert_eq!(citations[0]["source_id"], "eidas-910-2014");
        assert_eq!(citations[0]["verification"], "Verified");
        assert_eq!(citations[0]["source_complete"], true);
        assert!(citations[0]["source_url"].is_string());

        // csc:63 is now automated-review authentic text (wp22): the resolver must surface that tier
        // faithfully (complete source, real url) and must NOT upgrade it to human-`Verified`.
        assert_eq!(citations[1]["source_id"], "csc");
        assert_eq!(citations[1]["verification"], "automated_review");
        assert_ne!(citations[1]["verification"], "Verified");
        assert_eq!(citations[1]["source_complete"], true);
        assert!(citations[1]["source_url"].is_string());
    }

    #[tokio::test]
    async fn law_citation_resolver_is_bounded_and_gated() {
        let too_many: Vec<_> = (0..33)
            .map(|_| json!({ "diploma_id": "csc", "article": "63" }))
            .collect();
        let (status, _) = send(
            AppState::default(),
            post_json(
                "/v1/law/citations/resolve",
                json!({ "references": too_many }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = send_raw(
            AppState::default(),
            post_json(
                "/v1/law/citations/resolve",
                json!({ "references": [{ "diploma_id": "csc", "article": "63" }] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn law_corpus_404_on_unknown_diploma_and_article() {
        let (status, _) = send(AppState::default(), get("/v1/law/corpus/nope")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Known diploma, unknown article number.
        let (status, _) = send(
            AppState::default(),
            get("/v1/law/corpus/eidas-910-2014/9999"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Unknown diploma, any article.
        let (status, _) = send(AppState::default(), get("/v1/law/corpus/nope/1")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn law_corpus_search_returns_hits_with_snippets() {
        let (status, body) = send(
            AppState::default(),
            get("/v1/law/corpus/search?q=mercado%20interno"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["query"], "mercado interno");
        let results = body["results"].as_array().expect("results");
        assert!(!results.is_empty(), "the phrase occurs in the corpus");
        assert_eq!(body["count"], results.len());

        // At least one hit is the fully-verified eIDAS text, with a non-empty context snippet and
        // its authenticity status surfaced.
        let hit = results
            .iter()
            .find(|r| r["diploma_id"] == "eidas-910-2014")
            .expect("an eIDAS hit");
        assert!(hit["diploma_title"].is_string());
        assert!(
            !hit["snippet"].as_str().expect("snippet").is_empty(),
            "a context snippet is extracted"
        );
        assert!(hit["verification"].is_string(), "authenticity surfaced");
        assert_eq!(hit["verified"], true);
    }

    #[tokio::test]
    async fn law_corpus_search_is_diacritic_and_case_insensitive() {
        // Folded search: "eletronica" (no accent) must match "eletrónica"; case must not matter.
        let (_, folded) = send(
            AppState::default(),
            get("/v1/law/corpus/search?q=eletronica"),
        )
        .await;
        let (_, accented) = send(
            AppState::default(),
            get("/v1/law/corpus/search?q=eletr%C3%B3nica"),
        )
        .await;
        let (_, upper) = send(
            AppState::default(),
            get("/v1/law/corpus/search?q=ELETRONICA"),
        )
        .await;

        let n_folded = folded["results"].as_array().expect("results").len();
        assert!(n_folded > 0, "accent-folded query finds the accented term");
        assert_eq!(
            n_folded,
            accented["results"].as_array().unwrap().len(),
            "diacritic-insensitive: same hits with/without the accent"
        );
        assert_eq!(
            n_folded,
            upper["results"].as_array().unwrap().len(),
            "case-insensitive: uppercase yields the same hits"
        );
    }

    #[tokio::test]
    async fn law_corpus_search_blank_query_is_empty() {
        let (status, body) = send(AppState::default(), get("/v1/law/corpus/search?q=%20%20")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 0);
        assert_eq!(body["results"].as_array().expect("results").len(), 0);

        // An absent query is likewise empty (not an error).
        let (status, body) = send(AppState::default(), get("/v1/law/corpus/search")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 0);
    }

    #[tokio::test]
    async fn law_corpus_search_honours_limit() {
        let (_, capped) = send(
            AppState::default(),
            get("/v1/law/corpus/search?q=artigo&limit=3"),
        )
        .await;
        assert!(capped["results"].as_array().expect("results").len() <= 3);
    }

    #[tokio::test]
    async fn law_corpus_reads_require_an_authenticated_session() {
        // No session → 401 (the CurrentActor extractor), across every corpus read.
        for uri in [
            "/v1/law/corpus",
            "/v1/law/corpus/search?q=mercado",
            "/v1/law/corpus/eidas-910-2014",
            "/v1/law/corpus/eidas-910-2014/1",
        ] {
            let (status, _) = send_raw(AppState::default(), get(uri)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "no session on {uri}");
        }
    }

    #[tokio::test]
    async fn law_corpus_reads_are_forbidden_without_law_read() {
        // A valid session whose user holds no permissions → 403 (Gated on law.read@Global).
        let state = AppState::default();
        let token = powerless_token(&state).await;
        let (status, _) =
            send_raw(state.clone(), with_session(get("/v1/law/corpus"), &token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send_raw(
            state,
            with_session(get("/v1/law/corpus/search?q=mercado"), &token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // --- Users + session + actor attribution (§2.8) --------------------------------------

    /// Create a user and return (user_id, username).
    async fn create_user(state: &AppState, username: &str) -> String {
        let (status, user) = send(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": username, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "user created");
        user["id"].as_str().expect("user id").to_owned()
    }

    /// Open a session for a user id and return its token.
    async fn open_session(state: &AppState, user_id: &str) -> String {
        let (status, s) = send_raw(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": user_id, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "session opened");
        s["token"].as_str().expect("token").to_owned()
    }

    #[tokio::test]
    async fn create_user_appends_event_and_lists() {
        let state = AppState::default();
        // Bootstrap: first user created without auth (no users exist yet).
        let (status, user) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": DEFAULT_TEST_PASSWORD,
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["username"], "amelia.marques");
        assert_eq!(user["display_name"], "Amélia Marques");
        assert_eq!(user["active"], true);
        assert!(user.get("password_hash").is_none());
        let id = user["id"].as_str().expect("id").to_owned();

        // GET by id (RBAC t64-E3: `user.read`; the auto-seeded Owner session satisfies it).
        let (status, got) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["username"], "amelia.marques");

        // List requires auth (t41); auto-seed adds "test.actor" as well.
        let (status, list) = send(state.clone(), get("/v1/users")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            list.as_array()
                .expect("list")
                .iter()
                .any(|u| u["username"] == "amelia.marques"),
            "amelia.marques is in the list: {list}"
        );

        // A `user.created` event was appended.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.created" && e["actor"] == "api")
            .expect("user.created event present with actor=api (bootstrap)");
        assert_eq!(created["scope"], "user");
    }

    #[tokio::test]
    async fn create_user_requires_password_and_persists_hardened_hash() {
        let state = AppState::default();
        let password = "Criar-Forte7!X";
        let (status, user) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": password }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["has_secret"], true);
        assert!(user.get("password_hash").is_none());

        let uid = crate::users::UserId(Uuid::parse_str(user["id"].as_str().unwrap()).unwrap());
        let stored = state
            .users
            .read()
            .await
            .get(&uid)
            .and_then(|u| u.password_hash.as_deref().map(ToOwned::to_owned))
            .expect("stored password hash");
        assert!(stored.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(stored.contains("$argon2id$"));
        assert!(!stored.contains(password));
    }

    #[tokio::test]
    async fn create_user_rejects_missing_or_weak_password_with_policy_errors() {
        let status = send_status(
            AppState::default(),
            post_json("/v1/users", json!({ "username": "amelia.marques" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = send_raw(
            AppState::default(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": "" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].as_str().expect("error").contains("at least"));

        for (password, expected_rule) in [("abcdefgh", "length"), ("Password123!", "not_common")] {
            let (status, body) = send_raw(
                AppState::default(),
                post_json(
                    "/v1/users",
                    json!({ "username": "amelia.marques", "password": password }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            let codes: Vec<&str> = body["failed_rules"]
                .as_array()
                .expect("failed_rules")
                .iter()
                .map(|f| f["code"].as_str().expect("code"))
                .collect();
            assert!(codes.contains(&expected_rule), "codes: {codes:?}");
        }
    }

    #[tokio::test]
    async fn create_user_rejects_unauthenticated_non_bootstrap_before_password_policy() {
        let state = AppState::default();
        let (status, _) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, body) = send_raw(
            state,
            post_json(
                "/v1/users",
                json!({ "username": "bruno.dias", "password": "abcdefgh" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "sessão requerida");
        assert!(
            body.get("failed_rules").is_none(),
            "password policy details must not run before auth: {body}"
        );
    }

    #[tokio::test]
    async fn create_user_defaults_display_name_to_username() {
        let (status, user) = send(
            AppState::default(),
            post_json(
                "/v1/users",
                json!({ "username": "auditor", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["display_name"], "auditor");
    }

    #[tokio::test]
    async fn create_user_accepts_and_normalizes_email() {
        let state = AppState::default();
        let (status, user) = send(
            state.clone(),
            post_json(
                "/v1/users",
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "email": "  Amelia.Marques@Example.PT ",
                    "password": DEFAULT_TEST_PASSWORD
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(user["email"], "amelia.marques@example.pt");
        let id = user["id"].as_str().expect("id");

        let (status, got) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["email"], "amelia.marques@example.pt");

        let (status, no_email) = send(
            state,
            post_json(
                "/v1/users",
                json!({ "username": "bruno.dias", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            no_email.get("email").is_none(),
            "unset user email is omitted from UserView"
        );
    }

    #[tokio::test]
    async fn create_user_rejects_invalid_username_422() {
        for bad in ["", "Amelia", "has space", "a@b"] {
            let (status, body) = send(
                AppState::default(),
                post_json(
                    "/v1/users",
                    json!({ "username": bad, "password": DEFAULT_TEST_PASSWORD }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "rejects {bad:?}");
            assert!(body["error"].is_string());
        }
    }

    #[tokio::test]
    async fn create_duplicate_user_is_409() {
        let state = AppState::default();
        create_user(&state, "amelia.marques").await;
        // The same username again is a conflict (uniqueness is case-insensitive).
        let (status, body) = send(
            state,
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn patch_user_renames_and_deactivates() {
        let state = AppState::default();
        let id = create_user(&state, "amelia.marques").await;

        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "display_name": "Amélia M.", "active": false }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["display_name"], "Amélia M.");
        assert_eq!(patched["active"], false);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "user.updated")
        );
    }

    #[tokio::test]
    async fn patch_user_updates_clears_and_rejects_email() {
        let state = AppState::default();
        let id = create_user(&state, "amelia.marques").await;

        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "email": "  Amelia.Marques@Example.PT " }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["email"], "amelia.marques@example.pt");

        let (status, rejected) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "email": "not-an-email" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            rejected["error"]
                .as_str()
                .unwrap_or_default()
                .contains("email")
        );

        let (status, got) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(got["email"], "amelia.marques@example.pt");

        let (status, cleared) = send(
            state,
            patch_json(&format!("/v1/users/{id}"), json!({ "email": null })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cleared.get("email").is_none(),
            "null email clears and is omitted from UserView"
        );
    }

    #[tokio::test]
    async fn session_issue_and_inspect() {
        let state = AppState::default();
        let id = create_user(&state, "amelia.marques").await;
        let token = open_session(&state, &id).await;

        // GET /v1/session with the header resolves the user.
        let (status, s) = send(state.clone(), with_session(get("/v1/session"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(s["user"]["username"], "amelia.marques");

        // No header → user is null.
        let (status, s) = send_raw(state.clone(), get("/v1/session")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(s["user"], Value::Null);

        // DELETE drops it; a subsequent GET is null again.
        let del = with_session(
            Request::builder()
                .method("DELETE")
                .uri("/v1/session")
                .body(Body::empty())
                .unwrap(),
            &token,
        );
        let (status, _) = send(state.clone(), del).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, s) = send(state, with_session(get("/v1/session"), &token)).await;
        assert_eq!(s["user"], Value::Null);
    }

    #[tokio::test]
    async fn session_for_unknown_user_is_401() {
        // t41 H1: uniform 401, no enumeration
        let missing = Uuid::new_v4();
        let (status, _) = send_raw(
            AppState::default(),
            post_json(
                "/v1/session",
                json!({ "user_id": missing, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn session_attributes_the_ledger_actor_to_the_username() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let user_id = create_user(&state, "amelia.marques").await;
        let token = open_session(&state, &user_id).await;

        // t41: all mutations now require a session. Draft WITH the amelia.marques session →
        // the ledger actor is "amelia.marques".
        let (status, act) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/acts",
                    json!({ "book_id": book_id, "title": "Ata da AG", "channel": "Physical" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Fill content + advance, all with the amelia.marques session.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(
                    &format!("/v1/acts/{act_id}"),
                    json!({
                        "meeting_date": "2026-03-30",
                        "meeting_time": "10:00",
                        "place": "Sede social",
                        "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                        "agenda": [{ "number": 1, "text": "Contas" }],
                        "attendance_reference": "Lista de presenças",
                        "deliberations": "Aprovadas as contas.",
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send_raw(
                state.clone(),
                with_session(
                    post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
                    &token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // Seal WITH the session → the seal event's actor is "amelia.marques".
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let arr = events.as_array().expect("events");
        let drafted = arr
            .iter()
            .find(|e| e["kind"] == "act.drafted")
            .expect("act.drafted present");
        let sealed = arr
            .iter()
            .find(|e| e["kind"] == "act.sealed")
            .expect("act.sealed present");
        // t41: with a session, both draft and seal events are attributed to "amelia.marques".
        assert_eq!(drafted["actor"], "amelia.marques");
        assert_eq!(sealed["actor"], "amelia.marques");
    }

    // --- Per-family dispatch + statute overlay + back-compat (t31) ------------------------

    /// Advance an act (already drafted + filled) through the lifecycle to `Signing`.
    async fn advance_to_signing(state: &AppState, act_id: &str) {
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "advance to {to}");
        }
    }

    #[tokio::test]
    async fn condominium_seals_under_the_condominio_pack_without_a_mesa() {
        // Per-family dispatch: a condominium ata is checked by the DL 268/94 pack, which does not
        // require a mesa — so an act with no mesa seals clean, proving the gate is family-anchored
        // (not the CSC one, which would block on the missing chair).
        let (state, _entity_id, book_id) = entity_and_open_book("Condominio").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da assembleia", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Hall do prédio",
                    "attendance_reference": "Folha de presenças",
                    "deliberations": "Aprovado o orçamento anual.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        let (status, comp) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comp["rule_pack"], "condominio-dl268/v1");
        assert_eq!(comp["family"], "Condominium");
        assert_eq!(comp["statute_overlay"], false);
        assert_eq!(comp["errors"], 0);
        assert_eq!(comp["seal_allowed"], true);

        // Seals with no mesa and no acknowledgement — the condo pack has nothing to flag here.
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "condo seal: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    #[tokio::test]
    async fn csc_seal_blocked_without_mesa_then_passes_with_mesa() {
        // The re-promoted mesa Error: a CSC ata missing its presidente da mesa is refused at the
        // seal (422), then seals once the mesa is filled through the wire.
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();

        // Fill everything except the mesa.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "agenda": [{ "number": 1, "text": "Contas" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberations": "Aprovadas as contas.",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        // Compliance reports the blocking mesa Error and refuses the seal.
        let (_, comp) = send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert!(comp["errors"].as_u64().expect("errors") >= 1);
        assert_eq!(comp["seal_allowed"], false);
        assert!(
            comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| { i["rule_id"] == "CSC-63/mesa-presidente" && i["severity"] == "Error" }),
            "the blocking mesa Error is present: {comp}"
        );

        let (status, body) = send(
            state.clone(),
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "CSC-63/mesa-presidente"),
            "the seal refusal carries the mesa Error: {body}"
        );

        // Fill the mesa through the wire → the seal now succeeds.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal after mesa: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    #[tokio::test]
    async fn patch_entity_statute_drives_the_overlay_and_audits() {
        // PATCH /v1/entities/{id} sets a statute overlay, appends `entity.statute_updated`, and the
        // overlay then drives the STATUTE/majority check over a structured vote — all through the
        // wire. A null statute clears it.
        let state = AppState::default();
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();
        // The view carries the derived profile and a null statute.
        assert!(entity["statute"].is_null());
        assert_eq!(entity["profile"]["rule_pack_id"], "csc-art63/v2");
        assert_eq!(entity["profile"]["family"], "CommercialCompany");

        // Set a 2/3 statutory majority.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/entities/{entity_id}"),
                json!({ "statute": { "majority": { "numerator": 2, "denominator": 3 } } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["statute"]["majority"]["numerator"], 2);
        assert_eq!(patched["statute"]["majority"]["denominator"], 3);

        // The audit trail records the overlay edit.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "entity.statute_updated"),
            "entity.statute_updated is on the chain: {events}"
        );

        // Open a book, draft an ata with a structured non-unanimous vote below the 2/3 majority.
        let (_, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] }),
            ),
        )
        .await;
        let book_id = book["id"].as_str().expect("book id").to_owned();
        let (_, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Alteração ao contrato" }],
                    "attendance_reference": "Lista de presenças",
                    "deliberation_items": [{
                        "agenda_number": 1,
                        "text": "Deliberada a alteração ao contrato.",
                        "vote": { "type": "Recorded", "em_favor": 60, "contra": 40, "abstencoes": 0 },
                        "statements": []
                    }],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_id).await;

        let (_, comp) = send(state.clone(), get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(comp["statute_overlay"], true);
        assert!(
            comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "STATUTE/majority" && i["severity"] == "Warning"),
            "60/100 misses the 2/3 majority: {comp}"
        );

        // Clearing the statute removes the overlay.
        let (status, cleared) = send(
            state.clone(),
            patch_json(
                &format!("/v1/entities/{entity_id}"),
                json!({ "statute": null }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(cleared["statute"].is_null());
        let (_, comp) = send(state, get(&format!("/v1/acts/{act_id}/compliance"))).await;
        assert_eq!(comp["statute_overlay"], false);
        assert!(
            !comp["issues"]
                .as_array()
                .expect("issues")
                .iter()
                .any(|i| i["rule_id"] == "STATUTE/majority"),
            "cleared statute drops the overlay finding: {comp}"
        );
    }

    #[tokio::test]
    async fn old_shape_persisted_act_is_served_patched_and_sealed() {
        // §3 back-compat: an act persisted in the pre-t31 shape (no mesa/time/agenda/…, attachments
        // without `beginning_of_proof`, signatories without `permilage`) deserializes with defaults
        // and flows through GET / PATCH / advance / seal on the wire.
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_uuid = Uuid::new_v4();
        let old_shape = format!(
            r#"{{
                "id": "{act_uuid}",
                "book_id": "{book_id}",
                "title": "Ata antiga",
                "channel": "Physical",
                "meeting_date": null,
                "place": "Sede social",
                "attendance_reference": "Lista de presenças",
                "deliberations": "Aprovadas as contas.",
                "telematic_evidence": null,
                "attachments": [{{ "label": "Anexo", "kind": "Exhibit", "digest": null }}],
                "signatories": [{{ "name": "Ana", "capacity": "Chair", "signed": false }}],
                "state": "Draft",
                "ata_number": null,
                "payload_digest": null,
                "seal_event_seq": null,
                "retifies": null
            }}"#
        );
        let act: Act = serde_json::from_str(&old_shape).expect("old-shape act deserializes");
        state.acts.write().await.insert(ActId(act_uuid), act);

        // GET serves it with the new fields defaulted (mesa empty, time/agenda absent, and the new
        // nested flags at their defaults).
        let (status, got) = send(state.clone(), get(&format!("/v1/acts/{act_uuid}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(got["mesa"]["presidente"].is_null());
        assert!(got["meeting_time"].is_null());
        assert_eq!(got["agenda"].as_array().expect("agenda").len(), 0);
        assert_eq!(
            got["deliberation_items"].as_array().expect("items").len(),
            0
        );
        assert_eq!(got["attachments"][0]["beginning_of_proof"], false);
        assert!(got["signatories"][0]["permilage"].is_null());

        // PATCH a mesa (+ time/agenda) onto it, advance, and seal — the whole wire serves it.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_uuid}"),
                json!({
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                    "agenda": [{ "number": 1, "text": "Contas" }],
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        advance_to_signing(&state, &act_uuid.to_string()).await;
        let (status, sealed) = send(
            state,
            post_json(&format!("/v1/acts/{act_uuid}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "old-shape seal: {sealed}");
        assert_eq!(sealed["ata_number"], 1);
    }

    // --- Durable store persistence (t30) --------------------------------------------------

    fn assert_csc_seal_metadata(metadata: &Value) {
        assert_eq!(metadata["rule_pack_id"], "csc-art63/v2");
        assert_eq!(metadata["version"], "v2");
        assert_eq!(metadata["family"], "CommercialCompany");
        assert_eq!(metadata["profile"], "SociedadeAnonima");
    }

    /// Drive a full create → open book → draft → fill → advance → seal against `state`,
    /// returning `(entity_id, book_id, act_id)` with the act sealed as ata n.º 1.
    async fn seal_one(state: &AppState) -> (String, String, String) {
        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({ "name": "Encosto Estratégico, S.A.", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({ "entity_id": entity_id, "kind": "AssembleiaGeral", "purpose": "livro", "opening_date": "2026-01-15", "required_signatories": ["Administrador"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_str().expect("book id").to_owned();

        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let act_id = act["id"].as_str().expect("act id").to_owned();

        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "meeting_date": "2026-03-30", "meeting_time": "10:00", "place": "Sede social", "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] }, "agenda": [{ "number": 1, "text": "Contas" }], "attendance_reference": "Lista de presenças", "deliberations": "Aprovadas as contas." }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            let (status, _) = send(
                state.clone(),
                post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, sealed) = send(
            state.clone(),
            // A fully-filled CSC v2 ata (mesa set) has no findings — no acknowledgement needed.
            post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(sealed["ata_number"], 1);
        assert_csc_seal_metadata(&sealed["act"]["seal_metadata"]);
        (entity_id, book_id, act_id)
    }

    #[tokio::test]
    async fn domain_and_ledger_survive_a_restart_via_the_store() {
        let tmp = TempDir::new();
        let (entity_id, book_id, act_id) = {
            let state = AppState::with_data_dir(tmp.dir.clone());
            assert!(
                state.store.is_some(),
                "with_data_dir opens the durable store"
            );
            seal_one(&state).await
        };

        // A fresh state over the same dir rebuilds every aggregate + the whole chain from disk.
        let restarted = AppState::with_data_dir(tmp.dir.clone());

        let (status, entity) =
            send(restarted.clone(), get(&format!("/v1/entities/{entity_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entity["nipc"], "503004642");

        let (status, book) = send(restarted.clone(), get(&format!("/v1/books/{book_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(book["id"], book_id);

        let (status, act) = send(restarted.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(act["state"], "Sealed");
        assert_eq!(
            act["ata_number"], 1,
            "the sealed ata number survived the restart"
        );
        assert_csc_seal_metadata(&act["seal_metadata"]);

        // The rehydrated chain verifies and the dashboard counts are intact.
        let (_, verify) = send(restarted.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert!(
            verify["length"].as_u64().expect("length") >= 4,
            "the whole chain reloaded: {verify}"
        );

        let (_, dash) = send(restarted, get("/v1/dashboard")).await;
        assert_eq!(dash["entities"], 1);
        assert_eq!(dash["acts_sealed"], 1);
    }

    #[tokio::test]
    async fn in_memory_state_has_no_store() {
        // AppState::default() keeps the historical in-memory behaviour: no durable store.
        let state = AppState::default();
        assert!(state.store.is_none());
        let _ = seal_one(&state).await;
        // A separate default state shares nothing durable — its chain is empty.
        let (_, verify) = send(AppState::default(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["length"], 0);
    }

    #[tokio::test]
    async fn import_from_registry_persists_entity_and_extract_across_restart() {
        let tmp = TempDir::new();
        let html = "<!DOCTYPE html><html lang=\"pt-PT\"><body><div class=\"matricula\">\
             <p>MATRÍCULA</p><table>\
             <tr><td>Matrícula:</td><td>99999/20200101</td></tr>\
             <tr><td>NIF/NIPC:</td><td>503004642</td></tr>\
             <tr><td>Firma:</td><td>Encosto Estratégico, Lda</td></tr>\
             <tr><td>Natureza Jurídica:</td><td>Sociedade por quotas</td></tr>\
             <tr><td>Sede:</td><td>Lisboa</td></tr>\
             </table></div></body></html>";
        let entity_id = {
            let mut state = AppState::with_data_dir(tmp.dir.clone());
            state.registry = Some(Arc::new(
                chancela_registry::MockRegistryTransport::empty().with_html(html.to_owned()),
            ));
            let (status, report) = send(
                state.clone(),
                post_json(
                    "/v1/entities/import-from-registry",
                    json!({ "code": "1234-5678-9012" }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            report["entity"]["id"]
                .as_str()
                .expect("entity id")
                .to_owned()
        };

        // Rebuild from disk: both the created entity and the imported extract are durable.
        let restarted = AppState::with_data_dir(tmp.dir.clone());
        let (status, entity) =
            send(restarted.clone(), get(&format!("/v1/entities/{entity_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(entity["nipc"], "503004642");

        let (status, extract) = send(
            restarted.clone(),
            get(&format!("/v1/entities/{entity_id}/registry")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(extract["nipc"], "503004642");

        // Both events (entity.created + registry.imported) persisted and the chain verifies.
        let (_, verify) = send(restarted, get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert_eq!(verify["length"], 2);
    }

    #[tokio::test]
    async fn backup_returns_a_manifest_when_persistent() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        std::fs::write(
            tmp.dir.join(crate::apikeys::API_KEYS_FILE),
            br#"[{"prefix":"chk_manifest"}]"#,
        )
        .expect("api key sidecar");

        let (status, manifest) = send(state.clone(), post_json("/v1/backup", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            manifest["path"].as_str().expect("path").ends_with(".zip"),
            "manifest path is the archive: {manifest}"
        );
        assert!(manifest["bytes"].as_u64().expect("bytes") > 0);
        assert_eq!(
            manifest["store_schema_version"],
            chancela_store::schema::SCHEMA_VERSION
        );
        assert_eq!(manifest["ledger_verified"], true);
        assert!(manifest["ledger_length"].as_u64().expect("length") >= 4);
        let files = manifest["files"].as_array().expect("files");
        assert!(files.iter().any(|f| f["name"] == "chancela.db"));
        assert!(files.iter().any(|f| f["name"] == "apikeys.json"));

        // The archive really exists on disk under backups/.
        let path = manifest["path"].as_str().expect("path");
        assert!(
            std::path::Path::new(path).is_file(),
            "archive written: {path}"
        );

        // The backup itself is recorded in the chain.
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "backup.created"),
            "a backup.created event was appended"
        );
    }

    #[tokio::test]
    async fn backup_with_passphrase_returns_encrypted_envelope() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;

        let (status, manifest) = send(
            state,
            post_json(
                "/v1/backup",
                json!({ "passphrase": "correct horse battery staple" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let path = manifest["path"].as_str().expect("path");
        assert!(path.ends_with(".cbackup"), "encrypted path: {path}");
        let bytes = std::fs::read(path).expect("encrypted backup exists");
        assert!(chancela_store::is_encrypted_backup(&bytes));
        assert!(!contains_subslice(&bytes, b"PK"));
        assert!(!contains_subslice(&bytes, b"SQLite format 3"));
        assert!(
            chancela_store::decrypt_backup_envelope(&bytes, "correct horse battery staple").is_ok()
        );
    }

    #[tokio::test]
    async fn restore_endpoint_accepts_encrypted_backup_passphrase() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        let settings = tmp.dir.join(crate::settings::SETTINGS_FILE);
        std::fs::write(&settings, br#"{"schema_version":1}"#).expect("settings sidecar");

        let (_, manifest) = send(
            state.clone(),
            post_json(
                "/v1/backup",
                json!({ "passphrase": "correct horse battery staple" }),
            ),
        )
        .await;
        let archive = manifest["path"].as_str().expect("path").to_owned();

        {
            let mut ledger = state.ledger.write().await;
            ledger.append("api", "settings", "settings.changed", None, b"after backup");
            state
                .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
                .expect("persist post-backup event");
        }
        std::fs::write(
            &settings,
            br#"{"schema_version":1,"appearance":{"theme":"dark"}}"#,
        )
        .expect("mutate settings sidecar");

        let (status, restored) = send(
            state.clone(),
            post_json(
                "/v1/ledger/recovery/restore",
                json!({
                    "archive": archive,
                    "passphrase": "correct horse battery staple"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "restore response: {restored}");
        assert_eq!(
            std::fs::read(&settings).unwrap(),
            br#"{"schema_version":1}"#
        );
        let loaded = state.store.as_ref().unwrap().load().unwrap();
        assert!(
            !loaded
                .ledger
                .events()
                .iter()
                .any(|e| e.kind == "settings.changed"),
            "post-backup event is absent after restore"
        );
        assert!(
            loaded
                .ledger
                .events()
                .iter()
                .any(|e| e.kind == "ledger.restored")
        );
    }

    #[tokio::test]
    async fn restore_preflight_accepts_encrypted_backup_without_mutating_state() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        let settings = tmp.dir.join(crate::settings::SETTINGS_FILE);
        std::fs::write(&settings, br#"{"schema_version":1}"#).expect("settings sidecar");

        let (_, manifest) = send(
            state.clone(),
            post_json(
                "/v1/backup",
                json!({ "passphrase": "correct horse battery staple" }),
            ),
        )
        .await;
        let archive = manifest["path"].as_str().expect("path").to_owned();

        {
            let mut ledger = state.ledger.write().await;
            ledger.append("api", "settings", "settings.changed", None, b"after backup");
            state
                .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
                .expect("persist post-backup event");
        }
        std::fs::write(
            &settings,
            br#"{"schema_version":1,"appearance":{"theme":"dark"}}"#,
        )
        .expect("mutate settings sidecar");
        let live_len = state.store.as_ref().unwrap().load().unwrap().ledger.len();

        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/ledger/recovery/restore/preflight",
                json!({
                    "archive": archive,
                    "passphrase": "correct horse battery staple"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "preflight response: {body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["ready"], true);
        assert_eq!(body["encrypted"], true);
        assert_eq!(body["ledger_verified"], true);
        assert_eq!(body["manifest"]["path"], "manifest.json");
        assert_eq!(body["manifest"]["schema"], "chancela-backup-manifest/v1");
        assert_eq!(body["manifest"]["version"], 1);
        assert!(body["manifest"]["member_count"].as_u64().unwrap() >= 1);
        assert!(body["manifest"]["db_member_present"].as_bool().unwrap());
        assert_eq!(body["errors"].as_array().unwrap().len(), 0);
        assert!(
            !body.to_string().contains("sha256"),
            "preflight response must not expose member hashes: {body}"
        );

        assert_eq!(
            std::fs::read(&settings).unwrap(),
            br#"{"schema_version":1,"appearance":{"theme":"dark"}}"#,
            "preflight does not replace sidecars"
        );
        let loaded = state.store.as_ref().unwrap().load().unwrap();
        assert_eq!(loaded.ledger.len(), live_len, "preflight does not swap DB");
        assert!(
            loaded
                .ledger
                .events()
                .iter()
                .any(|e| e.kind == "settings.changed"),
            "live post-backup event remains"
        );
        assert!(
            !loaded
                .ledger
                .events()
                .iter()
                .any(|e| e.kind == "ledger.restored"),
            "preflight does not append restore events"
        );
    }

    #[tokio::test]
    async fn backup_in_memory_is_422() {
        let (status, body) = send(AppState::default(), post_json("/v1/backup", json!({}))).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("CHANCELA_DATA_DIR"),
            "422 explains how to enable persistence: {body}"
        );
    }

    #[tokio::test]
    async fn health_reports_durability_fields() {
        // In-memory: not persistent, boot-verify is null, no schema version key.
        let (status, body) = send(AppState::default(), get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["persistent"], false);
        assert_eq!(body["ledger_length"], 0);
        assert_eq!(body["ledger_verified"], Value::Null);
        assert!(body.get("store_schema_version").is_none());

        // Persistent: durable store, a boot-verified chain, and the schema version present.
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        let (status, body) = send(state, get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["persistent"], true);
        assert_eq!(body["ledger_verified"], true);
        assert_eq!(
            body["store_schema_version"],
            chancela_store::schema::SCHEMA_VERSION
        );
        assert!(body["ledger_length"].as_u64().expect("length") >= 4);
    }

    #[tokio::test]
    async fn data_status_requires_settings_read() {
        let state = AppState::default();

        let (status, _) = send_raw(state.clone(), get("/v1/data/status")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "session required");

        let token = powerless_token(&state).await;
        let (status, body) = send_raw(state, with_session(get("/v1/data/status"), &token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    }

    #[tokio::test]
    async fn data_status_reports_in_memory_storage_without_health_exposure() {
        let (status, body) = send(AppState::default(), get("/v1/data/status")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body["generated_at"].as_str().is_some());
        assert_eq!(body["persistence"]["mode"], "in_memory");
        assert_eq!(body["persistence"]["data_dir_configured"], false);
        assert_eq!(body["persistence"]["durable_store_open"], false);
        assert_eq!(body["persistence"]["store_schema_version"], Value::Null);
        assert_eq!(body["persistence"]["ledger_length"], 0);
        assert_eq!(body["persistence"]["ledger_verified"], Value::Null);
        assert_eq!(body["data_dir"]["path"], Value::Null);
        assert_eq!(body["data_dir"]["exists"], Value::Null);
        assert_eq!(body["data_dir"]["is_directory"], Value::Null);
        assert_eq!(body["permissions"]["read_dir"]["checked"], false);
        assert_eq!(body["permissions"]["create_file"]["checked"], false);
        assert_eq!(body["permissions"]["write_file"]["checked"], false);
        assert_eq!(body["permissions"]["delete_probe_file"]["checked"], false);
        assert_eq!(body["permissions"]["sqlite_store_open"]["checked"], true);
        assert_eq!(body["permissions"]["sqlite_store_open"]["ok"], false);
        assert_eq!(body["usage"]["total_bytes"], 0);
        assert_eq!(
            body["usage"]["filesystem"]
                .as_array()
                .expect("filesystem")
                .len(),
            0
        );
        assert_eq!(
            body["usage"]["sqlite_logical"]
                .as_array()
                .expect("sqlite_logical")
                .len(),
            0
        );

        let (status, health) = send(AppState::default(), get("/health")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(health.get("data_dir").is_none());
        assert!(health.get("permissions").is_none());
        assert!(health.get("usage").is_none());
    }

    #[tokio::test]
    async fn data_status_reports_durable_permissions_and_filesystem_usage() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let _ = seal_one(&state).await;
        std::fs::write(
            tmp.dir.join(crate::settings::SETTINGS_FILE),
            br#"{"schema_version":1}"#,
        )
        .expect("settings sidecar");
        std::fs::write(
            tmp.dir.join(crate::platform_logs::PLATFORM_LOGS_FILE),
            br#"[]"#,
        )
        .expect("platform logs sidecar");
        std::fs::write(
            tmp.dir
                .join(crate::backup_recovery::BACKUP_RECOVERY_DRILLS_FILE),
            br#"[]"#,
        )
        .expect("backup recovery drill receipts sidecar");
        let laws = tmp.dir.join(crate::law::LAWS_DIR);
        std::fs::create_dir_all(&laws).expect("laws dir");
        std::fs::write(laws.join("dl-1-2026.pdf"), b"law").expect("law file");

        let (status, body) = send(state, get("/v1/data/status")).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["persistence"]["mode"], "durable");
        assert_eq!(body["persistence"]["data_dir_configured"], true);
        assert_eq!(body["persistence"]["durable_store_open"], true);
        assert_eq!(
            body["persistence"]["store_schema_version"],
            chancela_store::schema::SCHEMA_VERSION
        );
        assert_eq!(body["persistence"]["ledger_verified"], true);
        assert_eq!(
            body["data_dir"]["path"],
            tmp.dir.to_string_lossy().into_owned()
        );
        assert_eq!(body["data_dir"]["exists"], true);
        assert_eq!(body["data_dir"]["is_directory"], true);

        for key in ["read_dir", "create_file", "write_file", "delete_probe_file"] {
            assert_eq!(body["permissions"][key]["checked"], true, "{key}");
            assert_eq!(body["permissions"][key]["ok"], true, "{key}");
        }
        assert_eq!(body["permissions"]["sqlite_store_open"]["ok"], true);

        let database = data_status_filesystem_concern(&body, "database");
        assert_eq!(database["basis"], "sqlite_file");
        assert!(database["bytes"].as_u64().expect("database bytes") > 0);
        assert!(database["file_count"].as_u64().expect("database files") >= 1);
        assert!(
            database["relative_roots"]
                .as_array()
                .expect("database roots")
                .iter()
                .any(|root| root == "chancela.db")
        );

        let settings = data_status_filesystem_concern(&body, "settings");
        assert_eq!(settings["basis"], "filesystem");
        assert_eq!(settings["file_count"], 1);
        assert!(settings["bytes"].as_u64().expect("settings bytes") > 0);

        let platform_logs = data_status_filesystem_concern(&body, "platform_logs");
        assert_eq!(platform_logs["basis"], "filesystem");
        assert_eq!(platform_logs["file_count"], 1);
        assert!(
            platform_logs["relative_roots"]
                .as_array()
                .expect("platform log roots")
                .iter()
                .any(|root| root == crate::platform_logs::PLATFORM_LOGS_FILE)
        );

        let backup_recovery_drills =
            data_status_filesystem_concern(&body, "backup_recovery_drills");
        assert_eq!(backup_recovery_drills["basis"], "filesystem");
        assert_eq!(backup_recovery_drills["file_count"], 1);
        assert!(
            backup_recovery_drills["relative_roots"]
                .as_array()
                .expect("backup recovery drill roots")
                .iter()
                .any(|root| root == crate::backup_recovery::BACKUP_RECOVERY_DRILLS_FILE)
        );

        let laws = data_status_filesystem_concern(&body, "laws");
        assert_eq!(laws["file_count"], 1);
        assert!(laws["directory_count"].as_u64().expect("law dirs") >= 1);

        let sqlite_logical = body["usage"]["sqlite_logical"]
            .as_array()
            .expect("sqlite logical");
        assert!(
            !sqlite_logical.is_empty(),
            "durable status reports logical SQLite usage"
        );
        let ledger = sqlite_logical
            .iter()
            .find(|entry| entry["id"] == "ledger")
            .unwrap_or_else(|| panic!("missing ledger logical usage in {body}"));
        assert_eq!(ledger["basis"], "sqlite_logical_payload");
        assert_eq!(ledger["exact"], false);
        assert!(ledger["row_count"].as_u64().expect("ledger rows") > 0);
        assert!(ledger["bytes"].as_u64().expect("ledger bytes") > 0);
        let domain = sqlite_logical
            .iter()
            .find(|entry| entry["id"] == "domain")
            .unwrap_or_else(|| panic!("missing domain logical usage in {body}"));
        assert!(domain["row_count"].as_u64().expect("domain rows") >= 3);
        assert!(domain["bytes"].as_u64().expect("domain bytes") > 0);
        let event_table = sqlite_logical
            .iter()
            .find(|entry| entry["id"] == "sqlite_table_events")
            .unwrap_or_else(|| panic!("missing events table logical usage in {body}"));
        assert_eq!(event_table["kind"], "sqlite_logical_table");
        assert_eq!(
            event_table["payload_stats"]["estimate_method"],
            "local_loaded_payload_estimate"
        );
        assert_eq!(
            event_table["payload_stats"]["estimate_basis"],
            "sqlite_logical_payload"
        );
        assert_eq!(event_table["payload_stats"]["table_name"], "events");
        assert_eq!(
            event_table["payload_stats"]["estimated_payload_bytes"],
            event_table["bytes"]
        );
        assert_eq!(
            event_table["payload_stats"]["row_count"],
            event_table["row_count"]
        );
        assert!(
            event_table["payload_stats"]["average_bytes_per_row"]
                .as_u64()
                .expect("events average bytes per row")
                > 0
        );
        assert_eq!(
            body["usage"]["sqlite_largest_payload_table"]["estimate_method"],
            "local_loaded_payload_estimate"
        );

        assert!(body["usage"]["total_bytes"].as_u64().expect("total bytes") > 0);
        assert!(
            body["usage"]["scan_errors"]
                .as_array()
                .expect("scan errors")
                .iter()
                .all(|err| !err
                    .as_str()
                    .is_some_and(|msg| msg.contains("sqlite logical usage not reported"))),
            "old sqlite logical placeholder must not be emitted: {body}"
        );

        let leftovers: Vec<_> = std::fs::read_dir(&tmp.dir)
            .expect("read temp dir")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".chancela-data-status-probe-")
            })
            .collect();
        assert!(leftovers.is_empty(), "probe files left behind");
    }

    #[tokio::test]
    async fn data_cleanup_crash_deletes_only_crash_concern_contents() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let crash = tmp.dir.join("crash");
        std::fs::create_dir_all(crash.join("nested")).expect("crash dirs");
        std::fs::write(crash.join("one.log"), b"crash").expect("crash file");
        std::fs::write(crash.join("nested").join("two.log"), b"report").expect("nested crash");
        std::fs::write(tmp.dir.join("crash-report.txt"), b"top").expect("top crash");
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("kept.zip"), b"export").expect("export file");

        let (status, body) = send(
            state,
            post_json("/v1/data/cleanup", json!({ "target": "crash" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["target"], "crash");
        assert_eq!(body["data_dir"], tmp.dir.to_string_lossy().into_owned());
        assert_eq!(body["deleted_files"], 3);
        assert_eq!(body["deleted_directories"], 1);
        assert_eq!(body["deleted_bytes"], 14);
        assert!(
            body["skipped"].as_array().expect("skipped").is_empty(),
            "no skipped entries: {body}"
        );
        assert!(crash.is_dir(), "cleanup preserves the crash root directory");
        assert!(
            std::fs::read_dir(&crash)
                .expect("read crash root")
                .next()
                .is_none(),
            "crash root emptied"
        );
        assert!(!tmp.dir.join("crash-report.txt").exists());
        assert!(exports.join("kept.zip").is_file(), "exports untouched");
    }

    #[tokio::test]
    async fn data_cleanup_platform_logs_deletes_sidecar_and_clears_ring_only() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        seed_platform_log(
            &state,
            "api",
            PlatformLogLevel::Info,
            "platform.services",
            "test platform log",
            None,
        )
        .await;
        let log_file = tmp.dir.join(platform_logs::PLATFORM_LOGS_FILE);
        assert!(log_file.is_file(), "platform log sidecar is present");

        let crash = tmp.dir.join("crash");
        std::fs::create_dir_all(&crash).expect("crash dir");
        std::fs::write(crash.join("kept.log"), b"crash").expect("crash file");
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("kept.zip"), b"export").expect("export file");

        let (status, body) = send(
            state.clone(),
            post_json("/v1/data/cleanup", json!({ "target": "platform_logs" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["target"], "platform_logs");
        assert_eq!(body["dry_run"], false);
        assert_eq!(body["deleted_files"], 1);
        assert_eq!(body["deleted_directories"], 0);
        assert!(
            body["deleted_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0),
            "platform log sidecar bytes counted: {body}"
        );
        assert!(!log_file.exists(), "platform log sidecar deleted");
        assert!(crash.join("kept.log").is_file(), "crash reports untouched");
        assert!(exports.join("kept.zip").is_file(), "exports untouched");

        let (status, logs) = send(state, get("/v1/platform/logs")).await;
        assert_eq!(status, StatusCode::OK, "body: {logs}");
        assert_eq!(logs["logs"], json!([]));
        assert_eq!(logs["retention"]["retained_count"], 0);
        assert_eq!(
            logs["retention"]["source"],
            platform_logs::PLATFORM_LOGS_FILE
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_execution_requires_preview_token() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(exports.join("nested")).expect("exports dirs");
        std::fs::write(exports.join("nested").join("bundle.zip"), b"bundle").expect("bundle");
        std::fs::write(tmp.dir.join("crash.log"), b"crash").expect("crash");

        let (status, body) = send(
            state,
            post_json("/v1/data/cleanup", json!({ "target": "exports" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| message.contains("preview_token")),
            "clear token error: {body}"
        );
        assert!(
            exports.join("nested").join("bundle.zip").is_file(),
            "direct cleanup did not delete exports"
        );
        assert!(tmp.dir.join("crash.log").is_file(), "crash untouched");
    }

    #[tokio::test]
    async fn data_cleanup_exports_confirm_with_matching_token_deletes_preview_manifest_only() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(exports.join("nested")).expect("exports dirs");
        std::fs::write(exports.join("nested").join("bundle.zip"), b"bundle").expect("bundle");
        std::fs::write(tmp.dir.join("crash.log"), b"crash").expect("crash");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        let token = cleanup_preview_token(&preview);
        assert_eq!(preview["target"], "exports");
        assert_eq!(preview["dry_run"], true);
        assert_eq!(preview["would_delete_files"], 1);
        assert_eq!(preview["would_delete_directories"], 1);

        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token.clone() }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["target"], "exports");
        assert_eq!(body["dry_run"], false);
        assert_eq!(body["deleted_files"], 1);
        assert_eq!(body["deleted_directories"], 1);
        assert_eq!(body["deleted_bytes"], 6);
        assert!(body.get("preview_token").is_none());
        assert!(
            exports.is_dir(),
            "cleanup preserves the exports root directory"
        );
        assert!(
            std::fs::read_dir(&exports)
                .expect("read exports root")
                .next()
                .is_none(),
            "exports root emptied"
        );
        assert!(tmp.dir.join("crash.log").is_file(), "crash untouched");

        let (status, reuse) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {reuse}");
        assert!(
            reuse["error"]
                .as_str()
                .is_some_and(|message| message.contains("invalid or expired")),
            "successful confirm consumes token: {reuse}"
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_dry_run_reports_no_delete_and_preserves_files() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(exports.join("nested")).expect("exports dirs");
        std::fs::write(exports.join("one.zip"), b"one").expect("export");
        std::fs::write(exports.join("nested").join("two.zip"), b"two").expect("nested export");

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["target"], "exports");
        assert_eq!(body["dry_run"], true);
        assert!(
            body["preview_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty()),
            "dry run returns token: {body}"
        );
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert_eq!(body["deleted_bytes"], 0);
        assert!(exports.join("one.zip").is_file(), "root export preserved");
        assert!(
            exports.join("nested").join("two.zip").is_file(),
            "nested export preserved"
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_minimum_age_filters_recent_files() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("recent.zip"), b"recent").expect("export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true, "minimum_age_days": 36500 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 0);
        let token = cleanup_preview_token(&preview);

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({
                    "target": "exports",
                    "dry_run": false,
                    "minimum_age_days": 36500,
                    "preview_token": token
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert_eq!(body["deleted_bytes"], 0);
        assert!(exports.join("recent.zip").is_file(), "recent export kept");
    }

    #[tokio::test]
    async fn data_cleanup_exports_keep_latest_retains_newest_files() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("old.zip"), b"old").expect("old export");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(exports.join("new.zip"), b"new").expect("new export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true, "keep_latest": 1 }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 1);
        let token = cleanup_preview_token(&preview);

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({
                    "target": "exports",
                    "dry_run": false,
                    "keep_latest": 1,
                    "preview_token": token
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 1);
        assert_eq!(body["deleted_bytes"], 3);
        assert!(!exports.join("old.zip").exists(), "older export deleted");
        assert!(exports.join("new.zip").is_file(), "newest export retained");
    }

    #[tokio::test]
    async fn data_cleanup_exports_changed_policy_rejects_preview_token() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("old.zip"), b"old").expect("old export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({
                    "target": "exports",
                    "dry_run": true,
                    "minimum_age_days": 30,
                    "keep_latest": 5
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        let token = cleanup_preview_token(&preview);

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({
                    "target": "exports",
                    "dry_run": false,
                    "minimum_age_days": 31,
                    "keep_latest": 5,
                    "preview_token": token
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| message.contains("cleanup policy")),
            "policy mismatch error: {body}"
        );
        assert!(exports.join("old.zip").is_file(), "mismatch did not delete");
    }

    #[tokio::test]
    async fn data_cleanup_exports_new_file_after_preview_is_not_deleted() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let nested = tmp.dir.join("exports").join("nested");
        std::fs::create_dir_all(&nested).expect("exports dirs");
        std::fs::write(nested.join("old.zip"), b"old").expect("old export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 1);
        assert_eq!(preview["would_delete_directories"], 1);
        let token = cleanup_preview_token(&preview);
        std::fs::write(nested.join("new-after-preview.zip"), b"new").expect("new export");

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_bytes"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert!(
            nested.join("old.zip").is_file(),
            "containing directory changed, so previewed file is retained"
        );
        assert!(
            nested.join("new-after-preview.zip").is_file(),
            "new file was not in preview manifest"
        );
        assert!(
            nested.is_dir(),
            "directory remains because new file was not selected"
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_directory_metadata_changed_after_preview_is_not_deleted() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let nested = tmp.dir.join("exports").join("nested");
        std::fs::create_dir_all(&nested).expect("exports dirs");
        std::fs::write(nested.join("old.zip"), b"old").expect("old export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 1);
        assert_eq!(preview["would_delete_directories"], 1);
        let token = cleanup_preview_token(&preview);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::remove_dir_all(&nested).expect("replace previewed directory");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::create_dir_all(&nested).expect("replacement dir");
        std::fs::write(nested.join("replacement.zip"), b"replacement").expect("replacement export");

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert!(
            body["skipped"]
                .as_array()
                .expect("skipped")
                .iter()
                .any(|message| message
                    .as_str()
                    .is_some_and(|message| message.contains("directory metadata changed"))),
            "directory metadata change is reported: {body}"
        );
        assert!(nested.is_dir(), "changed directory is retained");
        assert!(
            nested.join("replacement.zip").is_file(),
            "replacement contents are retained"
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_file_metadata_changed_after_preview_is_not_deleted() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let nested = tmp.dir.join("exports").join("nested");
        let export = nested.join("old.zip");
        std::fs::create_dir_all(&nested).expect("exports dirs");
        std::fs::write(&export, b"old").expect("old export");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 1);
        let token = cleanup_preview_token(&preview);

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&export, b"changed-size").expect("changed export");

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert!(
            body["skipped"]
                .as_array()
                .expect("skipped")
                .iter()
                .any(|message| message
                    .as_str()
                    .is_some_and(|message| message.contains("target metadata changed"))),
            "file metadata change is reported: {body}"
        );
        assert_eq!(
            std::fs::read(&export).expect("changed export retained"),
            b"changed-size"
        );
    }

    #[tokio::test]
    async fn data_cleanup_exports_same_size_rewrite_with_preserved_timestamp_is_not_deleted() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let nested = tmp.dir.join("exports").join("nested");
        let export = nested.join("old.zip");
        std::fs::create_dir_all(&nested).expect("exports dirs");
        std::fs::write(&export, b"alpha").expect("old export");
        let preview_modified = std::fs::symlink_metadata(&export)
            .expect("preview metadata")
            .modified()
            .expect("preview modified timestamp");

        let (status, preview) = send(
            state.clone(),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {preview}");
        assert_eq!(preview["would_delete_files"], 1);
        let token = cleanup_preview_token(&preview);

        std::fs::write(&export, b"bravo").expect("same-size changed export");
        set_file_modified(&export, preview_modified);
        assert_eq!(
            std::fs::symlink_metadata(&export)
                .expect("changed metadata")
                .modified()
                .expect("changed modified timestamp"),
            preview_modified,
            "test precondition: changed file keeps the preview timestamp"
        );

        let (status, body) = send(
            state,
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "exports", "dry_run": false, "preview_token": token }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["deleted_files"], 0);
        assert_eq!(body["deleted_directories"], 0);
        assert!(
            body["skipped"]
                .as_array()
                .expect("skipped")
                .iter()
                .any(|message| message
                    .as_str()
                    .is_some_and(|message| message.contains("content changed since preview"))),
            "content hash mismatch is reported: {body}"
        );
        assert_eq!(
            std::fs::read(&export).expect("changed export retained"),
            b"bravo"
        );
    }

    #[tokio::test]
    async fn data_cleanup_is_settings_manage_gated_and_rejects_unknown_targets() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};

        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let (status, _) = send_raw(
            state.clone(),
            post_json("/v1/data/cleanup", json!({ "target": "crash" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "session required");

        let leitor = seed_user(
            &state,
            "leitor.storage",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let token = open_session(&state, &leitor.to_string()).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json("/v1/data/cleanup", json!({ "target": "crash" })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

        let exports = tmp.dir.join("exports");
        std::fs::create_dir_all(&exports).expect("exports dir");
        std::fs::write(exports.join("kept.zip"), b"export").expect("export");
        let (status, body) = send(
            state,
            post_json("/v1/data/cleanup", json!({ "target": "database" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            exports.join("kept.zip").is_file(),
            "unsupported target did not delete"
        );

        let (status, body) = send(
            AppState::with_data_dir(tmp.dir.clone()),
            post_json(
                "/v1/data/cleanup",
                json!({ "target": "crash", "dry_run": true }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
        assert!(
            exports.join("kept.zip").is_file(),
            "exports policy guardrail did not delete"
        );
    }

    // --- t29: optional passwords + PKI audit attestation ----------------------------------
    //
    // These exercise the §4 contract over the router. Attestation is checked against
    // `entity.created`/`book.opened` mutations (not `seal`) so the suite is independent of the
    // CSC rule-pack's seal preconditions.

    /// Create a user and return its id.
    async fn make_user(state: &AppState, username: &str) -> String {
        let (status, u) = send(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": username, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = u["id"].as_str().expect("user id").to_owned();
        // RBAC (t64-E3): the API assigns a subsequent user Gestor\@Global, but these pre-t64 tests act
        // AS this user for full-authority operations (destructive ops, cross-user credential resets,
        // user administration). Promote them to Owner\@Global so those journeys authorize exactly as
        // they did before RBAC. Tests that assert a *restricted* role use `seed_user` with an explicit
        // assignment instead (e.g. the new non-Owner-403 journeys).
        {
            use crate::users::UserId;
            use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
            let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
            let mut users = state.users.write().await;
            if let Some(user) = users.get_mut(&uid) {
                user.role_assignments = vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)];
            }
        }
        id
    }

    /// Give a user a secret + attestation key, sign in with the password, and create one attested
    /// entity. Returns `(user_id, session_token, entity_event_seq)`.
    async fn attested_entity(state: &AppState, username: &str) -> (String, String, u64) {
        let id = make_user(state, username).await;
        // t51: setting one's own secret/key is a self-service op — open a session as this user so
        // the requester matches the target (a cross-user set would now be a 403).
        let self_tok = open_session(state, &id).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let (status, sess) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "Segur0-Chave7!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "Ent", "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let seq = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created present")["seq"]
            .as_u64()
            .expect("seq");
        (id, token, seq)
    }

    #[tokio::test]
    async fn create_session_requires_password_for_hashed_user() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;
        let self_tok = open_session(&state, &id).await;

        let (_, view) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(view["has_secret"], true);
        assert_eq!(view["has_attestation_key"], false);
        assert!(view.get("attestation_key_fingerprint").is_none());

        let status = send_status(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id, "password": "nope" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body["error"].is_string());
        state.signin_backoff.write().await.clear();

        // Change the password — current_password is required for a credentialed self-service user.
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Cavalo-Certo9!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);

        // Now the new password is required: wrong → 401, right → 200.
        let (status, body) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id, "password": "nope" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body["error"].is_string());
        // t41 M1: the new backoff table [1,2,4,...] kicks in after the first failure,
        // so clear the backoff before the correct attempt.
        state.signin_backoff.write().await.clear();
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "Cavalo-Certo9!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn create_session_rejects_legacy_no_hash_user_409() {
        let state = AppState::default();
        let id = make_user(&state, "legacy.user").await;
        {
            let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
            let mut users = state.users.write().await;
            let user = users.get_mut(&uid).expect("user exists");
            user.password_hash = None;
        }

        let (_, view) = send(state.clone(), get(&format!("/v1/users/{id}"))).await;
        assert_eq!(view["has_secret"], false);
        let session_count_before = state.sessions.read().await.len();
        let (status, body) = send_raw(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não configurada")
        );
        assert!(
            body.get("token").is_none(),
            "legacy no-hash rejection must not return a session token: {body}"
        );
        assert_eq!(
            state.sessions.read().await.len(),
            session_count_before,
            "legacy no-hash rejection must not insert a session"
        );
    }

    #[tokio::test]
    async fn password_and_recovery_verifiers_persist_hardened_and_secret_free() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        let password = "Senha-Forte7!X";

        let (status, first_view) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "bootstrap user");
        let first = first_view["id"].as_str().expect("first id").to_owned();
        let first_token = open_session(&state, &first).await;

        let (status, second_view) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/users",
                    json!({ "username": "bruno.dias", "password": DEFAULT_TEST_PASSWORD }),
                ),
                &first_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "second user");
        let second = second_view["id"].as_str().expect("second id").to_owned();
        let second_token = open_session(&state, &second).await;

        for (user_id, token) in [(&first, &first_token), (&second, &second_token)] {
            let (status, view) = send(
                state.clone(),
                with_session(
                    post_json(
                        &format!("/v1/users/{user_id}/secret"),
                        json!({ "password": password, "current_password": DEFAULT_TEST_PASSWORD }),
                    ),
                    token,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "password set for {user_id}");
            assert_eq!(view["has_secret"], true);
        }

        let (status, issued) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{first}/recovery"),
                    json!({ "current_password": password }),
                ),
                &first_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "recovery phrase issued");
        let recovery_phrase = issued["recovery_phrase"].as_str().expect("phrase");

        let first_user = stored_user(&state, &first).await;
        let second_user = stored_user(&state, &second).await;
        let first_hash = first_user.password_hash.as_deref().expect("first hash");
        let second_hash = second_user.password_hash.as_deref().expect("second hash");
        let recovery_hash = first_user.recovery_hash.as_deref().expect("recovery hash");

        assert!(first_hash.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(second_hash.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(recovery_hash.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert_ne!(
            first_hash, second_hash,
            "same password for two users must not produce the same verifier"
        );
        assert!(!first_hash.contains(password));
        assert!(!second_hash.contains(password));
        assert!(!recovery_hash.contains(recovery_phrase));

        let users_json =
            std::fs::read_to_string(tmp.dir.join(crate::users::USERS_FILE)).expect("users.json");
        assert!(!users_json.contains(password));
        assert!(!users_json.contains(recovery_phrase));
        assert!(users_json.contains(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(
            tmp.dir
                .join(crate::attestation::VERIFIER_SEED_FILE)
                .is_file(),
            "first hardened verifier persists the per-install seed sidecar"
        );

        state.signin_backoff.write().await.clear();
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": first, "password": "wrong-password" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        state.signin_backoff.write().await.clear();
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": first, "password": password }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn legacy_password_phc_signs_in_and_upgrades_to_hardened_verifier() {
        let state = AppState::default();
        let uid = UserId(Uuid::new_v4());
        let legacy_hash = crate::attestation::hash_secret("Migrar-Chave7!").unwrap();
        state.users.write().await.insert(
            uid,
            User {
                id: uid,
                username: "legacy.user".to_owned(),
                display_name: "Legacy User".to_owned(),
                email: None,
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                active: true,
                password_hash: Some(legacy_hash.clone()),
                attestation_key: None,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: vec![crate::roles::bootstrap_assignment(true)],
            },
        );

        let (status, _) = send_raw(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": uid.0, "password": "Migrar-Chave7!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let upgraded = state
            .users
            .read()
            .await
            .get(&uid)
            .and_then(|u| u.password_hash.clone())
            .expect("upgraded hash");
        assert_ne!(upgraded, legacy_hash);
        assert!(upgraded.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(!upgraded.contains("Migrar-Chave7!"));
    }

    #[tokio::test]
    async fn repeated_wrong_password_triggers_backoff_429() {
        let state = AppState::default();
        let id = make_user(&state, "bruno").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service secret set.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        // t41 M1: the new backoff table [1,2,4,...] means the FIRST wrong attempt sets a 1s
        // window. So the first attempt is 401, and any immediate subsequent attempt is 429.
        let (status, _) = send(
            state.clone(),
            post_json("/v1/session", json!({ "user_id": id, "password": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        {
            let uid = crate::users::UserId(Uuid::parse_str(&id).expect("uuid"));
            let mut backoff = state.signin_backoff.write().await;
            let entry = backoff
                .get_mut(&uid)
                .expect("wrong password records sign-in backoff");
            entry.next_allowed_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
        }
        // Within the backoff window even the correct password is refused with 429.
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "Segur0-Chave7!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("tente novamente")
        );
    }

    #[tokio::test]
    async fn attestation_key_requires_a_secret_and_verifies_the_current_one() {
        let state = AppState::default();
        let id = make_user(&state, "carla").await;
        {
            let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
            let mut users = state.users.write().await;
            users.get_mut(&uid).expect("user exists").password_hash = None;
        }
        let self_tok = seed_session(&state, &id).await; // t51: self-service key/secret ops.
        // No secret → 409 (self-service precondition; requester == target).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/users/{id}/attestation-key"), json!({})),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Wrong current password → 401 (self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "nope" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct → 200 with a 32-hex fingerprint.
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_attestation_key"], true);
        assert_eq!(
            view["attestation_key_fingerprint"]
                .as_str()
                .expect("fingerprint")
                .len(),
            32
        );
    }

    #[tokio::test]
    async fn attested_mutation_verifies_and_names_the_user() {
        let state = AppState::default();
        let (_id, _token, seq) = attested_entity(&state, "diana").await;

        // The ledger event carries the attestation summary.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert_eq!(created["attestation"]["username"], "diana");
        assert_eq!(created["attestation"]["algorithm"], "ES256");
        assert_eq!(
            created["attestation"]["fingerprint"]
                .as_str()
                .expect("fingerprint")
                .len(),
            32
        );

        // Server-side verify: valid, correct user, no reason.
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], true);
        assert_eq!(v["attestation"]["username"], "diana");
        assert_eq!(v["attestation"]["event_seq"], seq);
        assert!(v.get("reason").is_none_or(Value::is_null));
    }

    #[tokio::test]
    async fn tampered_attestation_is_reported_invalid() {
        let state = AppState::default();
        let (_id, _token, seq) = attested_entity(&state, "elsa").await;
        // Simulate a rebuilt/tampered chain: overwrite the stored event_hash so the signature no
        // longer matches what is recorded.
        {
            let mut atts = state.attestations.write().await;
            let att = atts.get_mut(&seq).expect("attestation present");
            att.event_hash = "00".repeat(32);
        }
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], false);
        assert!(v["reason"].is_string());
    }

    #[tokio::test]
    async fn removing_the_key_makes_prior_attestations_unverifiable() {
        let state = AppState::default();
        let (id, token, seq) = attested_entity(&state, "iris").await;
        // Valid while the key exists.
        let (_, v) = send(
            state.clone(),
            get(&format!("/v1/ledger/attestations/{seq}")),
        )
        .await;
        assert_eq!(v["valid"], true);
        // Remove the attestation key (self-service: iris's own session).
        let (status, view) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_attestation_key"], false);
        // The attestation is still stored, but its key is gone → invalid with a key-not-found reason.
        let (status, v) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["valid"], false);
        assert!(v["reason"].as_str().expect("reason").contains("key"));
    }

    #[tokio::test]
    async fn mutation_without_attestation_key_has_no_attestation() {
        let state = AppState::default();
        let id = make_user(&state, "eva").await;
        let (_, sess) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "E", "nipc": "503004642", "seat": "L", "kind": "Cooperativa" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert!(created["attestation"].is_null());
        let seq = created["seq"].as_u64().expect("seq");
        // No attestation to fetch → 404.
        let (status, _) = send(state, get(&format!("/v1/ledger/attestations/{seq}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn removing_the_secret_is_rejected_and_preserves_the_attestation_key() {
        let state = AppState::default();
        let id = make_user(&state, "fabio").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Wrong current password on removal → 401 (self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/secret"),
                    json!({ "current_password": "nope" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // Correct proof still cannot remove the password; replacing it via POST is supported.
        let before = stored_user(&state, &id).await;
        let (status, body) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{id}/secret"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("defina uma nova palavra-passe"),
            "clear replacement guidance: {body}"
        );
        let after = stored_user(&state, &id).await;
        assert_eq!(after.password_hash, before.password_hash);
        assert_eq!(after.attestation_key, before.attestation_key);
    }

    #[tokio::test]
    async fn changing_the_secret_rewraps_the_key() {
        let state = AppState::default();
        let id = make_user(&state, "gita").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Velho-Codigo3!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Velho-Codigo3!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        // Change the secret (current one required, self-service).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "Novo-Codigo8!", "current_password": "Velho-Codigo3!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Old password no longer signs in; the new one does and still unlocks the re-wrapped key.
        let (status, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "Velho-Codigo3!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // t41 M1: clear backoff so the correct attempt isn't blocked by the 1s window.
        state.signin_backoff.write().await.clear();
        let (status, sess) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": id, "password": "Novo-Codigo8!" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = sess["token"].as_str().expect("token").to_owned();
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "E", "nipc": "503004642", "seat": "L", "kind": "Cooperativa" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, events) = send(state, get("/v1/ledger/events")).await;
        let created = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "entity.created")
            .expect("entity.created");
        assert_eq!(created["attestation"]["username"], "gita");
    }

    #[tokio::test]
    async fn onboarding_flag_round_trips() {
        let state = AppState::default();
        let (_, body) = send(state.clone(), get("/v1/settings")).await;
        assert_eq!(body["onboarding"]["completed"], false);
        assert_eq!(body["onboarding"]["completed_at"], Value::Null);

        let mut doc = sample_settings();
        doc["onboarding"] = json!({ "completed": true, "completed_at": "2026-07-07T10:00:00Z" });
        let (status, stored) = send(state.clone(), put_json("/v1/settings", doc)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored["onboarding"]["completed"], true);

        let (_, got) = send(state, get("/v1/settings")).await;
        assert_eq!(got["onboarding"]["completed"], true);
        assert_eq!(got["onboarding"]["completed_at"], "2026-07-07T10:00:00Z");
    }

    #[tokio::test]
    async fn short_secret_is_422_and_users_wire_hides_material() {
        let state = AppState::default();
        let id = make_user(&state, "hugo").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        // Below the 8-char floor → 422 (validation precedes authorization).
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "short" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());

        // Set a valid secret + key, then confirm the wire dump carries no secret material.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let (_, list) = send(state, get("/v1/users")).await;
        let dump = list.to_string().to_lowercase();
        assert!(!dump.contains("password"), "no password token: {dump}");
        assert!(!dump.contains("$argon2"), "no PHC hash: {dump}");
        assert!(!dump.contains("ciphertext"), "no wrapped key: {dump}");
        assert!(!dump.contains("kdf_salt"), "no KDF material: {dump}");
    }

    // --- t68: password strength policy (mandatory + strength on set_secret; policy endpoint) ------

    #[tokio::test]
    async fn password_policy_endpoint_is_unauthenticated_and_reports_the_ruleset() {
        let state = AppState::default();
        // No session header: the onboarding checklist reads this before any user/session exists.
        let (status, body) = send(state, get("/v1/session/password-policy")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["min_length"], 10);
        assert_eq!(body["require_lowercase"], true);
        assert_eq!(body["require_uppercase"], true);
        assert_eq!(body["require_digit"], true);
        assert_eq!(body["require_special"], true);
        assert_eq!(body["forbid_username"], true);
        assert_eq!(body["forbid_common"], true);
        // Default enforces strong passwords (the settings toggle is deferred to t68-web).
        assert_eq!(body["allow_weak_passwords"], false);
        assert!(
            body["rules"].as_array().expect("rules").len() >= 8,
            "a checklist row per strength rule: {body}"
        );
    }

    #[tokio::test]
    async fn set_secret_rejects_a_weak_password_with_structured_failures() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;
        let tok = open_session(&state, &id).await; // self-service credential op.
        // Lowercase-only, below the strong-length floor, no upper/digit/special.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "abcdefgh" }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body["error"].is_string());
        let codes: Vec<&str> = body["failed_rules"]
            .as_array()
            .expect("failed_rules array")
            .iter()
            .map(|f| f["code"].as_str().expect("code"))
            .collect();
        for expected in ["length", "uppercase", "digit", "special"] {
            assert!(
                codes.contains(&expected),
                "expected {expected} in {codes:?}"
            );
        }
        // The account is untouched — no weak secret was set.
        let (_, view) = send(state, get(&format!("/v1/users/{id}"))).await;
        assert_eq!(view["has_secret"], true);
    }

    #[tokio::test]
    async fn set_secret_rejects_an_empty_password() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;
        let tok = open_session(&state, &id).await;
        let (status, _) = send(
            state,
            with_session(
                post_json(&format!("/v1/users/{id}/secret"), json!({ "password": "" })),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn set_secret_rejects_a_password_containing_the_username() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;
        let tok = open_session(&state, &id).await;
        // Otherwise strong, but embeds the username (case-insensitive) → the not_username rule fails.
        let (status, body) = send(
            state,
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({ "password": "Amelia.Marques-9!" }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let codes: Vec<&str> = body["failed_rules"]
            .as_array()
            .expect("failed_rules array")
            .iter()
            .map(|f| f["code"].as_str().expect("code"))
            .collect();
        assert!(codes.contains(&"not_username"), "codes: {codes:?}");
    }

    #[tokio::test]
    async fn set_secret_accepts_a_compliant_password() {
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await;
        let tok = open_session(&state, &id).await;
        let (status, view) = send(
            state,
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);
    }

    #[tokio::test]
    async fn bootstrap_user_can_be_issued_the_mandatory_recovery_phrase() {
        // t68 item 3: the audit/recovery key (recovery phrase) is the recovery credential the
        // onboarding flow issues. The API mechanism is `POST /v1/users/{id}/recovery`, which returns
        // the plaintext EXACTLY ONCE and thereafter exposes only `has_recovery_phrase`. Making it a
        // non-skippable onboarding STEP is enforced client-side (t68-web); folding the once-shown
        // phrase into create_user's response would drift contracts/user.json (a response fixture).
        let state = AppState::default();
        let id = make_user(&state, "amelia.marques").await; // first (bootstrap) user
        let tok = open_session(&state, &id).await;
        // t68 item 3: issuing the recovery phrase is a self-service secret op, so it now re-proves the
        // current password (step-up) exactly like setting the secret. The bootstrap user set this
        // password during onboarding, so this is a re-auth, not a lockout — onboarding already holds it.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/recovery"),
                    json!({ "current_password": DEFAULT_TEST_PASSWORD }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["recovery_phrase"].as_str().expect("phrase").len() >= 32,
            "the phrase is returned once, in full: {body}"
        );
        assert_eq!(body["has_recovery_phrase"], true);
        // Only the verifier persists — a re-read exposes the boolean, never the plaintext.
        let (_, view) = send(state, get(&format!("/v1/users/{id}"))).await;
        assert_eq!(view["has_recovery_phrase"], true);
    }

    #[tokio::test]
    async fn cross_user_no_proof_is_403_before_strength_is_checked() {
        // Anti-enumeration: an unauthorized cross-user caller gets the uniform 403 FIRST, so the
        // policy can never become an oracle for "this target exists". Strength is validated only once
        // the caller is authorized (a self-service or a proof-backed cross-user reset).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (status, _) = send(
            state,
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    // Weak, but ≥ the 8-char floor so it clears validate_secret and reaches authz.
                    json!({ "password": "weakpassword" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // --- t45: signed-out sign-in roster (GET /v1/session/roster) --------------------------

    #[tokio::test]
    async fn session_roster_is_unauthenticated_and_signals_onboarding() {
        let state = fresh_state().await;

        // No users yet → onboarding required, empty roster, and NO session on the request.
        let (status, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(roster["onboarding_required"], true);
        assert_eq!(roster["users"].as_array().expect("users").len(), 0);

        // Bootstrap amelia (no session), sign in, create bruno with that session — no auto-seeded
        // "test.actor" pollutes the roster this way.
        let (status, amelia) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = amelia["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/users",
                    json!({ "username": "bruno", "password": DEFAULT_TEST_PASSWORD }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        {
            let mut users = state.users.write().await;
            let bruno = users
                .values_mut()
                .find(|u| u.username == "bruno")
                .expect("bruno created");
            bruno.password_hash = None;
        }

        // Still signed out on this call → onboarding no longer required, both users listed.
        let (status, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(roster["onboarding_required"], false);
        let users = roster["users"].as_array().expect("users");
        assert_eq!(users.len(), 2);

        let amelia = users
            .iter()
            .find(|u| u["username"] == "amelia.marques")
            .expect("amelia in roster");
        assert_eq!(amelia["has_secret"], true);
        assert_eq!(amelia["display_name"], "amelia.marques");
        assert!(amelia["id"].is_string());
        // NOTHING sensitive leaks to an anonymous caller: no fingerprint, no created_at, no
        // has_attestation_key, no hash or wrapped-key material, not even `active`.
        for forbidden in [
            "attestation_key_fingerprint",
            "has_attestation_key",
            "created_at",
            "active",
            "password_hash",
            "attestation_key",
        ] {
            assert!(
                amelia.get(forbidden).is_none(),
                "roster user must not carry {forbidden}: {amelia}"
            );
        }
        // A legacy no-hash user reads has_secret:false, but POST /v1/session still rejects it.
        let bruno = users
            .iter()
            .find(|u| u["username"] == "bruno")
            .expect("bruno in roster");
        assert_eq!(bruno["has_secret"], false);
    }

    #[tokio::test]
    async fn session_roster_omits_inactive_users() {
        let state = fresh_state().await;
        let (status, u) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = u["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;
        let (status, bruno) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/users",
                    json!({ "username": "bruno", "password": DEFAULT_TEST_PASSWORD }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let bruno_id = bruno["id"].as_str().expect("id").to_owned();

        // Deactivate bruno (amelia stays active, so the last-active guard allows it).
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{bruno_id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (_, roster) = send_raw(state.clone(), get("/v1/session/roster")).await;
        let users = roster["users"].as_array().expect("users");
        assert_eq!(
            users.len(),
            1,
            "inactive bruno is not sign-in-able: {roster}"
        );
        assert_eq!(users[0]["username"], "amelia.marques");
    }

    // --- t45: last-active-user deactivation guard -----------------------------------------

    #[tokio::test]
    async fn patch_user_refuses_deactivating_the_last_active_user() {
        let state = fresh_state().await;
        let (status, u) = send_raw(
            state.clone(),
            post_json(
                "/v1/users",
                json!({ "username": "amelia.marques", "password": DEFAULT_TEST_PASSWORD }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = u["id"].as_str().expect("id").to_owned();
        let token = open_session(&state, &id).await;

        // She is the only active user → deactivating her is a 409 with the PT message.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("último utilizador ativo"),
            "PT last-active message: {body}"
        );

        // Add a second active user; now deactivating one of the two is allowed.
        let (status, u2) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/users",
                    json!({ "username": "bruno", "password": DEFAULT_TEST_PASSWORD }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id2 = u2["id"].as_str().expect("id").to_owned();
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id2}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // With only amelia active again, she is once more the last active → 409.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{id}"), json!({ "active": false })),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // --- t45: patch_user ledger payload carries no secret material ------------------------

    #[tokio::test]
    async fn patch_user_ledger_payload_carries_no_secret_material() {
        use crate::users::{UserId, UserView};
        let state = AppState::default();
        let id = make_user(&state, "hugo").await;
        let self_tok = open_session(&state, &id).await; // t51: self-service credential ops.
        // Give hugo a secret + attestation key so the full `User` carries the argon2 PHC and the
        // AEAD-wrapped key — exactly the material that must never reach the ledger payload.
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/secret"),
                    json!({
                        "password": "Segur0-Chave7!",
                        "current_password": DEFAULT_TEST_PASSWORD,
                    }),
                ),
                &self_tok,
            ),
        )
        .await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{id}/attestation-key"),
                    json!({ "current_password": "Segur0-Chave7!" }),
                ),
                &self_tok,
            ),
        )
        .await;

        // Rename him — this patch is the final mutation, so its `user.updated` event is the tail.
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/users/{id}"),
                json!({ "display_name": "Hugo P." }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The stored `User` (unchanged since the patch) reproduces exactly what was digested.
        let uid = UserId(Uuid::parse_str(&id).expect("uuid"));
        let user = state
            .users
            .read()
            .await
            .get(&uid)
            .cloned()
            .expect("hugo present");
        assert!(
            user.password_hash.is_some() && user.attestation_key.is_some(),
            "hugo holds secret material for the test to be meaningful"
        );
        let view_digest = crate::hex::hex(&chancela_ledger::digest(
            &serde_json::to_vec(&UserView::from(&user)).expect("view serializes"),
        ));
        let full_digest = crate::hex::hex(&chancela_ledger::digest(
            &serde_json::to_vec(&user).expect("user serializes"),
        ));
        assert_ne!(
            view_digest, full_digest,
            "UserView and full User digest differently — the guard below is meaningful"
        );

        // The patch's `user.updated` payload digest must be the UserView digest, never the full User.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let patch_ev = events
            .as_array()
            .expect("events")
            .iter()
            .rev()
            .find(|e| e["kind"] == "user.updated" && e["justification"] == "user updated")
            .expect("patch user.updated event present");
        assert_eq!(
            patch_ev["payload_digest"], view_digest,
            "patch payload is the UserView (no hash/key material)"
        );
        assert_ne!(
            patch_ev["payload_digest"], full_digest,
            "patch payload is NOT the full User"
        );
    }

    // --- t51: cross-user credential authorization + recovery-phrase credential ---------------
    //
    // Matrix (§4): self vs cross × {no secret, password-only, recovery, both} × {no proof, wrong
    // pw, right pw, valid recovery, invalid recovery}. Cross-user no-valid-proof cases collapse to
    // an indistinguishable 403 with constant-work argon2 (no user enumeration). Examples use
    // "amelia.marques" (target) and "bruno" (the other operator); never real names.

    /// Seed a self-service session for an existing user directly into state (works regardless of
    /// whether the user has a password — unlike `open_session`, which exercises password sign-in).
    async fn seed_session(state: &AppState, user_id: &str) -> String {
        let uid = UserId(Uuid::parse_str(user_id).expect("uuid"));
        let token = Uuid::new_v4().to_string();
        let now = time::OffsetDateTime::now_utc();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id: uid,
                unlocked_key: None,
                expires_at: now + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    // --- t64-E3: fail-closed RBAC enforcement (non-Owner 403; scoped role in/out of scope) --------

    #[tokio::test]
    async fn rbac_non_owner_leitor_reads_but_cannot_write() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};
        let state = fresh_state().await;
        // An Owner (auto-seeded session) creates one entity.
        let (status, _e) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Encosto Estratégico Lda",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // A Leitor\@Global (read-only role).
        let leitor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &leitor.to_string()).await;

        // READ → 200, and the row is visible (Leitor holds entity.read\@Global).
        let (status, list) = send_raw(state.clone(), with_session(get("/v1/entities"), &tok)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("list").len(), 1);

        // WRITE → 403 with the generic, non-enumerating message (no "valor probatório").
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Outra Sociedade Lda",
                        "nipc": "503004642",
                        "seat": "Porto",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "honest permission refusal: {body}"
        );

        // An admin-plane write is likewise refused for a Leitor.
        let (status, _) = send_raw(
            state.clone(),
            with_session(get("/v1/users"), &tok), // user.read — Leitor lacks it
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rbac_scoped_gestor_acts_within_scope_but_not_outside() {
        use chancela_authz::{EntityId as AuthzEntityId, GESTOR_ROLE_ID, RoleAssignment, Scope};
        let state = fresh_state().await;
        let mk = |name: &str| {
            json!({
                "name": name, "nipc": "503004642", "seat": "Lisboa", "kind": "SociedadeAnonima",
            })
        };
        // Owner creates two entities.
        let (_, e1) = send(
            state.clone(),
            post_json("/v1/entities", mk("Encosto Estratégico Lda")),
        )
        .await;
        let (_, e2) = send(
            state.clone(),
            post_json("/v1/entities", mk("Outra Sociedade Lda")),
        )
        .await;
        let e1_id = e1["id"].as_str().expect("e1 id").to_owned();
        let e2_id = e2["id"].as_str().expect("e2 id").to_owned();

        // A Gestor scoped to entity 1 ONLY.
        let e1_uuid = Uuid::parse_str(&e1_id).expect("uuid");
        let gestor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(
                GESTOR_ROLE_ID,
                Scope::Entity(AuthzEntityId(e1_uuid)),
            )],
        )
        .await;
        let tok = seed_session(&state, &gestor.to_string()).await;

        let open = |eid: &str| {
            post_json(
                "/v1/books",
                json!({
                    "entity_id": eid,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro de atas",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"],
                }),
            )
        };
        // WITHIN scope (entity 1) → 201.
        let (status, _) = send_raw(state.clone(), with_session(open(&e1_id), &tok)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "opening a book within the granted entity"
        );
        // OUTSIDE scope (entity 2) → 403 (a scoped grant never reaches another entity).
        let (status, _) = send_raw(state.clone(), with_session(open(&e2_id), &tok)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "opening a book outside the granted entity is refused"
        );
        // Scope-escape upward is structurally impossible: the Gestor holds ledger.read, but only at
        // Entity(1) — a **Global** integrity read is NOT satisfied by an entity-scoped grant → 403.
        let (status, _) = send_raw(
            state.clone(),
            with_session(get("/v1/ledger/integrity"), &tok),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an entity-scoped grant can never satisfy a Global-scoped check"
        );
    }

    // --- t64-E4: RBAC-management endpoints (role CRUD + assignment + scoped delegation) ------------

    #[tokio::test]
    async fn e4_owner_role_crud_roundtrip() {
        let state = fresh_state().await;
        // Owner (auto-seeded session) creates a custom role.
        let (status, role) = send(
            state.clone(),
            post_json(
                "/v1/roles",
                json!({ "name": "Auditor", "permissions": ["ledger.read", "entity.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(role["protected"], json!(false));
        let id = role["id"].as_str().expect("id").to_owned();
        assert!(
            role["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p == "ledger.read")
        );

        // The catalog now lists the seeded defaults + the new one.
        let (status, list) = send(state.clone(), get("/v1/roles")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            list.as_array().expect("roles").len(),
            chancela_authz::default_roles().len() + 1
        );

        // The frozen verb catalog is introspectable by any session. wp23 (e4) added the 39th verb
        // `template.manage`, so the catalog now enumerates 39.
        let (status, cat) = send(state.clone(), get("/v1/permissions")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cat["permissions"].as_array().expect("verbs").len(), 39);

        // Rename + narrow the permission-set.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/roles/{id}"),
                json!({ "name": "Auditor Sénior", "permissions": ["ledger.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(patched["name"], json!("Auditor Sénior"));
        assert_eq!(patched["permissions"].as_array().expect("perms").len(), 1);

        // Delete it; the catalog returns to the seeded defaults.
        let (status, _) = send(state.clone(), delete(&format!("/v1/roles/{id}"))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, list) = send(state.clone(), get("/v1/roles")).await;
        assert_eq!(
            list.as_array().expect("roles").len(),
            chancela_authz::default_roles().len()
        );
    }

    #[tokio::test]
    async fn e4_protected_owner_cannot_be_edited_or_deleted() {
        let state = fresh_state().await;
        let owner_role = chancela_authz::OWNER_ROLE_ID.0.to_string();
        // Even an Owner cannot narrow/rename the locked super-role...
        let (status, _) = send(
            state.clone(),
            patch_json(
                &format!("/v1/roles/{owner_role}"),
                json!({ "name": "Proprietário Fraco", "permissions": ["entity.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...nor delete it.
        let (status, _) = send(state.clone(), delete(&format!("/v1/roles/{owner_role}"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn seeded_role_drift_reconciliation_is_explicit_idempotent_and_audited() {
        use chancela_authz::{Permission, Role, TENANT_ADMIN_ROLE_ID};

        let state = fresh_state().await;
        {
            let mut tenant_admin = Role::tenant_administrator();
            assert!(
                tenant_admin
                    .permission_set
                    .remove(&Permission::EntityUpdate)
            );
            tenant_admin.permission_set.insert(Permission::DataExport);
            state.roles.write().await.insert(tenant_admin);
        }

        let role_id = TENANT_ADMIN_ROLE_ID.0.to_string();
        let uri = format!("/v1/roles/{role_id}/seeded-drift-reconciliation");

        let (status, proposal) = send(state.clone(), get(&uri)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proposal["applied"], json!(false));
        assert_eq!(
            proposal["missing_default_permissions"],
            json!(["entity.update"])
        );
        assert!(
            proposal["current_permissions"]
                .as_array()
                .expect("current")
                .iter()
                .any(|p| p == "data.export"),
            "custom extra permission is preserved in the proposal"
        );

        let (status, applied) = send(state.clone(), post_json(&uri, json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(applied["applied"], json!(true));
        assert_eq!(applied["applied_permissions"], json!(["entity.update"]));
        assert_eq!(applied["missing_default_permissions"], json!([]));
        let stored = state
            .roles
            .read()
            .await
            .get(TENANT_ADMIN_ROLE_ID)
            .cloned()
            .expect("tenant admin");
        assert!(stored.permission_set.contains(&Permission::EntityUpdate));
        assert!(
            stored.permission_set.contains(&Permission::DataExport),
            "reconciliation must not remove customized extra permissions"
        );

        let (status, second) = send(state.clone(), post_json(&uri, json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["applied"], json!(false));
        assert_eq!(second["applied_permissions"], json!([]));

        let (_, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        let reconcile_events: Vec<_> = events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "role.seeded_drift_reconciled")
            .collect();
        assert_eq!(
            reconcile_events.len(),
            1,
            "only the explicit state-changing apply is audited"
        );
        let event = reconcile_events[0];
        // wp19-fix: role.* audit events are scoped `role:{uuid}` (a keyword application-chain
        // scope), never a bare UUID (which the ledger would misread as a `company:` chain whose
        // genesis must be `entity.created`, breaking verify() after the mutation).
        assert_eq!(event["scope"], json!(format!("role:{role_id}")));
        assert_eq!(
            event["justification"],
            json!("admin explicitly applied seeded role drift reconciliation")
        );
        #[derive(serde::Serialize)]
        struct ExpectedReconciliationPayload {
            role_id: String,
            role_name: String,
            before_permissions: Vec<String>,
            added_permissions: Vec<String>,
            after_permissions: Vec<String>,
        }
        let expected_payload = ExpectedReconciliationPayload {
            role_id,
            role_name: "Tenant Administrator".to_owned(),
            before_permissions: proposal["current_permissions"]
                .as_array()
                .expect("before permissions")
                .iter()
                .map(|p| p.as_str().expect("permission").to_owned())
                .collect(),
            added_permissions: vec!["entity.update".to_owned()],
            after_permissions: applied["current_permissions"]
                .as_array()
                .expect("after permissions")
                .iter()
                .map(|p| p.as_str().expect("permission").to_owned())
                .collect(),
        };
        assert_eq!(
            event["payload_digest"],
            audit_payload_digest(&expected_payload),
            "audit digest commits to the explicit seeded-role reconciliation evidence"
        );
    }

    #[tokio::test]
    async fn seeded_role_drift_reconciliation_requires_role_manage_and_subset() {
        use chancela_authz::{
            Permission, Role, RoleAssignment, RoleId, Scope, TENANT_ADMIN_ROLE_ID,
        };

        let state = fresh_state().await;
        {
            let mut tenant_admin = Role::tenant_administrator();
            assert!(
                tenant_admin
                    .permission_set
                    .remove(&Permission::EntityUpdate)
            );
            state.roles.write().await.insert(tenant_admin);
        }
        let target = TENANT_ADMIN_ROLE_ID.0.to_string();
        let uri = format!("/v1/roles/{target}/seeded-drift-reconciliation");

        let reader = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(
                chancela_authz::LEITOR_ROLE_ID,
                Scope::Global,
            )],
        )
        .await;
        let reader_tok = seed_session(&state, &reader.to_string()).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(post_json(&uri, json!({})), &reader_tok),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let manager_role = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: manager_role,
            name: "Gestor de Acessos Limitado".to_owned(),
            permission_set: [Permission::RoleManage, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        let limited = seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(manager_role, Scope::Global)],
        )
        .await;
        let limited_tok = seed_session(&state, &limited.to_string()).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(post_json(&uri, json!({})), &limited_tok),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "role.manage does not bypass the subset invariant"
        );

        let stored = state
            .roles
            .read()
            .await
            .get(TENANT_ADMIN_ROLE_ID)
            .cloned()
            .expect("tenant admin");
        assert!(!stored.permission_set.contains(&Permission::EntityUpdate));
    }

    #[tokio::test]
    async fn seeded_role_drift_reconciliation_excludes_owner_and_custom_roles() {
        let state = fresh_state().await;
        let owner_role = chancela_authz::OWNER_ROLE_ID.0.to_string();
        let (status, _) = send(
            state.clone(),
            post_json(
                &format!("/v1/roles/{owner_role}/seeded-drift-reconciliation"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            state
                .roles
                .read()
                .await
                .get(chancela_authz::OWNER_ROLE_ID)
                .expect("owner"),
            &chancela_authz::Role::owner()
        );

        let (status, custom) = send(
            state.clone(),
            post_json(
                "/v1/roles",
                json!({ "name": "Custom", "permissions": ["entity.read"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let custom_id = custom["id"].as_str().expect("custom id");
        let (status, _) = send(
            state,
            post_json(
                &format!("/v1/roles/{custom_id}/seeded-drift-reconciliation"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn e4_subset_invariant_role_manage_does_not_exempt() {
        use chancela_authz::{Permission, Role, RoleAssignment, RoleId, Scope};
        let state = fresh_state().await;
        // A role that grants role.manage but only entity.read otherwise.
        let mgr = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: mgr,
            name: "Gestor de Acessos".to_owned(),
            permission_set: [Permission::RoleManage, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        let m = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(mgr, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &m.to_string()).await;

        // A role fully within the actor's own authority → 201.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/roles",
                    json!({ "name": "Só Leitura", "permissions": ["entity.read"] }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Crafting a role containing a permission the actor LACKS is refused — holding role.manage
        // does NOT exempt the subset check.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/roles",
                    json!({ "name": "Perigoso", "permissions": ["data.wipe"] }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body["error"].as_str().expect("err").contains("permissão"));
    }

    #[tokio::test]
    async fn e4_assign_subset_enforced_and_last_owner_guard() {
        use chancela_authz::{
            GESTOR_ROLE_ID, OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleId, Scope,
        };
        let state = fresh_state().await;

        // An actor holding role.assign but only entity.read otherwise.
        let ra = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: ra,
            name: "Atribuidor".to_owned(),
            permission_set: [Permission::RoleAssign, Permission::EntityRead]
                .into_iter()
                .collect(),
            protected: false,
        });
        // A role wholly within that actor's authority.
        let ro = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: ro,
            name: "Só Entidade".to_owned(),
            permission_set: [Permission::EntityRead].into_iter().collect(),
            protected: false,
        });
        let assigner = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(ra, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &assigner.to_string()).await;
        let target = seed_user(&state, "bruno.dias", vec![]).await;

        // Assigning the in-authority role → 200.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/roles"),
                    json!({ "role_id": ro.0.to_string(), "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Assigning the fat Gestor role (perms the assigner lacks) → 403 — role.assign does not exempt.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/roles"),
                    json!({ "role_id": GESTOR_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Last-Owner guard: two Owners, remove one (ok), then the last (409).
        let owner_a = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok_a = seed_session(&state, &owner_a.to_string()).await;
        let owner_b = seed_user(
            &state,
            "owner.b",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let owner_body =
            json!({ "role_id": OWNER_ROLE_ID.0.to_string(), "scope": { "kind": "global" } });
        // 2 → 1 Owner@Global: allowed.
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{owner_b}/roles"),
                    owner_body.clone(),
                ),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Removing the FINAL Owner@Global (its own) → 409, never lockable-out.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/users/{owner_a}/roles"), owner_body),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("err")
                .contains("Proprietário")
        );
    }

    /// t64-E8 regression: deactivating the last **active** Owner\@Global is refused (409), even when
    /// other active non-Owner users keep the last-active-user guard satisfied — otherwise the
    /// instance would reach a no-super-user lockout (inactive Owners confer no authority and cannot
    /// sign in to recover). Guards both `PATCH /v1/users/{id}` deactivation and the active-holder
    /// count used by the unassign guard.
    #[tokio::test]
    async fn e8_deactivating_the_last_active_owner_is_refused() {
        use chancela_authz::{LEITOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, Scope};
        let state = fresh_state().await;

        let owner_a = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let owner_b = seed_user(
            &state,
            "bruno.dias",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        // A non-Owner active user keeps the last-ACTIVE-user guard from masking the Owner guard.
        let _reader = seed_user(
            &state,
            "carla.nunes",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok_a = seed_session(&state, &owner_a.to_string()).await;

        // Two active Owners ⇒ deactivating one is allowed (one active Owner remains).
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{owner_b}"), json!({ "active": false })),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Now Amélia is the sole ACTIVE Owner; deactivating her (self) → 409, no lockout.
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/users/{owner_a}"), json!({ "active": false })),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("err")
                .contains("Proprietário")
        );

        // And unassigning her Owner@Global assignment is likewise refused (inactive Owner B must
        // not satisfy the guard).
        let owner_body =
            json!({ "role_id": OWNER_ROLE_ID.0.to_string(), "scope": { "kind": "global" } });
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/users/{owner_a}/roles"), owner_body),
                &tok_a,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn e4_delegation_grant_revoke_meta_and_redelegation_blocked() {
        use crate::delegations::{DelegationId, StoredDelegation};
        use chancela_authz::{
            Delegation, OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleId, Scope,
            UserId as AuthzUserId,
        };
        use time::format_description::well_known::Rfc3339;
        let state = fresh_state().await;

        let owner = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &owner.to_string()).await;
        let grantee = seed_user(&state, "amelia.marques", vec![]).await;
        let g_tok = seed_session(&state, &grantee.to_string()).await;

        // Grant a non-meta permission the Owner holds via a role → 201.
        let (status, view) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({
                        "to": grantee.to_string(),
                        "permission": "act.advance",
                        "scope": { "kind": "global" },
                        "legal_basis": "operator-recorded board minute R-64"
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(view["permission"], json!("act.advance"));
        assert_eq!(view["revoked"], json!(false));
        let del_id = view["id"].as_str().expect("id").to_owned();

        // The grantee now holds act.advance, sourced from the delegation.
        let (_, perms) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            perms["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.advance" && p["source"] == "delegation")
        );

        // A META permission is non-delegable → 403 (even for an Owner).
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({
                        "to": grantee.to_string(),
                        "permission": "role.manage",
                        "scope": { "kind": "global" },
                        "legal_basis": "operator-recorded board minute R-64"
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Re-delegation is impossible: an actor holding delegation.grant via a role but act.advance
        // only via a received delegation cannot pass it on.
        let dg = RoleId(Uuid::new_v4());
        state.roles.write().await.insert(Role {
            id: dg,
            name: "Delegador".to_owned(),
            permission_set: [Permission::DelegationGrant].into_iter().collect(),
            protected: false,
        });
        let carlos = seed_user(
            &state,
            "carlos.nunes",
            vec![RoleAssignment::new(dg, Scope::Global)],
        )
        .await;
        let granted_at = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("fmt");
        let recv = Delegation::new(
            AuthzUserId(owner.0),
            AuthzUserId(carlos.0),
            Permission::ActAdvance,
            Scope::Global,
        );
        let stored = StoredDelegation::new(DelegationId(Uuid::new_v4()), granted_at, recv);
        state.delegations.write().await.insert(stored.id, stored);
        let c_tok = seed_session(&state, &carlos.to_string()).await;
        let dora = seed_user(&state, "dora.silva", vec![]).await;
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({
                        "to": dora.to_string(),
                        "permission": "act.advance",
                        "scope": { "kind": "global" },
                        "legal_basis": "operator-recorded board minute R-65"
                    }),
                ),
                &c_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // An already-expired delegation is granted but contributes nothing (expiry honoured).
        let past = (time::OffsetDateTime::now_utc() - time::Duration::hours(1))
            .format(&Rfc3339)
            .expect("fmt");
        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({
                        "to": grantee.to_string(),
                        "permission": "act.read",
                        "scope": { "kind": "global" },
                        "expires_at": past,
                        "legal_basis": "operator-recorded expiry test evidence"
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, perms_exp) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            !perms_exp["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.read")
        );

        // Revoke is immediate: the grantee loses act.advance the moment it is revoked.
        let (status, rv) = send_raw(
            state.clone(),
            with_session(delete(&format!("/v1/delegations/{del_id}")), &tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rv["revoked"], json!(true));
        let (_, perms2) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            !perms2["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.advance")
        );
    }

    #[tokio::test]
    async fn e4_delegation_requires_bounded_legal_basis_for_new_grants() {
        use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};

        let state = fresh_state().await;
        let owner = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &owner.to_string()).await;
        let grantee = seed_user(&state, "amelia.marques", vec![]).await;

        let valid_base = || {
            json!({
                "to": grantee.to_string(),
                "permission": "act.read",
                "scope": { "kind": "global" }
            })
        };

        let (status, missing) = send_raw(
            state.clone(),
            with_session(post_json("/v1/delegations", valid_base()), &tok),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            missing["error"]
                .as_str()
                .expect("error")
                .contains("legal_basis")
        );

        let mut blank = valid_base();
        blank["legal_basis"] = json!(" \t\n ");
        let (status, blank_body) = send_raw(
            state.clone(),
            with_session(post_json("/v1/delegations", blank), &tok),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            blank_body["error"]
                .as_str()
                .expect("error")
                .contains("must not be empty")
        );

        let mut overlong = valid_base();
        overlong["legal_basis"] =
            json!("x".repeat(crate::delegations::MAX_DELEGATION_LEGAL_BASIS_CHARS + 1));
        let (status, overlong_body) = send_raw(
            state.clone(),
            with_session(post_json("/v1/delegations", overlong), &tok),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            overlong_body["error"]
                .as_str()
                .expect("error")
                .contains("at most")
        );

        assert!(
            state.delegations.read().await.is_empty(),
            "rejected grants must not create delegation records"
        );
    }

    #[tokio::test]
    async fn e4_delegation_start_and_legal_basis_roundtrip() {
        use chancela_authz::{
            NoBooks, OWNER_ROLE_ID, Permission, RoleAssignment, Scope, has_permission,
        };
        use time::format_description::well_known::Rfc3339;

        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        let owner = seed_user(
            &state,
            "owner.a",
            vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &owner.to_string()).await;
        let grantee = seed_user(&state, "amelia.marques", vec![]).await;
        let g_tok = seed_session(&state, &grantee.to_string()).await;

        let starts_at_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let starts_at = starts_at_time.format(&Rfc3339).expect("fmt");
        let legal_basis = "board resolution ROL-11";

        let (status, view) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    "/v1/delegations",
                    json!({
                        "to": grantee.to_string(),
                        "permission": "act.read",
                        "scope": { "kind": "global" },
                        "starts_at": starts_at,
                        "legal_basis": legal_basis
                    }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(view["starts_at"], json!(starts_at));
        assert_eq!(view["legal_basis"], json!(legal_basis));
        let del_id = view["id"].as_str().expect("id").to_owned();

        let (status, list) =
            send_raw(state.clone(), with_session(get("/v1/delegations"), &tok)).await;
        assert_eq!(status, StatusCode::OK);
        let listed = list
            .as_array()
            .expect("delegations")
            .iter()
            .find(|d| d["id"] == del_id)
            .expect("listed delegation");
        assert_eq!(listed["starts_at"], json!(starts_at));
        assert_eq!(listed["legal_basis"], json!(legal_basis));

        let persisted: serde_json::Value = serde_json::from_slice(
            &std::fs::read(tmp.dir.join(crate::delegations::DELEGATIONS_FILE)).expect("read"),
        )
        .expect("delegations json");
        let saved = persisted
            .as_array()
            .expect("persisted delegations")
            .iter()
            .find(|d| d["id"] == del_id)
            .expect("persisted delegation");
        assert!(saved.get("starts_at").is_some());
        assert_eq!(saved["legal_basis"], json!(legal_basis));
        let loaded = crate::delegations::load_delegations(
            &tmp.dir.join(crate::delegations::DELEGATIONS_FILE),
        )
        .expect("load delegations");
        let loaded = loaded
            .values()
            .find(|d| d.id.0.to_string() == del_id)
            .expect("loaded delegation");
        assert_eq!(loaded.inner.starts_at, starts_at_time);
        assert_eq!(loaded.inner.legal_basis.as_deref(), Some(legal_basis));

        let (_, perms_before) = send_raw(
            state.clone(),
            with_session(get("/v1/session/permissions"), &g_tok),
        )
        .await;
        assert!(
            !perms_before["permissions"]
                .as_array()
                .expect("perms")
                .iter()
                .any(|p| p["permission"] == "act.read" && p["source"] == "delegation")
        );

        let eff = crate::roles::effective_permissions_for(
            &state,
            grantee,
            starts_at_time + time::Duration::seconds(1),
        )
        .await;
        assert!(has_permission(
            &eff,
            Permission::ActRead,
            Scope::Global,
            &NoBooks
        ));
    }

    /// Change `target`'s default test password as a self-service op.
    async fn give_target_password(state: &AppState, target_id: &str, password: &str) {
        let self_tok = seed_session(state, target_id).await;
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target_id}/secret"),
                    json!({ "password": password, "current_password": DEFAULT_TEST_PASSWORD }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "self-service first password set");
    }

    /// Clear the t52 cross-user secret/reset backoff so an intentionally-repeated failed attempt in
    /// a matrix test is treated as a fresh (un-throttled) 403 rather than a 429 (mirrors how the
    /// signin tests clear `signin_backoff`). The throttle itself is asserted by the dedicated t52
    /// tests below; here it must not mask the uniform-403 / adjacent-op behaviour under test.
    async fn clear_secret_backoff(state: &AppState) {
        state.secret_backoff.write().await.clear();
    }

    /// Stored provenance + recovery presence for a user (reads the in-memory state directly).
    async fn stored_user(state: &AppState, id: &str) -> User {
        let uid = UserId(Uuid::parse_str(id).expect("uuid"));
        state
            .users
            .read()
            .await
            .get(&uid)
            .cloned()
            .expect("user present")
    }

    async fn clear_password_hash(state: &AppState, id: &str) {
        let uid = UserId(Uuid::parse_str(id).expect("uuid"));
        let mut users = state.users.write().await;
        users.get_mut(&uid).expect("user present").password_hash = None;
    }

    #[tokio::test]
    async fn t51_cross_user_set_on_legacy_no_hash_target_is_403() {
        // Matrix #7: the closed hole — a signed-in operator setting a FIRST password on a
        // legacy no-hash account is refused, never silently set.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        clear_password_hash(&state, &target).await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "attacker-chosen" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não autorizado")
        );
        // The target is untouched — still legacy no-hash.
        let (_, view) = send(state.clone(), get(&format!("/v1/users/{target}"))).await;
        assert_eq!(view["has_secret"], false);
    }

    #[tokio::test]
    async fn t51_cross_user_set_with_correct_password_succeeds_and_audits() {
        // Matrix #4: cross-user reset authorized by the target's known password → 200 + a
        // `user.secret.reset` event attributed to the requester (honest actor).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "Repor-Chave4!", "current_password": "Corrente-Ok3!X" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);

        // The reset is auditable as bruno's action, via the known password, with no secret material.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let reset = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset")
            .expect("user.secret.reset present");
        assert_eq!(reset["actor"], "bruno");
        assert!(
            reset["justification"]
                .as_str()
                .expect("justification")
                .contains("palavra-passe atual")
        );
        let dump = reset.to_string().to_lowercase();
        assert!(!dump.contains("Repor-Chave4!") && !dump.contains("$argon2"));

        // Provenance stays Password (a known-password reset is not a recovery).
        assert_eq!(
            stored_user(&state, &target).await.secret_source,
            crate::users::SecretSource::Password
        );
    }

    #[tokio::test]
    async fn t51_cross_user_wrong_password_no_proof_and_unknown_target_are_uniform_403() {
        // Matrix #5/#6 + §5 anti-enumeration: wrong password, no proof, and a non-existent target
        // all return the SAME 403 body — no status/message difference reveals target state.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let attempt = |body: Value, path_id: String| {
            let tok = bruno_tok.clone();
            let st = state.clone();
            async move {
                send(
                    st,
                    with_session(
                        post_json(&format!("/v1/users/{path_id}/secret"), body),
                        &tok,
                    ),
                )
                .await
            }
        };

        // The three attempts hit the same (requester,target) key back-to-back; the t52 backoff would
        // 429 the second one, masking the uniformity under test, so clear it between attempts. Each
        // remains a fresh, un-throttled, constant-work 403 — exactly what this test compares.
        let (s_wrong, b_wrong) = attempt(
            json!({ "password": "Xnova-Chave9!", "current_password": "WRONG" }),
            target.clone(),
        )
        .await;
        clear_secret_backoff(&state).await;
        let (s_none, b_none) =
            attempt(json!({ "password": "Xnova-Chave9!" }), target.clone()).await;
        clear_secret_backoff(&state).await;
        let (s_ghost, b_ghost) = attempt(
            json!({ "password": "Xnova-Chave9!", "current_password": "whatever" }),
            Uuid::new_v4().to_string(),
        )
        .await;

        assert_eq!(s_wrong, StatusCode::FORBIDDEN);
        assert_eq!(s_none, StatusCode::FORBIDDEN);
        assert_eq!(s_ghost, StatusCode::FORBIDDEN);
        // Indistinguishable bodies: an unknown target is NOT a 404, and no case leaks "has password".
        assert_eq!(b_wrong, b_none);
        assert_eq!(b_none, b_ghost);
    }

    #[tokio::test]
    async fn t51_403_is_distinct_from_401_session() {
        // The 403/401 split is honest: no session is 401 `sessão requerida`; a signed-in but
        // unauthorized cross-user reset is 403 with a different message.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;

        // No session → 401.
        let (s401, b401) = send_raw(
            state.clone(),
            post_json(
                &format!("/v1/users/{target}/secret"),
                json!({ "password": "Xnova-Chave9!" }),
            ),
        )
        .await;
        assert_eq!(s401, StatusCode::UNAUTHORIZED);
        assert_eq!(b401["error"], "sessão requerida");

        // Signed-in but no proof → 403 with a distinct message.
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (s403, b403) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "Xnova-Chave9!" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s403, StatusCode::FORBIDDEN);
        assert_ne!(b403["error"], b401["error"]);
    }

    #[tokio::test]
    async fn t51_cross_user_remove_and_key_ops_enforce_the_same_rule() {
        // Adjacent-op parity (§5): remove-secret and the attestation-key ops all refuse a
        // no-proof cross-user caller (matrix #10/#12). A correct-password delete-secret request is
        // authorized, then refused with 409 so passwordless users cannot be created.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;
        // Give the target an attestation key too (self-service).
        let self_tok = seed_session(&state, &target).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "Corrente-Ok3!X" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // No-proof cross-user remove-secret → 403 (does not leak via a 200 no-op).
        let (s, _) = send(
            state.clone(),
            with_session(
                body_json("DELETE", &format!("/v1/users/{target}/secret"), json!({})),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // These adjacent-op probes reuse the same (bruno,target) key back-to-back; clear the t52
        // backoff between them so each is a fresh 403 under test, not a 429 (the throttle has its
        // own dedicated tests below).
        clear_secret_backoff(&state).await;

        // No-proof cross-user attestation-key removal → 403 (matrix #12).
        let (s, _) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({}),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        clear_secret_backoff(&state).await;
        // Key is still there — nothing was removed.
        assert!(stored_user(&state, &target).await.attestation_key.is_some());

        // Correct-password cross-user attestation-key rotation → 200 (matrix #11).
        let (s, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "Corrente-Ok3!X" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::OK);

        // Correct-password cross-user remove-secret → 409 and preserves the password/key.
        let before = stored_user(&state, &target).await;
        let (s, body) = send(
            state.clone(),
            with_session(
                body_json(
                    "DELETE",
                    &format!("/v1/users/{target}/secret"),
                    json!({ "current_password": "Corrente-Ok3!X" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("defina uma nova palavra-passe")
        );
        let after = stored_user(&state, &target).await;
        assert_eq!(after.password_hash, before.password_hash);
        assert_eq!(after.attestation_key, before.attestation_key);
    }

    #[tokio::test]
    async fn t51_recovery_phrase_reset_flow_is_single_use() {
        // Matrix #14 + Phase B: issue an independent recovery phrase, reset a forgotten password
        // with it cross-user, and prove it is single-use and drops the password-locked key.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Esquecida-Ok8!X").await;
        // Target holds an attestation key (wrapped under the forgotten password).
        let self_tok = seed_session(&state, &target).await;
        send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "current_password": "Esquecida-Ok8!X" }),
                ),
                &self_tok,
            ),
        )
        .await;

        // Issue a recovery phrase for the target (self, proving the current password). Returned ONCE.
        let (status, issued) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/recovery"),
                    json!({ "current_password": "Esquecida-Ok8!X" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let phrase = issued["recovery_phrase"]
            .as_str()
            .expect("phrase")
            .to_owned();
        assert_eq!(phrase.len(), 32 + 3); // 4 groups of 8 base32 chars + 3 separators.
        assert_eq!(issued["has_recovery_phrase"], true);
        // The verifier is stored, never the plaintext.
        let stored = stored_user(&state, &target).await;
        let recovery_verifier = stored.recovery_hash.as_deref().expect("verifier");
        assert!(recovery_verifier.starts_with(crate::attestation::HARDENED_VERIFIER_PREFIX));
        assert!(recovery_verifier.contains("$argon2id$"));
        assert_ne!(stored.recovery_hash.as_deref(), Some(phrase.as_str()));

        // Bruno (another operator) resets the forgotten password using the recovery phrase.
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (status, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "Recuperar-Ok5!", "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["has_secret"], true);
        // Recovery consumed (single-use) and the password-locked key was dropped (unrecoverable).
        assert_eq!(view["has_recovery_phrase"], false);
        assert_eq!(view["has_attestation_key"], false);
        let stored = stored_user(&state, &target).await;
        assert_eq!(stored.secret_source, crate::users::SecretSource::Recovery);
        assert!(stored.recovery_hash.is_none());

        // The new password signs in; the forgotten one no longer does.
        let (s_new, _) = send(
            state.clone(),
            post_json(
                "/v1/session",
                json!({ "user_id": target, "password": "Recuperar-Ok5!" }),
            ),
        )
        .await;
        assert_eq!(s_new, StatusCode::OK);

        // Re-using the SAME phrase again is refused — it was consumed (403, uniform).
        let (s_reuse, _) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "Segunda-Vez6!", "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(s_reuse, StatusCode::FORBIDDEN);

        // The reset was audited as a recovery-phrase reset by bruno.
        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let reset = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset")
            .expect("reset event");
        assert_eq!(reset["actor"], "bruno");
        assert!(
            reset["justification"]
                .as_str()
                .expect("j")
                .contains("frase de recuperação")
        );
    }

    #[tokio::test]
    async fn t51_recovery_proof_cannot_generate_attestation_key() {
        // A recovery phrase authorizes a reset but CANNOT wrap a new attestation key (no password
        // to derive the KEK) — that specific cross-user op is refused with 403.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Alvo-Chave2!X").await;
        let self_tok = seed_session(&state, &target).await;
        let (_, issued) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/recovery"),
                    json!({ "current_password": "Alvo-Chave2!X" }),
                ),
                &self_tok,
            ),
        )
        .await;
        let phrase = issued["recovery_phrase"]
            .as_str()
            .expect("phrase")
            .to_owned();

        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/attestation-key"),
                    json!({ "recovery_phrase": phrase }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"]
                .as_str()
                .expect("e")
                .contains("chave de atestação")
        );
    }

    #[tokio::test]
    async fn t51_provenance_defaults_and_old_users_json_loads() {
        // F4: `secret_source` is additive with a `Password` default, so a pre-t51 users.json (no
        // `secret_source`, no `recovery_hash`) still deserializes.
        let json = json!({
            "id": Uuid::new_v4().to_string(),
            "username": "amelia.marques",
            "display_name": "Amélia Marques",
            "created_at": "2026-01-01T00:00:00Z",
            "active": true,
            "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g"
        })
        .to_string();
        let user: User = serde_json::from_str(&json).expect("old users.json still loads");
        assert_eq!(user.secret_source, crate::users::SecretSource::Password);
        assert!(user.recovery_hash.is_none());
    }

    // --- t52: target-keyed backoff + failed-attempt audit on the cross-user reset endpoints -------
    //
    // These layer ON TOP of the t51 constant-work / uniform-403 guarantees (never below them): a
    // repeated FAILED cross-user attempt is throttled, and each un-throttled 403 is audited — without
    // reintroducing an enumeration oracle (a non-existent target throttles IDENTICALLY to a real one)
    // and without letting an attacker lock a victim out of their own self-service.

    /// One cross-user `POST /v1/users/{target}/secret` from `bruno_tok`, returning (status, body).
    async fn cross_user_set(
        state: &AppState,
        bruno_tok: &str,
        target: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/users/{target}/secret"), body),
                bruno_tok,
            ),
        )
        .await
    }

    /// The t52 backoff key `(requester, target-from-request)` for two id strings (target may be a
    /// non-existent uuid — the key is request-derived, so a ghost target keys just like a real one).
    fn secret_backoff_key(requester: &str, target: &str) -> (Option<UserId>, UserId) {
        (
            Some(UserId(Uuid::parse_str(requester).expect("requester uuid"))),
            UserId(Uuid::parse_str(target).expect("target uuid")),
        )
    }

    /// The recorded consecutive-failure count for `(requester, target)`, or `None` if no failure has
    /// been recorded yet. Time-independent (unlike the window instant), so it is a robust signal that
    /// a failed attempt armed the throttle regardless of how slow argon2 is on the test machine.
    async fn secret_backoff_fails(state: &AppState, requester: &str, target: &str) -> Option<u32> {
        state
            .secret_backoff
            .read()
            .await
            .get(&secret_backoff_key(requester, target))
            .map(|b| b.fails)
    }

    /// Push the `(requester, target)` throttle window `secs` into the future, so the *response* to a
    /// throttled request (429) can be asserted deterministically without racing the real 1 s window
    /// (argon2 cost in a single request can otherwise consume most of it — the wall-clock flake
    /// t51-e2 flagged for signin). The window itself being SET by a real failure is asserted
    /// separately; this only fast-forwards an already-earned window to a stable value.
    async fn push_secret_backoff_window(
        state: &AppState,
        requester: &str,
        target: &str,
        secs: i64,
    ) {
        let now = time::OffsetDateTime::now_utc();
        let mut bo = state.secret_backoff.write().await;
        let entry =
            bo.entry(secret_backoff_key(requester, target))
                .or_insert(crate::session::Backoff {
                    fails: 0,
                    next_allowed_at: now,
                });
        entry.fails = entry.fails.max(1);
        entry.next_allowed_at = now + time::Duration::seconds(secs);
    }

    #[tokio::test]
    async fn t52_repeated_failed_cross_user_attempts_trigger_429() {
        // The reset endpoint now speed-bumps failed cross-user attempts, mirroring `signin_backoff`
        // on `POST /v1/session`: a failure records an escalating window on (requester,target), and a
        // request made while the window is open is refused 429 BEFORE any argon2 — so even the
        // correct password is throttled.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // A failed cross-user attempt → uniform 403, and it RECORDS a future throttle window.
        let (s1, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "Xnova-Chave9!", "current_password": "WRONG" }),
        )
        .await;
        assert_eq!(s1, StatusCode::FORBIDDEN);
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &target).await,
            Some(1),
            "the failed attempt armed the throttle (recorded a consecutive-failure window)"
        );

        // While throttled, the next request is 429 even with the CORRECT password (short-circuits
        // before argon2). Fast-forward the earned window to a stable value to avoid the wall-clock race.
        push_secret_backoff_window(&state, &bruno, &target, 30).await;
        let (s2, body) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "Xnova-Chave9!", "current_password": "Corrente-Ok3!X" }),
        )
        .await;
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "a request within the window is throttled, even with the right password"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("tente novamente")
        );
    }

    #[tokio::test]
    async fn t52_backoff_applies_identically_to_a_nonexistent_target() {
        // Anti-enumeration: a NON-EXISTENT target must throttle EXACTLY like a real one — same 403
        // body on the first attempt, and same 429 (byte-identical body) while throttled. If a ghost
        // target were not throttled, or throttled differently, "throttled ⇒ real user" would be an
        // enumeration oracle. Both keys are pushed to the same window so the 429 bodies must match.
        let state = AppState::default();
        let real = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &real, "Corrente-Ok3!X").await;
        let ghost = Uuid::new_v4().to_string(); // no such user
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // First attempt against each: a uniform, constant-work 403 with IDENTICAL body, and each
        // records its own throttle window (real and ghost alike).
        let (rs1, rb1) = cross_user_set(
            &state,
            &bruno_tok,
            &real,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        let (gs1, gb1) = cross_user_set(
            &state,
            &bruno_tok,
            &ghost,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        assert_eq!(rs1, StatusCode::FORBIDDEN);
        assert_eq!(gs1, StatusCode::FORBIDDEN);
        assert_eq!(
            rb1, gb1,
            "the first-attempt 403 body is identical (t51 uniform-403)"
        );
        // The non-existent target accrued a window JUST like the real one (no "not throttled ⇒ ghost").
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &real).await,
            Some(1),
            "the real target accrued a throttle window"
        );
        assert_eq!(
            secret_backoff_fails(&state, &bruno, &ghost).await,
            Some(1),
            "the NON-EXISTENT target accrued a throttle window identically"
        );

        // While throttled (both windows fast-forwarded to the same value), the 429 bodies are
        // byte-identical — a ghost target is indistinguishable from a real one.
        push_secret_backoff_window(&state, &bruno, &real, 30).await;
        push_secret_backoff_window(&state, &bruno, &ghost, 30).await;
        let (rs2, rb2) = cross_user_set(
            &state,
            &bruno_tok,
            &real,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        let (gs2, gb2) = cross_user_set(
            &state,
            &bruno_tok,
            &ghost,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        assert_eq!(rs2, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(gs2, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rb2, gb2,
            "the throttled 429 body is identical for a real vs a non-existent target"
        );
    }

    #[tokio::test]
    async fn t52_failed_cross_user_attempt_emits_denied_audit_event() {
        // A failed cross-user authorization (the 403 path) emits `user.secret.reset.denied`,
        // attributed to the honest requester, with a fixed-shape payload naming the target id, the
        // operation, and the attempted proof kind — and NO secret material.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Corrente-Ok3!X").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (s, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "Xnova-Chave9!", "current_password": "WRONG" }),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        let (_, events) = send(state.clone(), get("/v1/ledger/events")).await;
        let denied = events
            .as_array()
            .expect("events")
            .iter()
            .find(|e| e["kind"] == "user.secret.reset.denied")
            .expect("a denied audit event was appended");
        assert_eq!(denied["actor"], "bruno", "honest requester attribution");

        // The payload is exactly {target_id, operation, attempted_proof} (declaration order,
        // compact) — proving all three are recorded and nothing else leaks. The feed exposes only the
        // digest, so match against the reconstructed bytes.
        let expected_bytes = format!(
            r#"{{"target_id":"{target}","operation":"set_secret","attempted_proof":"palavra-passe"}}"#
        )
        .into_bytes();
        let expected_digest = crate::hex::hex(&chancela_ledger::digest(&expected_bytes));
        assert_eq!(
            denied["payload_digest"], expected_digest,
            "payload names the target id, operation, and attempted proof kind — no secret material"
        );
        // Defence in depth: neither the submitted password nor any argon2 hash appears anywhere.
        let dump = denied.to_string().to_lowercase();
        assert!(!dump.contains("wrong") && !dump.contains("$argon2"));
    }

    #[tokio::test]
    async fn t52_self_service_not_throttled_by_third_party_target_hammering() {
        // The throttle bites the abusive requester, keyed on (requester,target) — so an attacker
        // hammering a victim's id as a target can NOT lock the victim out of their own self-service
        // (a different key, `(victim,victim)`, which is never throttled at all).
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        give_target_password(&state, &target, "Atual-Chave1!X").await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        // Bruno hammers amelia's id and earns a throttle window on (bruno, amelia); fast-forward it
        // so his next attempt is deterministically 429.
        let (s1, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        assert_eq!(s1, StatusCode::FORBIDDEN);
        push_secret_backoff_window(&state, &bruno, &target, 30).await;
        let (s2, _) = cross_user_set(
            &state,
            &bruno_tok,
            &target,
            json!({ "password": "Xnova-Chave9!" }),
        )
        .await;
        assert_eq!(
            s2,
            StatusCode::TOO_MANY_REQUESTS,
            "the attacker is now throttled"
        );

        // Amelia's own self-service password change is UNAFFECTED (different key, never throttled).
        let self_tok = seed_session(&state, &target).await;
        let (s_self, view) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "Nova-Chave2!X", "current_password": "Atual-Chave1!X" }),
                ),
                &self_tok,
            ),
        )
        .await;
        assert_eq!(
            s_self,
            StatusCode::OK,
            "the victim's own self-service is not collateral-throttled"
        );
        assert_eq!(view["has_secret"], true);
    }

    // =============================================================================================
    // t54-E3: chain-recovery + per-book export/import/start-over + data management
    // =============================================================================================

    /// A fresh **persistent** state backed by a unique temp data dir (opens a real SQLite store, so
    /// the recovery/export/import/reset endpoints — which require durability — are exercisable). The
    /// dir lives under the OS temp dir; it is left in place (the open sqlite handle makes an eager
    /// remove flaky on Windows), which is fine for a hermetic per-test dir.
    fn persistent_state() -> AppState {
        let dir = std::env::temp_dir().join(format!("chancela-api-t54-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp data dir");
        AppState::with_data_dir(dir)
    }

    async fn sync_handoff_router_snapshot(
        state: &AppState,
    ) -> (usize, usize, usize, usize, usize, usize) {
        (
            state.books.read().await.len(),
            state.acts.read().await.len(),
            state.documents.read().await.len(),
            state.backup_recovery_drill_receipts.read().await.len(),
            state.ledger.read().await.len(),
            state.signed_documents.read().await.len(),
        )
    }

    #[tokio::test]
    async fn sync_handoff_preflight_http_requires_ledger_recover_and_does_not_mutate() {
        let state = AppState::default();

        let (status, _) = send_raw(state.clone(), get("/v1/sync/handoff-preflight")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let no_perms = powerless_token(&state).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(get("/v1/sync/handoff-preflight"), &no_perms),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let owner = auth_token(&state).await;
        let before = sync_handoff_router_snapshot(&state).await;
        let (status, report) = send_raw(
            state.clone(),
            with_session(get("/v1/sync/handoff-preflight"), &owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert_eq!(report["report_kind"], "sync_handoff_preflight");
        assert_eq!(report["readiness"]["status"], "blocked");
        assert_eq!(report["no_claims"]["records_mutated"], false);
        assert_eq!(sync_handoff_router_snapshot(&state).await, before);
    }

    /// Create an entity + open a book on `state` using `token`; returns `(entity_id, book_id)`.
    async fn seed_entity_and_book(state: &AppState, token: &str) -> (String, String) {
        let (status, entity) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({
                        "name": "Encosto Estratégico, S.A.",
                        "nipc": "503004642",
                        "seat": "Lisboa",
                        "kind": "SociedadeAnonima",
                    }),
                ),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "seed entity: {entity}");
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/books",
                    json!({
                        "entity_id": entity_id,
                        "kind": "AssembleiaGeral",
                        "purpose": "livro de atas da assembleia geral",
                        "opening_date": "2026-01-15",
                        "required_signatories": ["Administrador"],
                    }),
                ),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "seed book: {book}");
        let book_id = book["id"].as_str().expect("book id").to_owned();
        (entity_id, book_id)
    }

    /// Draft, fill, advance, and SEAL an ata into `book_id` on `state` with `token`.
    async fn seal_one_act(state: &AppState, book_id: &str, token: &str) {
        let (_, act) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/acts",
                    json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
                ),
                token,
            ),
        )
        .await;
        let act_id = act["id"].as_str().expect("act id").to_owned();
        send(
            state.clone(),
            with_session(
                patch_json(
                    &format!("/v1/acts/{act_id}"),
                    json!({
                        "meeting_date": "2026-03-30",
                        "meeting_time": "10:00",
                        "place": "Sede social",
                        "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretário"] },
                        "agenda": [{ "number": 1, "text": "Aprovação das contas do exercício" }],
                        "attendance_reference": "Lista de presenças",
                        "deliberations": "Aprovadas as contas do exercício.",
                    }),
                ),
                token,
            ),
        )
        .await;
        for to in [
            "Review",
            "Convened",
            "Deliberated",
            "TextApproved",
            "Signing",
        ] {
            send(
                state.clone(),
                with_session(
                    post_json(&format!("/v1/acts/{act_id}/advance"), json!({ "to": to })),
                    token,
                ),
            )
            .await;
        }
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(&format!("/v1/acts/{act_id}/seal"), seal_body()),
                token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seal one act");
    }

    // --- t61-E1: convocatória convening/attendee input + dispatch + antecedence advisory ----------

    /// Draft one act into `book_id` and return its id (Owner-authorized via auto-seeded session).
    async fn draft_one_act(state: &AppState, book_id: &str) -> String {
        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "draft act: {act}");
        act["id"].as_str().expect("act id").to_owned()
    }

    #[tokio::test]
    async fn draft_act_accepts_initial_convening_evidence() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;

        let (status, act) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({
                    "book_id": book_id,
                    "title": "Ata com convocatória",
                    "channel": "Physical",
                    "convening": {
                        "dispatch_date": "2026-03-01",
                        "antecedence_days": 21,
                        "channel": "RegisteredLetterAR",
                        "evidence_reference": "doc:convocatoria-inicial"
                    }
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED, "draft with convening: {act}");
        assert_eq!(act["convening"]["dispatch_date"], "2026-03-01");
        assert_eq!(act["convening"]["channel"], "RegisteredLetterAR");
        assert_eq!(
            act["convening"]["evidence_reference"],
            "doc:convocatoria-inicial"
        );
    }

    #[tokio::test]
    async fn follow_up_routes_create_patch_complete_and_leave_sealed_act_unchanged() {
        use chancela_core::ActState;

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        let act_key = ActId(Uuid::parse_str(&act_id).expect("act uuid"));
        let sealed_snapshot = {
            let mut acts = state.acts.write().await;
            let act = acts.get_mut(&act_key).expect("act in memory");
            act.state = ActState::Sealed;
            act.ata_number = Some(1);
            act.payload_digest = Some([42; 32]);
            act.seal_event_seq = Some(100);
            act.clone()
        };

        let (status, created) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/follow-ups"),
                json!({
                    "actor": "body.actor",
                    "agenda_number": 1,
                    "deliberation_index": 0,
                    "title": "Entregar certidao atualizada",
                    "detail": "Enviar comprovativo ao orgao fiscal.",
                    "due_date": "2026-04-30",
                    "assignee": "amelia.marques",
                    "assignee_display": "Amelia Marques"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create follow-up: {created}");
        let follow_up_id = created["id"].as_str().expect("follow-up id").to_owned();
        assert_eq!(created["act_id"], act_id);
        assert_eq!(created["status"], "Open");
        assert_eq!(created["created_by"], "test.actor");

        let after_create = state
            .acts
            .read()
            .await
            .get(&act_key)
            .expect("act after create")
            .clone();
        assert_eq!(after_create, sealed_snapshot);

        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/follow-ups/{follow_up_id}"),
                json!({
                    "title": "Entregar certidao e comprovativo",
                    "detail": null,
                    "due_date": "2026-05-15",
                    "assignee_display": "Amelia M.",
                    "agenda_number": null
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "patch follow-up: {patched}");
        assert_eq!(patched["title"], "Entregar certidao e comprovativo");
        assert!(patched["detail"].is_null());
        assert_eq!(patched["due_date"], "2026-05-15");
        assert!(patched["agenda_number"].is_null());
        assert_eq!(patched["status"], "Open");

        let after_patch = state
            .acts
            .read()
            .await
            .get(&act_key)
            .expect("act after patch")
            .clone();
        assert_eq!(after_patch, sealed_snapshot);

        let (status, completed) = send(
            state.clone(),
            post_json(
                &format!("/v1/follow-ups/{follow_up_id}/complete"),
                json!({ "actor": "body.actor" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "complete follow-up: {completed}");
        assert_eq!(completed["status"], "Completed");
        assert_eq!(completed["completed_by"], "test.actor");
        assert!(completed["completed_at"].as_str().is_some());

        let (status, list) =
            send(state.clone(), get(&format!("/v1/acts/{act_id}/follow-ups"))).await;
        assert_eq!(status, StatusCode::OK);
        let rows = list.as_array().expect("follow-up list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], follow_up_id);
        assert_eq!(rows[0]["status"], "Completed");

        let (status, body) = send(
            state.clone(),
            post_json(
                &format!("/v1/follow-ups/{follow_up_id}/complete"),
                json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "complete twice: {body}");

        let after_complete = state
            .acts
            .read()
            .await
            .get(&act_key)
            .expect("act after complete")
            .clone();
        assert_eq!(after_complete, sealed_snapshot);

        let follow_kinds: Vec<String> = state
            .ledger
            .read()
            .await
            .events()
            .iter()
            .filter(|event| event.kind.starts_with("follow_up."))
            .map(|event| event.kind.clone())
            .collect();
        assert_eq!(
            follow_kinds,
            vec![
                "follow_up.created",
                "follow_up.updated",
                "follow_up.completed"
            ]
        );
    }

    #[tokio::test]
    async fn follow_up_routes_allow_readers_to_list_but_not_mutate() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};

        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        let (status, created) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/follow-ups"),
                json!({ "title": "Preparar comprovativo" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let follow_up_id = created["id"].as_str().expect("follow-up id").to_owned();

        let leitor = seed_user(
            &state,
            "leitor.followups",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let token = seed_session(&state, &leitor.to_string()).await;

        let (status, list) = send_raw(
            state.clone(),
            with_session(get(&format!("/v1/acts/{act_id}/follow-ups")), &token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("list").len(), 1);

        let (status, _) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/acts/{act_id}/follow-ups"),
                    json!({ "title": "Tentativa de escrita" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = send_raw(
            state.clone(),
            with_session(
                patch_json(
                    &format!("/v1/follow-ups/{follow_up_id}"),
                    json!({ "title": "Tentativa de edicao" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = send_raw(
            state,
            with_session(
                post_json(
                    &format!("/v1/follow-ups/{follow_up_id}/complete"),
                    json!({}),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn follow_up_routes_persist_and_recover_from_store() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());

        let (status, entity) = send(
            state.clone(),
            post_json(
                "/v1/entities",
                json!({
                    "name": "Follow Ups, Lda",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let entity_id = entity["id"].as_str().expect("entity id").to_owned();

        let (status, book) = send(
            state.clone(),
            post_json(
                "/v1/books",
                json!({
                    "entity_id": entity_id,
                    "kind": "AssembleiaGeral",
                    "purpose": "livro de atas",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_str().expect("book id").to_owned();
        let act_id = draft_one_act(&state, &book_id).await;

        let (status, created) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/follow-ups"),
                json!({
                    "title": "Persistir tarefa",
                    "due_date": "2026-06-01"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let follow_up_id = created["id"].as_str().expect("follow-up id").to_owned();

        let recovered = AppState::with_data_dir(tmp.dir.clone());
        let (status, list) = send(recovered, get(&format!("/v1/acts/{act_id}/follow-ups"))).await;
        assert_eq!(status, StatusCode::OK);
        let rows = list.as_array().expect("follow-up list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], follow_up_id);
        assert_eq!(rows[0]["title"], "Persistir tarefa");
        assert_eq!(rows[0]["due_date"], "2026-06-01");
    }

    #[tokio::test]
    async fn patch_convening_and_attendees_round_trip_and_clear() {
        let (state, _entity_id, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;

        // Set a full convening + two attendance rows.
        let (status, patched) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({
                    "convening": {
                        "convener": "Amélia Marques",
                        "convener_capacity": "Administrator",
                        "dispatch_date": "2026-03-01",
                        "antecedence_days": 21,
                        "channel": "RegisteredLetter",
                        "evidence_reference": "doc:convocatoria-2026-03-01",
                        "recipients": [
                            { "name": "Amélia Marques", "contact": "amelia@example.test", "channel": "Email", "reference": "MSG-1" },
                            { "name": "Bruno Dias", "reference": "legacy-reference-only" }
                        ],
                        "second_call": { "date": "2026-03-30", "time": "11:00", "reduced_quorum": true }
                    },
                    "attendees": [
                        { "name": "Amélia Marques", "quality": "Administrator", "presence": "InPerson" },
                        { "name": "Bruno Dias", "quality": "Member", "presence": "Represented",
                          "represented_by": "Amélia Marques", "weight": { "Permilage": 250 } }
                    ]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "patch convening: {patched}");
        assert_eq!(patched["convening"]["convener"], "Amélia Marques");
        assert_eq!(patched["convening"]["antecedence_days"], 21);
        assert_eq!(patched["convening"]["dispatch_date"], "2026-03-01");
        assert_eq!(
            patched["convening"]["evidence_reference"],
            "doc:convocatoria-2026-03-01"
        );
        assert_eq!(patched["convening"]["second_call"]["time"], "11:00");
        assert_eq!(patched["convening"]["second_call"]["reduced_quorum"], true);
        assert_eq!(
            patched["convening"]["recipients"][0]["name"],
            "Amélia Marques"
        );
        assert_eq!(
            patched["convening"]["recipients"][0]["contact"],
            "amelia@example.test"
        );
        assert_eq!(patched["convening"]["recipients"][0]["reference"], "MSG-1");
        assert!(
            patched["convening"]["recipients"][1]["contact"].is_null(),
            "legacy reference must not be copied into contact: {patched}"
        );
        assert_eq!(
            patched["convening"]["recipients"][1]["reference"],
            "legacy-reference-only"
        );
        assert_eq!(patched["attendees"][1]["represented_by"], "Amélia Marques");
        assert_eq!(patched["attendees"][1]["weight"]["Permilage"], 250);

        // GET round-trips the same shape.
        let (status, fetched) = send(state.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched["convening"]["antecedence_days"], 21);
        assert_eq!(
            fetched["convening"]["evidence_reference"],
            "doc:convocatoria-2026-03-01"
        );
        assert_eq!(
            fetched["convening"]["recipients"][0]["contact"],
            "amelia@example.test"
        );
        assert!(
            fetched["convening"]["recipients"][1]["contact"].is_null(),
            "GET must not infer contact from legacy reference: {fetched}"
        );
        assert_eq!(fetched["attendees"].as_array().expect("attendees").len(), 2);

        // Explicit null clears convening; omitting attendees leaves them untouched.
        let (status, cleared) = send(
            state.clone(),
            patch_json(&format!("/v1/acts/{act_id}"), json!({ "convening": null })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            cleared.as_object().expect("obj").get("convening").is_none(),
            "convening cleared ⇒ skip-serialized (no key): {cleared}"
        );
        assert_eq!(
            cleared["attendees"].as_array().expect("attendees").len(),
            2,
            "omitted attendees are left untouched"
        );

        // [] clears attendees (⇒ skip-serialized).
        let (status, empty) = send(
            state.clone(),
            patch_json(&format!("/v1/acts/{act_id}"), json!({ "attendees": [] })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            empty.as_object().expect("obj").get("attendees").is_none(),
            "empty attendees ⇒ no key: {empty}"
        );
    }

    #[tokio::test]
    async fn patch_attendee_validation_returns_422() {
        let (state, _e, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;

        // Permilage > 1000 → 422.
        let (status, _b) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "attendees": [
                    { "name": "Amélia Marques", "quality": "CondoOwner", "presence": "InPerson",
                      "weight": { "Permilage": 1200 } }
                ]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "permilage > 1000");

        // Represented without a proxy → 422.
        let (status, _b) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "attendees": [
                    { "name": "Bruno Dias", "quality": "Member", "presence": "Represented" }
                ]}),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "represented w/o proxy"
        );

        // A malformed convening date → 422 (and the act is left untouched).
        let (status, _b) = send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "convening": { "dispatch_date": "2026-13-40" } }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "bad date");
    }

    #[tokio::test]
    async fn dispatch_stamps_recipients_and_emits_the_event() {
        let (state, _e, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "convening": {
                    "antecedence_days": 21,
                    "recipients": [
                        { "name": "Amélia Marques", "contact": "amelia@example.test" },
                        { "name": "Bruno Dias", "contact": "bruno@example.test", "reference": "preexisting-proof" }
                    ]
                }}),
            ),
        )
        .await;

        // Dispatch to a single named recipient stamps only that one.
        let (status, dispatched) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/convening/dispatch"),
                json!({ "dispatched_at": "2026-03-02", "channel": "Email",
                        "reference": "RC123", "recipients": ["Amélia Marques"] }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "dispatch: {dispatched}");
        let recips = dispatched["convening"]["recipients"]
            .as_array()
            .expect("recipients");
        let amelia = &recips[0];
        assert_eq!(amelia["name"], "Amélia Marques");
        assert_eq!(amelia["dispatched_at"], "2026-03-02");
        assert_eq!(amelia["channel"], "Email");
        assert_eq!(amelia["contact"], "amelia@example.test");
        assert_eq!(amelia["reference"], "RC123");
        // The unnamed recipient stays un-stamped.
        assert!(
            recips[1]["dispatched_at"].is_null(),
            "Bruno not dispatched: {dispatched}"
        );
        assert_eq!(recips[1]["contact"], "bruno@example.test");
        assert_eq!(recips[1]["reference"], "preexisting-proof");

        // A `convening.dispatched` ledger event was appended for this act.
        let (status, events) = send(
            state.clone(),
            get(&format!("/v1/ledger/events?scope=act:{act_id}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "convening.dispatched"),
            "convening.dispatched event present: {events}"
        );
    }

    #[tokio::test]
    async fn dispatch_422_without_a_convening() {
        let (state, _e, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        let (status, _b) = send(
            state.clone(),
            post_json(
                &format!("/v1/acts/{act_id}/convening/dispatch"),
                json!({ "dispatched_at": "2026-03-02" }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "no convening ⇒ 422"
        );
    }

    #[tokio::test]
    async fn actview_without_convening_or_attendees_emits_no_new_keys() {
        // DRIFT-SAFE guard: a convening-less act's ActView must carry NEITHER `convening` nor
        // `attendees` (skip-serialized), keeping the committed contracts/act.sealed.json byte-shape.
        let (state, _e, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        let (status, act) = send(state.clone(), get(&format!("/v1/acts/{act_id}"))).await;
        assert_eq!(status, StatusCode::OK);
        let obj = act.as_object().expect("act object");
        assert!(obj.get("convening").is_none(), "no convening key: {act}");
        assert!(obj.get("attendees").is_none(), "no attendees key: {act}");
    }

    #[tokio::test]
    async fn dispatch_is_forbidden_for_a_read_only_leitor() {
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};
        let (state, _e, book_id) = entity_and_open_book("SociedadeAnonima").await;
        let act_id = draft_one_act(&state, &book_id).await;
        send(
            state.clone(),
            patch_json(
                &format!("/v1/acts/{act_id}"),
                json!({ "convening": { "recipients": [ { "name": "Amélia Marques" } ] } }),
            ),
        )
        .await;

        // A Leitor\@Global holds act.read but NOT act.edit → dispatch is 403 (honest, non-enumerating).
        let leitor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let tok = seed_session(&state, &leitor.to_string()).await;
        let (status, body) = send_raw(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/acts/{act_id}/convening/dispatch"),
                    json!({ "dispatched_at": "2026-03-02" }),
                ),
                &tok,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "leitor cannot dispatch: {body}"
        );
    }

    /// Seed a signed-in user WITH a password (for step-up re-auth), returning `(user_id, token)`.
    /// The session is seeded directly (bypassing the password) so `require_step_up`'s re-auth is
    /// what actually proves the password — mirroring the real UI (a live session + a fresh re-auth).
    async fn user_with_password(state: &AppState, username: &str, password: &str) -> String {
        let uid = make_user(state, username).await;
        give_target_password(state, &uid, password).await;
        seed_session(state, &uid).await
    }

    /// POST a raw body (e.g. bundle bytes) with a session token.
    fn post_raw(uri: &str, bytes: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(bytes))
            .expect("request builds")
    }

    /// Re-zip a book bundle with a corrupted `events.jsonl` member (its sha256 no longer matches the
    /// unchanged manifest), so verify-before-trust quarantines it. Proves an api-level forgery is
    /// caught and isolated, never merged as a live chain.
    fn tamper_bundle(zip_bytes: &[u8]) -> Vec<u8> {
        use std::io::{Read, Write};
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).expect("valid bundle zip");
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).expect("zip member");
            let name = f.name().to_owned();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).expect("read member");
            members.push((name, buf));
        }
        for (name, bytes) in members.iter_mut() {
            if name == "events.jsonl" && !bytes.is_empty() {
                bytes[0] ^= 0xff; // corrupt → member digest mismatch → Quarantined
            }
        }
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in &members {
            out.start_file(name.as_str(), opts).expect("start file");
            out.write_all(bytes).expect("write member");
        }
        out.finish().expect("finish zip").into_inner()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ImportNoMutationSnapshot {
        ledger_len: usize,
        ledger_imported_events: usize,
        imported_records: usize,
        live_entities: usize,
        live_books: usize,
        live_acts: usize,
        live_documents: usize,
        staged_uploads: Vec<String>,
    }

    fn staged_import_uploads(state: &AppState) -> Vec<String> {
        let Some(data_dir) = state.data_dir() else {
            return Vec::new();
        };
        let imports_dir = data_dir.join("imports");
        let Ok(read_dir) = std::fs::read_dir(imports_dir) else {
            return Vec::new();
        };
        let mut entries = read_dir
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    async fn import_no_mutation_snapshot(state: &AppState) -> ImportNoMutationSnapshot {
        let (ledger_len, ledger_imported_events) = {
            let ledger = state.ledger.read().await;
            (
                ledger.events().len(),
                ledger
                    .events()
                    .iter()
                    .filter(|event| event.kind == "ledger.imported")
                    .count(),
            )
        };
        let imported_records = state
            .store
            .as_ref()
            .expect("persistent store")
            .imported_books()
            .expect("import feed")
            .len();
        ImportNoMutationSnapshot {
            ledger_len,
            ledger_imported_events,
            imported_records,
            live_entities: state.entities.read().await.len(),
            live_books: state.books.read().await.len(),
            live_acts: state.acts.read().await.len(),
            live_documents: state.documents.read().await.len(),
            staged_uploads: staged_import_uploads(state),
        }
    }

    async fn assert_import_preflight_did_not_mutate(
        state: &AppState,
        before: &ImportNoMutationSnapshot,
    ) {
        assert_eq!(
            import_no_mutation_snapshot(state).await,
            *before,
            "book import preflight must not mutate ledger, import namespace, live records, or staged uploads"
        );
    }

    #[tokio::test]
    async fn integrity_endpoint_reports_a_healthy_chain() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "amelia.marques").await).await;
        seed_entity_and_book(&state, &token).await;

        let (status, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["healthy"], true);
        assert_eq!(report["degraded"], false);
        assert_eq!(report["global"]["verified"], true);
        assert!(report["global"]["length"].as_u64().expect("length") >= 1);
        assert!(
            report["reanchored_segments"]
                .as_array()
                .expect("segments")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reanchor_requires_step_up_reauth() {
        // A signed-in operator WITH a password, so step-up re-auth has a credential to verify against.
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Reancorar-Cadeia5!").await;
        seed_entity_and_book(&state, &token).await;

        // A valid session alone (no step-up proof) is refused with 403 — mirrors the destructive wipes.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session alone is not enough for reanchor"
        );

        // A wrong password is likewise refused with a uniform 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia", "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "wrong step-up refused");

        // With valid step-up the op PROCEEDS past the gate: the in-memory chain is healthy, so it
        // reaches the handler and refuses with 409 (already valid — nothing to repair).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia", "reauth": { "password": "Reancorar-Cadeia5!" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "valid step-up proceeds; already-valid chain → 409"
        );
    }

    #[tokio::test]
    async fn books_import_preflight_valid_bundle_summarizes_without_mutation() {
        let a = persistent_state();
        let a_tok = seed_session(&a, &make_user(&a, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&a, &a_tok).await;
        seal_one_act(&a, &book_id, &a_tok).await;

        let (status, ctype, bundle) = send_bytes(
            a.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &a_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export book");
        assert!(ctype.starts_with("application/zip"), "ctype={ctype}");

        let b = persistent_state();
        let b_tok = seed_session(&b, &make_user(&b, "bruno").await).await;
        let before = import_no_mutation_snapshot(&b).await;
        let (status, preview) = send(
            b.clone(),
            with_session(post_raw("/v1/books/import/preflight", bundle), &b_tok),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "preflight valid bundle: {preview}");
        assert_eq!(preview["ok"], true);
        assert_eq!(preview["ready"], true);
        assert_eq!(preview["would_import"], true);
        assert_eq!(preview["would_record_ledger_event"], false);
        assert_eq!(preview["would_store_import_record"], false);
        assert_eq!(preview["policy"], "refuse");
        assert_eq!(preview["book_id"], book_id);
        assert_eq!(preview["verdict"]["status"], "Verified");
        assert_eq!(preview["collided"], false);
        assert!(
            preview["bundle_digest"]
                .as_str()
                .is_some_and(|v| v.len() == 64)
        );
        assert!(
            preview.get("import_id").is_none(),
            "no mutation id in preview"
        );
        assert!(
            preview["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .any(|finding| finding
                    .as_str()
                    .unwrap_or_default()
                    .contains("Preflight did not append ledger.imported")),
            "no-mutation finding present: {preview}"
        );
        assert_import_preflight_did_not_mutate(&b, &before).await;
    }

    #[tokio::test]
    async fn books_import_preflight_tampered_bundle_reports_quarantine_without_mutation() {
        let a = persistent_state();
        let a_tok = seed_session(&a, &make_user(&a, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&a, &a_tok).await;
        seal_one_act(&a, &book_id, &a_tok).await;

        let (status, _, bundle) = send_bytes(
            a.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &a_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export book");

        let c = persistent_state();
        let c_tok = seed_session(&c, &make_user(&c, "carla").await).await;
        let before = import_no_mutation_snapshot(&c).await;
        let forged = tamper_bundle(&bundle);
        let (status, preview) = send(
            c.clone(),
            with_session(post_raw("/v1/books/import/preflight", forged), &c_tok),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "preflight forged bundle: {preview}");
        assert_eq!(preview["ok"], false);
        assert_eq!(preview["ready"], false);
        assert_eq!(preview["would_import"], false);
        assert_eq!(preview["would_record_ledger_event"], false);
        assert_eq!(preview["would_store_import_record"], false);
        assert_eq!(preview["verdict"]["status"], "Quarantined");
        assert_ne!(
            preview["book_chain_verified"], true,
            "tampered/quarantined preflight must not expose manifest verified=true as the actual verification result: {preview}"
        );
        assert!(
            preview["verdict"]["break"].is_object(),
            "break detail present"
        );
        assert!(
            preview["errors"]
                .as_array()
                .expect("errors")
                .iter()
                .any(|error| error
                    .as_str()
                    .unwrap_or_default()
                    .contains("would be quarantined")),
            "quarantine blocker reported: {preview}"
        );
        assert_import_preflight_did_not_mutate(&c, &before).await;
    }

    #[tokio::test]
    async fn books_import_preflight_collision_refuse_blocks_without_mutation() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;

        let (status, _, bundle) = send_bytes(
            state.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export book");

        let before = import_no_mutation_snapshot(&state).await;
        let (status, preview) = send(
            state.clone(),
            with_session(
                post_raw("/v1/books/import/preflight?policy=refuse", bundle),
                &token,
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "preflight collision: {preview}");
        assert_eq!(preview["ok"], false);
        assert_eq!(preview["ready"], false);
        assert_eq!(preview["would_import"], false);
        assert_eq!(preview["collided"], true);
        assert_eq!(preview["policy"], "refuse");
        assert_eq!(preview["book_id"], book_id);
        assert_eq!(preview["verdict"]["status"], "Verified");
        assert!(
            preview["errors"]
                .as_array()
                .expect("errors")
                .iter()
                .any(|error| error
                    .as_str()
                    .unwrap_or_default()
                    .contains("policy=refuse would block")),
            "collision blocker reported: {preview}"
        );
        assert_import_preflight_did_not_mutate(&state, &before).await;
    }

    #[tokio::test]
    async fn export_import_round_trips_verified_and_a_forged_bundle_quarantines() {
        // Source instance A: a book with a sealed ata.
        let a = persistent_state();
        let a_tok = seed_session(&a, &make_user(&a, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&a, &a_tok).await;
        seal_one_act(&a, &book_id, &a_tok).await;

        // Export the book bundle (application/zip download, retained under exports/).
        let (status, ctype, bundle) = send_bytes(
            a.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &a_tok,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export book");
        assert!(ctype.starts_with("application/zip"), "ctype={ctype}");
        assert!(!bundle.is_empty(), "bundle has bytes");

        // Fresh instance B: importing the clean bundle VERIFIES (no collision on a fresh instance).
        let b = persistent_state();
        let b_tok = seed_session(&b, &make_user(&b, "bruno").await).await;
        let (status, outcome) = send(
            b.clone(),
            with_session(post_raw("/v1/books/import", bundle.clone()), &b_tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "import verified: {outcome}");
        assert_eq!(outcome["verdict"]["status"], "Verified");
        assert_eq!(outcome["collided"], false);
        assert_eq!(outcome["book_id"], book_id);

        // A forged bundle (tampered member) is QUARANTINED, never trusted as valid.
        let c = persistent_state();
        let c_tok = seed_session(&c, &make_user(&c, "carla").await).await;
        let forged = tamper_bundle(&bundle);
        let (status, outcome) = send(
            c.clone(),
            with_session(post_raw("/v1/books/import", forged), &c_tok),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "forged import handled: {outcome}");
        assert_eq!(outcome["verdict"]["status"], "Quarantined");
        assert!(
            outcome["verdict"]["break"].is_object(),
            "break detail present"
        );
    }

    #[tokio::test]
    async fn books_import_rejects_body_above_route_limit_before_staging() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "bruno").await).await;
        let data_dir = state.data_dir().expect("persistent state has data dir");
        let oversized = vec![0_u8; bundles::BOOK_IMPORT_BUNDLE_MAX_BYTES + 1];

        let status = send_status(
            state,
            with_session(post_raw("/v1/books/import", oversized), &token),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            !data_dir.join("imports").exists(),
            "body limit should reject before staging upload bytes"
        );
    }

    #[tokio::test]
    async fn per_book_start_over_archives_and_opens_a_fresh_successor() {
        let state = persistent_state();
        let token = seed_session(&state, &make_user(&state, "amelia.marques").await).await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/books/{book_id}/start-over"),
                    json!({
                        "reason": "livro esgotado — recomeçar",
                        "purpose": "livro de atas da assembleia geral (sucessor)",
                        "opening_date": "2026-07-08",
                        "required_signatories": ["Administrador"],
                    }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "start-over: {resp}");
        assert_eq!(resp["reinit"]["old_book_id"], book_id);
        assert_eq!(resp["new_book"]["state"], "Open");
        assert!(resp["reinit"]["archived_bundle_digest"].is_string());
        let new_book_id = resp["new_book"]["id"].as_str().expect("new id").to_owned();
        assert_ne!(new_book_id, book_id);

        // The old book still exists (append-only; nothing erased); both books are queryable.
        let (status, _) = send(state.clone(), get(&format!("/v1/books/{book_id}"))).await;
        assert_eq!(status, StatusCode::OK, "old book preserved");
        let (status, _) = send(state.clone(), get(&format!("/v1/books/{new_book_id}"))).await;
        assert_eq!(status, StatusCode::OK, "successor opened");

        // The lifecycle events are chained (exported + reinitialized), and the chain still verifies.
        let (_, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        let kinds: Vec<&str> = events
            .as_array()
            .expect("events")
            .iter()
            .map(|e| e["kind"].as_str().unwrap_or_default())
            .collect();
        assert!(
            kinds.contains(&"ledger.exported"),
            "exported chained: {kinds:?}"
        );
        assert!(kinds.contains(&"ledger.reinitialized"), "reinit chained");
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(
            verify["valid"], true,
            "chain still verifies after start-over"
        );
    }

    #[tokio::test]
    async fn whole_instance_start_over_requires_confirm_and_reauth_then_reseeds_empty() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Limpar-Dados6!X").await;
        seed_entity_and_book(&state, &token).await;

        // Wrong confirm phrase → 422 (reaches the handler; nothing destroyed).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "x", "confirm_phrase": "nope",
                            "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "wrong phrase refused"
        );

        // Right phrase but NO step-up re-auth → 403 (a session alone is not enough).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "x", "confirm_phrase": "RECOMEÇAR" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no step-up refused");

        // Confirm + re-auth → archives, then re-seeds a fresh (nearly empty) ledger.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/start-over",
                    json!({ "reason": "recomeçar a instância", "confirm_phrase": "RECOMEÇAR",
                            "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "instance start-over: {resp}");
        assert!(resp["archive_path"].is_string());

        // Domain is cleared; the fresh ledger's genesis is the reinitialization, and it verifies.
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain cleared"
        );
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true);
        assert_eq!(
            verify["length"], 1,
            "fresh ledger holds only the reinit genesis"
        );
    }

    #[tokio::test]
    async fn reset_backend_domain_preserves_the_ledger_and_emits_data_wiped() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Limpar-Dados6!X").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;
        let (_, verify_before) = send(state.clone(), get("/v1/ledger/verify")).await;
        let len_before = verify_before["length"].as_u64().expect("len");

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true, "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "domain wipe: {resp}");
        assert!(
            resp["export_archive"].is_string(),
            "export-first archive taken"
        );

        // Domain data cleared, but the append-only ledger is PRESERVED + grew a data.wiped event.
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain cleared"
        );
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["valid"], true, "ledger still verifies");
        assert!(
            verify["length"].as_u64().expect("len") > len_before,
            "ledger preserved and grew (data.wiped + export)"
        );
        let (_, events) = send(state.clone(), get("/v1/ledger/events?limit=1000")).await;
        assert!(
            events
                .as_array()
                .expect("events")
                .iter()
                .any(|e| e["kind"] == "data.wiped"),
            "a data.wiped event was chained"
        );
    }

    #[tokio::test]
    async fn reset_backend_factory_blanks_everything_after_export_first() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Limpar-Dados6!X").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;
        seal_one_act(&state, &book_id, &token).await;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_factory", "confirm_phrase": "REPOR FÁBRICA",
                            "export_first": true, "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "factory reset: {resp}");
        assert!(
            resp["export_archive"].is_string(),
            "export-first archive taken"
        );

        // Blank first-run: the ledger is gone (empty) — the retained archive IS the record.
        let (_, verify) = send(state.clone(), get("/v1/ledger/verify")).await;
        assert_eq!(verify["length"], 0, "ledger blanked");
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert!(
            entities.as_array().expect("entities").is_empty(),
            "domain blanked"
        );
    }

    #[tokio::test]
    async fn reset_requires_step_up_reauth_and_the_confirm_phrase() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Limpar-Dados6!X").await;
        seed_entity_and_book(&state, &token).await;

        // No re-auth (session only) → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session alone is not enough");

        // Wrong password → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true, "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "wrong step-up refused");

        // Right re-auth but wrong confirm phrase → 422; the domain is untouched throughout.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "wrong",
                            "export_first": true, "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "wrong phrase refused"
        );
        let (_, entities) = send(state.clone(), get("/v1/entities")).await;
        assert_eq!(
            entities.as_array().expect("entities").len(),
            1,
            "domain intact"
        );
    }

    #[tokio::test]
    async fn degraded_gate_blocks_mutations_but_leaves_reads_and_recovery_open() {
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Limpar-Dados6!X").await;
        let (_eid, book_id) = seed_entity_and_book(&state, &token).await;

        // Force the degraded (read-only) signal (as a broken boot chain would).
        *state.degraded.write().await = true;

        // An ordinary mutation is blocked with 503 + the honest read-only body.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/entities",
                    json!({ "name": "X, S.A.", "nipc": "500000000", "seat": "Porto", "kind": "SociedadeAnonima" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "mutation gated");
        assert_eq!(body["read_only"], true);
        assert_eq!(body["integrity"], "broken");

        // Reads stay open.
        let (status, _) = send(state.clone(), get("/v1/entities")).await;
        assert_eq!(status, StatusCode::OK, "reads open while degraded");
        let (status, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report["degraded"], true);

        // The recovery/reset plane stays reachable (NOT 503): each reaches its handler and returns a
        // handler-level status, never the gate's 503.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "wrong",
                            "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "reset reachable while degraded"
        );

        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "x", "reauth": { "password": "Limpar-Dados6!X" } }),
                ),
                &token,
            ),
        )
        .await;
        // The in-memory chain is actually healthy, so reanchor (with valid step-up) refuses with 409 —
        // proving it was REACHED (not 503-gated).
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "reanchor reachable while degraded"
        );

        // Export stays open (archive-first before a repair).
        let (status, _, _) = send_bytes(
            state.clone(),
            with_session(
                post_raw(&format!("/v1/books/{book_id}/export"), Vec::new()),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "export reachable while degraded");
    }

    // --- t69: legacy no-hash self-step-up (the lockout fix) ---------------------------------------

    /// Corrupt the in-memory ledger's tail self-hash so the chain no longer verifies (mirrors the
    /// `try_append` test's break). Used to drive a *real* re-anchor repair (→ 200) rather than the
    /// already-valid 409.
    async fn break_ledger_tail(state: &AppState) {
        let mut events = state.ledger.read().await.events().to_vec();
        let n = events.len();
        assert!(n > 0, "need at least one event to break");
        events[n - 1].hash[0] ^= 0xff;
        let (broken, _) = Ledger::try_from_events(events);
        *state.ledger.write().await = broken;
        assert!(
            !state.ledger.read().await.integrity_report().healthy,
            "chain is broken after tampering"
        );
    }

    #[tokio::test]
    async fn t69_legacy_no_hash_owner_recovers_while_degraded_without_stepup() {
        // t69 lockout fix: a legacy no-hash Owner (no password, no recovery phrase) that already
        // has a session on a DEGRADED instance can still drive the recovery/destructive plane with
        // the session only. POST /v1/session no longer creates such a session; this is test-only
        // legacy-state coverage.
        let state = persistent_state();
        let owner = make_user(&state, "amelia.marques").await;
        clear_password_hash(&state, &owner).await;
        let token = seed_session(&state, &owner).await;
        seed_entity_and_book(&state, &token).await;

        // Enter degraded (read-only) mode, as a broken boot chain would.
        *state.degraded.write().await = true;

        // Re-anchor with NO reauth: the in-memory chain is healthy so it reaches the handler and
        // returns 409 (already valid) — crucially NOT the 403 a missing step-up used to produce.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "legacy no-hash Owner reaches reanchor (no step-up 403): {body}"
        );

        // Data reset (backend_domain) with the correct confirm phrase and NO reauth → 200. Step-up
        // is satisfied by the self session; the type-to-confirm phrase is still required.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "legacy no-hash Owner completes a domain reset without step-up: {resp}"
        );

        // The type-to-confirm phrase is STILL enforced (a no-hash user is not waved through the
        // second confirmation): a wrong phrase is a 422, never a silent wipe.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "errado",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "type-to-confirm phrase still required for a legacy no-hash user"
        );
    }

    #[tokio::test]
    async fn t69_legacy_no_hash_owner_reanchors_a_broken_chain_and_discloses() {
        // The real repair: a legacy no-hash Owner with a genuinely broken chain re-anchors it with
        // a session only (no step-up) → 200; the disclosure is recorded and the chain verifies again.
        let state = persistent_state();
        let owner = make_user(&state, "amelia.marques").await;
        clear_password_hash(&state, &owner).await;
        let token = seed_session(&state, &owner).await;
        seed_entity_and_book(&state, &token).await;

        break_ledger_tail(&state).await;
        *state.degraded.write().await = true;

        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar cadeia partida" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "legacy no-hash Owner re-anchors a broken chain without step-up: {resp}"
        );
        // Re-anchor DISCLOSES (never erases): the permanent, chained disclosure is present.
        assert!(
            resp["record"]["pre_reanchor_digest"].is_string(),
            "re-anchor disclosure (pre_reanchor_digest) recorded: {resp}"
        );
        // The chain verifies again — recovery actually succeeded.
        let (_, report) = send(state.clone(), get("/v1/ledger/integrity")).await;
        assert_eq!(report["healthy"], true, "chain repaired");
    }

    #[tokio::test]
    async fn t69_legacy_no_hash_leitor_is_403_by_rbac_not_a_stepup_bypass() {
        // The relaxation is SELF-step-up ONLY; RBAC stays the primary gate. A legacy no-hash Leitor
        // (lacks ledger.recover / data.wipe) is refused with a PERMISSION 403 — never waved through
        // by the no-hash step-up carve-out. (`require_permission` runs before `require_step_up`.)
        use chancela_authz::{LEITOR_ROLE_ID, RoleAssignment, Scope};
        let state = persistent_state();
        let leitor = seed_user(
            &state,
            "amelia.marques",
            vec![RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global)],
        )
        .await;
        let token = seed_session(&state, &leitor.to_string()).await;
        *state.degraded.write().await = true;

        // Re-anchor → 403 on the permission gate (not a step-up bypass).
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "tentativa sem permissão" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Leitor cannot re-anchor: {body}"
        );
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "refused by RBAC (permission), not a step-up bypass: {body}"
        );

        // Data reset (correct phrase, so the phrase check passes) → 403 on the permission gate too.
        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/data/reset",
                    json!({ "scope": "backend_domain", "confirm_phrase": "LIMPAR DADOS",
                            "export_first": true }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Leitor cannot reset data: {body}"
        );
        assert!(
            body["error"].as_str().expect("error").contains("permissão"),
            "refused by RBAC (permission): {body}"
        );
    }

    #[tokio::test]
    async fn t69_credentialed_user_step_up_is_unchanged() {
        // The carve-out is ONLY for a user who holds NO credential. A user WITH a password must still
        // prove it: session-only and wrong-password both 403; the correct password proceeds (here to
        // a real 200 repair). Guards against the legacy no-hash relaxation leaking to credentialed users.
        let state = persistent_state();
        let token = user_with_password(&state, "amelia.marques", "Recuperar-Base7!").await;
        seed_entity_and_book(&state, &token).await;
        break_ledger_tail(&state).await;
        *state.degraded.write().await = true;

        // Session only → 403 (has a password, must supply it).
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar" }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "credentialed session-only still 403"
        );

        // Wrong password → 403.
        let (status, _) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar", "reauth": { "password": "WRONG" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "credentialed wrong password still 403"
        );

        // Correct password → proceeds and repairs → 200.
        let (status, resp) = send(
            state.clone(),
            with_session(
                post_json(
                    "/v1/ledger/recovery/reanchor",
                    json!({ "reason": "reparar", "reauth": { "password": "Recuperar-Base7!" } }),
                ),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "correct password repairs: {resp}");
    }

    #[tokio::test]
    async fn t69_cross_user_legacy_no_hash_target_stays_refused() {
        // The t52 hole stays CLOSED: the self-step-up relaxation must NOT be mistaken for reopening
        // cross-user resets against a legacy no-hash TARGET. A signed-in operator setting a first
        // password on ANOTHER no-hash user is still a uniform 403, and the target is untouched.
        let state = AppState::default();
        let target = make_user(&state, "amelia.marques").await;
        clear_password_hash(&state, &target).await;
        let bruno = make_user(&state, "bruno").await;
        let bruno_tok = open_session(&state, &bruno).await;

        let (status, body) = send(
            state.clone(),
            with_session(
                post_json(
                    &format!("/v1/users/{target}/secret"),
                    json!({ "password": "escolhida-pelo-atacante" }),
                ),
                &bruno_tok,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "cross-user legacy-no-hash target still refused: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não autorizado"),
            "uniform cross-user refusal (t52 intact): {body}"
        );
        let (_, view) = send(state.clone(), get(&format!("/v1/users/{target}"))).await;
        assert_eq!(
            view["has_secret"], false,
            "target untouched (still legacy no-hash)"
        );
    }

    #[tokio::test]
    async fn try_append_rejects_a_chain_breaking_mutation() {
        // In-memory state: an entity + open book, then corrupt the ledger's global tail so any
        // further append onto that chain must be rejected by the validating try_append (t54 #6).
        let (state, _eid, book_id) = entity_and_open_book("SociedadeAnonima").await;
        {
            let mut events = state.ledger.read().await.events().to_vec();
            let n = events.len();
            events[n - 1].hash[0] ^= 0xff; // break the tail's self-hash
            let (broken, _) = Ledger::try_from_events(events);
            *state.ledger.write().await = broken;
        }

        // Drafting an act joins the (now broken-tailed) chain → try_append rejects it → 409, and
        // nothing is persisted.
        let (status, body) = send(
            state.clone(),
            post_json(
                "/v1/acts",
                json!({ "book_id": book_id, "title": "Ata", "channel": "Physical" }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "chain-breaking append rejected: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("break a chain"),
            "the refusal names the chain-break cause: {body}"
        );
    }
}
