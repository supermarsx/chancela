//! # chancela-store
//!
//! The **durable system of record** for Chancela (t30, Wave A). It makes a process restart
//! never lose an entity, book, act, or ledger event, and provides the minimum trustworthy
//! hot-backup escape hatch.
//!
//! The store is an embedded single-file SQLite database (`<data_dir>/chancela.db`, WAL mode)
//! holding the four durable domain aggregates (`entity` / `book` / `act` / `registry_extract`)
//! as document-in-relational rows plus the append-only, hash-chained `events` table (the
//! integrity chain from [`chancela_ledger`], which today evaporates on restart). See
//! `.orchestration/plans/t30.md` for the full design (rulings D1–D6, §2 architecture).
//!
//! ## Position in the workspace DAG
//!
//! `chancela-core`, `chancela-ledger`, `chancela-registry` → **`chancela-store`** →
//! `chancela-api` → `chancela-server` / desktop. The store owns the data plane so `chancela-core`
//! stays pure (ARC-01) and `chancela-api` stays thin (ARC-02); it **must not** depend on
//! `chancela-api` (no cycle).
//!
//! ## Usage shape (bodies filled by t30-e1; this crate freezes the §3.1 API surface)
//!
//! ```ignore
//! let store = Store::open(data_dir)?;             // opens chancela.db, WAL, runs migration
//! let loaded = store.load()?;                     // aggregates + ledger + boot-verify outcome
//! store.persist(|tx| {                            // one transaction: event + changed aggregate
//!     tx.append_event(&event)?;
//!     tx.upsert_entity(&entity)?;
//!     Ok(())
//! })?;
//! let manifest = store.backup(data_dir, &sidecars)?; // VACUUM INTO + zip + manifest
//! ```

pub mod dialect;
#[cfg(feature = "postgres")]
pub(crate) mod pg;
#[cfg(feature = "postgres")]
pub(crate) mod pg_backup;
// wp16 P0 — Postgres advisory-lock leader election / step-down / failover-handoff primitives.
#[cfg(feature = "postgres")]
pub(crate) mod pg_cluster;
pub mod recovery;
pub mod schema;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_ledger::{
    AppendError, ChainId, ChainLink, Event, EventId, IntegrityReport, Ledger, LedgerError,
};
use chancela_registry::RegistryExtract;
use rand_core::{OsRng, RngCore};
use rusqlite::types::Value;
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

/// The database file created inside the data directory passed to [`Store::open`].
pub const DB_FILE: &str = "chancela.db";

/// The fixed primary-key value for the single-row `settings` table (schema v16, wp16 P3b). The
/// settings sidecar is one document, so it lives as one row keyed by this constant; [`Tx::put_settings`]
/// upserts it and [`Store::settings`] reads it back.
pub const SETTINGS_SINGLETON_ID: &str = "settings";

/// wp16 P1 — the Postgres `LISTEN/NOTIFY` channel the leader signals a durable ledger append on and
/// that followers listen on for near-real-time change-feed wakes (plan §2.2). The payload is the new
/// durable `MAX(seq)`; delivery is best-effort, so a follower's seq-poll backstop keeps retrying
/// after missed notifications. Exposed so the API-layer follower change-feed uses the identical
/// channel name.
pub const CLUSTER_CHANGE_CHANNEL: &str = "chancela_ledger";

/// Prefix identifying an encrypted whole-instance backup envelope.
pub const BACKUP_ENVELOPE_MAGIC: &[u8] = b"chancela-backup-envelope/v1\n";
const SQLITE_PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";
const BACKUP_ENVELOPE_FORMAT: &str = "chancela-backup-envelope/v1";
const BACKUP_KDF: &str = "argon2id-default";
const BACKUP_AEAD: &str = "XChaCha20-Poly1305";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEnvelopeHeader {
    format: String,
    kdf: String,
    aead: String,
    salt_hex: String,
    nonce_hex: String,
    plaintext_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEnvelope {
    #[serde(flatten)]
    header: BackupEnvelopeHeader,
    ciphertext_hex: String,
}

/// Errors surfaced by the durable store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An error from the underlying SQLite engine (open, migrate, query, transaction).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// An error from the PostgreSQL backend (open, migrate, query, transaction). Only present when
    /// the `postgres` feature is enabled (wp14 Phase 1).
    #[cfg(feature = "postgres")]
    #[error("postgres error: {0}")]
    Postgres(#[from] postgres::Error),
    /// A connection-pool error from the PostgreSQL read pool (`r2d2`). Only present when the
    /// `postgres` feature is enabled.
    #[cfg(feature = "postgres")]
    #[error("postgres connection pool error: {0}")]
    R2d2(#[from] r2d2::Error),
    /// A store operation was invoked on the PostgreSQL backend that is not yet ported to it
    /// (wp14 Phase 1). These paths still funnel through the SQLite-only `Tx::raw` / connection
    /// accessors and fail closed here with a clear, named operation rather than misbehaving. See
    /// [`crate::pg`] for the supported-vs-deferred split (recovery, backup/restore, blob/paged
    /// reads, and the non-core `Tx` writers are deferred to the testcontainers lane).
    #[error("operation not supported on the postgres backend yet: {op}")]
    UnsupportedOnPostgres {
        /// The store operation that is not yet available on the Postgres backend.
        op: &'static str,
    },
    /// A filesystem error (creating the data dir, the backup archive, reading a sidecar).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Serializing a domain aggregate to / from its `json` column, or a manifest.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A ledger append failed while a store transaction was being prepared.
    #[error("ledger append error: {0}")]
    LedgerAppend(#[source] Box<AppendError>),
    /// Writing the hot-backup zip archive.
    #[error("backup archive error: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The on-disk database was written by an incompatible (usually newer) schema version.
    #[error("unsupported store schema version {found} (this build supports {supported})")]
    UnsupportedSchemaVersion {
        /// The `schema_version` read from the database's `meta` table.
        found: i64,
        /// The `schema_version` this build knows how to operate ([`schema::SCHEMA_VERSION`]).
        supported: i64,
    },
    /// A backup was requested but the store has no on-disk location to snapshot (in-memory mode).
    #[error("backup requires on-disk persistence")]
    NotPersistent,
    /// wp16 P0: this node is not the elected cluster writer-leader (it is a follower, or a former
    /// leader that lost the advisory lock / had its `leader_epoch` fenced / lost its writer session).
    /// The write path fails closed with this rather than committing on a non-leader session, so at
    /// most one writer ever appends to the chain; the API maps it to a `503` "not leader".
    #[error("this node is not the cluster writer-leader")]
    NotLeader,
    /// A per-book import was refused because its book id already exists (live or imported) and the
    /// [`recovery::CollisionPolicy`] is `Refuse` — the safe default. Ids cannot be renamed on import
    /// without re-hashing (which would destroy the chain's tamper-evidence), so the only choices are
    /// refuse or quarantine-copy under the original ids (t54 §2.5).
    #[error("import refused: book id {book_id} already exists (collision policy = Refuse)")]
    ImportCollision {
        /// The colliding book id (the bundle's original id).
        book_id: String,
    },
    /// A bundle could not even be parsed enough to record provenance (not a zip, no `manifest.json`,
    /// or a wrong `format`). Distinct from a *tampered* bundle whose manifest parses but whose member
    /// digests / book chain fail verification — that is quarantined (not trusted), never merged.
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
    /// A whole-store restore refused a backup archive that did not verify **before** the swap: a
    /// member sha256 did not match the manifest, or the snapshot's ledger did not verify `Ok`. A bad
    /// backup is never trusted; the live store is left untouched (t54 §2.5 / §4.1(6)).
    #[error("bad backup: {0}")]
    BadBackup(String),
    /// A recovery/lifecycle operation could not locate a required aggregate (e.g. the book to
    /// export/start-over was not found in the store).
    #[error("not found: {0}")]
    NotFound(String),
    /// A store encryption key was supplied to a build that was not compiled with SQLCipher support.
    #[error(
        "store encryption key supplied but this build was not compiled with the sqlcipher feature; \
         rebuild with sqlcipher before enabling database encryption or remove the configured key to \
         keep the plaintext store"
    )]
    EncryptionUnavailable,
    /// A caller tried to convert an existing plaintext SQLite store by simply supplying a key.
    ///
    /// Direct keyed open is only safe for a fresh SQLCipher store or an already-encrypted store.
    /// Plaintext-to-encrypted migration must be an explicit backup/export-restore workflow so a
    /// default build never pretends to encrypt an existing plaintext database in place.
    #[error(
        "plaintext-to-encrypted store migration is not supported by direct keyed open; refusing to \
         rewrite plaintext SQLite database at {db_file}. Use the supported backup/export-restore \
         migration plan: back up/export the plaintext instance, restore into a fresh \
         SQLCipher-enabled store, verify the restored ledger, then retire the plaintext copy; or \
         remove the configured database key to keep plaintext"
    )]
    PlaintextEncryptionMigrationUnsupported {
        /// The plaintext database file that triggered the migration guard.
        db_file: String,
    },
    /// SQLCipher keying/rekeying was asked to use an empty key. Empty keys are rejected before
    /// touching the database so a caller cannot accidentally decrypt or weaken an encrypted store.
    #[error("store encryption key must not be empty")]
    EmptyEncryptionKey,
    /// SQLCipher refused the supplied key, or the database could not be authenticated with it.
    #[error("store encryption key was rejected or the encrypted database is unreadable")]
    EncryptionKeyRejected {
        /// The lower-level SQLite error produced while authenticating the keyed database.
        #[source]
        source: rusqlite::Error,
    },
}

impl From<AppendError> for StoreError {
    fn from(error: AppendError) -> Self {
        Self::LedgerAppend(Box::new(error))
    }
}

/// A handle to the durable store. Cheap to clone (shares one connection via `Arc`) and lives in
/// `chancela_api::AppState`.
///
/// The default SQLite arm uses one WAL-mode connection; the optional Postgres arm uses its own
/// pool/writer shape behind the same facade.
///
/// The concrete storage engine lives behind the internal [`Backend`] enum (wp14 Phase 0). The
/// public `Store` / [`Tx`] API is a byte-identical facade over it: every method delegates to the
/// backend arm. Phase 0 ships a single [`Backend::Sqlite`] arm holding today's rusqlite connection
/// verbatim, so a future `Postgres` arm can be added without changing any `Store`/`Tx` signature or
/// any of the ~35 `chancela-api` call sites.
#[derive(Debug, Clone)]
pub struct Store {
    /// The storage backend this facade delegates to. `pub(crate)` so the [`recovery`] module can
    /// reach the connection (through [`Store::conn`]) to swap it during a whole-store restore.
    pub(crate) backend: Backend,
}

/// The storage backend behind the public [`Store`] facade (wp14 Phase 0 seam).
///
/// This is an internal enum, not part of the frozen §3.1 API surface. All SQLite-specific
/// SQL/DDL/connection handling stays inside the SQLite arm, while Postgres-specific connection and
/// projection code stays behind the off-by-default feature-gated arm.
#[derive(Debug, Clone)]
pub(crate) enum Backend {
    /// The embedded SQLite / SQLCipher backend — the default, and the only backend compiled into
    /// the desktop/browser editions.
    Sqlite(SqliteBackend),
    /// The PostgreSQL backend for the self-hosted server edition (wp14 Phase 1). Only present when
    /// the off-by-default `postgres` feature is enabled; see [`crate::pg`].
    #[cfg(feature = "postgres")]
    Postgres(pg::PostgresBackend),
}

/// The rusqlite-backed backend arm: one WAL-mode connection, shared and mutex-guarded. rusqlite is
/// synchronous, so a mutation takes this lock for the (tiny, local) duration of its transaction.
#[derive(Debug, Clone)]
pub(crate) struct SqliteBackend {
    /// The one SQLite connection, shared and mutex-guarded.
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteBackend {
    /// Open (creating if absent) `<data_dir>/chancela.db` with the given options and wrap the
    /// resulting connection in the shared, mutex-guarded handle. All the SQLite-specific open path
    /// (SQLCipher keyed open, PRAGMAs, idempotent DDL migration) stays in [`open_connection_with_options`].
    fn open(data_dir: &Path, options: &StoreOpenOptions) -> Result<Self, StoreError> {
        let conn = open_connection_with_options(data_dir, options)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

/// Query shape for [`Store::ledger_events_page`].
///
/// The store returns newest-first events using the global `seq` as the cursor. `before_seq` is an
/// exclusive upper cursor boundary: passing a previous page's `next_cursor` fetches older events.
/// Cheap row predicates are pushed into SQLite, while filters that require reconstructed
/// [`Event`] values (chain membership and free-text search) are applied after row mapping.
#[derive(Debug, Clone)]
pub struct LedgerEventPageQuery {
    /// Exclusive cursor boundary over the global ledger sequence.
    pub before_seq: Option<u64>,
    /// Requested page size. The store clamps this to at least one event.
    pub limit: usize,
    /// Optional chain filter. [`ChainId::Global`] is equivalent to no chain filter.
    pub chain: Option<ChainId>,
    /// Free-text search across the same event fields exposed by the API ledger filters.
    pub q: Option<String>,
    /// Case-sensitive substring match against `event.scope`.
    pub scope: Option<String>,
    /// Exact event kind filter. Entries may be repeatable or comma-separated.
    pub kinds: Vec<String>,
    /// Exact actor filter.
    pub actor: Option<String>,
    /// Inclusive lower timestamp bound.
    pub from: Option<OffsetDateTime>,
    /// Upper timestamp bound.
    pub to: Option<LedgerEventUpperBound>,
}

/// Upper timestamp bound for [`LedgerEventPageQuery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerEventUpperBound {
    /// Include events whose timestamp equals this bound.
    Inclusive(OffsetDateTime),
    /// Exclude events whose timestamp equals this bound.
    Exclusive(OffsetDateTime),
}

impl LedgerEventUpperBound {
    fn contains(self, timestamp: OffsetDateTime) -> bool {
        match self {
            Self::Inclusive(to) => timestamp <= to,
            Self::Exclusive(to) => timestamp < to,
        }
    }
}

/// Newest-first persisted event page returned by [`Store::ledger_events_page`].
#[derive(Debug, Clone)]
pub struct LedgerEventPage {
    /// Events in `seq DESC` order.
    pub events: Vec<Event>,
    /// Cursor for the next older page, when one exists.
    pub next_cursor: Option<u64>,
    /// Whether another older page exists for this query.
    pub has_more: bool,
    /// Effective page size used by the store.
    pub limit: usize,
}

/// Normalize ledger free-text search the same way the archive UI's `livros` search does:
/// lowercase and fold common Latin diacritics while leaving all other substring semantics intact.
pub fn normalize_ledger_event_search_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars().flat_map(|c| c.to_lowercase()) {
        match c {
            '\u{0300}'..='\u{036f}' => {}
            '\u{00e0}' | '\u{00e1}' | '\u{00e2}' | '\u{00e3}' | '\u{00e4}' | '\u{00e5}' => {
                out.push('a')
            }
            '\u{00e7}' => out.push('c'),
            '\u{00e8}' | '\u{00e9}' | '\u{00ea}' | '\u{00eb}' => out.push('e'),
            '\u{00ec}' | '\u{00ed}' | '\u{00ee}' | '\u{00ef}' => out.push('i'),
            '\u{00f1}' => out.push('n'),
            '\u{00f2}' | '\u{00f3}' | '\u{00f4}' | '\u{00f5}' | '\u{00f6}' => out.push('o'),
            '\u{00f9}' | '\u{00fa}' | '\u{00fb}' | '\u{00fc}' => out.push('u'),
            '\u{00fd}' | '\u{00ff}' => out.push('y'),
            '\u{00e6}' => out.push_str("ae"),
            '\u{0153}' => out.push_str("oe"),
            '\u{00df}' => out.push_str("ss"),
            other => out.push(other),
        }
    }
    out
}

/// Options for opening the durable store.
///
/// By default no SQLCipher key is supplied, so [`Store::open`] and [`StoreOpenOptions::default`]
/// preserve the existing plaintext SQLite behavior. When the `sqlcipher` feature is enabled and a
/// key is supplied, the key is applied immediately after opening the SQLite handle and before any
/// schema query, migration, or PRAGMA touches the database.
#[derive(Clone, Default)]
pub struct StoreOpenOptions {
    encryption_key: Option<String>,
}

impl std::fmt::Debug for StoreOpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreOpenOptions")
            .field(
                "encryption_key",
                &self.encryption_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl StoreOpenOptions {
    /// Build default open options (no at-rest encryption key).
    pub fn new() -> Self {
        Self::default()
    }

    /// Supply the SQLCipher passphrase for a keyed database open.
    pub fn with_encryption_key(mut self, key: impl Into<String>) -> Self {
        self.encryption_key = Some(key.into());
        self
    }

    fn encryption_key(&self) -> Option<&str> {
        self.encryption_key.as_deref()
    }

    fn key_config_status(&self) -> StoreKeyConfigStatus {
        match self.encryption_key() {
            None => StoreKeyConfigStatus::Unconfigured,
            Some(key) if key.trim().is_empty() => StoreKeyConfigStatus::Empty,
            Some(_) => StoreKeyConfigStatus::Configured,
        }
    }
}

/// Which backend [`Store::open_backend`] should open (wp14 Phase 1, §2.4).
///
/// SQLite is the default and the only variant available to the embedded desktop/browser editions.
/// The `Postgres` variant only exists when the off-by-default `postgres` feature is compiled in, so
/// a stray `CHANCELA_DB_BACKEND=postgres` in an embedded build cannot even construct this — it fails
/// closed at the type level (the same fail-closed spirit as [`StoreError::EncryptionUnavailable`]).
#[derive(Debug, Clone)]
pub enum StoreBackendSelection {
    /// The embedded SQLite / SQLCipher backend (default). `data_dir` holds `chancela.db`.
    Sqlite {
        /// The data directory that holds (or will hold) `chancela.db`.
        data_dir: PathBuf,
        /// Open options (optional SQLCipher key).
        options: StoreOpenOptions,
    },
    /// The PostgreSQL backend for the self-hosted server edition.
    #[cfg(feature = "postgres")]
    Postgres {
        /// A libpq connection string, e.g. `postgres://user:pass@host:5432/chancela?sslmode=require`.
        database_url: String,
    },
}

/// Secret-free classification of the configured database key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKeyConfigStatus {
    /// No database encryption key was configured.
    Unconfigured,
    /// A key source was configured, but it resolved to an empty or whitespace-only value.
    Empty,
    /// A non-empty key was configured. The key material is never exposed by status reporting.
    Configured,
}

/// What the store can infer from the database file header without opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreDatabaseFormat {
    /// No `<data_dir>/chancela.db` file exists yet.
    Missing,
    /// The file has SQLite's plaintext header.
    PlaintextSqlite,
    /// The file is not plaintext SQLite. It may be SQLCipher-encrypted, corrupt, or otherwise not
    /// a Chancela SQLite store; the status surface deliberately does not claim live encryption.
    NonPlaintextOrEncrypted,
}

/// Operator-facing key operations plan for the current build, key config, and database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKeyOpsPlan {
    /// No key is configured and no database exists; startup would create a plaintext SQLite store.
    CreatePlaintextStore,
    /// No key is configured and the database is plaintext SQLite.
    OpenPlaintextStore,
    /// No key is configured but the database is not plaintext SQLite.
    KeyRequiredForNonPlaintextStore,
    /// A key source was configured but resolved to an empty value.
    RejectEmptyKey,
    /// A key is configured but this build cannot operate SQLCipher stores.
    SqlcipherBuildRequired,
    /// SQLCipher support is available and a configured key can create a fresh encrypted store.
    CreateEncryptedStore,
    /// SQLCipher support is available and a configured key can attempt an encrypted-store open.
    OpenEncryptedStore,
    /// An existing plaintext SQLite database must not be converted by direct keyed open.
    RefusePlaintextToEncryptedMigration,
}

/// One operator-safe step in a plaintext-to-encrypted store migration plan.
///
/// These steps are descriptive only. They never perform a migration and never carry key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyOpsMigrationStep {
    /// Stable 1-based step order for operator displays.
    pub order: u8,
    /// Short operator-facing step title.
    pub title: &'static str,
    /// Concrete action text. This must stay secret-free.
    pub detail: &'static str,
    /// Whether the step rewrites or deletes the source plaintext database.
    pub source_destructive: bool,
}

/// Non-secret evidence used to explain why a migration plan is or is not required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyOpsMigrationEvidence {
    /// The key-ops plan that produced this migration status.
    pub plan: &'static str,
    /// Header-level database format observed without opening the database.
    pub database_format: &'static str,
    /// Secret-free classification of key configuration.
    pub key_config: &'static str,
    /// Whether this build can open SQLCipher databases.
    pub sqlcipher_available: bool,
    /// The database path inspected by preflight.
    pub database_file: String,
}

/// Structured, secret-free migration guidance attached to key-ops status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyOpsMigrationPlan {
    /// Whether plaintext-to-encrypted migration is required for the current status.
    pub required: bool,
    /// Stable status code for API/CLI displays.
    pub status: &'static str,
    /// Operator-facing summary. This must stay secret-free.
    pub summary: &'static str,
    /// Ordered operator actions. Empty when `required` is false.
    pub steps: Vec<StoreKeyOpsMigrationStep>,
    /// Non-secret evidence for the status decision.
    pub evidence: StoreKeyOpsMigrationEvidence,
}

/// Secret-free key operations status for startup banners, CLIs, and focused preflight tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyOpsStatus {
    /// Whether this `chancela-store` build was compiled with the `sqlcipher` feature.
    pub sqlcipher_available: bool,
    /// Whether the configured key source is absent, empty, or non-empty.
    pub key_config: StoreKeyConfigStatus,
    /// The database file inspected for this report.
    pub database_file: PathBuf,
    /// Header-level database format, without claiming the store is actually decryptable.
    pub database_format: StoreDatabaseFormat,
    /// The bounded operation plan implied by the other fields.
    pub plan: StoreKeyOpsPlan,
    /// Structured migration guidance for plaintext-to-encrypted store transitions.
    pub migration_plan: StoreKeyOpsMigrationPlan,
}

/// Operator-facing status for a SQLCipher key rotation request.
///
/// The status is intentionally conservative: `NonPlaintextOrEncrypted` is enough to say a store may
/// be rotation-ready when a current key is configured, but it never claims live encryption until the
/// caller opens the store with SQLCipher and authenticates the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKeyRotationStatus {
    /// A non-empty current key and replacement key are configured for an existing non-plaintext
    /// store, and this build has SQLCipher support.
    Ready,
    /// No database exists yet; rotation only applies to an existing keyed store.
    StoreMissing,
    /// A plaintext SQLite store cannot be rekeyed into an encrypted store.
    PlaintextStoreNotRotatable,
    /// The existing store is not plaintext SQLite, but no current SQLCipher key was configured.
    CurrentKeyRequired,
    /// The configured current key source resolved to an empty value.
    RejectEmptyCurrentKey,
    /// The requested replacement key is empty.
    RejectEmptyNewKey,
    /// The store may need SQLCipher, but this build was not compiled with SQLCipher support.
    SqlcipherBuildRequired,
}

/// Non-secret evidence used to explain a key-rotation preflight decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyRotationEvidence {
    /// Header-level database format observed without opening the database.
    pub database_format: &'static str,
    /// Secret-free classification of the current key configuration.
    pub current_key_config: &'static str,
    /// Secret-free classification of the requested replacement key.
    pub requested_key_config: &'static str,
    /// Whether this build can operate SQLCipher databases.
    pub sqlcipher_available: bool,
    /// The database path inspected by preflight.
    pub database_file: String,
}

/// Secret-free preflight for a SQLCipher key rotation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyRotationPreflight {
    /// Whether the caller can proceed to open the store with the current key and rekey it.
    pub ready: bool,
    /// Stable status code for operator displays and tests.
    pub status: StoreKeyRotationStatus,
    /// Secret-free operator next action.
    pub next_action: &'static str,
    /// Non-secret evidence for the status decision.
    pub evidence: StoreKeyRotationEvidence,
}

/// Status returned after a SQLCipher rekey request has completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKeyRotationExecutionStatus {
    /// SQLCipher accepted the `PRAGMA rekey` request and the store was readable afterwards.
    RekeyApplied,
}

/// Non-secret evidence for a completed key rotation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyRotationExecutionEvidence {
    /// Stable operation code. This deliberately names the primitive, not any key material.
    pub operation: &'static str,
    /// Secret-free classification of the replacement key.
    pub requested_key_config: &'static str,
    /// Whether this build can operate SQLCipher databases.
    pub sqlcipher_available: bool,
    /// Whether the WAL was checkpointed before issuing `PRAGMA rekey`.
    pub checkpointed_before_rekey: bool,
    /// Whether the WAL was checkpointed after `PRAGMA rekey`.
    pub checkpointed_after_rekey: bool,
    /// Whether the durable ledger was read and checked after rekey.
    pub post_rekey_integrity_checked: bool,
}

/// Secret-free execution result for an accepted SQLCipher rekey request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreKeyRotationExecution {
    /// Stable execution status.
    pub status: StoreKeyRotationExecutionStatus,
    /// True when SQLCipher accepted the rekey command. This does not expose either key.
    pub rekey_executed: bool,
    /// Result of the post-rekey ledger integrity read.
    pub ledger_integrity_verified: bool,
    /// Number of events in the global ledger spine after rekey.
    pub ledger_length: u64,
    /// Non-secret evidence for audit/status surfaces.
    pub evidence: StoreKeyRotationExecutionEvidence,
}

impl StoreKeyOpsStatus {
    /// Whether a non-empty database key was configured.
    pub fn key_configured(&self) -> bool {
        self.key_config == StoreKeyConfigStatus::Configured
    }

    /// Whether an already-encrypted store can be opened and then rekeyed by this build, assuming the
    /// supplied key authenticates successfully. This never reports true for a plaintext database.
    pub fn rotation_ready(&self) -> bool {
        self.plan == StoreKeyOpsPlan::OpenEncryptedStore
    }

    /// Secret-free next action suitable for logs, CLIs, or startup diagnostics.
    pub fn operator_action(&self) -> &'static str {
        match self.plan {
            StoreKeyOpsPlan::CreatePlaintextStore => {
                "no database key is configured; startup will create a plaintext SQLite store"
            }
            StoreKeyOpsPlan::OpenPlaintextStore => {
                "no database key is configured; startup will open the plaintext SQLite store"
            }
            StoreKeyOpsPlan::KeyRequiredForNonPlaintextStore => {
                "database is not plaintext SQLite; configure the correct SQLCipher key if this is \
                 an encrypted store"
            }
            StoreKeyOpsPlan::RejectEmptyKey => {
                "configure a non-empty database key, or remove the key setting to keep plaintext"
            }
            StoreKeyOpsPlan::SqlcipherBuildRequired => {
                "database key is configured, but this build lacks SQLCipher; rebuild with the \
                 sqlcipher feature before enabling encryption, or remove the key to keep plaintext"
            }
            StoreKeyOpsPlan::CreateEncryptedStore => {
                "SQLCipher is available and no database exists; a configured key can create a fresh \
                 encrypted store"
            }
            StoreKeyOpsPlan::OpenEncryptedStore => {
                "SQLCipher is available; open the existing non-plaintext store with the configured \
                 key before attempting rotation"
            }
            StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration => {
                "plaintext SQLite database already exists; direct keyed open will not convert it in \
                 place. Use the supported backup/export-restore migration plan into a fresh \
                 SQLCipher store, verify the restored ledger, or remove the key to keep plaintext"
            }
        }
    }
}

impl StoreKeyRotationStatus {
    /// Secret-free next action suitable for logs, CLIs, or startup diagnostics.
    pub fn operator_action(self) -> &'static str {
        match self {
            StoreKeyRotationStatus::Ready => {
                "open the existing non-plaintext store with the current key and issue SQLCipher \
                 rekey with the replacement key"
            }
            StoreKeyRotationStatus::StoreMissing => {
                "no database exists yet; create or restore a keyed store before requesting key \
                 rotation"
            }
            StoreKeyRotationStatus::PlaintextStoreNotRotatable => {
                "plaintext SQLite cannot be rekeyed in place; use the supported \
                 backup/export-restore migration plan into a fresh SQLCipher store"
            }
            StoreKeyRotationStatus::CurrentKeyRequired => {
                "configure the current SQLCipher key before requesting rotation; the replacement \
                 key alone cannot authenticate the existing store"
            }
            StoreKeyRotationStatus::RejectEmptyCurrentKey => {
                "configure a non-empty current database key before requesting rotation"
            }
            StoreKeyRotationStatus::RejectEmptyNewKey => {
                "provide a non-empty replacement database key; no rekey should be attempted"
            }
            StoreKeyRotationStatus::SqlcipherBuildRequired => {
                "rebuild with the sqlcipher feature before rotating a non-plaintext store key"
            }
        }
    }
}

impl StoreKeyRotationPreflight {
    /// Whether the preflight permits an operator to attempt SQLCipher rekey.
    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Secret-free next action suitable for logs, CLIs, or startup diagnostics.
    pub fn operator_action(&self) -> &'static str {
        self.next_action
    }
}

impl StoreKeyOpsMigrationPlan {
    fn for_status(
        plan: StoreKeyOpsPlan,
        database_format: StoreDatabaseFormat,
        key_config: StoreKeyConfigStatus,
        sqlcipher_available: bool,
        database_file: &Path,
    ) -> Self {
        let evidence = StoreKeyOpsMigrationEvidence {
            plan: store_key_ops_plan_code(plan),
            database_format: store_database_format_code(database_format),
            key_config: store_key_config_status_code(key_config),
            sqlcipher_available,
            database_file: database_file.display().to_string(),
        };

        if plan != StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration {
            return Self {
                required: false,
                status: "not_required",
                summary: "no plaintext-to-encrypted export/restore migration is required for this key-ops status",
                steps: Vec::new(),
                evidence,
            };
        }

        Self {
            required: true,
            status: "refuse_direct_plaintext_to_encrypted_migration",
            summary: "direct keyed open is refused; use backup/export-restore into a fresh SQLCipher-enabled store",
            steps: vec![
                StoreKeyOpsMigrationStep {
                    order: 1,
                    title: "backup_export_plaintext",
                    detail: "start the existing plaintext instance without a database key and create a verified backup/export before changing encryption settings",
                    source_destructive: false,
                },
                StoreKeyOpsMigrationStep {
                    order: 2,
                    title: "create_fresh_encrypted_store",
                    detail: "provision a fresh data directory with a SQLCipher-enabled build and the configured database key",
                    source_destructive: false,
                },
                StoreKeyOpsMigrationStep {
                    order: 3,
                    title: "restore_and_verify",
                    detail: "restore/import the verified backup/export into the fresh encrypted store and verify the ledger before promoting it",
                    source_destructive: false,
                },
                StoreKeyOpsMigrationStep {
                    order: 4,
                    title: "retain_plaintext_until_cutover",
                    detail: "keep the original plaintext database untouched until the encrypted restore is verified and operational",
                    source_destructive: false,
                },
            ],
            evidence,
        }
    }
}

fn classify_key_rotation_status(
    database_format: StoreDatabaseFormat,
    current_key_config: StoreKeyConfigStatus,
    requested_key_config: StoreKeyConfigStatus,
    sqlcipher_available: bool,
) -> StoreKeyRotationStatus {
    if requested_key_config == StoreKeyConfigStatus::Empty {
        return StoreKeyRotationStatus::RejectEmptyNewKey;
    }
    if current_key_config == StoreKeyConfigStatus::Empty {
        return StoreKeyRotationStatus::RejectEmptyCurrentKey;
    }

    match database_format {
        StoreDatabaseFormat::Missing => StoreKeyRotationStatus::StoreMissing,
        StoreDatabaseFormat::PlaintextSqlite => StoreKeyRotationStatus::PlaintextStoreNotRotatable,
        StoreDatabaseFormat::NonPlaintextOrEncrypted => {
            if current_key_config == StoreKeyConfigStatus::Unconfigured {
                StoreKeyRotationStatus::CurrentKeyRequired
            } else if !sqlcipher_available {
                StoreKeyRotationStatus::SqlcipherBuildRequired
            } else {
                StoreKeyRotationStatus::Ready
            }
        }
    }
}

fn store_key_config_status_code(status: StoreKeyConfigStatus) -> &'static str {
    match status {
        StoreKeyConfigStatus::Unconfigured => "unconfigured",
        StoreKeyConfigStatus::Empty => "empty",
        StoreKeyConfigStatus::Configured => "configured",
    }
}

fn store_database_format_code(format: StoreDatabaseFormat) -> &'static str {
    match format {
        StoreDatabaseFormat::Missing => "missing",
        StoreDatabaseFormat::PlaintextSqlite => "plaintext_sqlite",
        StoreDatabaseFormat::NonPlaintextOrEncrypted => "non_plaintext_or_encrypted",
    }
}

fn store_key_ops_plan_code(plan: StoreKeyOpsPlan) -> &'static str {
    match plan {
        StoreKeyOpsPlan::CreatePlaintextStore => "create_plaintext_store",
        StoreKeyOpsPlan::OpenPlaintextStore => "open_plaintext_store",
        StoreKeyOpsPlan::KeyRequiredForNonPlaintextStore => "key_required_for_non_plaintext_store",
        StoreKeyOpsPlan::RejectEmptyKey => "reject_empty_key",
        StoreKeyOpsPlan::SqlcipherBuildRequired => "sqlcipher_build_required",
        StoreKeyOpsPlan::CreateEncryptedStore => "create_encrypted_store",
        StoreKeyOpsPlan::OpenEncryptedStore => "open_encrypted_store",
        StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration => {
            "refuse_plaintext_to_encrypted_migration"
        }
    }
}

/// Everything [`Store::load`] reconstructs from disk on boot: the four aggregate read-models, the
/// rehydrated ledger, and the boot-time chain verification outcome (§D-boot).
///
/// `chain_status` is the `verify()` result of the rehydrated chain: `Ok(len)` when the chain is
/// intact, or the first [`LedgerError`] when it is broken. A broken chain is surfaced loudly but
/// **never** refuses startup — `chancela-api` records it and the server still boots so the operator
/// can inspect and restore.
#[derive(Debug)]
pub struct LoadedState {
    /// All entities, keyed by id — loaded into `AppState.entities`.
    pub entities: HashMap<EntityId, Entity>,
    /// All books, keyed by id — loaded into `AppState.books`.
    pub books: HashMap<BookId, Book>,
    /// All acts, keyed by id — loaded into `AppState.acts`.
    pub acts: HashMap<ActId, Act>,
    /// All imported certidão extracts, keyed by the owning entity id.
    pub registry_extracts: HashMap<EntityId, RegistryExtract>,
    /// All act-scoped follow-up/task rows, keyed by id.
    pub follow_ups: HashMap<String, StoredFollowUp>,
    /// The rehydrated hash-chained ledger (events in `seq` order).
    pub ledger: Ledger,
    /// The boot-time `verify()` outcome of the rehydrated chain (§D-boot). Retained for back-compat;
    /// [`integrity`](LoadedState::integrity) is the richer surface E3 serves.
    pub chain_status: Result<u64, LedgerError>,
    /// The full boot-time [`IntegrityReport`] of the rehydrated ledger (t54 deliverable #6): the
    /// global spine + every non-global chain's status, each carrying the precise first
    /// [`ChainBreak`](chancela_ledger::ChainBreak) when broken, the overall `healthy` flag, and the
    /// permanent re-anchor disclosure. This **replaces the silent boot `eprintln!`-and-continue**:
    /// the api (E3) queries this to serve `GET /v1/ledger/integrity` and enter its degraded state.
    /// Open still never blocks on a break — the degraded 503 gate is E3's decision.
    pub integrity: IntegrityReport,
}

/// wp16 P1 — just the aggregate read-models a follower re-reads when it applies a change-feed delta,
/// **without** re-scanning the whole `events` table (plan §2.3). Populated by
/// [`Store::cluster_load_aggregates`]; the follower keeps its incrementally-applied in-memory ledger
/// and swaps these bounded maps in. The document / signed-document read models self-heal on read
/// (store fallback on a miss), so they are not part of this snapshot.
#[derive(Debug)]
pub struct AggregateSnapshot {
    /// All entities, keyed by id.
    pub entities: HashMap<EntityId, Entity>,
    /// All books, keyed by id.
    pub books: HashMap<BookId, Book>,
    /// All acts, keyed by id.
    pub acts: HashMap<ActId, Act>,
    /// All imported certidão extracts, keyed by the owning entity id.
    pub registry_extracts: HashMap<EntityId, RegistryExtract>,
    /// All act-scoped follow-up/task rows, keyed by id.
    pub follow_ups: HashMap<String, StoredFollowUp>,
}

/// A description of one backup archive, returned by [`Store::backup`] and by `POST /v1/backup`
/// (frozen contract, t30.md §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Absolute path to the written `backups/chancela-backup-<utc>.zip`.
    pub path: String,
    /// Total size of the zip archive in bytes.
    pub bytes: u64,
    /// When the backup was taken (UTC, RFC 3339 on the wire).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The application version that produced the backup.
    pub app_version: String,
    /// The store schema version of the snapshotted database ([`schema::SCHEMA_VERSION`]).
    pub store_schema_version: i64,
    /// Number of events in the ledger at snapshot time.
    pub ledger_length: u64,
    /// The chain head hash as lowercase hex, or `None` for an empty ledger.
    pub ledger_head: Option<String>,
    /// Whether the snapshotted chain verified at backup time.
    pub ledger_verified: bool,
    /// Per-file digests of the archive members (the db plus each bundled sidecar).
    pub files: Vec<BackupFile>,
}

/// One member file inside a [`BackupManifest`], with its sha256 for integrity checking on restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// The archive member name (e.g. `chancela.db`, `settings.json`).
    pub name: String,
    /// Lowercase-hex sha256 of the member's bytes.
    pub sha256: String,
    /// The member's size in bytes.
    pub bytes: u64,
}

/// Return whether `bytes` look like a Chancela encrypted backup envelope.
pub fn is_encrypted_backup(bytes: &[u8]) -> bool {
    bytes.starts_with(BACKUP_ENVELOPE_MAGIC)
}

/// Encrypt an existing verified backup zip into a passphrase-protected envelope.
///
/// The caller supplies the passphrase explicitly; the store never reads a key from the data
/// directory and never derives this from account/recovery credentials.
pub fn encrypt_backup_envelope(
    plaintext_zip: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, StoreError> {
    if passphrase.is_empty() {
        return Err(StoreError::BadBackup(
            "backup passphrase must not be empty".to_owned(),
        ));
    }

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_backup_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
        StoreError::BadBackup("could not initialize backup encryption key".to_owned())
    })?;
    let header = BackupEnvelopeHeader {
        format: BACKUP_ENVELOPE_FORMAT.to_owned(),
        kdf: BACKUP_KDF.to_owned(),
        aead: BACKUP_AEAD.to_owned(),
        salt_hex: hex(&salt),
        nonce_hex: hex(&nonce),
        plaintext_sha256: hex(&Sha256::digest(plaintext_zip)),
    };
    let aad = backup_envelope_aad(&header)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext_zip,
                aad: &aad,
            },
        )
        .map_err(|_| StoreError::BadBackup("backup encryption failed".to_owned()))?;

    let envelope = BackupEnvelope {
        header,
        ciphertext_hex: hex(&ciphertext),
    };
    let mut out = Vec::from(BACKUP_ENVELOPE_MAGIC);
    out.extend_from_slice(&serde_json::to_vec_pretty(&envelope)?);
    out.push(b'\n');
    Ok(out)
}

/// Decrypt a passphrase-protected backup envelope back to the legacy verified zip bytes.
pub fn decrypt_backup_envelope(
    envelope_bytes: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, StoreError> {
    if passphrase.is_empty() {
        return Err(StoreError::BadBackup(
            "backup passphrase must not be empty".to_owned(),
        ));
    }
    if !is_encrypted_backup(envelope_bytes) {
        return Err(StoreError::BadBackup(
            "backup is not an encrypted Chancela envelope".to_owned(),
        ));
    }
    let json_bytes = &envelope_bytes[BACKUP_ENVELOPE_MAGIC.len()..];
    let envelope: BackupEnvelope = serde_json::from_slice(json_bytes)
        .map_err(|e| StoreError::BadBackup(format!("bad backup envelope: {e}")))?;
    if envelope.header.format != BACKUP_ENVELOPE_FORMAT {
        return Err(StoreError::BadBackup(format!(
            "unsupported backup envelope format {}",
            envelope.header.format
        )));
    }
    if envelope.header.kdf != BACKUP_KDF || envelope.header.aead != BACKUP_AEAD {
        return Err(StoreError::BadBackup(
            "unsupported backup envelope crypto parameters".to_owned(),
        ));
    }

    let salt = decode_fixed_hex::<16>(&envelope.header.salt_hex, "backup envelope salt")?;
    let nonce = decode_fixed_hex::<24>(&envelope.header.nonce_hex, "backup envelope nonce")?;
    let ciphertext = decode_hex(&envelope.ciphertext_hex, "backup envelope ciphertext")?;
    let key = derive_backup_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
        StoreError::BadBackup("could not initialize backup decryption key".to_owned())
    })?;
    let aad = backup_envelope_aad(&envelope.header)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            StoreError::BadBackup(
                "encrypted backup could not be authenticated or decrypted".to_owned(),
            )
        })?;
    let digest = hex(&Sha256::digest(&plaintext));
    if digest != envelope.header.plaintext_sha256 {
        return Err(StoreError::BadBackup(
            "backup envelope plaintext digest mismatch".to_owned(),
        ));
    }
    Ok(plaintext)
}

/// A generated PDF/A document preserved alongside its sealed act (the `documents` table, schema v2;
/// plan t48 §3.4/D4). Used symmetrically as the argument to [`Tx::upsert_document`] (write) and the
/// return of [`Store::document_for_act`] / [`Store::document_by_id`] (read), so the api's
/// render→write→persist path and its `GET /v1/acts/{id}/document` + seal-response fields code
/// against one shape.
///
/// The PDF is a deterministic function of the frozen record + pinned `template_id`, so the record
/// remains the source of truth (plan D4 "regeneration, not storage-of-truth"); this row preserves
/// the produced bytes and the metadata that binds them (`pdf_digest`, `template_id`, `profile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocument {
    /// The document id (primary key; the upsert is idempotent on it).
    pub id: String,
    /// The owning act — the indexed scope column, keyed as its plain uuid text (mirrors `acts`).
    pub act_id: ActId,
    /// The versioned template spec id recorded verbatim (e.g. `csc-ata-ag/v1`).
    pub template_id: String,
    /// Lowercase-hex sha-256 of [`Self::pdf_bytes`] (the digest bound in the `document.generated` event).
    pub pdf_digest: String,
    /// The rule-pack / profile string the document was produced under.
    pub profile: String,
    /// When the document was generated (UTC); the inscription-ordering field for the by-act read.
    pub created_at: OffsetDateTime,
    /// The PDF/A-2u bytes themselves.
    pub pdf_bytes: Vec<u8>,
}

/// Metadata-only dispatch evidence recorded by an operator for a generated document. This table is
/// for generated absent-owner communications only; it does not store bytes and does not mutate the
/// canonical generated document or sealed act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGeneratedDocumentDispatchEvidence {
    /// Generated document id (`documents.id`) this evidence concerns.
    pub document_id: String,
    /// Deterministic idempotency key scoped by `document_id`.
    pub idempotency_key: String,
    /// Owning act id, denormalized for status/readback queries and ledger payloads.
    pub act_id: ActId,
    /// Generated template id. For this slice it must be `condominio-comunicacao-ausentes/v1`.
    pub template_id: String,
    /// Resolved ledger actor that recorded the evidence.
    pub actor: String,
    /// Operator-recorded dispatch timestamp. This is not delivery confirmation.
    pub dispatched_at: OffsetDateTime,
    /// Optional operator-recorded channel.
    pub channel: Option<String>,
    /// Optional dispatch/reference locator, such as a registered-letter tracking number.
    pub reference: Option<String>,
    /// Optional retained evidence locator.
    pub evidence_reference: Option<String>,
    /// Optional linked non-canonical imported document evidence row.
    pub imported_document_id: Option<String>,
    /// Absent recipients covered by this evidence row.
    pub recipients: Vec<String>,
    /// Optional operator note, stored locally and deliberately excluded from ledger payloads.
    pub operator_note: Option<String>,
    /// When the API recorded this evidence row.
    pub recorded_at: OffsetDateTime,
}

/// Result of idempotently recording generated-document dispatch evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratedDocumentDispatchEvidenceUpsert {
    /// The row was inserted by this transaction.
    Inserted(StoredGeneratedDocumentDispatchEvidence),
    /// The idempotency key already existed; this is the canonical stored row.
    Existing(StoredGeneratedDocumentDispatchEvidence),
}

impl GeneratedDocumentDispatchEvidenceUpsert {
    /// The canonical stored dispatch-evidence row after the idempotent write attempt.
    #[must_use]
    pub const fn evidence(&self) -> &StoredGeneratedDocumentDispatchEvidence {
        match self {
            Self::Inserted(evidence) | Self::Existing(evidence) => evidence,
        }
    }

    /// Whether this transaction inserted the row.
    #[must_use]
    pub const fn inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

/// Operator review state for a preserved, non-canonical imported document. These states describe
/// only the preservation/review workflow; they do not imply OCR, conversion, PDF/A conformance, or
/// legal acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredImportedDocumentReviewStatus {
    /// The import needs ordinary operator review.
    OperatorReviewRequired,
    /// The import is image evidence and needs operator OCR/reading review if required.
    OcrReviewRequired,
    /// The import is a legacy office document and needs operator conversion-policy review.
    CanonicalConversionReviewRequired,
    /// An operator reviewed the preserved original and kept it as non-canonical evidence only.
    ReviewedNonCanonicalOriginalOnly,
    /// An operator rejected the import as usable evidence while still preserving the uploaded bytes.
    RejectedNonCanonicalEvidence,
}

impl StoredImportedDocumentReviewStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorReviewRequired => "operator_review_required",
            Self::OcrReviewRequired => "ocr_review_required",
            Self::CanonicalConversionReviewRequired => "canonical_conversion_review_required",
            Self::ReviewedNonCanonicalOriginalOnly => "reviewed_non_canonical_original_only",
            Self::RejectedNonCanonicalEvidence => "rejected_non_canonical_evidence",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, StoreError> {
        match raw {
            "operator_review_required" => Ok(Self::OperatorReviewRequired),
            "ocr_review_required" => Ok(Self::OcrReviewRequired),
            "canonical_conversion_review_required" => Ok(Self::CanonicalConversionReviewRequired),
            "reviewed_non_canonical_original_only" => Ok(Self::ReviewedNonCanonicalOriginalOnly),
            "rejected_non_canonical_evidence" => Ok(Self::RejectedNonCanonicalEvidence),
            other => Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored imported-document review status {other:?}"),
            ))),
        }
    }
}

/// Metadata for a validated, non-canonical document evidence import (`imported_documents`, schema
/// v5). This is the list/read JSON surface and the ledger-event payload source: it intentionally
/// excludes raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImportedDocumentMeta {
    /// The import id (primary key; generated by the API as a UUID string).
    pub id: String,
    /// Optional owning act scope. `None` means a global, unlinked evidence import.
    pub act_id: Option<ActId>,
    /// Optional sanitized display name. Never a filesystem path.
    pub filename: Option<String>,
    /// Caller/header MIME type, when supplied.
    pub declared_content_type: Option<String>,
    /// API structural detector result.
    pub detected_content_type: String,
    /// Lowercase-hex sha-256 of the imported bytes.
    pub sha256: String,
    /// Imported byte length.
    pub size_bytes: usize,
    /// When the API persisted the import (UTC).
    pub imported_at: OffsetDateTime,
    /// The resolved ledger actor that performed the import.
    pub imported_by: String,
    /// Operator review transition state. This is a workflow state only.
    pub operator_review_status: StoredImportedDocumentReviewStatus,
    /// When an operator last transitioned the review state, if reviewed.
    pub operator_reviewed_at: Option<OffsetDateTime>,
    /// The resolved actor that last transitioned the review state, if reviewed.
    pub operator_reviewed_by: Option<String>,
    /// Optional operator note for the review decision.
    pub operator_review_note: Option<String>,
    /// Stable guardrail ids explicitly acknowledged by the operator during the review transition.
    pub operator_acknowledged_guardrail_ids: Vec<String>,
}

/// One stored operator review decision for an imported document. This is append-only technical
/// evidence; the latest projection remains on [`StoredImportedDocumentMeta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImportedDocumentReviewHistoryEntry {
    /// Monotonic SQLite row id for deterministic ordering.
    pub id: i64,
    /// Imported document id this review decision belongs to.
    pub imported_document_id: String,
    /// Review workflow status recorded by the operator.
    pub review_status: StoredImportedDocumentReviewStatus,
    /// When the operator review decision was recorded, if available.
    pub reviewed_at: Option<OffsetDateTime>,
    /// Resolved actor that recorded the decision, if available.
    pub reviewed_by: Option<String>,
    /// Optional operator note attached to this decision.
    pub review_note: Option<String>,
    /// Stable guardrail ids acknowledged for this decision.
    pub acknowledged_guardrail_ids: Vec<String>,
}

/// A validated, non-canonical document evidence import with retained bytes. These bytes live beside
/// but never replace [`StoredDocument`] or [`StoredSignedDocument`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImportedDocument {
    /// The metadata row.
    pub meta: StoredImportedDocumentMeta,
    /// The retained uploaded bytes.
    pub bytes: Vec<u8>,
}

/// OCR hook state for a preserved historical paper-book import package. This is only status; OCR
/// output is deliberately not part of the preserved-package slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPaperBookOcrStatus {
    /// OCR is unavailable or intentionally disabled for this preserved package.
    Disabled,
    /// Package retained; no OCR work has been executed by this slice.
    NotRun,
    /// OCR work has been queued by an operator or later worker.
    Queued,
    /// OCR work has been marked as running by an operator or later worker.
    Running,
    /// OCR work has been marked completed. No OCR text is stored by this slice.
    Completed,
    /// OCR work has been marked failed. No OCR text is stored by this slice.
    Failed,
}

impl StoredPaperBookOcrStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NotRun => "not_run",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, StoreError> {
        match raw {
            "disabled" => Ok(Self::Disabled),
            "not_run" | "not_started" => Ok(Self::NotRun),
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored paper-book OCR status {other:?}"),
            ))),
        }
    }
}

/// Metadata for a preserved historical paper-book import package (`paper_book_imports`, schema v10).
/// This is the ledger payload source and intentionally excludes raw bytes. Page and original
/// number ranges are non-canonical linking/planning metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaperBookImportMeta {
    pub import_id: String,
    pub entity_ref: String,
    pub entity_name: String,
    pub entity_nipc: String,
    pub book_ref: String,
    pub date_from: Date,
    pub date_to: Date,
    pub page_count: u32,
    pub page_from: u32,
    pub page_to: u32,
    pub original_number_from: Option<u64>,
    pub original_number_to: Option<u64>,
    pub sha256: String,
    pub size_bytes: usize,
    pub content_type: String,
    pub source_filename: Option<String>,
    pub notes: Option<String>,
    pub imported_at: OffsetDateTime,
    pub imported_by: String,
    pub ocr_status: StoredPaperBookOcrStatus,
}

/// A preserved historical paper-book import package with retained bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaperBookImport {
    pub meta: StoredPaperBookImportMeta,
    pub bytes: Vec<u8>,
}

/// One inclusive page span covered by a non-authoritative OCR draft result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPaperBookOcrPageSpan {
    pub start_page: u32,
    pub end_page: u32,
}

/// Review status for a non-authoritative OCR draft result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPaperBookOcrReviewStatus {
    Unreviewed,
    Accepted,
    Rejected,
    Superseded,
}

impl StoredPaperBookOcrReviewStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, StoreError> {
        match raw {
            "unreviewed" => Ok(Self::Unreviewed),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "superseded" => Ok(Self::Superseded),
            other => Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored paper-book OCR review status {other:?}"),
            ))),
        }
    }
}

/// Non-authoritative OCR draft result linked to a preserved paper-book import. It may carry
/// extracted text or only the digest of externally held text; it is never canonical act text.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPaperBookOcrDraft {
    pub draft_id: String,
    pub import_id: String,
    pub extracted_text: Option<String>,
    pub text_digest: Option<String>,
    pub page_spans: Vec<StoredPaperBookOcrPageSpan>,
    pub confidence: Option<f64>,
    pub engine_name: String,
    pub engine_version: Option<String>,
    pub created_at: OffsetDateTime,
    pub created_by: String,
    pub review_status: StoredPaperBookOcrReviewStatus,
    pub reviewed_at: Option<OffsetDateTime>,
    pub reviewed_by: Option<String>,
    pub review_note: Option<String>,
    pub superseded_by: Option<String>,
}

/// Metadata-only conversion dossier for an accepted paper-book OCR draft.
///
/// This intentionally contains no raw OCR extracted text. It records only the accepted draft's
/// digest/review/page-span metadata and never represents canonical minutes or a legal-validity
/// claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaperBookOcrConversionDossier {
    pub dossier_id: String,
    pub import_id: String,
    pub draft_id: String,
    pub source_text_digest: Option<String>,
    pub source_page_spans: Vec<StoredPaperBookOcrPageSpan>,
    pub source_review_status: StoredPaperBookOcrReviewStatus,
    pub source_reviewed_at: Option<OffsetDateTime>,
    pub source_reviewed_by: Option<String>,
    pub created_at: OffsetDateTime,
    pub created_by: String,
}

/// Result of idempotently inserting a paper-book OCR conversion dossier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaperBookOcrConversionDossierUpsert {
    /// The row was inserted by this transaction.
    Inserted(StoredPaperBookOcrConversionDossier),
    /// A row for the same import/draft pair already existed; this is the canonical stored row.
    Existing(StoredPaperBookOcrConversionDossier),
}

impl PaperBookOcrConversionDossierUpsert {
    /// The canonical stored dossier row after the idempotent write attempt.
    #[must_use]
    pub const fn dossier(&self) -> &StoredPaperBookOcrConversionDossier {
        match self {
            Self::Inserted(dossier) | Self::Existing(dossier) => dossier,
        }
    }

    /// Whether this transaction inserted the row.
    #[must_use]
    pub const fn inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

/// Reviewed, metadata-only execution artifact for accepted paper-book OCR draft promotion.
///
/// The artifact binds the source import/draft, optional conversion dossier, and target mutable
/// draft act. It deliberately stores no raw OCR text and carries explicit false claim flags for
/// canonical/legal/PDF/signature/archive assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaperBookOcrConversionExecutionArtifact {
    pub artifact_id: String,
    pub import_id: String,
    pub draft_id: String,
    pub dossier_id: Option<String>,
    pub source_text_digest: Option<String>,
    pub source_page_spans: Vec<StoredPaperBookOcrPageSpan>,
    pub source_review_status: StoredPaperBookOcrReviewStatus,
    pub source_reviewed_at: Option<OffsetDateTime>,
    pub source_reviewed_by: Option<String>,
    pub target_act_id: String,
    pub target_act_state: String,
    pub mutable_draft_act_created: bool,
    pub created_at: OffsetDateTime,
    pub created_by: String,
    pub canonical_conversion_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signed_document_created: bool,
    pub archive_package_created: bool,
    pub pdfa_created: bool,
    pub pdfua_created: bool,
    pub signature_created: bool,
    pub seal_created: bool,
    pub archive_certification_claimed: bool,
    pub legal_validity_claimed: bool,
    pub source_extracted_text_in_artifact: bool,
    pub source_extracted_text_in_ledger_event: bool,
}

/// Result of idempotently inserting a paper-book OCR conversion execution artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaperBookOcrConversionExecutionArtifactUpsert {
    /// The row was inserted by this transaction.
    Inserted(StoredPaperBookOcrConversionExecutionArtifact),
    /// A row for the same import/draft/target-act already existed; this is the stored row.
    Existing(StoredPaperBookOcrConversionExecutionArtifact),
}

impl PaperBookOcrConversionExecutionArtifactUpsert {
    /// The canonical stored execution artifact row after the idempotent write attempt.
    #[must_use]
    pub const fn artifact(&self) -> &StoredPaperBookOcrConversionExecutionArtifact {
        match self {
            Self::Inserted(artifact) | Self::Existing(artifact) => artifact,
        }
    }

    /// Whether this transaction inserted the row.
    #[must_use]
    pub const fn inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

/// Status of a persisted act follow-up. Serialized and stored with the contract's exact
/// `Open`/`Completed` spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredFollowUpStatus {
    /// Work is still outstanding.
    Open,
    /// Work was completed and carries completion metadata.
    Completed,
}

impl StoredFollowUpStatus {
    /// The stable text stored in SQLite and emitted by the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            StoredFollowUpStatus::Open => "Open",
            StoredFollowUpStatus::Completed => "Completed",
        }
    }

    fn parse(raw: &str) -> Result<Self, StoreError> {
        match raw {
            "Open" => Ok(Self::Open),
            "Completed" => Ok(Self::Completed),
            other => Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored follow-up status {other:?}"),
            ))),
        }
    }
}

/// A first-class follow-up/task row tied to an act. The act JSON remains untouched, including after
/// sealing; this row is the mutable task read model and its mutations are ledger-audited by the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFollowUp {
    /// The follow-up id (primary key; generated by the API as a UUID string).
    pub id: String,
    /// Owning act scope.
    pub act_id: ActId,
    /// Optional agenda point anchor.
    pub agenda_number: Option<u32>,
    /// Optional zero-based index into the structured deliberation list.
    pub deliberation_index: Option<u32>,
    /// Short task title.
    pub title: String,
    /// Optional longer task detail.
    pub detail: Option<String>,
    /// Optional due date.
    pub due_date: Option<Date>,
    /// Optional stable assignee identifier or username.
    pub assignee: Option<String>,
    /// Optional display label for the assignee.
    pub assignee_display: Option<String>,
    /// Open/completed lifecycle status.
    pub status: StoredFollowUpStatus,
    /// When the follow-up was created (UTC).
    pub created_at: OffsetDateTime,
    /// Resolved actor that created it.
    pub created_by: String,
    /// When the follow-up was completed (UTC), if completed.
    pub completed_at: Option<OffsetDateTime>,
    /// Resolved actor that completed it, if completed.
    pub completed_by: Option<String>,
}

/// The SIGNED PDF variant + qualified-signature metadata for a sealed act's document (the
/// `signed_documents` table, schema v4; t57-S3). Argument to [`Tx::upsert_signed_document`] (write)
/// and return of [`Store::signed_document_for_act`] (read).
///
/// **Never carries a PIN or an OTP** — only public signature material. The unsigned
/// [`StoredDocument`] it augments is left in place; this is the post-seal qualified artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSignedDocument {
    /// The owning act (primary key; the upsert is idempotent on it).
    pub act_id: ActId,
    /// The source unsigned `documents` row this signature covers.
    pub document_id: String,
    /// Lowercase-hex sha-256 of [`Self::signed_pdf_bytes`] (bound into the `document.signed` event).
    pub signed_pdf_digest: String,
    /// The signing family (e.g. `ChaveMovelDigital`).
    pub signature_family: String,
    /// The evidentiary weight actually carried (e.g. `Qualified`; SIG-01).
    pub evidentiary_level: String,
    /// The signer issuer's trusted-list status at signing time, or `None`.
    pub trusted_list_status: Option<String>,
    /// The signer leaf certificate subject DN, or `None`.
    pub signer_cert_subject: Option<String>,
    /// The authoritative CAdES signed-attributes signing time (UTC).
    pub signing_time: OffsetDateTime,
    /// When the api completed the signature (UTC; storage metadata).
    pub signed_at: OffsetDateTime,
    /// The signer leaf certificate (DER).
    pub signer_cert_der: Vec<u8>,
    /// An optional RFC 3161 timestamp token (DER), or `None` (a B-B signature has none).
    pub timestamp_token_der: Option<Vec<u8>>,
    /// Optional technical timestamp-trust diagnostic report JSON captured at signing completion.
    pub timestamp_trust_report_json: Option<String>,
    /// Optional declared signer-capacity evidence JSON. This is request/operator evidence only;
    /// the store does not interpret it as SCAP or authority verification.
    pub signer_capacity_evidence_json: Option<String>,
    /// The signed PDF/A bytes.
    pub signed_pdf_bytes: Vec<u8>,
}

/// An in-flight two-phase Chave Móvel Digital signing session (the `pending_cmd_sessions` table,
/// schema v4; t57-S3), persisted so the `initiate`→`confirm` request pair survives across the two
/// stateless requests (and a restart).
///
/// **Never carries a PIN or an OTP.** `session_json` / `prepared_json` are opaque serde blobs of the
/// non-secret `chancela_signing::CmdSignSession` / `chancela_pades::PreparedSignature` (the crypto
/// types live above the store in the DAG, so the store treats them as text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCmdSession {
    /// A fresh uuid minted at initiate (primary key).
    pub session_id: String,
    /// The act being signed.
    pub act_id: ActId,
    /// The acting username that initiated (session gating: only it may confirm).
    pub actor: String,
    /// `"otp_pending"` while awaiting the OTP.
    pub status: String,
    /// The citizen phone with the middle digits masked (non-secret, for the UI).
    pub masked_phone: String,
    /// The human-readable document label used at initiate.
    pub doc_name: String,
    /// Optional declared signer-capacity evidence JSON preserved across initiate/confirm.
    pub signer_capacity_evidence_json: Option<String>,
    /// The non-secret `CmdSignSession` serde blob (opaque to the store).
    pub session_json: String,
    /// The non-secret `PreparedSignature` serde blob (opaque to the store).
    pub prepared_json: String,
    /// When the session was created (UTC).
    pub created_at: OffsetDateTime,
    /// When the session expires (UTC; single-use, TTL-bounded).
    pub expires_at: OffsetDateTime,
}

/// One stored provider-credential record row (`provider_credentials`, schema v16; wp16 P3b),
/// returned by [`Store::read_credential_records`] and written by [`Tx::put_credential_record`].
///
/// This is the store's opaque mirror of one entry in the `provider-credentials.enc.json` sidecar's
/// `records` list. `record_blob` is the **OPAQUE** serialized `EncryptedCredentialRecord`: it holds
/// only AEAD ciphertext envelopes (never a plaintext secret), and the store never encrypts, decrypts,
/// or parses it — the XChaCha20-Poly1305 / AAD envelope stays entirely in `chancela-api`'s
/// secretstore, only its storage moves here. `key_version` / `updated_at` are the non-secret metadata
/// columns the status/rotation surfaces read without touching key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredentialRecord {
    /// The `CredentialMode` wire string (e.g. `cmd` / `csc` / `scap` / `pkcs12`); half the primary key.
    pub mode: String,
    /// The provider id (empty for the single-instance CMD/SCAP modes); the other half of the key.
    pub provider_id: String,
    /// The key version the record was last written under (non-secret rotation marker).
    pub key_version: i64,
    /// RFC 3339 last-update timestamp (non-secret metadata).
    pub updated_at: String,
    /// The opaque serialized `EncryptedCredentialRecord` bytes — AEAD ciphertext only, never plaintext.
    pub record_blob: Vec<u8>,
}

impl Store {
    /// Open (creating if absent) `<data_dir>/chancela.db`, set `journal_mode=WAL` and
    /// `foreign_keys=ON`, run the idempotent [`schema::ALL`] migration, and record/read
    /// `meta.schema_version`.
    ///
    /// `data_dir` is the directory; the database file name is [`DB_FILE`].
    pub fn open(data_dir: &Path) -> Result<Store, StoreError> {
        Self::open_with_options(data_dir, StoreOpenOptions::default())
    }

    /// Open the store with explicit options. Supplying an encryption key requires the `sqlcipher`
    /// feature; otherwise the call fails loudly with [`StoreError::EncryptionUnavailable`].
    pub fn open_with_options(
        data_dir: &Path,
        options: StoreOpenOptions,
    ) -> Result<Store, StoreError> {
        Ok(Store {
            backend: Backend::Sqlite(SqliteBackend::open(data_dir, &options)?),
        })
    }

    /// Lock and borrow the SQLite connection behind the backend seam.
    ///
    /// Internal to the crate — the read methods, `backup`, and the [`recovery`] restore all funnel
    /// their SQLite connection access through here so the rusqlite specifics stay in one arm. On the
    /// [`Backend::Postgres`] arm (wp14 Phase 1) these bespoke SQLite-shaped paths are not yet ported,
    /// so this fails closed with [`StoreError::UnsupportedOnPostgres`] rather than misbehaving.
    /// The hot write path ([`Store::persist_result`]) and the boot [`Store::load`] dispatch on the
    /// backend directly and do **not** go through this accessor.
    pub(crate) fn locked_conn(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, StoreError> {
        match &self.backend {
            Backend::Sqlite(backend) => Ok(backend.conn.lock().unwrap_or_else(|e| e.into_inner())),
            #[cfg(feature = "postgres")]
            Backend::Postgres(_) => Err(StoreError::UnsupportedOnPostgres {
                op: "direct SQLite connection access (bespoke read / backup / recovery path)",
            }),
        }
    }

    /// Open the store on the backend named by `selection` (wp14 Phase 1, §2.4). This is the seam
    /// Phase 2 wires `CHANCELA_DB_BACKEND` / `DATABASE_URL` into: SQLite (the default) resolves to
    /// [`Store::open_with_options`]; Postgres connects the pool + advisory-locked writer and runs
    /// the per-backend DDL. The Postgres arm only exists when the off-by-default `postgres` feature
    /// is compiled in, so an embedded build fails closed at the type level.
    pub fn open_backend(selection: StoreBackendSelection) -> Result<Store, StoreError> {
        match selection {
            StoreBackendSelection::Sqlite { data_dir, options } => {
                Store::open_with_options(&data_dir, options)
            }
            #[cfg(feature = "postgres")]
            StoreBackendSelection::Postgres { database_url } => Ok(Store {
                backend: Backend::Postgres(pg::PostgresBackend::open(&database_url)?),
            }),
        }
    }

    // ── wp16 P0 cluster / leader-election facade ──────────────────────────────────────────────────
    //
    // For the SQLite backend (the embedded single-node editions and the default build) there is no
    // election: the sole process is always its own writer-leader, so these resolve to the
    // always-writable single-node answers and the default build is totally unaffected. For the
    // Postgres backend they delegate to the advisory-lock election in [`crate::pg_cluster`]. Every
    // method fails closed on the leadership question.

    /// Whether this backend participates in advisory-lock leader election (Postgres) at all. The API
    /// only mounts its promotion/heartbeat supervisor when this is `true`.
    pub fn cluster_election_enabled(&self) -> bool {
        match &self.backend {
            Backend::Sqlite(_) => false,
            #[cfg(feature = "postgres")]
            Backend::Postgres(_) => true,
        }
    }

    /// Is this node currently the cluster writer-leader? SQLite is always its own leader.
    pub fn cluster_is_leader(&self) -> bool {
        match &self.backend {
            Backend::Sqlite(_) => true,
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.is_leader(),
        }
    }

    /// **Fail-closed write gate**, consulted immediately before every durable append. SQLite is
    /// always writable; Postgres re-verifies — on the writer session itself — that it still holds the
    /// advisory lock AND owns the current `leader_epoch`, returning [`StoreError::NotLeader`] on ANY
    /// doubt (lost lock, stolen epoch, broken session). A node that lost leadership is rejected by
    /// this gate before opening a durable write transaction.
    pub fn cluster_assert_writable(&self) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => Ok(()),
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => {
                if crate::pg_cluster::write_gate_allows(
                    backend.verify_still_leader(),
                    backend.writes_enabled(),
                ) {
                    Ok(())
                } else {
                    Err(StoreError::NotLeader)
                }
            }
        }
    }

    /// Re-check leadership without requiring the write-enable handoff flag. Used by the supervisor
    /// heartbeat path so a promoted node can hold the lock read-only while catch-up/handoff is still
    /// in progress or has failed closed.
    pub fn cluster_verify_leader(&self) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => Ok(()),
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => {
                if backend.verify_still_leader() {
                    Ok(())
                } else {
                    Err(StoreError::NotLeader)
                }
            }
        }
    }

    /// Enable durable writes after a promoted Postgres node completes the API catch-up/handoff gate.
    /// No-op on SQLite.
    pub fn cluster_enable_writes(&self) {
        match &self.backend {
            Backend::Sqlite(_) => {}
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.enable_writes(),
        }
    }

    /// Disable durable writes while preserving any held leadership lock. No-op on SQLite.
    pub fn cluster_disable_writes(&self) {
        match &self.backend {
            Backend::Sqlite(_) => {}
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.disable_writes(),
        }
    }

    /// **wp16 P4 — proactive fail-closed step-down.** Flip this node to follower and disable writes
    /// *without* waiting for the next write or supervisor verify to discover a lost lock — used by the
    /// leader self-fence watchdog when it cannot prove leadership within its deadline (a partition to
    /// Postgres, a wedged/hung writer session, or an outright verify failure). Idempotent. Backed by
    /// atomic role flags, so it succeeds even while the writer connection is held/wedged by a stalled
    /// `persist`/`verify` (the fence must never itself block on the resource it is fencing). No-op on
    /// SQLite (single-node is always its own leader; there is nothing to step down from).
    pub fn cluster_step_down(&self) {
        match &self.backend {
            Backend::Sqlite(_) => {}
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.step_down(),
        }
    }

    /// Attempt promotion (follower → leader). SQLite is already the leader. Postgres tries the
    /// advisory lock; on success it bumps the epoch and returns `Ok(true)` — the caller MUST then run
    /// the catch-up + chain re-verify handoff (§4.2) before the first append.
    pub fn cluster_try_promote(&self) -> Result<bool, StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => Ok(true),
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.try_promote(),
        }
    }

    /// Leader liveness heartbeat into `cluster_leader`. A no-op (`Ok`) on SQLite; on Postgres it
    /// stamps `last_heartbeat` while still owning the epoch, failing closed (and stepping down) if the
    /// node has been deposed.
    pub fn cluster_heartbeat(&self) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => Ok(()),
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.heartbeat(),
        }
    }

    /// This node's claimed `leader_epoch` (`0` on SQLite; `-1` on Postgres until it has ever led).
    pub fn cluster_leader_epoch(&self) -> i64 {
        match &self.backend {
            Backend::Sqlite(_) => 0,
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.leader_epoch(),
        }
    }

    /// Durable `MAX(seq)` from the store (the handoff catch-up target). `None` on SQLite (handoff is
    /// a Postgres-cluster concept) or when the ledger is empty.
    pub fn cluster_durable_max_seq(&self) -> Result<Option<i64>, StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => Ok(None),
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.durable_max_seq(),
        }
    }

    /// wp16 P2 — the current leader's externally-reachable advertised base URL for the follower
    /// write-redirect (plan §3.2), or `None` when no *fresh* leader address is recorded (brief
    /// failover / mid-handoff window, or the leader has no `CHANCELA_ADVERTISED_URL`). The API turns
    /// `Some(url)` into a `307` `Location` and `None` into `503 + Retry-After` (never a broken
    /// redirect). `stale_after_secs` bounds how old the leader heartbeat may be. SQLite is single-node
    /// (always its own leader; a follower redirect never arises) → `None`.
    pub fn cluster_leader_address(
        &self,
        stale_after_secs: i64,
    ) -> Result<Option<String>, StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => {
                let _ = stale_after_secs;
                Ok(None)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.leader_address(stale_after_secs),
        }
    }

    /// wp16 P1 — the ordered ledger tail `seq > after_seq` for the follower change-feed's incremental
    /// delta apply (plan §2.2/§2.3). SQLite is single-node (never a follower), so it has no change
    /// feed and returns an empty delta.
    pub fn cluster_events_since(&self, after_seq: i64) -> Result<Vec<Event>, StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => {
                let _ = after_seq;
                Ok(Vec::new())
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.events_since(after_seq),
        }
    }

    /// wp16 P1 — re-read only the bounded aggregate read-models (no `events` scan), the follower's
    /// simple v1 aggregate refresh when it applies a change-feed delta (plan §2.3). SQLite is
    /// single-node, so this falls back to the aggregate half of [`Store::load`].
    pub fn cluster_load_aggregates(&self) -> Result<AggregateSnapshot, StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => {
                let loaded = self.load()?;
                Ok(AggregateSnapshot {
                    entities: loaded.entities,
                    books: loaded.books,
                    acts: loaded.acts,
                    registry_extracts: loaded.registry_extracts,
                    follow_ups: loaded.follow_ups,
                })
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.load_aggregates(),
        }
    }

    /// wp16 P1 — the leader's change signal: `NOTIFY chancela_ledger, '<max_seq>'` after a durable
    /// append commits (plan §2.2). Best-effort by design — a missed notification is retried by the
    /// follower's seq-poll backstop once Postgres can be queried — so callers may ignore the result.
    /// No-op on SQLite (single-node, no followers to wake).
    pub fn cluster_notify_append(&self, max_seq: i64) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Sqlite(_) => {
                let _ = max_seq;
                Ok(())
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => backend.notify_append(max_seq),
        }
    }

    /// wp16 P1 — the libpq DSN for the follower change-feed's own dedicated `LISTEN` connection (plan
    /// §2.2). `None` on SQLite (no change feed) so the API only spawns a listener on the electing
    /// Postgres backend.
    pub fn cluster_listen_dsn(&self) -> Option<String> {
        match &self.backend {
            Backend::Sqlite(_) => None,
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => Some(backend.listen_dsn()),
        }
    }

    /// Inspect the configured key, current build capabilities, and database header without opening
    /// or mutating the SQLite file. This is the operator-facing key-ops preflight used to avoid
    /// accidental plaintext creation and to refuse unsupported plaintext-to-encrypted migration.
    pub fn key_ops_status(
        data_dir: &Path,
        options: &StoreOpenOptions,
    ) -> Result<StoreKeyOpsStatus, StoreError> {
        let database_file = data_dir.join(DB_FILE);
        let database_format = inspect_database_format(&database_file)?;
        let key_config = options.key_config_status();
        let sqlcipher_available = cfg!(feature = "sqlcipher");
        let plan = match key_config {
            StoreKeyConfigStatus::Unconfigured => match database_format {
                StoreDatabaseFormat::Missing => StoreKeyOpsPlan::CreatePlaintextStore,
                StoreDatabaseFormat::PlaintextSqlite => StoreKeyOpsPlan::OpenPlaintextStore,
                StoreDatabaseFormat::NonPlaintextOrEncrypted => {
                    StoreKeyOpsPlan::KeyRequiredForNonPlaintextStore
                }
            },
            StoreKeyConfigStatus::Empty => StoreKeyOpsPlan::RejectEmptyKey,
            StoreKeyConfigStatus::Configured => match database_format {
                StoreDatabaseFormat::PlaintextSqlite => {
                    StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration
                }
                StoreDatabaseFormat::Missing if sqlcipher_available => {
                    StoreKeyOpsPlan::CreateEncryptedStore
                }
                StoreDatabaseFormat::NonPlaintextOrEncrypted if sqlcipher_available => {
                    StoreKeyOpsPlan::OpenEncryptedStore
                }
                StoreDatabaseFormat::Missing | StoreDatabaseFormat::NonPlaintextOrEncrypted => {
                    StoreKeyOpsPlan::SqlcipherBuildRequired
                }
            },
        };
        let migration_plan = StoreKeyOpsMigrationPlan::for_status(
            plan,
            database_format,
            key_config,
            sqlcipher_available,
            &database_file,
        );

        Ok(StoreKeyOpsStatus {
            sqlcipher_available,
            key_config,
            database_file,
            database_format,
            plan,
            migration_plan,
        })
    }

    /// Inspect whether a key rotation request is safe to attempt, without opening or mutating the
    /// database. Both the current key and the requested replacement key are classified only as
    /// absent/empty/configured; key material is never returned.
    pub fn key_rotation_preflight(
        data_dir: &Path,
        current_options: &StoreOpenOptions,
        new_key: &str,
    ) -> Result<StoreKeyRotationPreflight, StoreError> {
        let database_file = data_dir.join(DB_FILE);
        let database_format = inspect_database_format(&database_file)?;
        let current_key_config = current_options.key_config_status();
        let requested_key_config = StoreOpenOptions::new()
            .with_encryption_key(new_key)
            .key_config_status();
        let sqlcipher_available = cfg!(feature = "sqlcipher");
        let status = classify_key_rotation_status(
            database_format,
            current_key_config,
            requested_key_config,
            sqlcipher_available,
        );
        let evidence = StoreKeyRotationEvidence {
            database_format: store_database_format_code(database_format),
            current_key_config: store_key_config_status_code(current_key_config),
            requested_key_config: store_key_config_status_code(requested_key_config),
            sqlcipher_available,
            database_file: database_file.display().to_string(),
        };

        Ok(StoreKeyRotationPreflight {
            ready: status == StoreKeyRotationStatus::Ready,
            status,
            next_action: status.operator_action(),
            evidence,
        })
    }

    /// The stable per-install `instance_id` stamped into `meta` on first open (t54): bundle
    /// provenance (`BundleManifest.source_instance_id`) and the import feed both read it. A restored
    /// backup keeps the *source* instance's id (the stamp is only minted when absent).
    pub fn instance_id(&self) -> Result<String, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.instance_id();
        }
        let guard = self.locked_conn()?;
        read_instance_id(&guard)
    }

    /// Rotate the SQLCipher passphrase for an already-keyed store connection.
    ///
    /// The new key is never included in errors or logs. Empty keys are rejected before issuing
    /// `PRAGMA rekey`, leaving the open database untouched.
    #[cfg(feature = "sqlcipher")]
    pub fn rotate_encryption_key(&self, new_key: &str) -> Result<(), StoreError> {
        self.rotate_encryption_key_with_evidence(new_key)
            .map(|_| ())
    }

    /// Rotate the SQLCipher passphrase and return secret-free execution evidence for operator
    /// audit/status surfaces. The caller must have opened the store with the current key already;
    /// this method never accepts, returns, logs, or serializes that current key.
    #[cfg(feature = "sqlcipher")]
    pub fn rotate_encryption_key_with_evidence(
        &self,
        new_key: &str,
    ) -> Result<StoreKeyRotationExecution, StoreError> {
        self.rekey(new_key)?;
        let integrity = self.integrity_report()?;
        Ok(StoreKeyRotationExecution {
            status: StoreKeyRotationExecutionStatus::RekeyApplied,
            rekey_executed: true,
            ledger_integrity_verified: integrity.healthy,
            ledger_length: integrity.global.length,
            evidence: StoreKeyRotationExecutionEvidence {
                operation: "sqlcipher_rekey",
                requested_key_config: store_key_config_status_code(
                    StoreOpenOptions::new()
                        .with_encryption_key(new_key)
                        .key_config_status(),
                ),
                sqlcipher_available: true,
                checkpointed_before_rekey: true,
                checkpointed_after_rekey: true,
                post_rekey_integrity_checked: true,
            },
        })
    }

    /// Feature-stable rotation API for callers that are compiled without SQLCipher. It fails
    /// closed and returns no key material.
    #[cfg(not(feature = "sqlcipher"))]
    pub fn rotate_encryption_key_with_evidence(
        &self,
        new_key: &str,
    ) -> Result<StoreKeyRotationExecution, StoreError> {
        if new_key.trim().is_empty() {
            return Err(StoreError::EmptyEncryptionKey);
        }
        Err(StoreError::EncryptionUnavailable)
    }

    /// Alias for [`Store::rotate_encryption_key`], matching SQLCipher's primitive name.
    #[cfg(feature = "sqlcipher")]
    pub fn rekey(&self, new_key: &str) -> Result<(), StoreError> {
        if new_key.trim().is_empty() {
            return Err(StoreError::EmptyEncryptionKey);
        }

        let guard = self.locked_conn()?;
        guard.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        guard
            .pragma_update(None, "rekey", new_key)
            .map_err(|source| StoreError::EncryptionKeyRejected { source })?;
        verify_keyed_database(&guard)?;
        guard.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Load the ledger and return its full [`IntegrityReport`] (t54 deliverable #6) — the queryable
    /// integrity status E3 serves and gates its degraded state on, without holding onto a
    /// [`LoadedState`]. A convenience over `self.load()?.integrity`.
    pub fn integrity_report(&self) -> Result<IntegrityReport, StoreError> {
        Ok(self.load()?.integrity)
    }

    /// Read all aggregate rows into their maps and all event rows (ordered by `seq`) into a
    /// [`Ledger`] via `chancela_ledger::Ledger::try_from_events` (added by t30-e1a), then return
    /// the maps, the ledger, and the boot-verify outcome as [`LoadedState`].
    pub fn load(&self) -> Result<LoadedState, StoreError> {
        // The Postgres backend replays the same aggregate + event rows into an identical
        // `LoadedState` (the `events` rows feed `Ledger::try_from_events`, which re-verifies the
        // chain byte-for-byte — §1.3/§4). It dispatches here instead of through the SQLite-only
        // `locked_conn` accessor used by the rest of this method.
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.load();
        }
        let guard = self.locked_conn()?;

        // Aggregates: the `json` column is the full serde value; its own `id` field is the map key,
        // so the scope columns (entity_id/book_id) never need re-parsing on load.
        let mut entities = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM entities")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let entity: Entity = serde_json::from_str(&json?)?;
                entities.insert(entity.id, entity);
            }
        }
        let mut books = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM books")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let book: Book = serde_json::from_str(&json?)?;
                books.insert(book.id, book);
            }
        }
        let mut acts = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT json FROM acts")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for json in rows {
                let act: Act = serde_json::from_str(&json?)?;
                acts.insert(act.id, act);
            }
        }

        // Registry extracts are keyed by the owning entity id, which the extract does not carry, so
        // the map key comes from the `entity_id` scope column.
        let mut registry_extracts = HashMap::new();
        {
            let mut stmt = guard.prepare("SELECT entity_id, json FROM registry_extracts")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (entity_id_raw, json) = row?;
                let entity_id: EntityId = parse_uuid_newtype(&entity_id_raw)?;
                let extract: RegistryExtract = serde_json::from_str(&json)?;
                registry_extracts.insert(entity_id, extract);
            }
        }

        let mut follow_ups = HashMap::new();
        {
            let mut stmt = guard.prepare(
                "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
                 assignee, assignee_display, status, created_at, created_by, completed_at, \
                 completed_by FROM follow_ups",
            )?;
            let rows = stmt.query_map([], row_to_follow_up)?;
            for row in rows {
                let follow_up = row??;
                follow_ups.insert(follow_up.id.clone(), follow_up);
            }
        }

        // Events, in chain order. Read the columns as raw primitives inside the rusqlite closure
        // (which must yield `rusqlite::Result`), then rebuild each `Event` where the timestamp /
        // uuid / fixed-width-digest conversions can surface as `StoreError`.
        let mut raw_events: Vec<RawEventRow> = Vec::new();
        {
            let mut stmt = guard.prepare(&format!(
                "SELECT {EVENT_SELECT_COLUMNS} FROM events ORDER BY seq"
            ))?;
            let rows = stmt.query_map([], raw_event_row)?;
            for row in rows {
                raw_events.push(row?);
            }
        }
        let mut events = Vec::with_capacity(raw_events.len());
        for raw in raw_events {
            events.push(raw.into_event()?);
        }

        let (ledger, chain_status) = Ledger::try_from_events(events);
        // Surface the rich, per-chain integrity picture on every load (t54 #6): the api enters its
        // degraded state and serves the exact break location from this, instead of the old silent
        // boot log. Computing it here (once, on load) keeps the source of truth in the store.
        let integrity = ledger.integrity_report();
        Ok(LoadedState {
            entities,
            books,
            acts,
            registry_extracts,
            follow_ups,
            ledger,
            chain_status,
            integrity,
        })
    }

    /// Fetch a persisted newest-first ledger event page without loading the full ledger.
    ///
    /// SQLite handles the global sequence cursor and direct row predicates (`seq`, `scope`,
    /// `kind`, `actor`, `timestamp`). Chain membership and free-text search are intentionally
    /// checked on reconstructed [`Event`] values so they stay aligned with the native ledger link
    /// model and the API's searchable event fields.
    pub fn ledger_events_page(
        &self,
        query: &LedgerEventPageQuery,
    ) -> Result<LedgerEventPage, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.ledger_events_page(query);
        }
        let limit = query.limit.max(1);
        let target = limit.saturating_add(1);
        let filters = NormalizedLedgerEventPageFilters::from_query(query);
        let batch_limit = ledger_event_page_batch_limit(limit, filters.has_residual_filters());
        let mut before_seq = query.before_seq;
        let mut accepted = Vec::with_capacity(target);
        let guard = self.locked_conn()?;

        loop {
            let (sql, values) = ledger_events_page_sql(&filters, before_seq, batch_limit);
            let mut stmt = guard.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(values.iter()), raw_event_row)?;
            let mut raw_events = Vec::new();
            for row in rows {
                raw_events.push(row?);
            }

            let row_count = raw_events.len();
            let oldest_seq = raw_events.last().map(|row| row.seq);
            if row_count == 0 {
                break;
            }

            for raw in raw_events {
                let event = raw.into_event()?;
                if !filters.matches(&event) {
                    continue;
                }
                accepted.push(event);
                if accepted.len() >= target {
                    break;
                }
            }

            if accepted.len() >= target || row_count < batch_limit {
                break;
            }

            let Some(oldest_seq) = oldest_seq else {
                break;
            };
            if oldest_seq <= 0 {
                break;
            }
            before_seq = Some(oldest_seq as u64);
        }

        let has_more = accepted.len() > limit;
        if has_more {
            accepted.truncate(limit);
        }
        let next_cursor = has_more
            .then(|| accepted.last().map(|event| event.seq))
            .flatten();
        Ok(LedgerEventPage {
            events: accepted,
            next_cursor,
            has_more,
            limit,
        })
    }

    /// Fetch the document generated for `act_id`, returning its bytes + metadata, or `None` if the
    /// act has no persisted document yet (the api maps `None` to the `GET /v1/acts/{id}/document`
    /// 404-until-sealed). If an act was regenerated more than once, the most recently created row
    /// wins (ordered by `created_at`, then the physical `rowid` as a stable tie-break).
    pub fn document_for_act(&self, act_id: ActId) -> Result<Option<StoredDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.document_for_act(act_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE act_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
        )?;
        stmt.query_row(params![act_id.to_string()], row_to_document)
            .optional()?
            .transpose()
    }

    /// Fetch all documents generated for `act_id`, oldest first. The api uses this to keep the
    /// original sealed Ata as the canonical signing/download target even after later certidão or
    /// extrato rows are generated for the same act.
    pub fn documents_for_act(&self, act_id: ActId) -> Result<Vec<StoredDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.documents_for_act(act_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE act_id = ?1 ORDER BY created_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![act_id.to_string()], row_to_document)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch a document by its own id (bytes + metadata), or `None` if unknown.
    pub fn document_by_id(&self, id: &str) -> Result<Option<StoredDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.document_by_id(id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE id = ?1",
        )?;
        stmt.query_row(params![id], row_to_document)
            .optional()?
            .transpose()
    }

    /// Fetch all operator-recorded dispatch evidence rows for one generated document, oldest first.
    pub fn generated_document_dispatch_evidence(
        &self,
        document_id: &str,
    ) -> Result<Vec<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.generated_document_dispatch_evidence(document_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
             channel, reference, evidence_reference, imported_document_id, recipients_json, \
             operator_note, recorded_at \
             FROM generated_document_dispatch_evidence \
             WHERE document_id = ?1 ORDER BY recorded_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![document_id], row_to_generated_dispatch_evidence)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch a generated-document dispatch evidence row by its deterministic idempotency key.
    pub fn generated_document_dispatch_evidence_by_key(
        &self,
        document_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend
                .generated_document_dispatch_evidence_by_key(document_id, idempotency_key);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
             channel, reference, evidence_reference, imported_document_id, recipients_json, \
             operator_note, recorded_at \
             FROM generated_document_dispatch_evidence \
             WHERE document_id = ?1 AND idempotency_key = ?2",
        )?;
        stmt.query_row(
            params![document_id, idempotency_key],
            row_to_generated_dispatch_evidence,
        )
        .optional()?
        .transpose()
    }

    /// List imported, non-canonical document evidence metadata, newest first. When `act_id` is
    /// supplied, returns only imports linked to that act; otherwise returns the global feed.
    pub fn imported_documents(
        &self,
        act_id: Option<ActId>,
    ) -> Result<Vec<StoredImportedDocumentMeta>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.imported_documents(act_id);
        }
        let guard = self.locked_conn()?;
        let mut out = Vec::new();
        if let Some(act_id) = act_id {
            let mut stmt = guard.prepare(
                "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
                 sha256, size_bytes, imported_at, imported_by, operator_review_status, \
                 operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                 operator_acknowledged_guardrail_ids_json \
                 FROM imported_documents \
                 WHERE act_id = ?1 ORDER BY imported_at DESC, rowid DESC",
            )?;
            let rows =
                stmt.query_map(params![act_id.to_string()], row_to_imported_document_meta)?;
            for row in rows {
                out.push(row??);
            }
        } else {
            let mut stmt = guard.prepare(
                "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
                 sha256, size_bytes, imported_at, imported_by, operator_review_status, \
                 operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                 operator_acknowledged_guardrail_ids_json \
                 FROM imported_documents \
                 ORDER BY imported_at DESC, rowid DESC",
            )?;
            let rows = stmt.query_map([], row_to_imported_document_meta)?;
            for row in rows {
                out.push(row??);
            }
        }
        Ok(out)
    }

    /// Fetch one imported, non-canonical document evidence record by id, including retained bytes.
    pub fn imported_document(
        &self,
        id: &str,
    ) -> Result<Option<StoredImportedDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.imported_document(id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, filename, declared_content_type, detected_content_type, sha256, \
             size_bytes, imported_at, imported_by, operator_review_status, operator_reviewed_at, \
             operator_reviewed_by, operator_review_note, operator_acknowledged_guardrail_ids_json, \
             bytes FROM imported_documents \
             WHERE id = ?1",
        )?;
        stmt.query_row(params![id], row_to_imported_document)
            .optional()?
            .transpose()
    }

    /// List append-only review decisions for one imported document, oldest first.
    pub fn imported_document_review_history(
        &self,
        imported_document_id: &str,
    ) -> Result<Vec<StoredImportedDocumentReviewHistoryEntry>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.imported_document_review_history(imported_document_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, imported_document_id, review_status, reviewed_at, reviewed_by, \
             review_note, acknowledged_guardrail_ids_json \
             FROM imported_document_review_history \
             WHERE imported_document_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(
            params![imported_document_id],
            row_to_imported_document_review_history_entry,
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch one preserved historical paper-book import package by id, including retained bytes.
    pub fn paper_book_import(
        &self,
        import_id: &str,
    ) -> Result<Option<StoredPaperBookImport>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_import(import_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, date_to, \
             page_count, page_from, page_to, original_number_from, original_number_to, sha256, \
             size_bytes, content_type, source_filename, notes, imported_at, imported_by, \
             ocr_status, bytes FROM paper_book_imports WHERE import_id = ?1",
        )?;
        stmt.query_row(params![import_id], row_to_paper_book_import)
            .optional()?
            .transpose()
    }

    /// List preserved historical paper-book import metadata, newest first. When `book_ref` is
    /// supplied, returns only imports linked to that operator-supplied book reference.
    pub fn paper_book_imports(
        &self,
        book_ref: Option<&str>,
    ) -> Result<Vec<StoredPaperBookImportMeta>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_imports(book_ref);
        }
        let guard = self.locked_conn()?;
        let mut out = Vec::new();
        if let Some(book_ref) = book_ref {
            let mut stmt = guard.prepare(
                "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                 date_to, page_count, page_from, page_to, original_number_from, \
                 original_number_to, sha256, size_bytes, content_type, source_filename, notes, \
                 imported_at, imported_by, ocr_status FROM paper_book_imports \
                 WHERE book_ref = ?1 ORDER BY imported_at DESC, rowid DESC",
            )?;
            let rows = stmt.query_map(params![book_ref], row_to_paper_book_import_meta)?;
            for row in rows {
                out.push(row??);
            }
        } else {
            let mut stmt = guard.prepare(
                "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                 date_to, page_count, page_from, page_to, original_number_from, \
                 original_number_to, sha256, size_bytes, content_type, source_filename, notes, \
                 imported_at, imported_by, ocr_status FROM paper_book_imports \
                 ORDER BY imported_at DESC, rowid DESC",
            )?;
            let rows = stmt.query_map([], row_to_paper_book_import_meta)?;
            for row in rows {
                out.push(row??);
            }
        }
        Ok(out)
    }

    /// Update only the OCR lifecycle marker for a preserved historical paper-book import.
    /// This is metadata-only: it never stores OCR text and never changes retained package bytes.
    pub fn update_paper_book_import_ocr_status(
        &self,
        import_id: &str,
        status: StoredPaperBookOcrStatus,
    ) -> Result<bool, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.update_paper_book_import_ocr_status(import_id, status);
        }
        let guard = self.locked_conn()?;
        let changed = guard.execute(
            "UPDATE paper_book_imports SET ocr_status = ?1 WHERE import_id = ?2",
            params![status.as_str(), import_id],
        )?;
        Ok(changed > 0)
    }

    /// Fetch one non-authoritative OCR draft result by id.
    pub fn paper_book_ocr_draft(
        &self,
        draft_id: &str,
    ) -> Result<Option<StoredPaperBookOcrDraft>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_ocr_draft(draft_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT draft_id, import_id, extracted_text, text_digest, page_spans_json, confidence, \
             engine_name, engine_version, created_at, created_by, review_status, reviewed_at, \
             reviewed_by, review_note, superseded_by FROM paper_book_ocr_drafts WHERE draft_id = ?1",
        )?;
        stmt.query_row(params![draft_id], row_to_paper_book_ocr_draft)
            .optional()?
            .transpose()
    }

    /// List non-authoritative OCR draft results for a preserved paper-book import, newest first.
    pub fn paper_book_ocr_drafts(
        &self,
        import_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrDraft>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_ocr_drafts(import_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT draft_id, import_id, extracted_text, text_digest, page_spans_json, confidence, \
             engine_name, engine_version, created_at, created_by, review_status, reviewed_at, \
             reviewed_by, review_note, superseded_by FROM paper_book_ocr_drafts \
             WHERE import_id = ?1 ORDER BY created_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map(params![import_id], row_to_paper_book_ocr_draft)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch the metadata-only OCR conversion dossier for one import/draft pair, if it exists.
    pub fn paper_book_ocr_conversion_dossier_for_draft(
        &self,
        import_id: &str,
        draft_id: &str,
    ) -> Result<Option<StoredPaperBookOcrConversionDossier>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_ocr_conversion_dossier_for_draft(import_id, draft_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT dossier_id, import_id, draft_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, created_at, created_by \
             FROM paper_book_ocr_conversion_dossiers WHERE import_id = ?1 AND draft_id = ?2",
        )?;
        stmt.query_row(
            params![import_id, draft_id],
            row_to_paper_book_ocr_conversion_dossier,
        )
        .optional()?
        .transpose()
    }

    /// List metadata-only OCR conversion dossiers for a preserved paper-book import, newest first.
    pub fn paper_book_ocr_conversion_dossiers(
        &self,
        import_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrConversionDossier>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_ocr_conversion_dossiers(import_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT dossier_id, import_id, draft_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, created_at, created_by \
             FROM paper_book_ocr_conversion_dossiers \
             WHERE import_id = ?1 ORDER BY created_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map(params![import_id], row_to_paper_book_ocr_conversion_dossier)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch one reviewed OCR conversion execution artifact by import/draft/target-act.
    pub fn paper_book_ocr_conversion_execution_artifact(
        &self,
        import_id: &str,
        draft_id: &str,
        target_act_id: &str,
    ) -> Result<Option<StoredPaperBookOcrConversionExecutionArtifact>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.paper_book_ocr_conversion_execution_artifact(
                import_id,
                draft_id,
                target_act_id,
            );
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT artifact_id, import_id, draft_id, dossier_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, target_act_id, target_act_state, mutable_draft_act_created, \
             created_at, created_by, canonical_conversion_claimed, canonical_minutes_claimed, \
             canonical_act_created, canonical_document_created, signed_document_created, \
             archive_package_created, pdfa_created, pdfua_created, signature_created, \
             seal_created, archive_certification_claimed, legal_validity_claimed, \
             source_extracted_text_in_artifact, source_extracted_text_in_ledger_event \
             FROM paper_book_ocr_conversion_execution_artifacts \
             WHERE import_id = ?1 AND draft_id = ?2 AND target_act_id = ?3",
        )?;
        stmt.query_row(
            params![import_id, draft_id, target_act_id],
            row_to_paper_book_ocr_conversion_execution_artifact,
        )
        .optional()?
        .transpose()
    }

    /// List reviewed OCR conversion execution artifacts for one import/draft pair, newest first.
    pub fn paper_book_ocr_conversion_execution_artifacts_for_draft(
        &self,
        import_id: &str,
        draft_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrConversionExecutionArtifact>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend
                .paper_book_ocr_conversion_execution_artifacts_for_draft(import_id, draft_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT artifact_id, import_id, draft_id, dossier_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, target_act_id, target_act_state, mutable_draft_act_created, \
             created_at, created_by, canonical_conversion_claimed, canonical_minutes_claimed, \
             canonical_act_created, canonical_document_created, signed_document_created, \
             archive_package_created, pdfa_created, pdfua_created, signature_created, \
             seal_created, archive_certification_claimed, legal_validity_claimed, \
             source_extracted_text_in_artifact, source_extracted_text_in_ledger_event \
             FROM paper_book_ocr_conversion_execution_artifacts \
             WHERE import_id = ?1 AND draft_id = ?2 ORDER BY created_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map(
            params![import_id, draft_id],
            row_to_paper_book_ocr_conversion_execution_artifact,
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// List follow-ups for an act, open items first, then oldest-created first.
    pub fn follow_ups_for_act(&self, act_id: ActId) -> Result<Vec<StoredFollowUp>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.follow_ups_for_act(act_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
             assignee, assignee_display, status, created_at, created_by, completed_at, \
             completed_by FROM follow_ups WHERE act_id = ?1 \
             ORDER BY CASE status WHEN 'Open' THEN 0 ELSE 1 END, created_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![act_id.to_string()], row_to_follow_up)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Fetch one follow-up by id, or `None` if unknown.
    pub fn follow_up(&self, id: &str) -> Result<Option<StoredFollowUp>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.follow_up(id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
             assignee, assignee_display, status, created_at, created_by, completed_at, \
             completed_by FROM follow_ups WHERE id = ?1",
        )?;
        stmt.query_row(params![id], row_to_follow_up)
            .optional()?
            .transpose()
    }

    /// Fetch the SIGNED PDF variant for `act_id` (bytes + metadata), or `None` if the act has no
    /// qualified signature yet (the api maps `None` to `GET /v1/acts/{id}/document/signed` 404).
    pub fn signed_document_for_act(
        &self,
        act_id: ActId,
    ) -> Result<Option<StoredSignedDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.signed_document_for_act(act_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
             trusted_list_status, signer_cert_subject, signing_time, signed_at, signer_cert_der, \
             timestamp_token_der, timestamp_trust_report_json, signer_capacity_evidence_json, \
             signed_pdf_bytes \
             FROM signed_documents WHERE act_id = ?1",
        )?;
        stmt.query_row(params![act_id.to_string()], row_to_signed_document)
            .optional()?
            .transpose()
    }

    /// Load every SIGNED PDF variant (metadata + bytes), keyed by act id — used to rehydrate the
    /// in-memory read model on boot.
    pub fn all_signed_documents(&self) -> Result<HashMap<ActId, StoredSignedDocument>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.all_signed_documents();
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
             trusted_list_status, signer_cert_subject, signing_time, signed_at, signer_cert_der, \
             timestamp_token_der, timestamp_trust_report_json, signer_capacity_evidence_json, \
             signed_pdf_bytes \
             FROM signed_documents",
        )?;
        let rows = stmt.query_map([], row_to_signed_document)?;
        let mut out = HashMap::new();
        for row in rows {
            let doc = row??;
            out.insert(doc.act_id, doc);
        }
        Ok(out)
    }

    /// Fetch one pending CMD signing session by id, or `None` if unknown/consumed. The api falls back
    /// to this after a restart drops the in-memory pending-session map.
    pub fn pending_cmd_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PendingCmdSession>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.pending_cmd_session(session_id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at, signer_capacity_evidence_json \
             FROM pending_cmd_sessions WHERE session_id = ?1",
        )?;
        stmt.query_row(params![session_id], row_to_pending_session)
            .optional()?
            .transpose()
    }

    /// Load every pending CMD signing session, keyed by session id — used to rehydrate the in-memory
    /// read model on boot (deliverable #2: sessions survive a restart).
    pub fn all_pending_cmd_sessions(
        &self,
    ) -> Result<HashMap<String, PendingCmdSession>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.all_pending_cmd_sessions();
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at, signer_capacity_evidence_json \
             FROM pending_cmd_sessions",
        )?;
        let rows = stmt.query_map([], row_to_pending_session)?;
        let mut out = HashMap::new();
        for row in rows {
            let session = row??;
            out.insert(session.session_id.clone(), session);
        }
        Ok(out)
    }

    // ── wp16 P3b — non-ledger sidecar stores (users / roles / delegations / settings / credentials) ──
    //
    // These read the shared-store mirror of the JSON file sidecars (plan §8.2). They are ADDITIVE:
    // `chancela-api` still loads from the per-node files today; a later coordinated phase switches the
    // loaders to these methods so a multi-node cluster reads consistent state. The `(id, json)` rows
    // are document-in-relational — the store never interprets `json` — exactly like the domain
    // aggregates. Rows are returned ordered by `id` for deterministic, stable enumeration.

    /// Load every stored user directory row as `(id, json)`, ordered by id. Mirrors the `users.json`
    /// array; the API deserializes each `json` back into its `User` value. Empty when unpopulated.
    pub fn users(&self) -> Result<Vec<(String, String)>, StoreError> {
        self.document_rows("users")
    }

    /// Load every stored role-catalog row as `(id, json)`, ordered by id. Mirrors the `roles.json`
    /// array. Empty when unpopulated.
    pub fn roles(&self) -> Result<Vec<(String, String)>, StoreError> {
        self.document_rows("roles")
    }

    /// Load every stored delegation row as `(id, json)`, ordered by id. Mirrors the `delegations.json`
    /// array (active **and** revoked). Empty when unpopulated.
    pub fn delegations(&self) -> Result<Vec<(String, String)>, StoreError> {
        self.document_rows("delegations")
    }

    /// Load every stored user-authored template row as `(id, json)`, ordered by id. Each `json` is
    /// the API's serialized `TemplateSpecDto` value (opaque to the store). Empty when unpopulated.
    pub fn user_templates(&self) -> Result<Vec<(String, String)>, StoreError> {
        self.document_rows("user_templates")
    }

    /// Read one user-authored template's serialized `json` by id, or `None` when unknown. The `json`
    /// is the API's serialized `TemplateSpecDto` value (opaque to the store).
    pub fn user_template(&self, id: &str) -> Result<Option<String>, StoreError> {
        self.document_row("user_templates", id)
    }

    /// Shared reader for the `(id, json)` document-in-relational sidecar tables (users/roles/
    /// delegations). `table` is a fixed internal identifier (never user input), so interpolating it
    /// into the query is safe. Ordered by id for a deterministic enumeration.
    fn document_rows(&self, table: &str) -> Result<Vec<(String, String)>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.document_rows(table);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(&format!("SELECT id, json FROM {table} ORDER BY id ASC"))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Shared single-row reader for the `(id, json)` document-in-relational sidecar tables. Returns
    /// the `json` column for `id`, or `None` when the id is unknown. `table` is a fixed internal
    /// identifier (never user input), so interpolating it into the query is safe.
    fn document_row(&self, table: &str, id: &str) -> Result<Option<String>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.document_row(table, id);
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(&format!("SELECT json FROM {table} WHERE id = ?1"))?;
        stmt.query_row(params![id], |row| row.get::<_, String>(0))
            .optional()
            .map_err(StoreError::from)
    }

    /// Read the single stored settings document as its serialized `json`, or `None` when the store has
    /// never persisted one. Mirrors `settings.json`; the API deserializes it into its `Settings` value.
    pub fn settings(&self) -> Result<Option<String>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.settings();
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare("SELECT json FROM settings WHERE id = ?1")?;
        stmt.query_row(params![SETTINGS_SINGLETON_ID], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(StoreError::from)
    }

    /// Read every stored provider-credential record ([`StoredCredentialRecord`]), ordered by
    /// `(mode, provider_id)`. Mirrors the `provider-credentials.enc.json` `records` list. Each
    /// `record_blob` is returned verbatim (opaque AEAD ciphertext — the store never decrypts it);
    /// the API's secretstore unwraps it. Empty when unpopulated.
    pub fn read_credential_records(&self) -> Result<Vec<StoredCredentialRecord>, StoreError> {
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return backend.read_credential_records();
        }
        let guard = self.locked_conn()?;
        let mut stmt = guard.prepare(
            "SELECT mode, provider_id, key_version, updated_at, record_blob \
             FROM provider_credentials ORDER BY mode ASC, provider_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredCredentialRecord {
                mode: row.get(0)?,
                provider_id: row.get(1)?,
                key_version: row.get(2)?,
                updated_at: row.get(3)?,
                record_blob: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Run a single transaction: append exactly one event row and upsert zero or more changed
    /// aggregate rows, committing on `Ok(())` and rolling back on `Err`.
    ///
    /// The closure receives a [`Tx`] handle over the open transaction; see the crate-level example.
    pub fn persist<F>(&self, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&Tx<'_>) -> Result<(), StoreError>,
    {
        self.persist_result(f)
    }

    /// Run a single transaction and return the closure's value after commit.
    ///
    /// This has the same atomicity guarantees as [`Store::persist`], but allows idempotent writers
    /// to report whether they inserted a row or observed an existing canonical row.
    pub fn persist_result<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce(&Tx<'_>) -> Result<T, StoreError>,
    {
        self.cluster_assert_writable()?;
        // Both backends roll back on drop by default, so any early return from `f` (its `?`) or a
        // mid-closure `Err` discards every statement already issued — nothing is persisted unless
        // the whole closure succeeds and we reach `commit`. On Postgres this is one transaction on
        // the single advisory-locked writer connection, preserving the ledger's atomic-append and
        // single-writer invariants (§4): a duplicate application-assigned `seq` trips the `events`
        // primary key and rolls the whole transaction back.
        match &self.backend {
            Backend::Sqlite(backend) => {
                let mut guard = backend.conn.lock().unwrap_or_else(|e| e.into_inner());
                let txn = guard.transaction()?;
                let tx = Tx {
                    kind: TxKind::Sqlite(txn),
                };
                let out = f(&tx)?;
                tx.commit()?;
                Ok(out)
            }
            #[cfg(feature = "postgres")]
            Backend::Postgres(backend) => {
                let mut writer = backend.writer();
                let txn = writer.transaction()?;
                let tx = Tx {
                    kind: TxKind::Postgres(std::cell::RefCell::new(txn)),
                };
                let out = f(&tx)?;
                tx.commit()?;
                Ok(out)
            }
        }
    }

    /// Snapshot the database with `VACUUM INTO` (transactionally consistent, no downtime), bundle
    /// it with the given `sidecars` and a `manifest.json` into a single zip under
    /// `<data_dir>/backups/`, and return the [`BackupManifest`] (frozen §3.2).
    ///
    /// Each `sidecars` entry is a path to an extra file or directory to include verbatim
    /// (`settings.json`, `users.json`, `cae-catalog.json`, `laws/`).
    pub fn backup(
        &self,
        data_dir: &Path,
        sidecars: &[PathBuf],
    ) -> Result<BackupManifest, StoreError> {
        // The Postgres backend has no on-disk SQLite file to `VACUUM INTO`; it produces a portable
        // logical export (all tables + the ledger head) into the same bundle/manifest shape instead
        // (wp15). Dispatched here before the SQLite-only `locked_conn` path check below.
        #[cfg(feature = "postgres")]
        if let Backend::Postgres(backend) = &self.backend {
            return self.pg_backup(backend, data_dir, sidecars);
        }
        // In-memory / anonymous databases have no on-disk snapshot to bundle → NotPersistent
        // (the api maps this to the §3.2 422). A real file store reports its path here.
        {
            let guard = self.locked_conn()?;
            match guard.path() {
                Some(p) if !p.is_empty() && p != ":memory:" => {}
                _ => return Err(StoreError::NotPersistent),
            }
        }

        let created_at = OffsetDateTime::now_utc();
        let stamp = utc_stamp(created_at);
        let backups_dir = data_dir.join("backups");
        std::fs::create_dir_all(&backups_dir)?;

        // 1. Transactionally-consistent hot snapshot via VACUUM INTO (no downtime, plan §D6). The
        //    target must not pre-exist; the per-run stamp keeps it unique. Cleaned up after zipping.
        let snapshot = backups_dir.join(format!(".snapshot-{stamp}.db"));
        {
            let guard = self.locked_conn()?;
            guard.execute(
                "VACUUM INTO ?1",
                params![snapshot.to_string_lossy().as_ref()],
            )?;
        }

        // 2. Ledger head/length/verified from a fresh load of the live DB (identical to the snapshot
        //    just taken). Done after releasing the lock — `load` re-locks the connection.
        let loaded = self.load()?;
        let ledger_length = loaded.ledger.len() as u64;
        let ledger_head = loaded.ledger.head().map(|h| hex(&h));
        let ledger_verified = loaded.chain_status.is_ok();

        // 3. Build the archive at a temp path, then atomically rename into place.
        let final_path = backups_dir.join(format!("chancela-backup-{stamp}.zip"));
        let tmp_path = backups_dir.join(format!(".chancela-backup-{stamp}.zip.tmp"));
        let mut files: Vec<BackupFile> = Vec::new();
        {
            let file = std::fs::File::create(&tmp_path)?;
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();

            add_file_to_zip(&mut zip, DB_FILE, &snapshot, opts, &mut files)?;
            for sidecar in sidecars {
                // Skip-missing is tolerated; a name comes from the sidecar's own file/dir name.
                if let Some(base) = sidecar
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                {
                    add_path_to_zip(&mut zip, &base, sidecar, opts, &mut files)?;
                }
            }

            // The manifest is embedded for the restore path (its per-file digests are what a restore
            // verifies). Its own `bytes` cannot include the enclosing archive's final size, so the
            // embedded copy carries `bytes: 0`; the returned/api manifest below carries the real size.
            let embedded = BackupManifest {
                path: final_path.to_string_lossy().into_owned(),
                bytes: 0,
                created_at,
                app_version: env!("CARGO_PKG_VERSION").to_string(),
                store_schema_version: schema::SCHEMA_VERSION,
                ledger_length,
                ledger_head: ledger_head.clone(),
                ledger_verified,
                files: files.clone(),
            };
            zip.start_file("manifest.json", opts)?;
            zip.write_all(serde_json::to_string_pretty(&embedded)?.as_bytes())?;
            zip.finish()?;
        }

        // Best-effort cleanup of the transient snapshot (VACUUM INTO yields a single standalone DB).
        let _ = std::fs::remove_file(&snapshot);

        std::fs::rename(&tmp_path, &final_path)?;
        let bytes = std::fs::metadata(&final_path)?.len();

        Ok(BackupManifest {
            path: final_path.to_string_lossy().into_owned(),
            bytes,
            created_at,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            store_schema_version: schema::SCHEMA_VERSION,
            ledger_length,
            ledger_head,
            ledger_verified,
            files,
        })
    }

    /// Take the normal verified backup zip, wrap it in an encrypted envelope, and return the same
    /// manifest shape with `path`/`bytes` describing the encrypted artifact.
    pub fn backup_encrypted(
        &self,
        data_dir: &Path,
        sidecars: &[PathBuf],
        passphrase: &str,
    ) -> Result<BackupManifest, StoreError> {
        let mut manifest = self.backup(data_dir, sidecars)?;
        let plaintext_path = PathBuf::from(&manifest.path);
        let result = (|| {
            let zip_bytes = std::fs::read(&plaintext_path)?;
            let envelope = encrypt_backup_envelope(&zip_bytes, passphrase)?;
            let encrypted_path = plaintext_path.with_extension("cbackup");
            let tmp_path = tmp_backup_path(&encrypted_path);
            std::fs::write(&tmp_path, &envelope)?;
            std::fs::rename(&tmp_path, &encrypted_path).inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp_path);
            })?;
            manifest.path = encrypted_path.to_string_lossy().into_owned();
            manifest.bytes = std::fs::metadata(&encrypted_path)?.len();
            Ok(manifest)
        })();
        let _ = std::fs::remove_file(&plaintext_path);
        result
    }
}

/// A transactional write handle passed to the [`Store::persist`] closure. Each method appends or
/// upserts one row inside the enclosing transaction; the whole closure commits atomically.
///
/// The lifetime ties the handle to the open transaction borrowed from the store's connection.
pub struct Tx<'conn> {
    /// The backend-specific transaction handle. Every `Tx` method issues one statement against it;
    /// the whole closure commits (or, on any `Err`, rolls back) in [`Store::persist`]. Internal —
    /// not part of the frozen §3.1 API.
    kind: TxKind<'conn>,
}

/// Backend-specific transaction handle behind the public [`Tx`] facade (wp14 Phase 0 seam).
///
/// Internal enum, not part of the §3.1 API. Each `Tx` method matches on this to pick the backend
/// dialect while preserving the public synchronous transaction facade.
pub(crate) enum TxKind<'conn> {
    /// The open rusqlite transaction (default backend).
    Sqlite(rusqlite::Transaction<'conn>),
    /// The open Postgres transaction (wp14 Phase 1). Wrapped in a `RefCell` because the frozen
    /// `Tx` methods take `&self` while `postgres::Transaction::execute` needs `&mut self`; the
    /// interior mutability restores the SQLite-parity `&self` write API. Only present when the
    /// off-by-default `postgres` feature is enabled.
    #[cfg(feature = "postgres")]
    Postgres(std::cell::RefCell<postgres::Transaction<'conn>>),
}

impl<'conn> Tx<'conn> {
    /// Internal: borrow the raw transaction so the [`recovery`] paths can run their bespoke
    /// DELETE / INSERT SQL (domain-wipe, factory-blank, imported-book upsert) inside the same
    /// atomic commit as an `append_event`. This raw escape hatch is SQLite-only. Not part of the
    /// public API surface.
    pub(crate) fn raw(&self) -> Result<&rusqlite::Transaction<'conn>, StoreError> {
        match &self.kind {
            TxKind::Sqlite(txn) => Ok(txn),
            #[cfg(feature = "postgres")]
            TxKind::Postgres(_) => Err(StoreError::UnsupportedOnPostgres {
                op: "raw SQLite transaction SQL (bespoke recovery / non-core writer)",
            }),
        }
    }

    /// Internal: run one or more parameter-free statements (`;`-separated) inside the enclosing
    /// transaction on **either** backend. The recovery-plane row-clearing (`DELETE FROM …`) and the
    /// re-anchor `events` rewrite use this so those atomic operations work on Postgres as well as
    /// SQLite, instead of funnelling through the SQLite-only [`Tx::raw`] escape hatch. Not part of
    /// the public API surface.
    pub(crate) fn execute_recovery_batch(&self, sql: &str) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(txn) => {
                txn.execute_batch(sql)?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().batch_execute(sql)?;
            }
        }
        Ok(())
    }

    /// Commit the enclosing transaction, consuming the handle. Called by [`Store::persist_result`]
    /// once the closure has succeeded.
    fn commit(self) -> Result<(), StoreError> {
        match self.kind {
            TxKind::Sqlite(txn) => txn.commit()?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell.into_inner().commit()?,
        }
        Ok(())
    }
}

impl Tx<'_> {
    /// Persist one ledger event row into the `events` table (append-only, keyed by `seq`).
    ///
    /// The hash-chain fields are stored directly: the ids/scope/kind/actor as text, the timestamp
    /// as RFC 3339 text (round-trips the instant), and the three 32-byte digests as BLOBs.
    pub fn append_event(&self, event: &Event) -> Result<(), StoreError> {
        const SQL: &str = "INSERT INTO events \
             (seq, id, actor, justification, timestamp, scope, kind, payload_digest, prev_hash, hash, links) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
        let timestamp = format_event_timestamp(event.timestamp);
        let links_json = serde_json::to_string(&event.links)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    SQL,
                    params![
                        event.seq as i64,
                        event.id.to_string(),
                        event.actor,
                        event.justification,
                        timestamp,
                        event.scope,
                        event.kind,
                        &event.payload_digest[..],
                        &event.prev_hash[..],
                        &event.hash[..],
                        links_json,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                // No ON CONFLICT: `events` is append-only, so a duplicate application-assigned
                // `seq` must trip the primary key and roll the whole transaction back (§4).
                let seq = event.seq as i64;
                let id = event.id.to_string();
                let payload_digest: &[u8] = &event.payload_digest;
                let prev_hash: &[u8] = &event.prev_hash;
                let hash: &[u8] = &event.hash;
                cell.borrow_mut().execute(
                    &crate::dialect::rewrite_placeholders(SQL),
                    &[
                        &seq,
                        &id,
                        &event.actor,
                        &event.justification,
                        &timestamp,
                        &event.scope,
                        &event.kind,
                        &payload_digest,
                        &prev_hash,
                        &hash,
                        &links_json,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert an entity's row (`entities`, document-in-relational).
    pub fn upsert_entity(&self, entity: &Entity) -> Result<(), StoreError> {
        let id = entity.id.to_string();
        let json = serde_json::to_string(entity)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO entities (id, json) VALUES (?1, ?2)",
                    params![id, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO entities (id, json) VALUES ($1, $2) \
                     ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json",
                    &[&id, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert a book's row (`books`, with the indexed `entity_id` scope column).
    pub fn upsert_book(&self, book: &Book) -> Result<(), StoreError> {
        let id = book.id.to_string();
        let entity_id = book.entity_id.to_string();
        let json = serde_json::to_string(book)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO books (id, entity_id, json) VALUES (?1, ?2, ?3)",
                    params![id, entity_id, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO books (id, entity_id, json) VALUES ($1, $2, $3) \
                     ON CONFLICT (id) DO UPDATE SET entity_id = EXCLUDED.entity_id, \
                     json = EXCLUDED.json",
                    &[&id, &entity_id, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert an act's row (`acts`, with the indexed `book_id` scope column).
    pub fn upsert_act(&self, act: &Act) -> Result<(), StoreError> {
        let id = act.id.to_string();
        let book_id = act.book_id.to_string();
        let json = serde_json::to_string(act)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO acts (id, book_id, json) VALUES (?1, ?2, ?3)",
                    params![id, book_id, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO acts (id, book_id, json) VALUES ($1, $2, $3) \
                     ON CONFLICT (id) DO UPDATE SET book_id = EXCLUDED.book_id, \
                     json = EXCLUDED.json",
                    &[&id, &book_id, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert an imported certidão extract for an entity (`registry_extracts`, keyed by entity id).
    pub fn upsert_registry_extract(
        &self,
        entity_id: EntityId,
        extract: &RegistryExtract,
    ) -> Result<(), StoreError> {
        let entity_id = entity_id.to_string();
        let json = serde_json::to_string(extract)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO registry_extracts (entity_id, json) VALUES (?1, ?2)",
                    params![entity_id, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO registry_extracts (entity_id, json) VALUES ($1, $2) \
                     ON CONFLICT (entity_id) DO UPDATE SET json = EXCLUDED.json",
                    &[&entity_id, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert a generated PDF/A document bound to an act (`documents`, with the indexed `act_id`
    /// scope column). Idempotent on the document id (`INSERT OR REPLACE`), mirroring the aggregate
    /// writers.
    ///
    /// This is a [`Tx`] method precisely so the api can call it **inside the seal transaction** —
    /// alongside `append_event(act.sealed)`, `append_event(document.generated)` and `upsert_act` —
    /// so the document, its digest event, and the act all land in one durable commit and roll back
    /// together on any failure (plan t48 §3.4 "one durable commit").
    pub fn upsert_document(&self, doc: &StoredDocument) -> Result<(), StoreError> {
        let created_at = doc
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO documents \
                     (id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        doc.id,
                        doc.act_id.to_string(),
                        doc.template_id,
                        doc.pdf_digest,
                        doc.profile,
                        created_at,
                        doc.pdf_bytes,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let act_id = doc.act_id.to_string();
                let pdf_bytes: &[u8] = &doc.pdf_bytes;
                cell.borrow_mut().execute(
                    "INSERT INTO documents \
                     (id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     ON CONFLICT (id) DO UPDATE SET act_id = EXCLUDED.act_id, \
                     template_id = EXCLUDED.template_id, pdf_digest = EXCLUDED.pdf_digest, \
                     profile = EXCLUDED.profile, created_at = EXCLUDED.created_at, \
                     pdf_bytes = EXCLUDED.pdf_bytes",
                    &[
                        &doc.id,
                        &act_id,
                        &doc.template_id,
                        &doc.pdf_digest,
                        &doc.profile,
                        &created_at,
                        &pdf_bytes,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Insert one isolated `imported_books` row inside the enclosing transaction (wp21). Portable
    /// across the SQLite and Postgres backends so [`Store::import_book`] persists the retained bundle
    /// and its verify-before-trust verdict atomically with the chained `ledger.imported` event, rather
    /// than through the SQLite-only [`Tx::raw`] escape hatch. The `import_id` primary key is a fresh
    /// uuid, so a plain `INSERT` is correct: a collision would be a programming error, not a retry.
    pub(crate) fn insert_imported_book(
        &self,
        row: &crate::recovery::ImportedBookInsert<'_>,
    ) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT INTO imported_books \
                     (import_id, entity_id, book_id, source_instance_id, bundle_digest, verdict, \
                      break_json, collided, imported_at, bundle_bytes) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        row.import_id,
                        row.entity_id,
                        row.book_id,
                        row.source_instance_id,
                        row.bundle_digest,
                        row.verdict,
                        row.break_json,
                        row.collided as i64,
                        row.imported_at,
                        row.bundle_bytes,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let collided = row.collided as i64;
                let bundle_bytes: &[u8] = row.bundle_bytes;
                cell.borrow_mut().execute(
                    "INSERT INTO imported_books \
                     (import_id, entity_id, book_id, source_instance_id, bundle_digest, verdict, \
                      break_json, collided, imported_at, bundle_bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &row.import_id,
                        &row.entity_id,
                        &row.book_id,
                        &row.source_instance_id,
                        &row.bundle_digest,
                        &row.verdict,
                        &row.break_json,
                        &collided,
                        &row.imported_at,
                        &bundle_bytes,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Insert metadata-only dispatch evidence for a generated document, returning the canonical row.
    ///
    /// The `(document_id, idempotency_key)` primary key enforces exact-retry idempotency. A duplicate
    /// key is not an error: the first row is retained and returned so callers can avoid appending a
    /// second durable ledger event.
    pub fn upsert_generated_document_dispatch_evidence(
        &self,
        evidence: &StoredGeneratedDocumentDispatchEvidence,
    ) -> Result<GeneratedDocumentDispatchEvidenceUpsert, StoreError> {
        let dispatched_at = evidence
            .dispatched_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let recorded_at = evidence
            .recorded_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let recipients_json = serde_json::to_string(&evidence.recipients)?;
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "INSERT OR IGNORE INTO generated_document_dispatch_evidence \
                 (document_id, idempotency_key, act_id, template_id, actor, dispatched_at, channel, \
                  reference, evidence_reference, imported_document_id, recipients_json, \
                  operator_note, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    evidence.document_id.as_str(),
                    evidence.idempotency_key.as_str(),
                    evidence.act_id.to_string(),
                    evidence.template_id.as_str(),
                    evidence.actor.as_str(),
                    dispatched_at.as_str(),
                    evidence.channel.as_deref(),
                    evidence.reference.as_deref(),
                    evidence.evidence_reference.as_deref(),
                    evidence.imported_document_id.as_deref(),
                    recipients_json.as_str(),
                    evidence.operator_note.as_deref(),
                    recorded_at.as_str(),
                ],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                // `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`: a duplicate `(document_id,
                // idempotency_key)` is not an error; the existing row is retained and read back below.
                let act_id = evidence.act_id.to_string();
                let channel = evidence.channel.as_deref();
                let reference = evidence.reference.as_deref();
                let evidence_reference = evidence.evidence_reference.as_deref();
                let imported_document_id = evidence.imported_document_id.as_deref();
                let operator_note = evidence.operator_note.as_deref();
                cell.borrow_mut().execute(
                    "INSERT INTO generated_document_dispatch_evidence \
                     (document_id, idempotency_key, act_id, template_id, actor, dispatched_at, \
                      channel, reference, evidence_reference, imported_document_id, \
                      recipients_json, operator_note, recorded_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                     ON CONFLICT (document_id, idempotency_key) DO NOTHING",
                    &[
                        &evidence.document_id,
                        &evidence.idempotency_key,
                        &act_id,
                        &evidence.template_id,
                        &evidence.actor,
                        &dispatched_at,
                        &channel,
                        &reference,
                        &evidence_reference,
                        &imported_document_id,
                        &recipients_json,
                        &operator_note,
                        &recorded_at,
                    ],
                )? as usize
            }
        };
        let stored = self
            .generated_document_dispatch_evidence_by_key(
                &evidence.document_id,
                &evidence.idempotency_key,
            )?
            .ok_or_else(|| {
                StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "generated document dispatch evidence insert did not return a row",
                ))
            })?;
        Ok(if changed == 0 {
            GeneratedDocumentDispatchEvidenceUpsert::Existing(stored)
        } else {
            GeneratedDocumentDispatchEvidenceUpsert::Inserted(stored)
        })
    }

    /// Fetch a generated-document dispatch evidence row by key inside the current transaction.
    pub fn generated_document_dispatch_evidence_by_key(
        &self,
        document_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredGeneratedDocumentDispatchEvidence>, StoreError> {
        const SQL: &str = "SELECT document_id, idempotency_key, act_id, template_id, actor, \
             dispatched_at, channel, reference, evidence_reference, imported_document_id, \
             recipients_json, operator_note, recorded_at \
             FROM generated_document_dispatch_evidence \
             WHERE document_id = ?1 AND idempotency_key = ?2";
        match &self.kind {
            TxKind::Sqlite(_) => {
                let raw = self.raw()?;
                let mut stmt = raw.prepare(SQL)?;
                stmt.query_row(
                    params![document_id, idempotency_key],
                    row_to_generated_dispatch_evidence,
                )
                .optional()?
                .transpose()
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let row = cell.borrow_mut().query_opt(
                    &crate::dialect::rewrite_placeholders(SQL),
                    &[&document_id, &idempotency_key],
                )?;
                row.as_ref()
                    .map(crate::pg::row_to_generated_dispatch_evidence)
                    .transpose()
            }
        }
    }

    /// Upsert a validated, non-canonical imported document (`imported_documents`, schema v5).
    /// Idempotent on the import id and intended to run in the same transaction as the
    /// `document.imported` ledger event. This never touches the canonical generated `documents` row
    /// nor the `signed_documents` variant.
    pub fn upsert_imported_document(&self, doc: &StoredImportedDocument) -> Result<(), StoreError> {
        let imported_at = doc
            .meta
            .imported_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let size_bytes = i64::try_from(doc.meta.size_bytes).map_err(|_| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "imported document size does not fit sqlite INTEGER",
            ))
        })?;
        let act_id = doc.meta.act_id.as_ref().map(ToString::to_string);
        let reviewed_at = doc.meta.operator_reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let review_status = doc.meta.operator_review_status.as_str();
        let guardrails_json = serde_json::to_string(&doc.meta.operator_acknowledged_guardrail_ids)?;
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO imported_documents \
                     (id, act_id, filename, declared_content_type, detected_content_type, sha256, \
                      size_bytes, imported_at, imported_by, operator_review_status, \
                      operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                      operator_acknowledged_guardrail_ids_json, bytes) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        doc.meta.id,
                        act_id,
                        doc.meta.filename,
                        doc.meta.declared_content_type,
                        doc.meta.detected_content_type,
                        doc.meta.sha256,
                        size_bytes,
                        imported_at,
                        doc.meta.imported_by,
                        review_status,
                        reviewed_at,
                        doc.meta.operator_reviewed_by,
                        doc.meta.operator_review_note,
                        guardrails_json,
                        doc.bytes,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let filename = doc.meta.filename.as_deref();
                let declared_content_type = doc.meta.declared_content_type.as_deref();
                let reviewed_by = doc.meta.operator_reviewed_by.as_deref();
                let review_note = doc.meta.operator_review_note.as_deref();
                let bytes: &[u8] = &doc.bytes;
                cell.borrow_mut().execute(
                    "INSERT INTO imported_documents \
                     (id, act_id, filename, declared_content_type, detected_content_type, sha256, \
                      size_bytes, imported_at, imported_by, operator_review_status, \
                      operator_reviewed_at, operator_reviewed_by, operator_review_note, \
                      operator_acknowledged_guardrail_ids_json, bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                     ON CONFLICT (id) DO UPDATE SET act_id = EXCLUDED.act_id, \
                     filename = EXCLUDED.filename, \
                     declared_content_type = EXCLUDED.declared_content_type, \
                     detected_content_type = EXCLUDED.detected_content_type, \
                     sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, \
                     imported_at = EXCLUDED.imported_at, imported_by = EXCLUDED.imported_by, \
                     operator_review_status = EXCLUDED.operator_review_status, \
                     operator_reviewed_at = EXCLUDED.operator_reviewed_at, \
                     operator_reviewed_by = EXCLUDED.operator_reviewed_by, \
                     operator_review_note = EXCLUDED.operator_review_note, \
                     operator_acknowledged_guardrail_ids_json = \
                     EXCLUDED.operator_acknowledged_guardrail_ids_json, bytes = EXCLUDED.bytes",
                    &[
                        &doc.meta.id,
                        &act_id,
                        &filename,
                        &declared_content_type,
                        &doc.meta.detected_content_type,
                        &doc.meta.sha256,
                        &size_bytes,
                        &imported_at,
                        &doc.meta.imported_by,
                        &review_status,
                        &reviewed_at,
                        &reviewed_by,
                        &review_note,
                        &guardrails_json,
                        &bytes,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Update the operator review metadata for a preserved imported document. This deliberately
    /// touches no retained bytes and no canonical document/signed-document rows.
    pub fn review_imported_document(
        &self,
        id: &str,
        status: StoredImportedDocumentReviewStatus,
        reviewed_at: Option<OffsetDateTime>,
        reviewed_by: Option<&str>,
        review_note: Option<&str>,
        acknowledged_guardrail_ids: &[String],
    ) -> Result<(), StoreError> {
        let reviewed_at = reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let acknowledged_guardrail_ids_json = serde_json::to_string(acknowledged_guardrail_ids)?;
        let status_str = status.as_str();
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "UPDATE imported_documents SET operator_review_status = ?1, \
                 operator_reviewed_at = ?2, operator_reviewed_by = ?3, operator_review_note = ?4, \
                 operator_acknowledged_guardrail_ids_json = ?5 \
                 WHERE id = ?6",
                params![
                    status_str,
                    reviewed_at,
                    reviewed_by,
                    review_note,
                    acknowledged_guardrail_ids_json,
                    id,
                ],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell.borrow_mut().execute(
                "UPDATE imported_documents SET operator_review_status = $1, \
                 operator_reviewed_at = $2, operator_reviewed_by = $3, operator_review_note = $4, \
                 operator_acknowledged_guardrail_ids_json = $5 WHERE id = $6",
                &[
                    &status_str,
                    &reviewed_at,
                    &reviewed_by,
                    &review_note,
                    &acknowledged_guardrail_ids_json,
                    &id,
                ],
            )? as usize,
        };
        if changed == 0 {
            return Err(StoreError::NotFound(format!("imported document {id}")));
        }
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT INTO imported_document_review_history \
                     (imported_document_id, review_status, reviewed_at, reviewed_by, review_note, \
                      acknowledged_guardrail_ids_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        id,
                        status_str,
                        reviewed_at,
                        reviewed_by,
                        review_note,
                        acknowledged_guardrail_ids_json,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                // `id` is omitted: the Postgres `GENERATED ALWAYS AS IDENTITY` column serves it,
                // mirroring SQLite's rowid autoincrement for this append-only history table.
                cell.borrow_mut().execute(
                    "INSERT INTO imported_document_review_history \
                     (imported_document_id, review_status, reviewed_at, reviewed_by, review_note, \
                      acknowledged_guardrail_ids_json) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &id,
                        &status_str,
                        &reviewed_at,
                        &reviewed_by,
                        &review_note,
                        &acknowledged_guardrail_ids_json,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert a preserved historical paper-book package (`paper_book_imports`, schema v8).
    /// Intended to run in the same transaction as its metadata-only `paper_book_import.preserved`
    /// ledger event. This never touches canonical book, act, document, or signed-document rows.
    pub fn upsert_paper_book_import(
        &self,
        import: &StoredPaperBookImport,
    ) -> Result<(), StoreError> {
        validate_paper_book_import_ranges(&import.meta, std::io::ErrorKind::InvalidInput)?;
        let imported_at = import
            .meta
            .imported_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let size_bytes = i64::try_from(import.meta.size_bytes).map_err(|_| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "paper-book import size does not fit sqlite INTEGER",
            ))
        })?;
        let original_number_from = optional_u64_to_i64(
            import.meta.original_number_from,
            "paper-book import original_number_from",
        )?;
        let original_number_to = optional_u64_to_i64(
            import.meta.original_number_to,
            "paper-book import original_number_to",
        )?;
        let date_from = format_date(import.meta.date_from);
        let date_to = format_date(import.meta.date_to);
        let page_count = i64::from(import.meta.page_count);
        let page_from = i64::from(import.meta.page_from);
        let page_to = i64::from(import.meta.page_to);
        let ocr_status = import.meta.ocr_status.as_str();
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO paper_book_imports \
                     (import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                      date_to, page_count, page_from, page_to, original_number_from, \
                      original_number_to, sha256, size_bytes, content_type, source_filename, \
                      notes, imported_at, imported_by, ocr_status, bytes) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                             ?16, ?17, ?18, ?19, ?20, ?21)",
                    params![
                        import.meta.import_id,
                        import.meta.entity_ref,
                        import.meta.entity_name,
                        import.meta.entity_nipc,
                        import.meta.book_ref,
                        date_from,
                        date_to,
                        page_count,
                        page_from,
                        page_to,
                        original_number_from,
                        original_number_to,
                        import.meta.sha256,
                        size_bytes,
                        import.meta.content_type,
                        import.meta.source_filename,
                        import.meta.notes,
                        imported_at,
                        import.meta.imported_by,
                        ocr_status,
                        import.bytes,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let source_filename = import.meta.source_filename.as_deref();
                let notes = import.meta.notes.as_deref();
                let bytes: &[u8] = &import.bytes;
                cell.borrow_mut().execute(
                    "INSERT INTO paper_book_imports \
                     (import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                      date_to, page_count, page_from, page_to, original_number_from, \
                      original_number_to, sha256, size_bytes, content_type, source_filename, \
                      notes, imported_at, imported_by, ocr_status, bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                             $16, $17, $18, $19, $20, $21) \
                     ON CONFLICT (import_id) DO UPDATE SET entity_ref = EXCLUDED.entity_ref, \
                     entity_name = EXCLUDED.entity_name, entity_nipc = EXCLUDED.entity_nipc, \
                     book_ref = EXCLUDED.book_ref, date_from = EXCLUDED.date_from, \
                     date_to = EXCLUDED.date_to, page_count = EXCLUDED.page_count, \
                     page_from = EXCLUDED.page_from, page_to = EXCLUDED.page_to, \
                     original_number_from = EXCLUDED.original_number_from, \
                     original_number_to = EXCLUDED.original_number_to, sha256 = EXCLUDED.sha256, \
                     size_bytes = EXCLUDED.size_bytes, content_type = EXCLUDED.content_type, \
                     source_filename = EXCLUDED.source_filename, notes = EXCLUDED.notes, \
                     imported_at = EXCLUDED.imported_at, imported_by = EXCLUDED.imported_by, \
                     ocr_status = EXCLUDED.ocr_status, bytes = EXCLUDED.bytes",
                    &[
                        &import.meta.import_id,
                        &import.meta.entity_ref,
                        &import.meta.entity_name,
                        &import.meta.entity_nipc,
                        &import.meta.book_ref,
                        &date_from,
                        &date_to,
                        &page_count,
                        &page_from,
                        &page_to,
                        &original_number_from,
                        &original_number_to,
                        &import.meta.sha256,
                        &size_bytes,
                        &import.meta.content_type,
                        &source_filename,
                        &notes,
                        &imported_at,
                        &import.meta.imported_by,
                        &ocr_status,
                        &bytes,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Update only the OCR lifecycle marker for a preserved historical paper-book import inside
    /// the caller's transaction. This stores no OCR output and leaves package bytes untouched.
    pub fn update_paper_book_import_ocr_status(
        &self,
        import_id: &str,
        status: StoredPaperBookOcrStatus,
    ) -> Result<(), StoreError> {
        let status_str = status.as_str();
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "UPDATE paper_book_imports SET ocr_status = ?1 WHERE import_id = ?2",
                params![status_str, import_id],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell.borrow_mut().execute(
                "UPDATE paper_book_imports SET ocr_status = $1 WHERE import_id = $2",
                &[&status_str, &import_id],
            )? as usize,
        };
        if changed == 0 {
            return Err(StoreError::NotFound(format!(
                "paper-book import {import_id}"
            )));
        }
        Ok(())
    }

    /// Upsert a non-authoritative OCR draft result for a preserved historical paper-book import.
    /// This never changes package bytes or canonical book/act/document rows.
    pub fn upsert_paper_book_ocr_draft(
        &self,
        draft: &StoredPaperBookOcrDraft,
    ) -> Result<(), StoreError> {
        let created_at = draft
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let reviewed_at = draft.reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let page_spans_json = serde_json::to_string(&draft.page_spans)?;
        let review_status = draft.review_status.as_str();
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO paper_book_ocr_drafts \
                     (draft_id, import_id, extracted_text, text_digest, page_spans_json, \
                      confidence, engine_name, engine_version, created_at, created_by, \
                      review_status, reviewed_at, reviewed_by, review_note, superseded_by) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        draft.draft_id,
                        draft.import_id,
                        draft.extracted_text,
                        draft.text_digest,
                        page_spans_json,
                        draft.confidence,
                        draft.engine_name,
                        draft.engine_version,
                        created_at,
                        draft.created_by,
                        review_status,
                        reviewed_at,
                        draft.reviewed_by,
                        draft.review_note,
                        draft.superseded_by,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let extracted_text = draft.extracted_text.as_deref();
                let text_digest = draft.text_digest.as_deref();
                let engine_version = draft.engine_version.as_deref();
                let reviewed_by = draft.reviewed_by.as_deref();
                let review_note = draft.review_note.as_deref();
                let superseded_by = draft.superseded_by.as_deref();
                cell.borrow_mut().execute(
                    "INSERT INTO paper_book_ocr_drafts \
                     (draft_id, import_id, extracted_text, text_digest, page_spans_json, \
                      confidence, engine_name, engine_version, created_at, created_by, \
                      review_status, reviewed_at, reviewed_by, review_note, superseded_by) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                     ON CONFLICT (draft_id) DO UPDATE SET import_id = EXCLUDED.import_id, \
                     extracted_text = EXCLUDED.extracted_text, text_digest = EXCLUDED.text_digest, \
                     page_spans_json = EXCLUDED.page_spans_json, confidence = EXCLUDED.confidence, \
                     engine_name = EXCLUDED.engine_name, engine_version = EXCLUDED.engine_version, \
                     created_at = EXCLUDED.created_at, created_by = EXCLUDED.created_by, \
                     review_status = EXCLUDED.review_status, reviewed_at = EXCLUDED.reviewed_at, \
                     reviewed_by = EXCLUDED.reviewed_by, review_note = EXCLUDED.review_note, \
                     superseded_by = EXCLUDED.superseded_by",
                    &[
                        &draft.draft_id,
                        &draft.import_id,
                        &extracted_text,
                        &text_digest,
                        &page_spans_json,
                        &draft.confidence,
                        &draft.engine_name,
                        &engine_version,
                        &created_at,
                        &draft.created_by,
                        &review_status,
                        &reviewed_at,
                        &reviewed_by,
                        &review_note,
                        &superseded_by,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Insert a metadata-only OCR conversion dossier for an accepted paper-book OCR draft.
    ///
    /// Duplicate import/draft creation is idempotent: the first row is retained and later attempts
    /// for the same pair are ignored. This stores no raw OCR text and touches no canonical
    /// book/act/document/signed-document/archive rows.
    pub fn upsert_paper_book_ocr_conversion_dossier(
        &self,
        dossier: &StoredPaperBookOcrConversionDossier,
    ) -> Result<PaperBookOcrConversionDossierUpsert, StoreError> {
        if dossier.source_review_status != StoredPaperBookOcrReviewStatus::Accepted {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "paper-book OCR conversion dossier requires an accepted OCR draft",
            )));
        }
        let source_page_spans_json = serde_json::to_string(&dossier.source_page_spans)?;
        let source_reviewed_at = dossier.source_reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let created_at = dossier
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let source_review_status = dossier.source_review_status.as_str();
        const READBACK_SQL: &str = "SELECT dossier_id, import_id, draft_id, source_text_digest, \
             source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, created_at, created_by \
             FROM paper_book_ocr_conversion_dossiers WHERE import_id = ?1 AND draft_id = ?2";
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "INSERT OR IGNORE INTO paper_book_ocr_conversion_dossiers \
                 (dossier_id, import_id, draft_id, source_text_digest, source_page_spans_json, \
                  source_review_status, source_reviewed_at, source_reviewed_by, created_at, \
                  created_by) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    dossier.dossier_id.as_str(),
                    dossier.import_id.as_str(),
                    dossier.draft_id.as_str(),
                    dossier.source_text_digest.as_deref(),
                    source_page_spans_json.as_str(),
                    source_review_status,
                    source_reviewed_at.as_deref(),
                    dossier.source_reviewed_by.as_deref(),
                    created_at.as_str(),
                    dossier.created_by.as_str(),
                ],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let source_text_digest = dossier.source_text_digest.as_deref();
                let source_reviewed_at = source_reviewed_at.as_deref();
                let source_reviewed_by = dossier.source_reviewed_by.as_deref();
                cell.borrow_mut().execute(
                    "INSERT INTO paper_book_ocr_conversion_dossiers \
                     (dossier_id, import_id, draft_id, source_text_digest, source_page_spans_json, \
                      source_review_status, source_reviewed_at, source_reviewed_by, created_at, \
                      created_by) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
                    &[
                        &dossier.dossier_id,
                        &dossier.import_id,
                        &dossier.draft_id,
                        &source_text_digest,
                        &source_page_spans_json,
                        &source_review_status,
                        &source_reviewed_at,
                        &source_reviewed_by,
                        &created_at,
                        &dossier.created_by,
                    ],
                )? as usize
            }
        };
        let stored = match &self.kind {
            TxKind::Sqlite(_) => {
                let raw = self.raw()?;
                let mut stmt = raw.prepare(READBACK_SQL)?;
                stmt.query_row(
                    params![dossier.import_id.as_str(), dossier.draft_id.as_str()],
                    row_to_paper_book_ocr_conversion_dossier,
                )
                .optional()?
                .transpose()?
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell
                .borrow_mut()
                .query_opt(
                    &crate::dialect::rewrite_placeholders(READBACK_SQL),
                    &[&dossier.import_id, &dossier.draft_id],
                )?
                .as_ref()
                .map(crate::pg::row_to_paper_book_ocr_conversion_dossier)
                .transpose()?,
        };
        let stored = stored.ok_or_else(|| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "paper-book OCR conversion dossier insert was ignored but no canonical import/draft row exists",
            ))
        })?;
        if changed > 0 {
            Ok(PaperBookOcrConversionDossierUpsert::Inserted(stored))
        } else {
            Ok(PaperBookOcrConversionDossierUpsert::Existing(stored))
        }
    }

    /// Insert a reviewed OCR conversion execution artifact for a mutable act draft.
    ///
    /// Duplicate import/draft/target-act creation is idempotent: the first row is retained and later
    /// attempts return that stored row. The artifact stores no raw OCR text and all no-claim flags
    /// must be explicitly false.
    pub fn upsert_paper_book_ocr_conversion_execution_artifact(
        &self,
        artifact: &StoredPaperBookOcrConversionExecutionArtifact,
    ) -> Result<PaperBookOcrConversionExecutionArtifactUpsert, StoreError> {
        validate_paper_book_ocr_conversion_execution_artifact(artifact)?;
        let source_page_spans_json = serde_json::to_string(&artifact.source_page_spans)?;
        let source_reviewed_at = artifact.source_reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let created_at = artifact
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let source_review_status = artifact.source_review_status.as_str();
        const READBACK_SQL: &str = "SELECT artifact_id, import_id, draft_id, dossier_id, \
             source_text_digest, source_page_spans_json, source_review_status, source_reviewed_at, \
             source_reviewed_by, target_act_id, target_act_state, mutable_draft_act_created, \
             created_at, created_by, canonical_conversion_claimed, canonical_minutes_claimed, \
             canonical_act_created, canonical_document_created, signed_document_created, \
             archive_package_created, pdfa_created, pdfua_created, signature_created, \
             seal_created, archive_certification_claimed, legal_validity_claimed, \
             source_extracted_text_in_artifact, source_extracted_text_in_ledger_event \
             FROM paper_book_ocr_conversion_execution_artifacts \
             WHERE import_id = ?1 AND draft_id = ?2 AND target_act_id = ?3";
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "INSERT OR IGNORE INTO paper_book_ocr_conversion_execution_artifacts \
                 (artifact_id, import_id, draft_id, dossier_id, source_text_digest, \
                  source_page_spans_json, source_review_status, source_reviewed_at, \
                  source_reviewed_by, target_act_id, target_act_state, mutable_draft_act_created, \
                  created_at, created_by, canonical_conversion_claimed, canonical_minutes_claimed, \
                  canonical_act_created, canonical_document_created, signed_document_created, \
                  archive_package_created, pdfa_created, pdfua_created, signature_created, \
                  seal_created, archive_certification_claimed, legal_validity_claimed, \
                  source_extracted_text_in_artifact, source_extracted_text_in_ledger_event) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                         ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28)",
                params![
                    artifact.artifact_id.as_str(),
                    artifact.import_id.as_str(),
                    artifact.draft_id.as_str(),
                    artifact.dossier_id.as_deref(),
                    artifact.source_text_digest.as_deref(),
                    source_page_spans_json.as_str(),
                    source_review_status,
                    source_reviewed_at.as_deref(),
                    artifact.source_reviewed_by.as_deref(),
                    artifact.target_act_id.as_str(),
                    artifact.target_act_state.as_str(),
                    artifact.mutable_draft_act_created,
                    created_at.as_str(),
                    artifact.created_by.as_str(),
                    artifact.canonical_conversion_claimed,
                    artifact.canonical_minutes_claimed,
                    artifact.canonical_act_created,
                    artifact.canonical_document_created,
                    artifact.signed_document_created,
                    artifact.archive_package_created,
                    artifact.pdfa_created,
                    artifact.pdfua_created,
                    artifact.signature_created,
                    artifact.seal_created,
                    artifact.archive_certification_claimed,
                    artifact.legal_validity_claimed,
                    artifact.source_extracted_text_in_artifact,
                    artifact.source_extracted_text_in_ledger_event,
                ],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                // The SQLite `INTEGER` boolean-flag columns map to Postgres `BIGINT`, so the Rust
                // `bool` flags are bound as `i64` 0/1 (and read back the same way) — matching how
                // rusqlite stores `bool`. `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING`.
                let dossier_id = artifact.dossier_id.as_deref();
                let source_text_digest = artifact.source_text_digest.as_deref();
                let source_reviewed_at = source_reviewed_at.as_deref();
                let source_reviewed_by = artifact.source_reviewed_by.as_deref();
                let mutable_draft_act_created = i64::from(artifact.mutable_draft_act_created);
                let canonical_conversion_claimed = i64::from(artifact.canonical_conversion_claimed);
                let canonical_minutes_claimed = i64::from(artifact.canonical_minutes_claimed);
                let canonical_act_created = i64::from(artifact.canonical_act_created);
                let canonical_document_created = i64::from(artifact.canonical_document_created);
                let signed_document_created = i64::from(artifact.signed_document_created);
                let archive_package_created = i64::from(artifact.archive_package_created);
                let pdfa_created = i64::from(artifact.pdfa_created);
                let pdfua_created = i64::from(artifact.pdfua_created);
                let signature_created = i64::from(artifact.signature_created);
                let seal_created = i64::from(artifact.seal_created);
                let archive_certification_claimed =
                    i64::from(artifact.archive_certification_claimed);
                let legal_validity_claimed = i64::from(artifact.legal_validity_claimed);
                let source_extracted_text_in_artifact =
                    i64::from(artifact.source_extracted_text_in_artifact);
                let source_extracted_text_in_ledger_event =
                    i64::from(artifact.source_extracted_text_in_ledger_event);
                cell.borrow_mut().execute(
                    "INSERT INTO paper_book_ocr_conversion_execution_artifacts \
                     (artifact_id, import_id, draft_id, dossier_id, source_text_digest, \
                      source_page_spans_json, source_review_status, source_reviewed_at, \
                      source_reviewed_by, target_act_id, target_act_state, \
                      mutable_draft_act_created, created_at, created_by, \
                      canonical_conversion_claimed, canonical_minutes_claimed, \
                      canonical_act_created, canonical_document_created, signed_document_created, \
                      archive_package_created, pdfa_created, pdfua_created, signature_created, \
                      seal_created, archive_certification_claimed, legal_validity_claimed, \
                      source_extracted_text_in_artifact, source_extracted_text_in_ledger_event) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                             $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28) \
                     ON CONFLICT DO NOTHING",
                    &[
                        &artifact.artifact_id,
                        &artifact.import_id,
                        &artifact.draft_id,
                        &dossier_id,
                        &source_text_digest,
                        &source_page_spans_json,
                        &source_review_status,
                        &source_reviewed_at,
                        &source_reviewed_by,
                        &artifact.target_act_id,
                        &artifact.target_act_state,
                        &mutable_draft_act_created,
                        &created_at,
                        &artifact.created_by,
                        &canonical_conversion_claimed,
                        &canonical_minutes_claimed,
                        &canonical_act_created,
                        &canonical_document_created,
                        &signed_document_created,
                        &archive_package_created,
                        &pdfa_created,
                        &pdfua_created,
                        &signature_created,
                        &seal_created,
                        &archive_certification_claimed,
                        &legal_validity_claimed,
                        &source_extracted_text_in_artifact,
                        &source_extracted_text_in_ledger_event,
                    ],
                )? as usize
            }
        };
        let stored = match &self.kind {
            TxKind::Sqlite(_) => {
                let raw = self.raw()?;
                let mut stmt = raw.prepare(READBACK_SQL)?;
                stmt.query_row(
                    params![
                        artifact.import_id.as_str(),
                        artifact.draft_id.as_str(),
                        artifact.target_act_id.as_str()
                    ],
                    row_to_paper_book_ocr_conversion_execution_artifact,
                )
                .optional()?
                .transpose()?
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell
                .borrow_mut()
                .query_opt(
                    &crate::dialect::rewrite_placeholders(READBACK_SQL),
                    &[
                        &artifact.import_id,
                        &artifact.draft_id,
                        &artifact.target_act_id,
                    ],
                )?
                .as_ref()
                .map(crate::pg::row_to_paper_book_ocr_conversion_execution_artifact)
                .transpose()?,
        };
        let stored = stored.ok_or_else(|| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "paper-book OCR conversion execution artifact insert was ignored but no canonical import/draft/act row exists",
            ))
        })?;
        if changed > 0 {
            Ok(PaperBookOcrConversionExecutionArtifactUpsert::Inserted(
                stored,
            ))
        } else {
            Ok(PaperBookOcrConversionExecutionArtifactUpsert::Existing(
                stored,
            ))
        }
    }

    /// Attach a conversion dossier id to existing execution artifacts for the same import/draft.
    pub fn bind_paper_book_ocr_conversion_execution_artifacts_to_dossier(
        &self,
        import_id: &str,
        draft_id: &str,
        dossier_id: &str,
    ) -> Result<Vec<StoredPaperBookOcrConversionExecutionArtifact>, StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "UPDATE paper_book_ocr_conversion_execution_artifacts SET dossier_id = ?3 \
                     WHERE import_id = ?1 AND draft_id = ?2 \
                     AND (dossier_id IS NULL OR dossier_id = ?3)",
                    params![import_id, draft_id, dossier_id],
                )?;
                let raw = self.raw()?;
                let mut stmt = raw.prepare(
                    "SELECT artifact_id, import_id, draft_id, dossier_id, source_text_digest, \
                     source_page_spans_json, source_review_status, source_reviewed_at, \
                     source_reviewed_by, target_act_id, target_act_state, \
                     mutable_draft_act_created, created_at, created_by, \
                     canonical_conversion_claimed, canonical_minutes_claimed, \
                     canonical_act_created, canonical_document_created, signed_document_created, \
                     archive_package_created, pdfa_created, pdfua_created, signature_created, \
                     seal_created, archive_certification_claimed, legal_validity_claimed, \
                     source_extracted_text_in_artifact, source_extracted_text_in_ledger_event \
                     FROM paper_book_ocr_conversion_execution_artifacts \
                     WHERE import_id = ?1 AND draft_id = ?2 ORDER BY created_at DESC, rowid DESC",
                )?;
                let rows = stmt.query_map(
                    params![import_id, draft_id],
                    row_to_paper_book_ocr_conversion_execution_artifact,
                )?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row??);
                }
                Ok(out)
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "UPDATE paper_book_ocr_conversion_execution_artifacts SET dossier_id = $3 \
                     WHERE import_id = $1 AND draft_id = $2 \
                     AND (dossier_id IS NULL OR dossier_id = $3)",
                    &[&import_id, &draft_id, &dossier_id],
                )?;
                let rows = cell.borrow_mut().query(
                    &format!(
                        "SELECT {} FROM paper_book_ocr_conversion_execution_artifacts \
                         WHERE import_id = $1 AND draft_id = $2 ORDER BY created_at DESC, ctid DESC",
                        crate::pg::ARTIFACT_COLUMNS
                    ),
                    &[&import_id, &draft_id],
                )?;
                rows.iter()
                    .map(crate::pg::row_to_paper_book_ocr_conversion_execution_artifact)
                    .collect()
            }
        }
    }

    /// Update the review status and reviewer metadata for a non-authoritative OCR draft result.
    pub fn review_paper_book_ocr_draft(
        &self,
        draft_id: &str,
        status: StoredPaperBookOcrReviewStatus,
        reviewed_at: Option<OffsetDateTime>,
        reviewed_by: Option<&str>,
        review_note: Option<&str>,
        superseded_by: Option<&str>,
    ) -> Result<(), StoreError> {
        let reviewed_at = reviewed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let status_str = status.as_str();
        let changed = match &self.kind {
            TxKind::Sqlite(_) => self.raw()?.execute(
                "UPDATE paper_book_ocr_drafts SET review_status = ?1, reviewed_at = ?2, \
                 reviewed_by = ?3, review_note = ?4, superseded_by = ?5 WHERE draft_id = ?6",
                params![
                    status_str,
                    reviewed_at,
                    reviewed_by,
                    review_note,
                    superseded_by,
                    draft_id,
                ],
            )?,
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => cell.borrow_mut().execute(
                "UPDATE paper_book_ocr_drafts SET review_status = $1, reviewed_at = $2, \
                 reviewed_by = $3, review_note = $4, superseded_by = $5 WHERE draft_id = $6",
                &[
                    &status_str,
                    &reviewed_at,
                    &reviewed_by,
                    &review_note,
                    &superseded_by,
                    &draft_id,
                ],
            )? as usize,
        };
        if changed == 0 {
            return Err(StoreError::NotFound(format!(
                "paper-book OCR draft {draft_id}"
            )));
        }
        Ok(())
    }

    /// Upsert an act-scoped follow-up/task row (`follow_ups`, schema v6). Intended to run in the
    /// same transaction as its `follow_up.*` ledger event.
    pub fn upsert_follow_up(&self, follow_up: &StoredFollowUp) -> Result<(), StoreError> {
        let created_at = follow_up
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let completed_at = follow_up.completed_at.map(|t| {
            t.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        });
        let act_id = follow_up.act_id.to_string();
        let agenda_number = follow_up.agenda_number.map(i64::from);
        let deliberation_index = follow_up.deliberation_index.map(i64::from);
        let due_date = follow_up.due_date.map(format_date);
        let status = follow_up.status.as_str();
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO follow_ups \
                     (id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
                      assignee, assignee_display, status, created_at, created_by, completed_at, \
                      completed_by) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        follow_up.id,
                        act_id,
                        agenda_number,
                        deliberation_index,
                        follow_up.title,
                        follow_up.detail,
                        due_date,
                        follow_up.assignee,
                        follow_up.assignee_display,
                        status,
                        created_at,
                        follow_up.created_by,
                        completed_at,
                        follow_up.completed_by,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let detail = follow_up.detail.as_deref();
                let assignee = follow_up.assignee.as_deref();
                let assignee_display = follow_up.assignee_display.as_deref();
                let completed_by = follow_up.completed_by.as_deref();
                cell.borrow_mut().execute(
                    "INSERT INTO follow_ups \
                     (id, act_id, agenda_number, deliberation_index, title, detail, due_date, \
                      assignee, assignee_display, status, created_at, created_by, completed_at, \
                      completed_by) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
                     ON CONFLICT (id) DO UPDATE SET act_id = EXCLUDED.act_id, \
                     agenda_number = EXCLUDED.agenda_number, \
                     deliberation_index = EXCLUDED.deliberation_index, title = EXCLUDED.title, \
                     detail = EXCLUDED.detail, due_date = EXCLUDED.due_date, \
                     assignee = EXCLUDED.assignee, assignee_display = EXCLUDED.assignee_display, \
                     status = EXCLUDED.status, created_at = EXCLUDED.created_at, \
                     created_by = EXCLUDED.created_by, completed_at = EXCLUDED.completed_at, \
                     completed_by = EXCLUDED.completed_by",
                    &[
                        &follow_up.id,
                        &act_id,
                        &agenda_number,
                        &deliberation_index,
                        &follow_up.title,
                        &detail,
                        &due_date,
                        &assignee,
                        &assignee_display,
                        &status,
                        &created_at,
                        &follow_up.created_by,
                        &completed_at,
                        &completed_by,
                    ],
                )?;
            }
        }
        Ok(())
    }

    // ── wp16 P3b — non-ledger sidecar writers (users / roles / delegations / settings / credentials) ──
    //
    // Document-in-relational `(id, json)` upsert/delete for the JSON file sidecars moved into the
    // shared store (plan §8.2). ADDITIVE: no existing signature changes. The store never interprets
    // `json`; the API serializes its own `User` / role / `StoredDelegation` / `Settings` value into it.

    /// Upsert one user directory row (`users`, `(id, json)`), idempotent on the id. The `json` is the
    /// API's serialized `User` value (opaque to the store). Mirrors a `users.json` array element.
    pub fn upsert_user(&self, id: &str, json: &str) -> Result<(), StoreError> {
        self.upsert_document_row("users", id, json)
    }

    /// Remove one user directory row by id (mirrors a user dropped from `users.json`). A no-op when
    /// the id is unknown.
    pub fn delete_user(&self, id: &str) -> Result<(), StoreError> {
        self.delete_document_row("users", id)
    }

    /// Upsert one role-catalog row (`roles`, `(id, json)`), idempotent on the id. Mirrors a
    /// `roles.json` array element.
    pub fn upsert_role(&self, id: &str, json: &str) -> Result<(), StoreError> {
        self.upsert_document_row("roles", id, json)
    }

    /// Remove one role row by id (mirrors a role dropped from `roles.json`). A no-op when unknown.
    pub fn delete_role(&self, id: &str) -> Result<(), StoreError> {
        self.delete_document_row("roles", id)
    }

    /// Upsert one delegation row (`delegations`, `(id, json)`), idempotent on the id. Mirrors a
    /// `delegations.json` array element (active **or** revoked).
    pub fn upsert_delegation(&self, id: &str, json: &str) -> Result<(), StoreError> {
        self.upsert_document_row("delegations", id, json)
    }

    /// Remove one delegation row by id (mirrors a delegation dropped from `delegations.json`). A
    /// no-op when unknown.
    pub fn delete_delegation(&self, id: &str) -> Result<(), StoreError> {
        self.delete_document_row("delegations", id)
    }

    /// Upsert one user-authored template row (`user_templates`, `(id, json)`), idempotent on the id.
    /// The `json` is the API's serialized `TemplateSpecDto` value (opaque to the store).
    pub fn upsert_user_template(&self, id: &str, json: &str) -> Result<(), StoreError> {
        self.upsert_document_row("user_templates", id, json)
    }

    /// Remove one user-authored template row by id. A no-op when the id is unknown.
    pub fn delete_user_template(&self, id: &str) -> Result<(), StoreError> {
        self.delete_document_row("user_templates", id)
    }

    /// Shared document-in-relational upsert for the `(id, json)` sidecar tables. `table` is a fixed
    /// internal identifier (never user input), so interpolating it is safe.
    fn upsert_document_row(&self, table: &str, id: &str, json: &str) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    &format!("INSERT OR REPLACE INTO {table} (id, json) VALUES (?1, ?2)"),
                    params![id, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    &format!(
                        "INSERT INTO {table} (id, json) VALUES ($1, $2) \
                         ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json"
                    ),
                    &[&id, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Shared delete for the `(id, json)` sidecar tables. `table` is a fixed internal identifier.
    fn delete_document_row(&self, table: &str, id: &str) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?
                    .execute(&format!("DELETE FROM {table} WHERE id = ?1"), params![id])?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut()
                    .execute(&format!("DELETE FROM {table} WHERE id = $1"), &[&id])?;
            }
        }
        Ok(())
    }

    /// Upsert the single settings document (`settings`, keyed by [`SETTINGS_SINGLETON_ID`]). The
    /// `json` is the API's serialized `Settings` value (opaque to the store). Mirrors `settings.json`.
    pub fn put_settings(&self, json: &str) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO settings (id, json) VALUES (?1, ?2)",
                    params![SETTINGS_SINGLETON_ID, json],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO settings (id, json) VALUES ($1, $2) \
                     ON CONFLICT (id) DO UPDATE SET json = EXCLUDED.json",
                    &[&SETTINGS_SINGLETON_ID, &json],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert one provider-credential record (`provider_credentials`, keyed by `(mode, provider_id)`).
    ///
    /// `record_blob` is stored **verbatim** as opaque bytes — it is the API's serialized
    /// `EncryptedCredentialRecord` holding only AEAD ciphertext envelopes (never a plaintext secret).
    /// The store neither encrypts, decrypts, nor parses it; the crypto envelope stays in the API's
    /// secretstore and only its storage moves here. `key_version` / `updated_at` are non-secret
    /// metadata. Mirrors one entry of the `provider-credentials.enc.json` `records` list.
    pub fn put_credential_record(
        &self,
        mode: &str,
        provider_id: &str,
        key_version: i64,
        updated_at: &str,
        record_blob: &[u8],
    ) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO provider_credentials \
                     (mode, provider_id, key_version, updated_at, record_blob) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![mode, provider_id, key_version, updated_at, record_blob],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "INSERT INTO provider_credentials \
                     (mode, provider_id, key_version, updated_at, record_blob) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (mode, provider_id) DO UPDATE SET \
                     key_version = EXCLUDED.key_version, updated_at = EXCLUDED.updated_at, \
                     record_blob = EXCLUDED.record_blob",
                    &[&mode, &provider_id, &key_version, &updated_at, &record_blob],
                )?;
            }
        }
        Ok(())
    }

    /// Remove one provider-credential record by `(mode, provider_id)` (mirrors a record cleared from
    /// `provider-credentials.enc.json`). A no-op when the record is absent.
    pub fn delete_credential_record(
        &self,
        mode: &str,
        provider_id: &str,
    ) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "DELETE FROM provider_credentials WHERE mode = ?1 AND provider_id = ?2",
                    params![mode, provider_id],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "DELETE FROM provider_credentials WHERE mode = $1 AND provider_id = $2",
                    &[&mode, &provider_id],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert the SIGNED PDF variant for an act (`signed_documents`, keyed by `act_id`, schema v4).
    /// Idempotent on the act id. Called inside the confirm transaction alongside the `document.signed`
    /// event append (t57-S3), so the signed variant and its ledger event land in one durable commit.
    ///
    /// **Never persists a PIN or an OTP** — only the public signed PDF + signature metadata.
    pub fn upsert_signed_document(&self, doc: &StoredSignedDocument) -> Result<(), StoreError> {
        let signing_time = doc
            .signing_time
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let signed_at = doc
            .signed_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let act_id = doc.act_id.to_string();
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO signed_documents \
                     (act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
                      trusted_list_status, signer_cert_subject, signing_time, signed_at, \
                      signer_cert_der, timestamp_token_der, timestamp_trust_report_json, \
                      signer_capacity_evidence_json, signed_pdf_bytes) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    params![
                        act_id,
                        doc.document_id,
                        doc.signed_pdf_digest,
                        doc.signature_family,
                        doc.evidentiary_level,
                        doc.trusted_list_status,
                        doc.signer_cert_subject,
                        signing_time,
                        signed_at,
                        doc.signer_cert_der,
                        doc.timestamp_token_der,
                        doc.timestamp_trust_report_json,
                        doc.signer_capacity_evidence_json,
                        doc.signed_pdf_bytes,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let trusted_list_status = doc.trusted_list_status.as_deref();
                let signer_cert_subject = doc.signer_cert_subject.as_deref();
                let timestamp_trust_report_json = doc.timestamp_trust_report_json.as_deref();
                let signer_capacity_evidence_json = doc.signer_capacity_evidence_json.as_deref();
                let signer_cert_der: &[u8] = &doc.signer_cert_der;
                let timestamp_token_der = doc.timestamp_token_der.as_deref();
                let signed_pdf_bytes: &[u8] = &doc.signed_pdf_bytes;
                cell.borrow_mut().execute(
                    "INSERT INTO signed_documents \
                     (act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
                      trusted_list_status, signer_cert_subject, signing_time, signed_at, \
                      signer_cert_der, timestamp_token_der, timestamp_trust_report_json, \
                      signer_capacity_evidence_json, signed_pdf_bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
                     ON CONFLICT (act_id) DO UPDATE SET document_id = EXCLUDED.document_id, \
                     signed_pdf_digest = EXCLUDED.signed_pdf_digest, \
                     signature_family = EXCLUDED.signature_family, \
                     evidentiary_level = EXCLUDED.evidentiary_level, \
                     trusted_list_status = EXCLUDED.trusted_list_status, \
                     signer_cert_subject = EXCLUDED.signer_cert_subject, \
                     signing_time = EXCLUDED.signing_time, signed_at = EXCLUDED.signed_at, \
                     signer_cert_der = EXCLUDED.signer_cert_der, \
                     timestamp_token_der = EXCLUDED.timestamp_token_der, \
                     timestamp_trust_report_json = EXCLUDED.timestamp_trust_report_json, \
                     signer_capacity_evidence_json = EXCLUDED.signer_capacity_evidence_json, \
                     signed_pdf_bytes = EXCLUDED.signed_pdf_bytes",
                    &[
                        &act_id,
                        &doc.document_id,
                        &doc.signed_pdf_digest,
                        &doc.signature_family,
                        &doc.evidentiary_level,
                        &trusted_list_status,
                        &signer_cert_subject,
                        &signing_time,
                        &signed_at,
                        &signer_cert_der,
                        &timestamp_token_der,
                        &timestamp_trust_report_json,
                        &signer_capacity_evidence_json,
                        &signed_pdf_bytes,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Upsert a pending CMD signing session (`pending_cmd_sessions`, schema v4). Idempotent on the
    /// session id. **Never persists a PIN or an OTP** — `session_json` / `prepared_json` are the
    /// non-secret resumable blobs (t57-S3 secret-discipline invariant).
    pub fn upsert_pending_cmd_session(
        &self,
        session: &PendingCmdSession,
    ) -> Result<(), StoreError> {
        let created_at = session
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let expires_at = session
            .expires_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let act_id = session.act_id.to_string();
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "INSERT OR REPLACE INTO pending_cmd_sessions \
                     (session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
                      prepared_json, created_at, expires_at, signer_capacity_evidence_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        session.session_id,
                        act_id,
                        session.actor,
                        session.status,
                        session.masked_phone,
                        session.doc_name,
                        session.session_json,
                        session.prepared_json,
                        created_at,
                        expires_at,
                        session.signer_capacity_evidence_json,
                    ],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                let signer_capacity_evidence_json =
                    session.signer_capacity_evidence_json.as_deref();
                cell.borrow_mut().execute(
                    "INSERT INTO pending_cmd_sessions \
                     (session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
                      prepared_json, created_at, expires_at, signer_capacity_evidence_json) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                     ON CONFLICT (session_id) DO UPDATE SET act_id = EXCLUDED.act_id, \
                     actor = EXCLUDED.actor, status = EXCLUDED.status, \
                     masked_phone = EXCLUDED.masked_phone, doc_name = EXCLUDED.doc_name, \
                     session_json = EXCLUDED.session_json, prepared_json = EXCLUDED.prepared_json, \
                     created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, \
                     signer_capacity_evidence_json = EXCLUDED.signer_capacity_evidence_json",
                    &[
                        &session.session_id,
                        &act_id,
                        &session.actor,
                        &session.status,
                        &session.masked_phone,
                        &session.doc_name,
                        &session.session_json,
                        &session.prepared_json,
                        &created_at,
                        &expires_at,
                        &signer_capacity_evidence_json,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Delete a pending CMD signing session by id (single-use: consumed on a successful confirm, or
    /// cancelled/expired). A no-op if it is already gone.
    pub fn delete_pending_cmd_session(&self, session_id: &str) -> Result<(), StoreError> {
        match &self.kind {
            TxKind::Sqlite(_) => {
                self.raw()?.execute(
                    "DELETE FROM pending_cmd_sessions WHERE session_id = ?1",
                    params![session_id],
                )?;
            }
            #[cfg(feature = "postgres")]
            TxKind::Postgres(cell) => {
                cell.borrow_mut().execute(
                    "DELETE FROM pending_cmd_sessions WHERE session_id = $1",
                    &[&session_id],
                )?;
            }
        }
        Ok(())
    }
}

const EVENT_SELECT_COLUMNS: &str = "seq, id, actor, justification, timestamp, scope, kind, \
    payload_digest, prev_hash, hash, links";

struct NormalizedLedgerEventPageFilters {
    chain: Option<ChainId>,
    query: Option<String>,
    scope: Option<String>,
    kinds: HashSet<String>,
    actor: Option<String>,
    from: Option<OffsetDateTime>,
    to: Option<LedgerEventUpperBound>,
}

impl NormalizedLedgerEventPageFilters {
    fn from_query(query: &LedgerEventPageQuery) -> Self {
        Self {
            chain: query
                .chain
                .as_ref()
                .filter(|chain| !chain.is_global())
                .cloned(),
            query: normalize_event_page_query(query.q.as_deref()),
            scope: query.scope.clone().filter(|scope| !scope.is_empty()),
            kinds: parse_event_page_kinds(&query.kinds),
            actor: query.actor.clone().filter(|actor| !actor.is_empty()),
            from: query.from,
            to: query.to,
        }
    }

    fn has_residual_filters(&self) -> bool {
        self.chain.is_some() || self.query.is_some()
    }

    fn matches(&self, event: &Event) -> bool {
        if let Some(chain) = &self.chain {
            if !event.links.iter().any(|link| &link.chain == chain) {
                return false;
            }
        }
        if let Some(query) = &self.query {
            if !event_matches_page_query(event, query) {
                return false;
            }
        }
        if let Some(scope) = &self.scope {
            if !event.scope.contains(scope) {
                return false;
            }
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&event.kind) {
            return false;
        }
        if let Some(actor) = &self.actor {
            if &event.actor != actor {
                return false;
            }
        }
        if let Some(from) = self.from {
            if event.timestamp < from {
                return false;
            }
        }
        if let Some(to) = self.to {
            if !to.contains(event.timestamp) {
                return false;
            }
        }
        true
    }
}

fn ledger_event_page_batch_limit(limit: usize, has_residual_filters: bool) -> usize {
    let target = limit.saturating_add(1);
    if has_residual_filters {
        target.max(256)
    } else {
        target
    }
}

fn ledger_events_page_sql(
    filters: &NormalizedLedgerEventPageFilters,
    before_seq: Option<u64>,
    batch_limit: usize,
) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut values = Vec::new();

    if let Some(before_seq) = before_seq {
        if let Ok(before_seq) = i64::try_from(before_seq) {
            clauses.push("seq < ?".to_owned());
            values.push(Value::Integer(before_seq));
        }
    }
    if let Some(scope) = &filters.scope {
        clauses.push("instr(scope, ?) > 0".to_owned());
        values.push(Value::Text(scope.clone()));
    }
    if !filters.kinds.is_empty() {
        let mut placeholders = Vec::with_capacity(filters.kinds.len());
        let mut kinds: Vec<&String> = filters.kinds.iter().collect();
        kinds.sort_unstable();
        for kind in kinds {
            placeholders.push("?".to_owned());
            values.push(Value::Text(kind.clone()));
        }
        clauses.push(format!("kind IN ({})", placeholders.join(", ")));
    }
    if let Some(actor) = &filters.actor {
        clauses.push("actor = ?".to_owned());
        values.push(Value::Text(actor.clone()));
    }
    if let Some(from) = filters.from {
        clauses.push("timestamp >= ?".to_owned());
        values.push(Value::Text(format_event_timestamp(from)));
    }
    if let Some(to) = filters.to {
        match to {
            LedgerEventUpperBound::Inclusive(to) => {
                clauses.push("timestamp <= ?".to_owned());
                values.push(Value::Text(format_event_timestamp(to)));
            }
            LedgerEventUpperBound::Exclusive(to) => {
                clauses.push("timestamp < ?".to_owned());
                values.push(Value::Text(format_event_timestamp(to)));
            }
        }
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    values.push(Value::Integer(sqlite_limit_value(batch_limit)));
    (
        format!("SELECT {EVENT_SELECT_COLUMNS} FROM events{where_sql} ORDER BY seq DESC LIMIT ?"),
        values,
    )
}

fn sqlite_limit_value(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn normalize_event_page_query(query: Option<&str>) -> Option<String> {
    query
        .map(|query| normalize_ledger_event_search_text(query.trim()))
        .filter(|query| !query.is_empty())
}

fn parse_event_page_kinds(raw: &[String]) -> HashSet<String> {
    raw.iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn event_matches_page_query(event: &Event, query: &str) -> bool {
    contains_event_page_query(event.id.to_string(), query)
        || contains_event_page_query(event.seq.to_string(), query)
        || contains_event_page_query(&event.actor, query)
        || event
            .justification
            .as_deref()
            .is_some_and(|value| contains_event_page_query(value, query))
        || contains_event_page_query(&event.scope, query)
        || contains_event_page_query(&event.kind, query)
        || contains_event_page_query(event.timestamp.format(&Rfc3339).unwrap_or_default(), query)
        || contains_event_page_query(hex(&event.payload_digest), query)
        || contains_event_page_query(hex(&event.prev_hash), query)
        || contains_event_page_query(hex(&event.hash), query)
        || event.links.iter().any(|link| {
            contains_event_page_query(link.chain.canonical(), query)
                || contains_event_page_query(link.seq.to_string(), query)
                || contains_event_page_query(hex(&link.prev_hash), query)
        })
}

fn contains_event_page_query(value: impl AsRef<str>, query: &str) -> bool {
    normalize_ledger_event_search_text(value.as_ref()).contains(query)
}

fn format_event_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn raw_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEventRow> {
    Ok(RawEventRow {
        seq: row.get(0)?,
        id: row.get(1)?,
        actor: row.get(2)?,
        justification: row.get(3)?,
        timestamp: row.get(4)?,
        scope: row.get(5)?,
        kind: row.get(6)?,
        payload_digest: row.get(7)?,
        prev_hash: row.get(8)?,
        hash: row.get(9)?,
        links: row.get(10)?,
    })
}

/// One row of the `events` table read back as raw primitives (the shape rusqlite's row closure can
/// yield). [`RawEventRow::into_event`] then rebuilds a [`Event`], surfacing the timestamp / uuid /
/// digest-width conversions as [`StoreError`] rather than forcing them into the rusqlite closure.
struct RawEventRow {
    seq: i64,
    id: String,
    actor: String,
    justification: Option<String>,
    timestamp: String,
    scope: String,
    kind: String,
    payload_digest: Vec<u8>,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    links: String,
}

impl RawEventRow {
    fn into_event(self) -> Result<Event, StoreError> {
        let links: Vec<ChainLink> = serde_json::from_str(&self.links).unwrap_or_default();
        Ok(Event {
            id: parse_uuid_newtype::<EventId>(&self.id)?,
            seq: self.seq as u64,
            actor: self.actor,
            justification: self.justification,
            timestamp: parse_rfc3339(&self.timestamp)?,
            scope: self.scope,
            kind: self.kind,
            payload_digest: blob32(self.payload_digest, "payload_digest")?,
            prev_hash: blob32(self.prev_hash, "prev_hash")?,
            links,
            hash: blob32(self.hash, "hash")?,
        })
    }
}

/// Map one `documents` row to a [`StoredDocument`]. The rusqlite closure must yield a
/// `rusqlite::Result`, so the `act_id` / `created_at` conversions (which surface as [`StoreError`])
/// are deferred into an inner `Result` the caller unwraps with `.transpose()`.
#[allow(clippy::type_complexity)]
fn row_to_document(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredDocument, StoreError>> {
    let id: String = row.get(0)?;
    let act_id_raw: String = row.get(1)?;
    let template_id: String = row.get(2)?;
    let pdf_digest: String = row.get(3)?;
    let profile: String = row.get(4)?;
    let created_at_raw: String = row.get(5)?;
    let pdf_bytes: Vec<u8> = row.get(6)?;
    Ok((|| {
        Ok(StoredDocument {
            id,
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            template_id,
            pdf_digest,
            profile,
            created_at: parse_rfc3339(&created_at_raw)?,
            pdf_bytes,
        })
    })())
}

/// Map one `generated_document_dispatch_evidence` row to
/// [`StoredGeneratedDocumentDispatchEvidence`].
#[allow(clippy::type_complexity)]
fn row_to_generated_dispatch_evidence(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredGeneratedDocumentDispatchEvidence, StoreError>> {
    let document_id: String = row.get(0)?;
    let idempotency_key: String = row.get(1)?;
    let act_id_raw: String = row.get(2)?;
    let template_id: String = row.get(3)?;
    let actor: String = row.get(4)?;
    let dispatched_at_raw: String = row.get(5)?;
    let channel: Option<String> = row.get(6)?;
    let reference: Option<String> = row.get(7)?;
    let evidence_reference: Option<String> = row.get(8)?;
    let imported_document_id: Option<String> = row.get(9)?;
    let recipients_json: String = row.get(10)?;
    let operator_note: Option<String> = row.get(11)?;
    let recorded_at_raw: String = row.get(12)?;
    Ok((|| {
        Ok(StoredGeneratedDocumentDispatchEvidence {
            document_id,
            idempotency_key,
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            template_id,
            actor,
            dispatched_at: parse_rfc3339(&dispatched_at_raw)?,
            channel,
            reference,
            evidence_reference,
            imported_document_id,
            recipients: serde_json::from_str(&recipients_json)?,
            operator_note,
            recorded_at: parse_rfc3339(&recorded_at_raw)?,
        })
    })())
}

/// Map one `imported_documents` metadata row to [`StoredImportedDocumentMeta`]. Deferred inner
/// `Result` lets timestamp / id / integer conversions surface as [`StoreError`].
#[allow(clippy::type_complexity)]
fn row_to_imported_document_meta(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredImportedDocumentMeta, StoreError>> {
    let id: String = row.get(0)?;
    let act_id_raw: Option<String> = row.get(1)?;
    let filename: Option<String> = row.get(2)?;
    let declared_content_type: Option<String> = row.get(3)?;
    let detected_content_type: String = row.get(4)?;
    let sha256: String = row.get(5)?;
    let size_raw: i64 = row.get(6)?;
    let imported_at_raw: String = row.get(7)?;
    let imported_by: String = row.get(8)?;
    let operator_review_status_raw: String = row.get(9)?;
    let operator_reviewed_at_raw: Option<String> = row.get(10)?;
    let operator_reviewed_by: Option<String> = row.get(11)?;
    let operator_review_note: Option<String> = row.get(12)?;
    let operator_acknowledged_guardrail_ids_json: String = row.get(13)?;
    Ok(imported_document_meta_from_raw(
        id,
        act_id_raw,
        filename,
        declared_content_type,
        detected_content_type,
        sha256,
        size_raw,
        imported_at_raw,
        imported_by,
        operator_review_status_raw,
        operator_reviewed_at_raw,
        operator_reviewed_by,
        operator_review_note,
        operator_acknowledged_guardrail_ids_json,
    ))
}

/// Map one `imported_documents` full row to [`StoredImportedDocument`] (metadata + retained bytes).
#[allow(clippy::type_complexity)]
fn row_to_imported_document(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredImportedDocument, StoreError>> {
    let id: String = row.get(0)?;
    let act_id_raw: Option<String> = row.get(1)?;
    let filename: Option<String> = row.get(2)?;
    let declared_content_type: Option<String> = row.get(3)?;
    let detected_content_type: String = row.get(4)?;
    let sha256: String = row.get(5)?;
    let size_raw: i64 = row.get(6)?;
    let imported_at_raw: String = row.get(7)?;
    let imported_by: String = row.get(8)?;
    let operator_review_status_raw: String = row.get(9)?;
    let operator_reviewed_at_raw: Option<String> = row.get(10)?;
    let operator_reviewed_by: Option<String> = row.get(11)?;
    let operator_review_note: Option<String> = row.get(12)?;
    let operator_acknowledged_guardrail_ids_json: String = row.get(13)?;
    let bytes: Vec<u8> = row.get(14)?;
    Ok((|| {
        Ok(StoredImportedDocument {
            meta: imported_document_meta_from_raw(
                id,
                act_id_raw,
                filename,
                declared_content_type,
                detected_content_type,
                sha256,
                size_raw,
                imported_at_raw,
                imported_by,
                operator_review_status_raw,
                operator_reviewed_at_raw,
                operator_reviewed_by,
                operator_review_note,
                operator_acknowledged_guardrail_ids_json,
            )?,
            bytes,
        })
    })())
}

fn row_to_imported_document_review_history_entry(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredImportedDocumentReviewHistoryEntry, StoreError>> {
    let id: i64 = row.get(0)?;
    let imported_document_id: String = row.get(1)?;
    let review_status_raw: String = row.get(2)?;
    let reviewed_at_raw: Option<String> = row.get(3)?;
    let reviewed_by: Option<String> = row.get(4)?;
    let review_note: Option<String> = row.get(5)?;
    let acknowledged_guardrail_ids_json: String = row.get(6)?;
    Ok((|| {
        Ok(StoredImportedDocumentReviewHistoryEntry {
            id,
            imported_document_id,
            review_status: StoredImportedDocumentReviewStatus::parse(&review_status_raw)?,
            reviewed_at: reviewed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
            reviewed_by,
            review_note,
            acknowledged_guardrail_ids: serde_json::from_str(&acknowledged_guardrail_ids_json)?,
        })
    })())
}

#[allow(clippy::too_many_arguments)]
fn imported_document_meta_from_raw(
    id: String,
    act_id_raw: Option<String>,
    filename: Option<String>,
    declared_content_type: Option<String>,
    detected_content_type: String,
    sha256: String,
    size_raw: i64,
    imported_at_raw: String,
    imported_by: String,
    operator_review_status_raw: String,
    operator_reviewed_at_raw: Option<String>,
    operator_reviewed_by: Option<String>,
    operator_review_note: Option<String>,
    operator_acknowledged_guardrail_ids_json: String,
) -> Result<StoredImportedDocumentMeta, StoreError> {
    let size_bytes = usize::try_from(size_raw).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored imported document size {size_raw} is negative or too large"),
        ))
    })?;
    let act_id = act_id_raw
        .as_deref()
        .map(parse_uuid_newtype::<ActId>)
        .transpose()?;
    let operator_acknowledged_guardrail_ids =
        serde_json::from_str(&operator_acknowledged_guardrail_ids_json)?;
    Ok(StoredImportedDocumentMeta {
        id,
        act_id,
        filename,
        declared_content_type,
        detected_content_type,
        sha256,
        size_bytes,
        imported_at: parse_rfc3339(&imported_at_raw)?,
        imported_by,
        operator_review_status: StoredImportedDocumentReviewStatus::parse(
            &operator_review_status_raw,
        )?,
        operator_reviewed_at: operator_reviewed_at_raw
            .as_deref()
            .map(parse_rfc3339)
            .transpose()?,
        operator_reviewed_by,
        operator_review_note,
        operator_acknowledged_guardrail_ids,
    })
}

/// Map one `paper_book_imports` metadata row to [`StoredPaperBookImportMeta`].
fn row_to_paper_book_import_meta(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredPaperBookImportMeta, StoreError>> {
    let import_id: String = row.get(0)?;
    let entity_ref: String = row.get(1)?;
    let entity_name: String = row.get(2)?;
    let entity_nipc: String = row.get(3)?;
    let book_ref: String = row.get(4)?;
    let date_from_raw: String = row.get(5)?;
    let date_to_raw: String = row.get(6)?;
    let page_count_raw: i64 = row.get(7)?;
    let page_from_raw: i64 = row.get(8)?;
    let page_to_raw: i64 = row.get(9)?;
    let original_number_from_raw: Option<i64> = row.get(10)?;
    let original_number_to_raw: Option<i64> = row.get(11)?;
    let sha256: String = row.get(12)?;
    let size_raw: i64 = row.get(13)?;
    let content_type: String = row.get(14)?;
    let source_filename: Option<String> = row.get(15)?;
    let notes: Option<String> = row.get(16)?;
    let imported_at_raw: String = row.get(17)?;
    let imported_by: String = row.get(18)?;
    let ocr_status_raw: String = row.get(19)?;
    Ok(paper_book_import_meta_from_raw(
        import_id,
        entity_ref,
        entity_name,
        entity_nipc,
        book_ref,
        date_from_raw,
        date_to_raw,
        page_count_raw,
        page_from_raw,
        page_to_raw,
        original_number_from_raw,
        original_number_to_raw,
        sha256,
        size_raw,
        content_type,
        source_filename,
        notes,
        imported_at_raw,
        imported_by,
        ocr_status_raw,
    ))
}

/// Map one `paper_book_imports` full row to [`StoredPaperBookImport`] (metadata + retained bytes).
fn row_to_paper_book_import(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredPaperBookImport, StoreError>> {
    let meta = row_to_paper_book_import_meta(row)?;
    let bytes: Vec<u8> = row.get(20)?;
    Ok((|| Ok(StoredPaperBookImport { meta: meta?, bytes }))())
}

/// Map one `paper_book_ocr_drafts` row to [`StoredPaperBookOcrDraft`].
fn row_to_paper_book_ocr_draft(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredPaperBookOcrDraft, StoreError>> {
    let draft_id: String = row.get(0)?;
    let import_id: String = row.get(1)?;
    let extracted_text: Option<String> = row.get(2)?;
    let text_digest: Option<String> = row.get(3)?;
    let page_spans_json: String = row.get(4)?;
    let confidence: Option<f64> = row.get(5)?;
    let engine_name: String = row.get(6)?;
    let engine_version: Option<String> = row.get(7)?;
    let created_at_raw: String = row.get(8)?;
    let created_by: String = row.get(9)?;
    let review_status_raw: String = row.get(10)?;
    let reviewed_at_raw: Option<String> = row.get(11)?;
    let reviewed_by: Option<String> = row.get(12)?;
    let review_note: Option<String> = row.get(13)?;
    let superseded_by: Option<String> = row.get(14)?;
    Ok((|| {
        Ok(StoredPaperBookOcrDraft {
            draft_id,
            import_id,
            extracted_text,
            text_digest,
            page_spans: serde_json::from_str(&page_spans_json)?,
            confidence,
            engine_name,
            engine_version,
            created_at: parse_rfc3339(&created_at_raw)?,
            created_by,
            review_status: StoredPaperBookOcrReviewStatus::parse(&review_status_raw)?,
            reviewed_at: reviewed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
            reviewed_by,
            review_note,
            superseded_by,
        })
    })())
}

/// Map one `paper_book_ocr_conversion_dossiers` row to
/// [`StoredPaperBookOcrConversionDossier`].
fn row_to_paper_book_ocr_conversion_dossier(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredPaperBookOcrConversionDossier, StoreError>> {
    let dossier_id: String = row.get(0)?;
    let import_id: String = row.get(1)?;
    let draft_id: String = row.get(2)?;
    let source_text_digest: Option<String> = row.get(3)?;
    let source_page_spans_json: String = row.get(4)?;
    let source_review_status_raw: String = row.get(5)?;
    let source_reviewed_at_raw: Option<String> = row.get(6)?;
    let source_reviewed_by: Option<String> = row.get(7)?;
    let created_at_raw: String = row.get(8)?;
    let created_by: String = row.get(9)?;
    Ok((|| {
        Ok(StoredPaperBookOcrConversionDossier {
            dossier_id,
            import_id,
            draft_id,
            source_text_digest,
            source_page_spans: serde_json::from_str(&source_page_spans_json)?,
            source_review_status: StoredPaperBookOcrReviewStatus::parse(&source_review_status_raw)?,
            source_reviewed_at: source_reviewed_at_raw
                .as_deref()
                .map(parse_rfc3339)
                .transpose()?,
            source_reviewed_by,
            created_at: parse_rfc3339(&created_at_raw)?,
            created_by,
        })
    })())
}

/// Map one `paper_book_ocr_conversion_execution_artifacts` row to
/// [`StoredPaperBookOcrConversionExecutionArtifact`].
fn row_to_paper_book_ocr_conversion_execution_artifact(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredPaperBookOcrConversionExecutionArtifact, StoreError>> {
    let artifact_id: String = row.get(0)?;
    let import_id: String = row.get(1)?;
    let draft_id: String = row.get(2)?;
    let dossier_id: Option<String> = row.get(3)?;
    let source_text_digest: Option<String> = row.get(4)?;
    let source_page_spans_json: String = row.get(5)?;
    let source_review_status_raw: String = row.get(6)?;
    let source_reviewed_at_raw: Option<String> = row.get(7)?;
    let source_reviewed_by: Option<String> = row.get(8)?;
    let target_act_id: String = row.get(9)?;
    let target_act_state: String = row.get(10)?;
    let mutable_draft_act_created: bool = row.get(11)?;
    let created_at_raw: String = row.get(12)?;
    let created_by: String = row.get(13)?;
    let canonical_conversion_claimed: bool = row.get(14)?;
    let canonical_minutes_claimed: bool = row.get(15)?;
    let canonical_act_created: bool = row.get(16)?;
    let canonical_document_created: bool = row.get(17)?;
    let signed_document_created: bool = row.get(18)?;
    let archive_package_created: bool = row.get(19)?;
    let pdfa_created: bool = row.get(20)?;
    let pdfua_created: bool = row.get(21)?;
    let signature_created: bool = row.get(22)?;
    let seal_created: bool = row.get(23)?;
    let archive_certification_claimed: bool = row.get(24)?;
    let legal_validity_claimed: bool = row.get(25)?;
    let source_extracted_text_in_artifact: bool = row.get(26)?;
    let source_extracted_text_in_ledger_event: bool = row.get(27)?;
    Ok((|| {
        let artifact = StoredPaperBookOcrConversionExecutionArtifact {
            artifact_id,
            import_id,
            draft_id,
            dossier_id,
            source_text_digest,
            source_page_spans: serde_json::from_str(&source_page_spans_json)?,
            source_review_status: StoredPaperBookOcrReviewStatus::parse(&source_review_status_raw)?,
            source_reviewed_at: source_reviewed_at_raw
                .as_deref()
                .map(parse_rfc3339)
                .transpose()?,
            source_reviewed_by,
            target_act_id,
            target_act_state,
            mutable_draft_act_created,
            created_at: parse_rfc3339(&created_at_raw)?,
            created_by,
            canonical_conversion_claimed,
            canonical_minutes_claimed,
            canonical_act_created,
            canonical_document_created,
            signed_document_created,
            archive_package_created,
            pdfa_created,
            pdfua_created,
            signature_created,
            seal_created,
            archive_certification_claimed,
            legal_validity_claimed,
            source_extracted_text_in_artifact,
            source_extracted_text_in_ledger_event,
        };
        validate_paper_book_ocr_conversion_execution_artifact(&artifact)?;
        Ok(artifact)
    })())
}

fn validate_paper_book_ocr_conversion_execution_artifact(
    artifact: &StoredPaperBookOcrConversionExecutionArtifact,
) -> Result<(), StoreError> {
    if artifact.source_review_status != StoredPaperBookOcrReviewStatus::Accepted {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "paper-book OCR conversion execution artifact requires an accepted OCR draft",
        )));
    }
    if artifact.target_act_state != "Draft" || !artifact.mutable_draft_act_created {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "paper-book OCR conversion execution artifact must target a mutable Draft act",
        )));
    }
    let forbidden_claims = [
        (
            "canonical_conversion_claimed",
            artifact.canonical_conversion_claimed,
        ),
        (
            "canonical_minutes_claimed",
            artifact.canonical_minutes_claimed,
        ),
        ("canonical_act_created", artifact.canonical_act_created),
        (
            "canonical_document_created",
            artifact.canonical_document_created,
        ),
        ("signed_document_created", artifact.signed_document_created),
        ("archive_package_created", artifact.archive_package_created),
        ("pdfa_created", artifact.pdfa_created),
        ("pdfua_created", artifact.pdfua_created),
        ("signature_created", artifact.signature_created),
        ("seal_created", artifact.seal_created),
        (
            "archive_certification_claimed",
            artifact.archive_certification_claimed,
        ),
        ("legal_validity_claimed", artifact.legal_validity_claimed),
        (
            "source_extracted_text_in_artifact",
            artifact.source_extracted_text_in_artifact,
        ),
        (
            "source_extracted_text_in_ledger_event",
            artifact.source_extracted_text_in_ledger_event,
        ),
    ];
    if let Some((field, _)) = forbidden_claims.iter().find(|(_, claimed)| *claimed) {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("paper-book OCR conversion execution artifact must keep {field} false"),
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn paper_book_import_meta_from_raw(
    import_id: String,
    entity_ref: String,
    entity_name: String,
    entity_nipc: String,
    book_ref: String,
    date_from_raw: String,
    date_to_raw: String,
    page_count_raw: i64,
    page_from_raw: i64,
    page_to_raw: i64,
    original_number_from_raw: Option<i64>,
    original_number_to_raw: Option<i64>,
    sha256: String,
    size_raw: i64,
    content_type: String,
    source_filename: Option<String>,
    notes: Option<String>,
    imported_at_raw: String,
    imported_by: String,
    ocr_status_raw: String,
) -> Result<StoredPaperBookImportMeta, StoreError> {
    let size_bytes = usize::try_from(size_raw).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored paper-book import size {size_raw} is negative or too large"),
        ))
    })?;
    let page_count = int_to_u32(page_count_raw)?;
    let page_from = int_to_u32(page_from_raw)?;
    let page_to = int_to_u32(page_to_raw)?;
    if page_from == 0 || page_to == 0 || page_from > page_to || page_to > page_count {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "stored paper-book page range {page_from}-{page_to} is outside page_count {page_count}"
            ),
        )));
    }
    let original_number_from = original_number_from_raw.map(int_to_u64).transpose()?;
    let original_number_to = original_number_to_raw.map(int_to_u64).transpose()?;
    if matches!(
        (original_number_from, original_number_to),
        (Some(from), Some(to)) if from == 0 || to == 0 || from > to
    ) || matches!(
        (original_number_from, original_number_to),
        (Some(_), None) | (None, Some(_))
    ) {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored paper-book original number range is invalid",
        )));
    }
    Ok(StoredPaperBookImportMeta {
        import_id,
        entity_ref,
        entity_name,
        entity_nipc,
        book_ref,
        date_from: parse_date(&date_from_raw)?,
        date_to: parse_date(&date_to_raw)?,
        page_count,
        page_from,
        page_to,
        original_number_from,
        original_number_to,
        sha256,
        size_bytes,
        content_type,
        source_filename,
        notes,
        imported_at: parse_rfc3339(&imported_at_raw)?,
        imported_by,
        ocr_status: StoredPaperBookOcrStatus::parse(&ocr_status_raw)?,
    })
}

/// Map one `follow_ups` row to [`StoredFollowUp`]. Deferred inner `Result` lets timestamp, date,
/// status, and integer conversions surface as [`StoreError`].
#[allow(clippy::type_complexity)]
fn row_to_follow_up(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredFollowUp, StoreError>> {
    let id: String = row.get(0)?;
    let act_id_raw: String = row.get(1)?;
    let agenda_number_raw: Option<i64> = row.get(2)?;
    let deliberation_index_raw: Option<i64> = row.get(3)?;
    let title: String = row.get(4)?;
    let detail: Option<String> = row.get(5)?;
    let due_date_raw: Option<String> = row.get(6)?;
    let assignee: Option<String> = row.get(7)?;
    let assignee_display: Option<String> = row.get(8)?;
    let status_raw: String = row.get(9)?;
    let created_at_raw: String = row.get(10)?;
    let created_by: String = row.get(11)?;
    let completed_at_raw: Option<String> = row.get(12)?;
    let completed_by: Option<String> = row.get(13)?;
    Ok((|| {
        Ok(StoredFollowUp {
            id,
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            agenda_number: agenda_number_raw.map(int_to_u32).transpose()?,
            deliberation_index: deliberation_index_raw.map(int_to_u32).transpose()?,
            title,
            detail,
            due_date: due_date_raw.as_deref().map(parse_date).transpose()?,
            assignee,
            assignee_display,
            status: StoredFollowUpStatus::parse(&status_raw)?,
            created_at: parse_rfc3339(&created_at_raw)?,
            created_by,
            completed_at: completed_at_raw.as_deref().map(parse_rfc3339).transpose()?,
            completed_by,
        })
    })())
}

/// Map one `signed_documents` row to a [`StoredSignedDocument`]. Deferred inner `Result` (the
/// `act_id` / timestamp conversions surface as [`StoreError`]) unwrapped by the caller's `.transpose()`.
#[allow(clippy::type_complexity)]
fn row_to_signed_document(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StoredSignedDocument, StoreError>> {
    let act_id_raw: String = row.get(0)?;
    let document_id: String = row.get(1)?;
    let signed_pdf_digest: String = row.get(2)?;
    let signature_family: String = row.get(3)?;
    let evidentiary_level: String = row.get(4)?;
    let trusted_list_status: Option<String> = row.get(5)?;
    let signer_cert_subject: Option<String> = row.get(6)?;
    let signing_time_raw: String = row.get(7)?;
    let signed_at_raw: String = row.get(8)?;
    let signer_cert_der: Vec<u8> = row.get(9)?;
    let timestamp_token_der: Option<Vec<u8>> = row.get(10)?;
    let timestamp_trust_report_json: Option<String> = row.get(11)?;
    let signer_capacity_evidence_json: Option<String> = row.get(12)?;
    let signed_pdf_bytes: Vec<u8> = row.get(13)?;
    Ok((|| {
        Ok(StoredSignedDocument {
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            document_id,
            signed_pdf_digest,
            signature_family,
            evidentiary_level,
            trusted_list_status,
            signer_cert_subject,
            signing_time: parse_rfc3339(&signing_time_raw)?,
            signed_at: parse_rfc3339(&signed_at_raw)?,
            signer_cert_der,
            timestamp_token_der,
            timestamp_trust_report_json,
            signer_capacity_evidence_json,
            signed_pdf_bytes,
        })
    })())
}

/// Map one `pending_cmd_sessions` row to a [`PendingCmdSession`]. Deferred inner `Result` (the
/// `act_id` / timestamp conversions surface as [`StoreError`]) unwrapped by the caller's `.transpose()`.
#[allow(clippy::type_complexity)]
fn row_to_pending_session(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<PendingCmdSession, StoreError>> {
    let session_id: String = row.get(0)?;
    let act_id_raw: String = row.get(1)?;
    let actor: String = row.get(2)?;
    let status: String = row.get(3)?;
    let masked_phone: String = row.get(4)?;
    let doc_name: String = row.get(5)?;
    let session_json: String = row.get(6)?;
    let prepared_json: String = row.get(7)?;
    let created_at_raw: String = row.get(8)?;
    let expires_at_raw: String = row.get(9)?;
    let signer_capacity_evidence_json: Option<String> = row.get(10)?;
    Ok((|| {
        Ok(PendingCmdSession {
            session_id,
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            actor,
            status,
            masked_phone,
            doc_name,
            signer_capacity_evidence_json,
            session_json,
            prepared_json,
            created_at: parse_rfc3339(&created_at_raw)?,
            expires_at: parse_rfc3339(&expires_at_raw)?,
        })
    })())
}

/// Reconstruct a uuid newtype id (e.g. [`EntityId`], [`EventId`]) stored as its plain uuid text.
///
/// These ids serialize transparently as their inner uuid (a JSON string), so quoting the stored
/// text and running it back through serde reconstructs the id without a direct `uuid` dependency.
fn parse_uuid_newtype<T: DeserializeOwned>(raw: &str) -> Result<T, StoreError> {
    Ok(serde_json::from_str(&format!("\"{raw}\""))?)
}

/// Parse an RFC 3339 timestamp stored in the `events.timestamp` column back to an [`OffsetDateTime`].
/// A malformed value means the row was corrupted after being written by [`Tx::append_event`].
fn parse_rfc3339(raw: &str) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|e| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid stored timestamp {raw:?}: {e}"),
        ))
    })
}

fn format_date(d: Date) -> String {
    let fmt = format_description!("[year]-[month]-[day]");
    d.format(&fmt).unwrap_or_default()
}

fn parse_date(raw: &str) -> Result<Date, StoreError> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(raw, &fmt).map_err(|e| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid stored date {raw:?}: {e}"),
        ))
    })
}

fn int_to_u32(raw: i64) -> Result<u32, StoreError> {
    u32::try_from(raw).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored integer {raw} is negative or too large for u32"),
        ))
    })
}

fn int_to_u64(raw: i64) -> Result<u64, StoreError> {
    u64::try_from(raw).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored integer {raw} is negative for u64"),
        ))
    })
}

fn optional_u64_to_i64(value: Option<u64>, field: &str) -> Result<Option<i64>, StoreError> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| {
                StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{field} does not fit sqlite INTEGER"),
                ))
            })
        })
        .transpose()
}

fn validate_paper_book_import_ranges(
    meta: &StoredPaperBookImportMeta,
    kind: std::io::ErrorKind,
) -> Result<(), StoreError> {
    if meta.page_count == 0
        || meta.page_from == 0
        || meta.page_to == 0
        || meta.page_from > meta.page_to
        || meta.page_to > meta.page_count
    {
        return Err(StoreError::Io(std::io::Error::new(
            kind,
            format!(
                "paper-book page range {}-{} is outside page_count {}",
                meta.page_from, meta.page_to, meta.page_count
            ),
        )));
    }
    match (meta.original_number_from, meta.original_number_to) {
        (None, None) => Ok(()),
        (Some(from), Some(to)) if from > 0 && to > 0 && from <= to => Ok(()),
        _ => Err(StoreError::Io(std::io::Error::new(
            kind,
            "paper-book original number range is invalid",
        ))),
    }
}

/// Convert a BLOB column into a fixed 32-byte digest, treating a wrong-length value as corruption.
fn blob32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("stored {what} is {len} bytes, expected 32"),
        ))
    })
}

/// Lowercase-hex encoding of a byte slice (sha256 digests and the ledger head hash).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn backup_envelope_aad(header: &BackupEnvelopeHeader) -> Result<Vec<u8>, StoreError> {
    let mut aad = Vec::from(BACKUP_ENVELOPE_MAGIC);
    aad.extend_from_slice(&serde_json::to_vec(header)?);
    Ok(aad)
}

fn derive_backup_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], StoreError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| StoreError::BadBackup(format!("backup key derivation failed: {e}")))?;
    Ok(key)
}

fn decode_fixed_hex<const N: usize>(raw: &str, what: &str) -> Result<[u8; N], StoreError> {
    let bytes = decode_hex(raw, what)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| StoreError::BadBackup(format!("{what} is {len} bytes, expected {N}")))
}

fn decode_hex(raw: &str, what: &str) -> Result<Vec<u8>, StoreError> {
    if raw.len() % 2 != 0 {
        return Err(StoreError::BadBackup(format!(
            "{what} is not valid hex: odd length"
        )));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for chunk in raw.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])
            .ok_or_else(|| StoreError::BadBackup(format!("{what} is not valid lowercase hex")))?;
        let lo = hex_nibble(chunk[1])
            .ok_or_else(|| StoreError::BadBackup(format!("{what} is not valid lowercase hex")))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Open (creating if absent) `<data_dir>/chancela.db`, apply the PRAGMAs + idempotent migration,
/// gate the schema version, and ensure the `instance_id` stamp. Factored out of [`Store::open`] so
/// the whole-store [`recovery`] restore can rebuild a fresh connection after swapping the db file.
pub(crate) fn open_connection(data_dir: &Path) -> Result<rusqlite::Connection, StoreError> {
    open_connection_with_options(data_dir, &StoreOpenOptions::default())
}

pub(crate) fn open_connection_with_options(
    data_dir: &Path,
    options: &StoreOpenOptions,
) -> Result<rusqlite::Connection, StoreError> {
    preflight_key_ops(data_dir, options)?;
    std::fs::create_dir_all(data_dir)?;
    let conn = rusqlite::Connection::open(data_dir.join(DB_FILE))?;
    apply_open_options(&conn, options)?;
    configure_and_migrate(&conn)?;
    Ok(conn)
}

fn preflight_key_ops(data_dir: &Path, options: &StoreOpenOptions) -> Result<(), StoreError> {
    let status = Store::key_ops_status(data_dir, options)?;
    match status.plan {
        StoreKeyOpsPlan::RejectEmptyKey => Err(StoreError::EmptyEncryptionKey),
        StoreKeyOpsPlan::SqlcipherBuildRequired => Err(StoreError::EncryptionUnavailable),
        StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration => {
            Err(StoreError::PlaintextEncryptionMigrationUnsupported {
                db_file: status.database_file.display().to_string(),
            })
        }
        StoreKeyOpsPlan::CreatePlaintextStore
        | StoreKeyOpsPlan::OpenPlaintextStore
        | StoreKeyOpsPlan::KeyRequiredForNonPlaintextStore
        | StoreKeyOpsPlan::CreateEncryptedStore
        | StoreKeyOpsPlan::OpenEncryptedStore => Ok(()),
    }
}

fn inspect_database_format(db_file: &Path) -> Result<StoreDatabaseFormat, StoreError> {
    let mut file = match std::fs::File::open(db_file) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StoreDatabaseFormat::Missing);
        }
        Err(err) => return Err(StoreError::Io(err)),
    };

    let mut header = [0u8; SQLITE_PLAINTEXT_HEADER.len()];
    let read = file.read(&mut header)?;
    if read == SQLITE_PLAINTEXT_HEADER.len() && &header == SQLITE_PLAINTEXT_HEADER {
        Ok(StoreDatabaseFormat::PlaintextSqlite)
    } else {
        Ok(StoreDatabaseFormat::NonPlaintextOrEncrypted)
    }
}

#[cfg(feature = "sqlcipher")]
fn apply_open_options(
    conn: &rusqlite::Connection,
    options: &StoreOpenOptions,
) -> Result<(), StoreError> {
    let Some(key) = options.encryption_key() else {
        return Ok(());
    };
    if key.trim().is_empty() {
        return Err(StoreError::EmptyEncryptionKey);
    }

    conn.pragma_update(None, "key", key)
        .map_err(|source| StoreError::EncryptionKeyRejected { source })?;
    verify_keyed_database(conn)
}

#[cfg(not(feature = "sqlcipher"))]
fn apply_open_options(
    _conn: &rusqlite::Connection,
    options: &StoreOpenOptions,
) -> Result<(), StoreError> {
    if options.encryption_key().is_some() {
        return Err(StoreError::EncryptionUnavailable);
    }
    Ok(())
}

#[cfg(feature = "sqlcipher")]
fn verify_keyed_database(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|_| ())
    .map_err(|source| StoreError::EncryptionKeyRejected { source })
}

/// Apply WAL/foreign-keys/busy-timeout PRAGMAs, run the idempotent [`schema::ALL`] DDL + the
/// additive `links` column guard, gate the `schema_version` (rejecting a newer file, advancing an
/// older stamp forward), and ensure a stable `instance_id`. Shared by open + restore.
pub(crate) fn configure_and_migrate(conn: &rusqlite::Connection) -> Result<(), StoreError> {
    // WAL gives crash-safety on partial writes; foreign_keys keeps referential intent honest;
    // busy_timeout lets a concurrent reader wait out a writer instead of erroring immediately.
    // `execute_batch` tolerates the row `PRAGMA journal_mode=WAL` returns (`execute` would not).
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;\n\
         PRAGMA foreign_keys=ON;\n\
         PRAGMA busy_timeout=5000;",
    )?;

    // Idempotent migration: a fresh DB is created, an existing one left untouched.
    for stmt in schema::ALL {
        conn.execute_batch(stmt)?;
    }

    // Additive migration: the `links` column (multi-chain event links) was added after the
    // initial schema v1. `ALTER TABLE ... ADD COLUMN` is idempotent-safe via this guard.
    if !table_has_column(conn, "events", "links")? {
        conn.execute_batch("ALTER TABLE events ADD COLUMN links TEXT NOT NULL DEFAULT '[]';")?;
    }

    if !table_has_column(conn, "signed_documents", "timestamp_trust_report_json")? {
        conn.execute_batch(
            "ALTER TABLE signed_documents ADD COLUMN timestamp_trust_report_json TEXT;",
        )?;
    }
    if !table_has_column(conn, "signed_documents", "signer_capacity_evidence_json")? {
        conn.execute_batch(
            "ALTER TABLE signed_documents ADD COLUMN signer_capacity_evidence_json TEXT;",
        )?;
    }
    if !table_has_column(
        conn,
        "pending_cmd_sessions",
        "signer_capacity_evidence_json",
    )? {
        conn.execute_batch(
            "ALTER TABLE pending_cmd_sessions ADD COLUMN signer_capacity_evidence_json TEXT;",
        )?;
    }

    if !table_has_column(conn, "imported_documents", "operator_review_status")? {
        conn.execute_batch(
            "ALTER TABLE imported_documents ADD COLUMN operator_review_status TEXT NOT NULL \
             DEFAULT 'operator_review_required';",
        )?;
        conn.execute_batch(
            "UPDATE imported_documents SET operator_review_status = CASE \
             WHEN detected_content_type IN ('image/png', 'image/jpeg') THEN 'ocr_review_required' \
             WHEN detected_content_type = 'application/msword' THEN \
             'canonical_conversion_review_required' \
             ELSE 'operator_review_required' END;",
        )?;
    }
    if !table_has_column(conn, "imported_documents", "operator_reviewed_at")? {
        conn.execute_batch("ALTER TABLE imported_documents ADD COLUMN operator_reviewed_at TEXT;")?;
    }
    if !table_has_column(conn, "imported_documents", "operator_reviewed_by")? {
        conn.execute_batch("ALTER TABLE imported_documents ADD COLUMN operator_reviewed_by TEXT;")?;
    }
    if !table_has_column(conn, "imported_documents", "operator_review_note")? {
        conn.execute_batch("ALTER TABLE imported_documents ADD COLUMN operator_review_note TEXT;")?;
    }
    if !table_has_column(
        conn,
        "imported_documents",
        "operator_acknowledged_guardrail_ids_json",
    )? {
        conn.execute_batch(
            "ALTER TABLE imported_documents ADD COLUMN \
             operator_acknowledged_guardrail_ids_json TEXT NOT NULL DEFAULT '[]';",
        )?;
    }

    if !table_has_column(conn, "paper_book_imports", "page_from")? {
        conn.execute_batch(
            "ALTER TABLE paper_book_imports ADD COLUMN page_from INTEGER NOT NULL DEFAULT 1;",
        )?;
    }
    if !table_has_column(conn, "paper_book_imports", "page_to")? {
        conn.execute_batch(
            "ALTER TABLE paper_book_imports ADD COLUMN page_to INTEGER NOT NULL DEFAULT 1;",
        )?;
        conn.execute_batch(
            "UPDATE paper_book_imports SET page_to = page_count WHERE page_count > 1;",
        )?;
    }
    if !table_has_column(conn, "paper_book_imports", "original_number_from")? {
        conn.execute_batch(
            "ALTER TABLE paper_book_imports ADD COLUMN original_number_from INTEGER;",
        )?;
    }
    if !table_has_column(conn, "paper_book_imports", "original_number_to")? {
        conn.execute_batch(
            "ALTER TABLE paper_book_imports ADD COLUMN original_number_to INTEGER;",
        )?;
    }

    // schema_version gate: reject a file written by a *newer* build (we don't know its layout);
    // stamp a fresh DB with our version. Older versions would key future real migrations.
    let found: Option<i64> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|s| s.parse::<i64>().ok());
    match found {
        Some(v) if v > schema::SCHEMA_VERSION => {
            return Err(StoreError::UnsupportedSchemaVersion {
                found: v,
                supported: schema::SCHEMA_VERSION,
            });
        }
        // Forward-only upgrade: a database written by an older build has already had the new,
        // additive DDL applied above (idempotent `CREATE TABLE IF NOT EXISTS` — e.g. the v2
        // `documents` table, the v3 `imported_books` table), so advancing the stamp is the whole
        // migration. No column of an existing table is dropped or retyped, so it is safe and one-way.
        Some(v) if v < schema::SCHEMA_VERSION => {
            conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                params![schema::SCHEMA_VERSION.to_string()],
            )?;
        }
        Some(_) => {}
        None => {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                params![schema::SCHEMA_VERSION.to_string()],
            )?;
        }
    }

    // Stable per-install id (t54): minted once, on first open, then immutable. A restored backup
    // already carries one, so this preserves the source instance's identity across a restore.
    if conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'instance_id'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_none()
    {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('instance_id', ?1)",
            params![uuid::Uuid::new_v4().to_string()],
        )?;
    }

    Ok(())
}

fn table_has_column(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<bool, StoreError> {
    let sql = format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'");
    Ok(conn
        .prepare(&sql)?
        .query_row([], |row| row.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false))
}

/// Read the stable `instance_id` from `meta` (present after [`configure_and_migrate`]).
pub(crate) fn read_instance_id(conn: &rusqlite::Connection) -> Result<String, StoreError> {
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'instance_id'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .ok_or_else(|| {
        StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "instance_id missing from meta",
        ))
    })
}

/// A filesystem-safe compact UTC stamp (`YYYYMMDDTHHMMSSZ`) for backup archive names — no colons,
/// which Windows forbids in paths.
pub(crate) fn utc_stamp(t: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

fn tmp_backup_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| "chancela-backup.cbackup".into());
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    path.with_file_name(name)
}

/// Add a single file to the zip, recording its sha256 and byte length in `files`.
fn add_file_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    name: &str,
    path: &Path,
    opts: zip::write::SimpleFileOptions,
    files: &mut Vec<BackupFile>,
) -> Result<(), StoreError> {
    // Zip-slip defense: reject member names containing path-traversal sequences.
    if name.contains("..") {
        return Ok(());
    }
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    zip.start_file(name, opts)?;
    zip.write_all(&bytes)?;
    files.push(BackupFile {
        name: name.to_string(),
        sha256: hex(&digest),
        bytes: bytes.len() as u64,
    });
    Ok(())
}

/// Add a sidecar path to the zip: a file directly, a directory recursively (member names carry the
/// relative sub-path), and a missing path is skipped (tolerated per the plan). Symlinks are skipped
/// and member names containing `..` are rejected (zip-slip defense, ZIP-01).
fn add_path_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    name: &str,
    path: &Path,
    opts: zip::write::SimpleFileOptions,
    files: &mut Vec<BackupFile>,
) -> Result<(), StoreError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        // Skip missing paths (tolerated per the plan, mirrors the original is_dir/is_file behavior).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::Io(e)),
    };
    // Skip symlinks — they could point outside the intended directory tree (zip-slip).
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    // Reject path-traversal sequences in the member name.
    if name.contains("..") {
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let child_name = format!("{name}/{}", entry.file_name().to_string_lossy());
            add_path_to_zip(zip, &child_name, &entry.path(), opts, files)?;
        }
    } else if meta.is_file() {
        add_file_to_zip(zip, name, path, opts, files)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway temp directory unique to this test run, removed on drop. The store's integration
    /// suite carries its own `TempDir`; this keeps the in-crate unit test self-contained.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-store-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            TempDir(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn user_templates_round_trip_upsert_get_list_delete() {
        let dir = TempDir::new();
        let store = Store::open(dir.path()).expect("open");

        // Empty store reads as empty / absent.
        assert!(store.user_templates().unwrap().is_empty());
        assert_eq!(store.user_template("user-ata-ag/v1").unwrap(), None);

        // Upsert two, deliberately out of id order to prove the list orders by id.
        store
            .persist(|tx| {
                tx.upsert_user_template("user-ata-ag/v2", r#"{"id":"user-ata-ag/v2"}"#)?;
                tx.upsert_user_template("user-ata-ag/v1", r#"{"id":"user-ata-ag/v1"}"#)?;
                Ok(())
            })
            .expect("persist templates");

        // Single-row get returns the stored json.
        assert_eq!(
            store.user_template("user-ata-ag/v1").unwrap().as_deref(),
            Some(r#"{"id":"user-ata-ag/v1"}"#)
        );

        // List is ordered by id.
        assert_eq!(
            store.user_templates().unwrap(),
            vec![
                (
                    "user-ata-ag/v1".to_owned(),
                    r#"{"id":"user-ata-ag/v1"}"#.to_owned()
                ),
                (
                    "user-ata-ag/v2".to_owned(),
                    r#"{"id":"user-ata-ag/v2"}"#.to_owned()
                ),
            ]
        );

        // Upsert is idempotent on id: a second write replaces the json, never duplicates the row.
        store
            .persist(|tx| {
                tx.upsert_user_template("user-ata-ag/v1", r#"{"id":"user-ata-ag/v1","v":2}"#)
            })
            .expect("update template");
        assert_eq!(store.user_templates().unwrap().len(), 2);
        assert_eq!(
            store.user_template("user-ata-ag/v1").unwrap().as_deref(),
            Some(r#"{"id":"user-ata-ag/v1","v":2}"#)
        );

        // Delete drops exactly one row; deleting an unknown id is a no-op.
        store
            .persist(|tx| {
                tx.delete_user_template("user-ata-ag/v2")?;
                tx.delete_user_template("user-does-not-exist/v1")?;
                Ok(())
            })
            .expect("delete template");
        assert_eq!(store.user_template("user-ata-ag/v2").unwrap(), None);
        assert_eq!(
            store.user_templates().unwrap(),
            vec![(
                "user-ata-ag/v1".to_owned(),
                r#"{"id":"user-ata-ag/v1","v":2}"#.to_owned()
            )]
        );

        // The row survives a reopen (durable, not in-memory).
        drop(store);
        let reopened = Store::open(dir.path()).expect("reopen");
        assert_eq!(reopened.user_templates().unwrap().len(), 1);
    }
}
