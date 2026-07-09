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

pub mod recovery;
pub mod schema;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chancela_core::{Act, ActId, Book, BookId, Entity, EntityId};
use chancela_ledger::{ChainLink, Event, EventId, IntegrityReport, Ledger, LedgerError};
use chancela_registry::RegistryExtract;
use rand_core::{OsRng, RngCore};
use rusqlite::{OptionalExtension, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

/// The database file created inside the data directory passed to [`Store::open`].
pub const DB_FILE: &str = "chancela.db";

/// Prefix identifying an encrypted whole-instance backup envelope.
pub const BACKUP_ENVELOPE_MAGIC: &[u8] = b"chancela-backup-envelope/v1\n";
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
    /// A filesystem error (creating the data dir, the backup archive, reading a sidecar).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Serializing a domain aggregate to / from its `json` column, or a manifest.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
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
        "store encryption key supplied but this build was not compiled with the sqlcipher feature"
    )]
    EncryptionUnavailable,
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

/// A handle to the durable store. Cheap to clone (shares one connection via `Arc`) and lives in
/// `chancela_api::AppState`.
///
/// The single connection runs in WAL mode; a connection pool is a later optimization behind this
/// same seam (t30.md §2 "Async/blocking note").
#[derive(Debug, Clone)]
pub struct Store {
    /// The one SQLite connection, shared and mutex-guarded. rusqlite is synchronous, so a mutation
    /// takes this lock for the (tiny, local) duration of its transaction. `pub(crate)` so the
    /// [`recovery`] module can swap the whole connection during a whole-store restore.
    pub(crate) conn: Arc<Mutex<rusqlite::Connection>>,
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
    /// Package retained; no OCR work has been executed by this slice.
    NotStarted,
}

impl StoredPaperBookOcrStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
        }
    }

    fn parse(raw: &str) -> Result<Self, StoreError> {
        match raw {
            "not_started" => Ok(Self::NotStarted),
            other => Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid stored paper-book OCR status {other:?}"),
            ))),
        }
    }
}

/// Metadata for a preserved historical paper-book import package (`paper_book_imports`, schema v8).
/// This is the ledger payload source and intentionally excludes raw bytes.
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
    /// The non-secret `CmdSignSession` serde blob (opaque to the store).
    pub session_json: String,
    /// The non-secret `PreparedSignature` serde blob (opaque to the store).
    pub prepared_json: String,
    /// When the session was created (UTC).
    pub created_at: OffsetDateTime,
    /// When the session expires (UTC; single-use, TTL-bounded).
    pub expires_at: OffsetDateTime,
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
        let conn = open_connection_with_options(data_dir, &options)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// The stable per-install `instance_id` stamped into `meta` on first open (t54): bundle
    /// provenance (`BundleManifest.source_instance_id`) and the import feed both read it. A restored
    /// backup keeps the *source* instance's id (the stamp is only minted when absent).
    pub fn instance_id(&self) -> Result<String, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        read_instance_id(&guard)
    }

    /// Rotate the SQLCipher passphrase for an already-keyed store connection.
    ///
    /// The new key is never included in errors or logs. Empty keys are rejected before issuing
    /// `PRAGMA rekey`, leaving the open database untouched.
    #[cfg(feature = "sqlcipher")]
    pub fn rotate_encryption_key(&self, new_key: &str) -> Result<(), StoreError> {
        self.rekey(new_key)
    }

    /// Alias for [`Store::rotate_encryption_key`], matching SQLCipher's primitive name.
    #[cfg(feature = "sqlcipher")]
    pub fn rekey(&self, new_key: &str) -> Result<(), StoreError> {
        if new_key.is_empty() {
            return Err(StoreError::EmptyEncryptionKey);
        }

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());

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
            let mut stmt = guard.prepare(
                "SELECT seq, id, actor, justification, timestamp, scope, kind, \
                 payload_digest, prev_hash, hash, links FROM events ORDER BY seq",
            )?;
            let rows = stmt.query_map([], |row| {
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
            })?;
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

    /// Fetch the document generated for `act_id`, returning its bytes + metadata, or `None` if the
    /// act has no persisted document yet (the api maps `None` to the `GET /v1/acts/{id}/document`
    /// 404-until-sealed). If an act was regenerated more than once, the most recently created row
    /// wins (ordered by `created_at`, then the physical `rowid` as a stable tie-break).
    pub fn document_for_act(&self, act_id: ActId) -> Result<Option<StoredDocument>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT id, act_id, template_id, pdf_digest, profile, created_at, pdf_bytes \
             FROM documents WHERE id = ?1",
        )?;
        stmt.query_row(params![id], row_to_document)
            .optional()?
            .transpose()
    }

    /// List imported, non-canonical document evidence metadata, newest first. When `act_id` is
    /// supplied, returns only imports linked to that act; otherwise returns the global feed.
    pub fn imported_documents(
        &self,
        act_id: Option<ActId>,
    ) -> Result<Vec<StoredImportedDocumentMeta>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        if let Some(act_id) = act_id {
            let mut stmt = guard.prepare(
                "SELECT id, act_id, filename, declared_content_type, detected_content_type, \
                 sha256, size_bytes, imported_at, imported_by FROM imported_documents \
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
                 sha256, size_bytes, imported_at, imported_by FROM imported_documents \
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT id, act_id, filename, declared_content_type, detected_content_type, sha256, \
             size_bytes, imported_at, imported_by, bytes FROM imported_documents WHERE id = ?1",
        )?;
        stmt.query_row(params![id], row_to_imported_document)
            .optional()?
            .transpose()
    }

    /// Fetch one preserved historical paper-book import package by id, including retained bytes.
    pub fn paper_book_import(
        &self,
        import_id: &str,
    ) -> Result<Option<StoredPaperBookImport>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, date_to, \
             page_count, sha256, size_bytes, content_type, source_filename, notes, imported_at, \
             imported_by, ocr_status, bytes FROM paper_book_imports WHERE import_id = ?1",
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        if let Some(book_ref) = book_ref {
            let mut stmt = guard.prepare(
                "SELECT import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, \
                 date_to, page_count, sha256, size_bytes, content_type, source_filename, notes, \
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
                 date_to, page_count, sha256, size_bytes, content_type, source_filename, notes, \
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

    /// List follow-ups for an act, open items first, then oldest-created first.
    pub fn follow_ups_for_act(&self, act_id: ActId) -> Result<Vec<StoredFollowUp>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
             trusted_list_status, signer_cert_subject, signing_time, signed_at, signer_cert_der, \
             timestamp_token_der, timestamp_trust_report_json, signed_pdf_bytes \
             FROM signed_documents WHERE act_id = ?1",
        )?;
        stmt.query_row(params![act_id.to_string()], row_to_signed_document)
            .optional()?
            .transpose()
    }

    /// Load every SIGNED PDF variant (metadata + bytes), keyed by act id — used to rehydrate the
    /// in-memory read model on boot.
    pub fn all_signed_documents(&self) -> Result<HashMap<ActId, StoredSignedDocument>, StoreError> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
             trusted_list_status, signer_cert_subject, signing_time, signed_at, signer_cert_der, \
             timestamp_token_der, timestamp_trust_report_json, signed_pdf_bytes \
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at FROM pending_cmd_sessions WHERE session_id = ?1",
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
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(
            "SELECT session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
             prepared_json, created_at, expires_at FROM pending_cmd_sessions",
        )?;
        let rows = stmt.query_map([], row_to_pending_session)?;
        let mut out = HashMap::new();
        for row in rows {
            let session = row??;
            out.insert(session.session_id.clone(), session);
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
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // rusqlite's `Transaction` rolls back on drop by default, so any early return from `f`
        // (its `?`) or a mid-closure `Err` discards every statement already issued — nothing is
        // persisted unless the whole closure succeeds and we reach `commit`.
        let txn = guard.transaction()?;
        let tx = Tx { txn };
        f(&tx)?;
        tx.txn.commit()?;
        Ok(())
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
        // In-memory / anonymous databases have no on-disk snapshot to bundle → NotPersistent
        // (the api maps this to the §3.2 422). A real file store reports its path here.
        {
            let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
            let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
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
    /// The open SQLite transaction. Every `Tx` method issues one statement against it; the whole
    /// closure commits (or, on any `Err`, rolls back) in [`Store::persist`]. Internal — not part of
    /// the frozen §3.1 API.
    txn: rusqlite::Transaction<'conn>,
}

impl<'conn> Tx<'conn> {
    /// Internal: borrow the raw transaction so the [`recovery`] paths can run their bespoke
    /// DELETE / INSERT SQL (domain-wipe, factory-blank, imported-book upsert) inside the same
    /// atomic commit as an `append_event`. Not part of the public API surface.
    pub(crate) fn raw(&self) -> &rusqlite::Transaction<'conn> {
        &self.txn
    }
}

impl Tx<'_> {
    /// Persist one ledger event row into the `events` table (append-only, keyed by `seq`).
    ///
    /// The hash-chain fields are stored directly: the ids/scope/kind/actor as text, the timestamp
    /// as RFC 3339 text (round-trips the instant), and the three 32-byte digests as BLOBs.
    pub fn append_event(&self, event: &Event) -> Result<(), StoreError> {
        let timestamp = event
            .timestamp
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        let links_json = serde_json::to_string(&event.links)?;
        self.txn.execute(
            "INSERT INTO events \
             (seq, id, actor, justification, timestamp, scope, kind, payload_digest, prev_hash, hash, links) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
        Ok(())
    }

    /// Upsert an entity's row (`entities`, document-in-relational).
    pub fn upsert_entity(&self, entity: &Entity) -> Result<(), StoreError> {
        let json = serde_json::to_string(entity)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO entities (id, json) VALUES (?1, ?2)",
            params![entity.id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert a book's row (`books`, with the indexed `entity_id` scope column).
    pub fn upsert_book(&self, book: &Book) -> Result<(), StoreError> {
        let json = serde_json::to_string(book)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO books (id, entity_id, json) VALUES (?1, ?2, ?3)",
            params![book.id.to_string(), book.entity_id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert an act's row (`acts`, with the indexed `book_id` scope column).
    pub fn upsert_act(&self, act: &Act) -> Result<(), StoreError> {
        let json = serde_json::to_string(act)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO acts (id, book_id, json) VALUES (?1, ?2, ?3)",
            params![act.id.to_string(), act.book_id.to_string(), json],
        )?;
        Ok(())
    }

    /// Upsert an imported certidão extract for an entity (`registry_extracts`, keyed by entity id).
    pub fn upsert_registry_extract(
        &self,
        entity_id: EntityId,
        extract: &RegistryExtract,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(extract)?;
        self.txn.execute(
            "INSERT OR REPLACE INTO registry_extracts (entity_id, json) VALUES (?1, ?2)",
            params![entity_id.to_string(), json],
        )?;
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
        self.txn.execute(
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
        Ok(())
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
        self.txn.execute(
            "INSERT OR REPLACE INTO imported_documents \
             (id, act_id, filename, declared_content_type, detected_content_type, sha256, \
              size_bytes, imported_at, imported_by, bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                doc.meta.id,
                doc.meta.act_id.as_ref().map(ToString::to_string),
                doc.meta.filename,
                doc.meta.declared_content_type,
                doc.meta.detected_content_type,
                doc.meta.sha256,
                size_bytes,
                imported_at,
                doc.meta.imported_by,
                doc.bytes,
            ],
        )?;
        Ok(())
    }

    /// Upsert a preserved historical paper-book package (`paper_book_imports`, schema v8).
    /// Intended to run in the same transaction as its metadata-only `paper_book_import.preserved`
    /// ledger event. This never touches canonical book, act, document, or signed-document rows.
    pub fn upsert_paper_book_import(
        &self,
        import: &StoredPaperBookImport,
    ) -> Result<(), StoreError> {
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
        self.txn.execute(
            "INSERT OR REPLACE INTO paper_book_imports \
             (import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from, date_to, \
              page_count, sha256, size_bytes, content_type, source_filename, notes, imported_at, \
              imported_by, ocr_status, bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                import.meta.import_id,
                import.meta.entity_ref,
                import.meta.entity_name,
                import.meta.entity_nipc,
                import.meta.book_ref,
                format_date(import.meta.date_from),
                format_date(import.meta.date_to),
                i64::from(import.meta.page_count),
                import.meta.sha256,
                size_bytes,
                import.meta.content_type,
                import.meta.source_filename,
                import.meta.notes,
                imported_at,
                import.meta.imported_by,
                import.meta.ocr_status.as_str(),
                import.bytes,
            ],
        )?;
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
        self.txn.execute(
            "INSERT OR REPLACE INTO follow_ups \
             (id, act_id, agenda_number, deliberation_index, title, detail, due_date, assignee, \
              assignee_display, status, created_at, created_by, completed_at, completed_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                follow_up.id,
                follow_up.act_id.to_string(),
                follow_up.agenda_number.map(i64::from),
                follow_up.deliberation_index.map(i64::from),
                follow_up.title,
                follow_up.detail,
                follow_up.due_date.map(format_date),
                follow_up.assignee,
                follow_up.assignee_display,
                follow_up.status.as_str(),
                created_at,
                follow_up.created_by,
                completed_at,
                follow_up.completed_by,
            ],
        )?;
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
        self.txn.execute(
            "INSERT OR REPLACE INTO signed_documents \
             (act_id, document_id, signed_pdf_digest, signature_family, evidentiary_level, \
              trusted_list_status, signer_cert_subject, signing_time, signed_at, signer_cert_der, \
              timestamp_token_der, timestamp_trust_report_json, signed_pdf_bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                doc.act_id.to_string(),
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
                doc.signed_pdf_bytes,
            ],
        )?;
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
        self.txn.execute(
            "INSERT OR REPLACE INTO pending_cmd_sessions \
             (session_id, act_id, actor, status, masked_phone, doc_name, session_json, \
              prepared_json, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                session.session_id,
                session.act_id.to_string(),
                session.actor,
                session.status,
                session.masked_phone,
                session.doc_name,
                session.session_json,
                session.prepared_json,
                created_at,
                expires_at,
            ],
        )?;
        Ok(())
    }

    /// Delete a pending CMD signing session by id (single-use: consumed on a successful confirm, or
    /// cancelled/expired). A no-op if it is already gone.
    pub fn delete_pending_cmd_session(&self, session_id: &str) -> Result<(), StoreError> {
        self.txn.execute(
            "DELETE FROM pending_cmd_sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(())
    }
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
    let bytes: Vec<u8> = row.get(9)?;
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
            )?,
            bytes,
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
    let sha256: String = row.get(8)?;
    let size_raw: i64 = row.get(9)?;
    let content_type: String = row.get(10)?;
    let source_filename: Option<String> = row.get(11)?;
    let notes: Option<String> = row.get(12)?;
    let imported_at_raw: String = row.get(13)?;
    let imported_by: String = row.get(14)?;
    let ocr_status_raw: String = row.get(15)?;
    Ok(paper_book_import_meta_from_raw(
        import_id,
        entity_ref,
        entity_name,
        entity_nipc,
        book_ref,
        date_from_raw,
        date_to_raw,
        page_count_raw,
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
    let bytes: Vec<u8> = row.get(16)?;
    Ok((|| Ok(StoredPaperBookImport { meta: meta?, bytes }))())
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
    Ok(StoredPaperBookImportMeta {
        import_id,
        entity_ref,
        entity_name,
        entity_nipc,
        book_ref,
        date_from: parse_date(&date_from_raw)?,
        date_to: parse_date(&date_to_raw)?,
        page_count: int_to_u32(page_count_raw)?,
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
    let signed_pdf_bytes: Vec<u8> = row.get(12)?;
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
    Ok((|| {
        Ok(PendingCmdSession {
            session_id,
            act_id: parse_uuid_newtype::<ActId>(&act_id_raw)?,
            actor,
            status,
            masked_phone,
            doc_name,
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
    std::fs::create_dir_all(data_dir)?;
    let conn = rusqlite::Connection::open(data_dir.join(DB_FILE))?;
    apply_open_options(&conn, options)?;
    configure_and_migrate(&conn)?;
    Ok(conn)
}

#[cfg(feature = "sqlcipher")]
fn apply_open_options(
    conn: &rusqlite::Connection,
    options: &StoreOpenOptions,
) -> Result<(), StoreError> {
    let Some(key) = options.encryption_key() else {
        return Ok(());
    };
    if key.is_empty() {
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
    let has_links: bool = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='links'")?
        .query_row([], |row| row.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false);
    if !has_links {
        conn.execute_batch("ALTER TABLE events ADD COLUMN links TEXT NOT NULL DEFAULT '[]';")?;
    }

    let has_timestamp_trust_report: bool = conn
        .prepare(
            "SELECT COUNT(*) FROM pragma_table_info('signed_documents') \
             WHERE name='timestamp_trust_report_json'",
        )?
        .query_row([], |row| row.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false);
    if !has_timestamp_trust_report {
        conn.execute_batch(
            "ALTER TABLE signed_documents ADD COLUMN timestamp_trust_report_json TEXT;",
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
