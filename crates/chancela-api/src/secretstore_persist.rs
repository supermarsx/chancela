//! Provider-credential **model** + encrypted **sidecar** persistence (plan t77 §1/§2, slice S2).
//!
//! This module sits on top of the [`crate::secretstore`] crypto core (S1). It owns:
//!
//! - the per-mode credential **model** ([`CmdCredentialFields`] / [`CscCredentialFields`] /
//!   [`ScapCredentialFields`] / [`Pkcs12CredentialFields`]) whose secret fields are
//!   `Option<Zeroizing<String>>` — `None` on a write means *leave unchanged*, an explicit clear-list
//!   removes a field;
//! - the at-rest **record** ([`EncryptedCredentialRecord`]) that holds an ordered list of
//!   [`CredentialEntry`]s (id / label / priority / enabled / endpoint / non-secret selectors + a map
//!   of encrypted [`SecretEnvelope`](crate::secretstore::SecretEnvelope)s) — **never** a plaintext
//!   secret;
//! - the encrypted **sidecar** file `provider-credentials.enc.json` in the data dir, written with the
//!   same schema-versioned, atomic temp+rename discipline as `attestation::write_seed_file`, plus the
//!   [`ProviderCredentialStore`] read/put/clear operations that wrap/unwrap through the S1 secretstore.
//!
//! ## Entries + entry-bound AEAD (plan §1/§6)
//!
//! A record's credentials are an ordered `Vec<CredentialEntry>` (priority/failover ordering), each
//! entry carrying its own encrypted fields. Every field's AEAD AAD binds the owning `entry_id`
//! (`mode ‖ provider_id ‖ entry_id ‖ field_name ‖ key_version`), so a ciphertext cannot be relocated
//! between a provider's entries. The flat [`ProviderCredentialStore::put`]/[`read`](
//! ProviderCredentialStore::read)/[`statuses`](ProviderCredentialStore::statuses) helpers are thin
//! shims over a single well-known [`DEFAULT_ENTRY_ID`] entry; multi-entry callers use
//! [`ProviderCredentialStore::put_entry`] / [`delete_entry`](ProviderCredentialStore::delete_entry) /
//! [`read_entries`](ProviderCredentialStore::read_entries).
//!
//! ## Fail-closed & honesty (mirrors S1 / plan §7)
//!
//! Startup is read-only-friendly: [`ProviderCredentialStore::load`] reads the sidecar records but
//! does **not** resolve the credential root key or create any key file — that happens lazily on the
//! first field that actually needs crypto. A deployment with no resolvable key source therefore boots
//! fine and serves empty reads, but any attempt to STORE a secret fails closed
//! ([`crate::secretstore::SecretStoreError::NoKeySource`]) rather than persisting plaintext. Strict
//! mode is enforced inside [`crate::secretstore::CredentialSecretStore::wrap`] before any plaintext is
//! touched. A corrupt or unknown-schema sidecar is **not** silently treated as empty (which would hide
//! corruption and risk overwriting good ciphertext); it puts the store into a fail-closed state where
//! every read/put/clear returns [`ProviderCredentialError::CorruptSidecar`] until an operator
//! intervenes.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use chancela_store::Store;

use crate::secretstore::{
    CredentialKeyReadOnlyStatus, CredentialKeySource, CredentialKeyStatusFailure,
    CredentialSecretStore, ProtectionLevel, SecretEnvelope, SecretStoreError,
};

/// File name of the encrypted credential sidecar in the data dir.
pub const CREDENTIAL_SIDECAR_FILE: &str = "provider-credentials.enc.json";

/// Schema version of the sidecar envelope. A mismatch fails closed rather than guessing.
///
/// v2 replaced the flat per-`(mode, provider_id)` field map with an ordered [`CredentialEntry`]
/// list (entry-bound AEAD AAD, priority/enabled/endpoint/selectors). The store is dormant — only
/// `statuses()` has a production caller and `put`/`read`/`clear` are exercised solely by tests — so
/// no on-disk v1 sidecar with real data can exist and there is **no** v1→v2 migration: the loader
/// fails closed on any other version.
const SIDECAR_SCHEMA_VERSION: u32 = 2;
/// `type` tag stamped in the sidecar envelope (guards against loading a foreign JSON file).
const SIDECAR_KIND: &str = "provider-credentials";
/// `purpose` tag stamped in the sidecar envelope.
const SIDECAR_PURPOSE: &str = "signing_provider_credentials_encrypted";

// --- Field-name constants (bound into the AEAD AAD; NEVER rename for an existing deployment) ---

/// CMD/SCAP application identifier field.
pub const FIELD_APPLICATION_ID: &str = "application_id";
/// HTTP-Basic gateway username field (all modes).
pub const FIELD_HTTP_BASIC_USERNAME: &str = "http_basic_username";
/// HTTP-Basic gateway password field (all modes).
pub const FIELD_HTTP_BASIC_PASSWORD: &str = "http_basic_password";
/// CMD AMA field-encryption certificate PEM field.
pub const FIELD_AMA_CERT_PEM: &str = "ama_cert_pem";
/// CSC OAuth client identifier field.
pub const FIELD_CLIENT_ID: &str = "client_id";
/// CSC OAuth client secret field.
pub const FIELD_CLIENT_SECRET: &str = "client_secret";
/// CSC OAuth access-token field.
pub const FIELD_ACCESS_TOKEN: &str = "access_token";
/// SCAP API-key/secret field.
pub const FIELD_SECRET: &str = "secret";
/// LocalPkcs12 base64-encoded PFX/PKCS#12 blob field. Base64 (not raw bytes) because the crypto
/// core validates decrypted plaintext as UTF-8, and a raw PFX is arbitrary binary.
pub const FIELD_PKCS12_PFX: &str = "pfx_der";
/// LocalPkcs12 PKCS#12 passphrase field.
pub const FIELD_PKCS12_PASSPHRASE: &str = "passphrase";

/// The entry id used by the legacy flat [`ProviderCredentialStore::put`]/[`read`](
/// ProviderCredentialStore::read)/[`statuses`](ProviderCredentialStore::statuses) shims, which map
/// the single implicit entry onto the ordered entry list. Multi-entry callers use
/// [`ProviderCredentialStore::put_entry`] with explicit ids.
const DEFAULT_ENTRY_ID: &str = "default";

// --- Credential mode -----------------------------------------------------------------------

/// Which signing-provider mode a credential record belongs to. The `as_str` form is stable and is
/// both the sidecar record key and part of the AEAD AAD, so it must never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// Chave Móvel Digital / SCMD.
    Cmd,
    /// Cloud Signature Consortium QTSP (per provider id).
    CscQtsp,
    /// AMA SCAP.
    Scap,
    /// Local PKCS#12 (PFX) software certificate held at rest (base64 blob + passphrase).
    LocalPkcs12,
}

impl CredentialMode {
    /// The stable wire/AAD string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cmd => "cmd",
            Self::CscQtsp => "csc",
            Self::Scap => "scap",
            Self::LocalPkcs12 => "pkcs12",
        }
    }

    /// Parse a mode back from its [`as_str`](Self::as_str) wire form.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "cmd" => Some(Self::Cmd),
            "csc" => Some(Self::CscQtsp),
            "scap" => Some(Self::Scap),
            "pkcs12" => Some(Self::LocalPkcs12),
            _ => None,
        }
    }

    /// The set of secret field names valid for this mode (plan §1). Used to reject unknown fields on
    /// write so the sidecar never accretes stray keys.
    pub fn field_names(self) -> &'static [&'static str] {
        match self {
            Self::Cmd => &[
                FIELD_APPLICATION_ID,
                FIELD_HTTP_BASIC_USERNAME,
                FIELD_HTTP_BASIC_PASSWORD,
                FIELD_AMA_CERT_PEM,
            ],
            Self::CscQtsp => &[
                FIELD_CLIENT_ID,
                FIELD_CLIENT_SECRET,
                FIELD_ACCESS_TOKEN,
                FIELD_HTTP_BASIC_USERNAME,
                FIELD_HTTP_BASIC_PASSWORD,
            ],
            Self::Scap => &[
                FIELD_APPLICATION_ID,
                FIELD_SECRET,
                FIELD_HTTP_BASIC_USERNAME,
                FIELD_HTTP_BASIC_PASSWORD,
            ],
            Self::LocalPkcs12 => &[FIELD_PKCS12_PFX, FIELD_PKCS12_PASSPHRASE],
        }
    }

    fn is_valid_field(self, field: &str) -> bool {
        self.field_names().contains(&field)
    }
}

// --- Per-mode credential field model -------------------------------------------------------

/// A per-mode set of secret fields to write. Each field is `Some(value)` to set/replace it or `None`
/// to leave the stored value unchanged (removal is a separate clear-list on
/// [`ProviderCredentialStore::put`]). Implemented by the mode structs below.
pub trait CredentialFieldSet {
    /// The mode these fields belong to.
    const MODE: CredentialMode;

    /// Consume the set and yield `(field_name, value)` for every field the caller wants to write,
    /// dropping the `None`s. The `Zeroizing<String>` values are moved out and wiped after wrapping.
    fn into_set_pairs(self) -> Vec<(&'static str, Zeroizing<String>)>;
}

/// CMD/SCMD secret fields (plan §1).
#[derive(Default)]
pub struct CmdCredentialFields {
    /// SCMD application id.
    pub application_id: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway username.
    pub http_basic_username: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway password.
    pub http_basic_password: Option<Zeroizing<String>>,
    /// AMA field-encryption certificate PEM.
    pub ama_cert_pem: Option<Zeroizing<String>>,
}

impl CredentialFieldSet for CmdCredentialFields {
    const MODE: CredentialMode = CredentialMode::Cmd;

    fn into_set_pairs(self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut pairs = Vec::new();
        push_pair(&mut pairs, FIELD_APPLICATION_ID, self.application_id);
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_USERNAME,
            self.http_basic_username,
        );
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_PASSWORD,
            self.http_basic_password,
        );
        push_pair(&mut pairs, FIELD_AMA_CERT_PEM, self.ama_cert_pem);
        pairs
    }
}

/// CSC/QTSP secret fields, per provider (plan §1).
#[derive(Default)]
pub struct CscCredentialFields {
    /// OAuth client id.
    pub client_id: Option<Zeroizing<String>>,
    /// OAuth client secret.
    pub client_secret: Option<Zeroizing<String>>,
    /// OAuth access token.
    pub access_token: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway username.
    pub http_basic_username: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway password.
    pub http_basic_password: Option<Zeroizing<String>>,
}

impl CredentialFieldSet for CscCredentialFields {
    const MODE: CredentialMode = CredentialMode::CscQtsp;

    fn into_set_pairs(self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut pairs = Vec::new();
        push_pair(&mut pairs, FIELD_CLIENT_ID, self.client_id);
        push_pair(&mut pairs, FIELD_CLIENT_SECRET, self.client_secret);
        push_pair(&mut pairs, FIELD_ACCESS_TOKEN, self.access_token);
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_USERNAME,
            self.http_basic_username,
        );
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_PASSWORD,
            self.http_basic_password,
        );
        pairs
    }
}

/// SCAP/AMA secret fields (plan §1).
#[derive(Default)]
pub struct ScapCredentialFields {
    /// SCAP application id.
    pub application_id: Option<Zeroizing<String>>,
    /// SCAP API-key/secret.
    pub secret: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway username.
    pub http_basic_username: Option<Zeroizing<String>>,
    /// HTTP-Basic gateway password.
    pub http_basic_password: Option<Zeroizing<String>>,
}

impl CredentialFieldSet for ScapCredentialFields {
    const MODE: CredentialMode = CredentialMode::Scap;

    fn into_set_pairs(self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut pairs = Vec::new();
        push_pair(&mut pairs, FIELD_APPLICATION_ID, self.application_id);
        push_pair(&mut pairs, FIELD_SECRET, self.secret);
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_USERNAME,
            self.http_basic_username,
        );
        push_pair(
            &mut pairs,
            FIELD_HTTP_BASIC_PASSWORD,
            self.http_basic_password,
        );
        pairs
    }
}

/// LocalPkcs12 secret fields: a base64-encoded PFX blob plus its passphrase (plan §1/§6).
#[derive(Default)]
pub struct Pkcs12CredentialFields {
    /// Base64 of the raw PKCS#12/PFX bytes (base64 so the UTF-8-validating crypto core accepts it).
    pub pfx_der_b64: Option<Zeroizing<String>>,
    /// The PKCS#12 passphrase.
    pub passphrase: Option<Zeroizing<String>>,
}

impl CredentialFieldSet for Pkcs12CredentialFields {
    const MODE: CredentialMode = CredentialMode::LocalPkcs12;

    fn into_set_pairs(self) -> Vec<(&'static str, Zeroizing<String>)> {
        let mut pairs = Vec::new();
        push_pair(&mut pairs, FIELD_PKCS12_PFX, self.pfx_der_b64);
        push_pair(&mut pairs, FIELD_PKCS12_PASSPHRASE, self.passphrase);
        pairs
    }
}

fn push_pair(
    pairs: &mut Vec<(&'static str, Zeroizing<String>)>,
    name: &'static str,
    value: Option<Zeroizing<String>>,
) {
    if let Some(value) = value {
        pairs.push((name, value));
    }
}

// --- At-rest record ------------------------------------------------------------------------

/// One encrypted credential field on disk: the AEAD [`SecretEnvelope`]. Never carries the plaintext.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCredentialField {
    /// The AEAD envelope wrapping this field's secret value.
    #[serde(flatten)]
    pub envelope: SecretEnvelope,
    /// Legacy plaintext display hint (≤4 chars). No longer written (M2: a short secret's last 4 chars
    /// can be the whole secret in cleartext); retained only to deserialize pre-existing sidecars.
    /// Always `None` on new writes and never surfaced as a fresh hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last4: Option<String>,
}

impl fmt::Debug for StoredCredentialField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredentialField")
            .field("envelope", &self.envelope)
            .field("last4", &self.last4)
            .finish()
    }
}

/// Non-secret per-mode selectors for one entry (e.g. an environment/sandbox tag or a routing hint).
/// Kept in the clear (never bound into the AEAD) so the status/assembly paths can read them without
/// decryption.
pub type EntrySelectors = BTreeMap<String, String>;

/// One credential **entry** within a provider record (plan §1/§6): a stable id, presentation/ordering
/// metadata, non-secret selectors, and this entry's encrypted fields. The `id` is bound into every
/// field's AEAD AAD so ciphertext cannot be relocated between a provider's entries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialEntry {
    /// Stable entry identifier (bound into the AEAD AAD; unique within a record).
    pub id: String,
    /// Human-facing label for the entry (non-secret; may be empty).
    #[serde(default)]
    pub label: String,
    /// Failover/priority order; entries are sorted ascending by `(priority, id)`.
    #[serde(default)]
    pub priority: i32,
    /// Whether this entry is eligible for use (disabled entries stay stored but are skipped).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional non-secret endpoint/base-URL override for this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Non-secret per-mode selectors.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selectors: EntrySelectors,
    /// Encrypted fields keyed by field name (sorted for a stable on-disk form).
    #[serde(default)]
    pub fields: BTreeMap<String, StoredCredentialField>,
    /// RFC 3339 creation timestamp (non-secret).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    /// RFC 3339 last-update timestamp (non-secret).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

/// A non-secret patch of an entry's presentation/ordering metadata, applied as a full overwrite on
/// [`ProviderCredentialStore::put_entry`] when `Some`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryMetadata {
    /// Human-facing label (non-secret).
    pub label: String,
    /// Failover/priority order.
    pub priority: i32,
    /// Whether the entry is eligible for use.
    pub enabled: bool,
    /// Optional non-secret endpoint/base-URL override.
    pub endpoint: Option<String>,
    /// Non-secret per-mode selectors.
    pub selectors: EntrySelectors,
}

/// The at-rest form of one provider's credentials (plan §1): an ordered list of [`CredentialEntry`]s,
/// tagged with the mode/provider selector and the key version last written.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedCredentialRecord {
    /// The [`CredentialMode::as_str`] this record belongs to.
    pub mode: String,
    /// The provider id (empty for the single-instance CMD/SCAP modes; the QTSP id for CSC).
    pub provider_id: String,
    /// The key version the most recent write used. Each envelope also carries its own version, which
    /// is the authoritative one for decryption; this is an informational/rotation marker.
    pub key_version: u32,
    /// Ordered credential entries (sorted by `(priority, id)` for a stable on-disk form).
    #[serde(default)]
    pub entries: Vec<CredentialEntry>,
}

impl EncryptedCredentialRecord {
    fn empty(mode: CredentialMode, provider_id: &str) -> Self {
        Self {
            mode: mode.as_str().to_owned(),
            provider_id: provider_id.to_owned(),
            key_version: 0,
            entries: Vec::new(),
        }
    }

    /// Sort the entries by `(priority, id)` for deterministic on-disk ordering and failover order.
    fn sort_entries(&mut self) {
        self.entries
            .sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    }

    /// The legacy flat entry, if present.
    fn default_entry(&self) -> Option<&CredentialEntry> {
        self.entries.iter().find(|e| e.id == DEFAULT_ENTRY_ID)
    }
}

/// A non-secret status view of one stored record for the credential status API (plan §4). Carries
/// configured field names + `last4` hints for the legacy flat entry only, never ciphertext or
/// plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecordStatus {
    /// The mode this record belongs to.
    pub mode: CredentialMode,
    /// The provider id (empty for CMD/SCAP).
    pub provider_id: String,
    /// The key version the record was last written under.
    pub key_version: u32,
    /// Per configured field of the flat entry: `(field_name, last4)`.
    pub fields: Vec<(String, Option<String>)>,
}

/// The decrypted fields of the legacy flat entry, returned by [`ProviderCredentialStore::read`] for
/// the provider-assembly path (S3). Every value is held in a [`Zeroizing`] buffer.
pub struct DecryptedCredentialRecord {
    /// The mode this record belongs to.
    pub mode: CredentialMode,
    /// The provider id (empty for CMD/SCAP).
    pub provider_id: String,
    /// Decrypted field values keyed by field name.
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

/// A non-secret, **non-decrypting** metadata view of one credential entry, for the write/management
/// API (plan §3). Reports the entry's ordering/label/enabled/endpoint/selectors plus, per stored
/// field, the field NAME and its non-secret `last4` hint. Never carries ciphertext or plaintext and
/// never touches key material — it is built purely from the loaded record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialEntryMetadataView {
    /// The entry id.
    pub entry_id: String,
    /// Non-secret label.
    pub label: String,
    /// Failover/priority order.
    pub priority: i32,
    /// Whether the entry is eligible for use.
    pub enabled: bool,
    /// Optional non-secret endpoint override.
    pub endpoint: Option<String>,
    /// Non-secret per-mode selectors.
    pub selectors: EntrySelectors,
    /// Per configured field: `(field_name, last4)`. `last4` is the non-secret ≤4-char display hint.
    pub fields: Vec<(String, Option<String>)>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-update timestamp.
    pub updated_at: String,
}

/// One decrypted credential entry, returned by [`ProviderCredentialStore::read_entries`]. Every
/// secret value is held in a [`Zeroizing`] buffer; the metadata is non-secret.
pub struct DecryptedCredentialEntry {
    /// The entry id.
    pub entry_id: String,
    /// Non-secret label.
    pub label: String,
    /// Failover/priority order.
    pub priority: i32,
    /// Whether the entry is eligible for use.
    pub enabled: bool,
    /// Optional non-secret endpoint override.
    pub endpoint: Option<String>,
    /// Non-secret per-mode selectors.
    pub selectors: EntrySelectors,
    /// Decrypted field values keyed by field name.
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

// --- Sidecar file envelope -----------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct CredentialSidecarFile {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: String,
    purpose: String,
    #[serde(default)]
    records: Vec<EncryptedCredentialRecord>,
}

type RecordMap = BTreeMap<(String, String), EncryptedCredentialRecord>;

/// Read + validate the sidecar at `path`. A missing file is a valid empty store; a present file that
/// fails to parse or carries an unknown schema/kind/purpose is reported as corrupt so the caller can
/// fail closed rather than silently starting empty.
fn load_sidecar(path: &Path) -> Result<RecordMap, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RecordMap::new()),
        Err(e) => return Err(format!("failed to read {}: {e}", path.display())),
    };
    let file: CredentialSidecarFile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not a valid credential sidecar: {e}", path.display()))?;
    if file.schema_version != SIDECAR_SCHEMA_VERSION {
        return Err(format!(
            "{} has unsupported schema version {} (expected {SIDECAR_SCHEMA_VERSION})",
            path.display(),
            file.schema_version
        ));
    }
    if file.kind != SIDECAR_KIND || file.purpose != SIDECAR_PURPOSE {
        return Err(format!(
            "{} is not a provider-credentials sidecar (type/purpose mismatch)",
            path.display()
        ));
    }
    let mut records = RecordMap::new();
    for record in file.records {
        if CredentialMode::from_wire(&record.mode).is_none() {
            return Err(format!(
                "{} references unknown credential mode {:?}",
                path.display(),
                record.mode
            ));
        }
        records.insert((record.mode.clone(), record.provider_id.clone()), record);
    }
    Ok(records)
}

/// Serialize `records` and atomically install them at `path` (temp file + rename, matching
/// `attestation::write_seed_file`).
fn write_sidecar_atomic(path: &Path, records: &RecordMap) -> Result<(), ProviderCredentialError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| ProviderCredentialError::Io {
                action: "create directory for",
                path: path.to_path_buf(),
                source,
            })?;
        }
    }
    let file = CredentialSidecarFile {
        schema_version: SIDECAR_SCHEMA_VERSION,
        kind: SIDECAR_KIND.to_owned(),
        purpose: SIDECAR_PURPOSE.to_owned(),
        records: records.values().cloned().collect(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(|e| ProviderCredentialError::Io {
        action: "serialize",
        path: path.to_path_buf(),
        source: std::io::Error::other(e),
    })?;
    let tmp = sidecar_tmp_path(path);
    std::fs::write(&tmp, &json).map_err(|source| ProviderCredentialError::Io {
        action: "write temporary sidecar for",
        path: tmp.clone(),
        source,
    })?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(source) => {
            let _ = std::fs::remove_file(&tmp);
            Err(ProviderCredentialError::Io {
                action: "install",
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

// --- Postgres blob storage (wp16 P3b) -----------------------------------------------------------

/// Read + decode every encrypted credential record from the shared `provider_credentials` DB table
/// into a [`RecordMap`]. Each row's `record_blob` is the opaque serialized [`EncryptedCredentialRecord`]
/// (AEAD ciphertext only — the store never decrypts it); this only relocates where the ciphertext
/// lives, so the wp13 envelope/AAD is untouched. A store error or a malformed blob is reported as a
/// reason string so the caller can fail closed (mirrors [`load_sidecar`]).
fn load_records_from_db(store: &Store) -> Result<RecordMap, String> {
    let rows = store
        .read_credential_records()
        .map_err(|e| format!("failed to read provider credentials from the durable store: {e}"))?;
    let mut records = RecordMap::new();
    for row in rows {
        if CredentialMode::from_wire(&row.mode).is_none() {
            return Err(format!(
                "durable store references unknown credential mode {:?}",
                row.mode
            ));
        }
        let record: EncryptedCredentialRecord =
            serde_json::from_slice(&row.record_blob).map_err(|e| {
                format!(
                    "durable provider-credential record ({}, {}) is not a valid credential record: {e}",
                    row.mode, row.provider_id
                )
            })?;
        records.insert((row.mode.clone(), row.provider_id.clone()), record);
    }
    Ok(records)
}

/// Reconcile `records` into the shared `provider_credentials` table in one transaction: upsert every
/// record's opaque encrypted blob and delete any DB row whose `(mode, provider_id)` is no longer
/// present (mirrors the whole-file atomic write, so a cleared record never lingers). Serializes every
/// blob **before** taking the transaction so a serialization failure never half-applies. Fails closed
/// on any store error.
fn write_records_to_db(store: &Store, records: &RecordMap) -> Result<(), ProviderCredentialError> {
    let mut rows = Vec::with_capacity(records.len());
    for ((mode, provider_id), record) in records {
        let blob = serde_json::to_vec(record).map_err(|e| db_error("serialize", e.to_string()))?;
        rows.push((
            mode.clone(),
            provider_id.clone(),
            i64::from(record.key_version),
            record_updated_at(record),
            blob,
        ));
    }
    let existing = store
        .read_credential_records()
        .map_err(|e| db_error("read", e.to_string()))?;
    let present: HashSet<(&str, &str)> = records
        .keys()
        .map(|(mode, provider_id)| (mode.as_str(), provider_id.as_str()))
        .collect();
    store
        .persist(|tx| {
            for (mode, provider_id, key_version, updated_at, blob) in &rows {
                tx.put_credential_record(mode, provider_id, *key_version, updated_at, blob)?;
            }
            for row in &existing {
                if !present.contains(&(row.mode.as_str(), row.provider_id.as_str())) {
                    tx.delete_credential_record(&row.mode, &row.provider_id)?;
                }
            }
            Ok(())
        })
        .map_err(|e| db_error("persist", e.to_string()))
}

/// The non-secret `updated_at` metadata column for a record row: the newest entry `updated_at`, or
/// the current time when no entry carries one. Informational only (each envelope self-describes its
/// key version); never used for decryption.
fn record_updated_at(record: &EncryptedCredentialRecord) -> String {
    record
        .entries
        .iter()
        .map(|entry| entry.updated_at.clone())
        .filter(|stamp| !stamp.is_empty())
        .max()
        .unwrap_or_else(now_rfc3339)
}

/// Map a durable-store credential-blob failure onto the existing [`ProviderCredentialError::Io`] arm
/// (so the write/status handlers keep their fail-closed mapping without a new variant). Never carries
/// secret material — only the store's own error text.
fn db_error(action: &'static str, detail: String) -> ProviderCredentialError {
    ProviderCredentialError::Io {
        action,
        path: PathBuf::from("provider_credentials (durable store)"),
        source: std::io::Error::other(detail),
    }
}

fn sidecar_tmp_path(path: &Path) -> PathBuf {
    use rand_core::{OsRng, RngCore};
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| CREDENTIAL_SIDECAR_FILE.into());
    name.push(format!(".{:016x}.tmp", u64::from_be_bytes(random)));
    path.with_file_name(name)
}

// --- Errors --------------------------------------------------------------------------------

/// A provider-credential persistence failure. `Display`/`Debug` never carry secret material.
#[derive(Debug)]
pub enum ProviderCredentialError {
    /// A crypto-core failure (no key source, strict-mode refusal, AEAD auth failure, …).
    Secret(SecretStoreError),
    /// Runtime plaintext use was refused because strict mode requires confidential protection.
    RuntimeStrictModeUnprotected {
        /// The current non-confidential protection level.
        level: ProtectionLevel,
    },
    /// The sidecar on disk is corrupt/unknown-schema; the store fails closed until it is repaired.
    CorruptSidecar(String),
    /// A write named a field that is not valid for the target mode.
    UnknownField {
        /// The mode the write targeted.
        mode: &'static str,
        /// The offending field name.
        field: String,
    },
    /// A filesystem operation on the sidecar failed.
    Io {
        /// What was being attempted (e.g. `"install"`).
        action: &'static str,
        /// The affected path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// An internal lock was poisoned by a panic on another thread.
    Poisoned,
}

impl fmt::Display for ProviderCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(e) => write!(f, "{e}"),
            Self::RuntimeStrictModeUnprotected { level } => write!(
                f,
                "refusing to read provider credentials at runtime: strict credential storage is \
                 enabled but the current protection level is {level} (not confidential)"
            ),
            Self::CorruptSidecar(reason) => write!(
                f,
                "the provider-credentials sidecar is unreadable and the credential store is failing \
                 closed until it is repaired: {reason}"
            ),
            Self::UnknownField { mode, field } => {
                write!(
                    f,
                    "{field:?} is not a valid credential field for mode {mode}"
                )
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(
                f,
                "failed to {action} the provider-credentials sidecar {}: {source}",
                path.display()
            ),
            Self::Poisoned => {
                write!(
                    f,
                    "the provider-credential store lock was poisoned by a panic"
                )
            }
        }
    }
}

impl std::error::Error for ProviderCredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Secret(e) => Some(e),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<SecretStoreError> for ProviderCredentialError {
    fn from(e: SecretStoreError) -> Self {
        Self::Secret(e)
    }
}

// --- The store -----------------------------------------------------------------------------

/// Where a [`ProviderCredentialStore`] persists and how it resolves its root key.
enum Backing {
    /// No persistence and no key source (the `Default`): reads are empty, writes fail closed.
    InMemory,
    /// Data-dir backed: the sidecar path plus the directory + optional DB key used to resolve the
    /// credential root lazily on first crypto use.
    DataDir {
        sidecar: PathBuf,
        data_dir: PathBuf,
        /// Raw SQLCipher key bytes when the durable store is encrypted, else `None`. Not threaded in
        /// the production S2 wiring (always `None`); tests set it so the derived-root source works
        /// deterministically on hosts without an OS key store.
        db_key: Option<Zeroizing<Vec<u8>>>,
    },
    /// wp16 P3b — Postgres-backed: the encrypted credential **blobs** live in the shared
    /// `provider_credentials` DB table (so every cluster node resolves the same credentials) instead
    /// of the `provider-credentials.enc.json` file. The wp13 crypto envelope + root-key resolution are
    /// unchanged — the root key still resolves from `data_dir` (the sealed root /
    /// `CHANCELA_CREDENTIAL_KEY_FILE` source); only the ciphertext storage moves. `db_key` is always
    /// `None` here — Postgres has no SQLCipher-derived key.
    Db {
        store: Store,
        data_dir: PathBuf,
        db_key: Option<Zeroizing<Vec<u8>>>,
    },
}

/// The provider-credential store wired into [`crate::AppState`]: the loaded encrypted records plus a
/// lazily-resolved handle to the S1 crypto core. Cloning shares nothing — it is held behind an `Arc`
/// in `AppState`, so the interior locks are the single shared state.
pub struct ProviderCredentialStore {
    backing: Backing,
    strict: bool,
    /// Loaded records, or the reason the sidecar was rejected (fail-closed on `Some`).
    records: Mutex<Result<RecordMap, String>>,
    /// Cache of a successfully resolved crypto core. A failed resolution is retried on the next op so
    /// a transiently-unavailable key source is never latched into a permanent empty state.
    secretstore: Mutex<Option<CredentialSecretStore>>,
}

impl Default for ProviderCredentialStore {
    fn default() -> Self {
        Self {
            backing: Backing::InMemory,
            strict: false,
            records: Mutex::new(Ok(RecordMap::new())),
            secretstore: Mutex::new(None),
        }
    }
}

impl fmt::Debug for ProviderCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record_count = self
            .records
            .lock()
            .ok()
            .map(|r| r.as_ref().map(|m| m.len()).map_err(|_| ()));
        f.debug_struct("ProviderCredentialStore")
            .field("persisted", &!matches!(self.backing, Backing::InMemory))
            .field("strict", &self.strict)
            .field("records", &record_count)
            .finish()
    }
}

impl ProviderCredentialStore {
    /// Load the credential sidecar from `data_dir` (read-only-friendly: no key file is created and no
    /// root is resolved here). A missing sidecar is an empty store; a corrupt/unknown-schema sidecar
    /// is recorded so every later op fails closed. `strict` mirrors S1's strict credential storage.
    pub fn load(data_dir: &Path, strict: bool) -> Self {
        Self::load_inner(data_dir, None, strict)
    }

    fn load_inner(data_dir: &Path, db_key: Option<Zeroizing<Vec<u8>>>, strict: bool) -> Self {
        let sidecar = data_dir.join(CREDENTIAL_SIDECAR_FILE);
        let records = match load_sidecar(&sidecar) {
            Ok(records) => Ok(records),
            Err(reason) => {
                eprintln!(
                    "warning: {reason}; the provider-credential store is failing closed until the \
                     sidecar is repaired"
                );
                Err(reason)
            }
        };
        Self {
            backing: Backing::DataDir {
                sidecar,
                data_dir: data_dir.to_path_buf(),
                db_key,
            },
            strict,
            records: Mutex::new(records),
            secretstore: Mutex::new(None),
        }
    }

    /// wp16 P3b — load a Postgres-backed credential store: the encrypted blobs come from (and persist
    /// to) the shared `provider_credentials` DB table instead of the file sidecar, so every cluster
    /// node resolves the same credentials. Root-key resolution is unchanged (it still uses `data_dir`
    /// / `CHANCELA_CREDENTIAL_KEY_FILE`; there is no SQLCipher-derived key on Postgres). A DB read
    /// error or a malformed blob records the reason so every later op fails closed, exactly like a
    /// corrupt file sidecar.
    pub fn load_db_backed(store: Store, data_dir: &Path, strict: bool) -> Self {
        let records = match load_records_from_db(&store) {
            Ok(records) => Ok(records),
            Err(reason) => {
                eprintln!(
                    "warning: {reason}; the provider-credential store is failing closed until the \
                     durable records are repaired"
                );
                Err(reason)
            }
        };
        Self {
            backing: Backing::Db {
                store,
                data_dir: data_dir.to_path_buf(),
                db_key: None,
            },
            strict,
            records: Mutex::new(records),
            secretstore: Mutex::new(None),
        }
    }

    /// Whether strict credential storage is enabled for this store.
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Metadata-only status of the credential root-key source. This never creates a root envelope,
    /// unwraps a root, decrypts a credential field, or returns key material.
    pub(crate) fn key_status(&self) -> CredentialKeyReadOnlyStatus {
        let cached = match self.secretstore.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                return CredentialKeyReadOnlyStatus::unavailable(
                    CredentialKeyStatusFailure::StoreUnavailable,
                );
            }
        };
        if let Some(store) = cached {
            return store.read_only_status();
        }

        match &self.backing {
            Backing::InMemory => {
                CredentialKeyReadOnlyStatus::unavailable(CredentialKeyStatusFailure::NoKeySource)
            }
            Backing::DataDir {
                data_dir, db_key, ..
            }
            | Backing::Db {
                data_dir, db_key, ..
            } => crate::secretstore::inspect_key_source_read_only(data_dir, db_key.is_some()),
        }
    }

    /// Resolve (and cache) the S1 crypto core, creating the OS-sealed root on first use. Fails closed
    /// with [`SecretStoreError::NoKeySource`] when no root key is available.
    fn secretstore(&self) -> Result<CredentialSecretStore, ProviderCredentialError> {
        let mut slot = self
            .secretstore
            .lock()
            .map_err(|_| ProviderCredentialError::Poisoned)?;
        if let Some(store) = slot.as_ref() {
            return Ok(store.clone());
        }
        let (data_dir, db_key) = match &self.backing {
            Backing::DataDir {
                data_dir, db_key, ..
            }
            | Backing::Db {
                data_dir, db_key, ..
            } => (data_dir.as_path(), db_key.as_ref()),
            Backing::InMemory => return Err(SecretStoreError::NoKeySource.into()),
        };
        let store = CredentialSecretStore::resolve(
            data_dir,
            db_key.map(|key| key.as_slice()),
            self.strict,
        )?;
        *slot = Some(store.clone());
        Ok(store)
    }

    /// The resolved protection level, or a fail-closed error when no key source is available. Surfaced
    /// by the status API (S4) so the UI can label the at-rest guarantee honestly.
    pub fn protection_level(&self) -> Result<ProtectionLevel, ProviderCredentialError> {
        Ok(self.secretstore()?.protection_level())
    }

    /// Where the resolved credential root key came from, or a fail-closed error when none is
    /// available. Non-secret; surfaced by the status API (S4).
    pub fn key_source(&self) -> Result<CredentialKeySource, ProviderCredentialError> {
        Ok(self.secretstore()?.key_source().clone())
    }

    fn with_records<T>(
        &self,
        f: impl FnOnce(&mut RecordMap) -> Result<T, ProviderCredentialError>,
    ) -> Result<T, ProviderCredentialError> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| ProviderCredentialError::Poisoned)?;
        match guard.as_mut() {
            Ok(records) => f(records),
            Err(reason) => Err(ProviderCredentialError::CorruptSidecar(reason.clone())),
        }
    }

    /// Write a set of secret fields into the `entry_id` entry of `(mode, provider_id)`, removing every
    /// field named in `clear`. Fields not in `set` and not in `clear` are left unchanged. When
    /// `metadata` is `Some`, the entry's non-secret metadata is overwritten wholesale. An entry left
    /// with no fields is dropped; a record left with no entries is dropped. Fails closed (nothing
    /// persisted) on an unresolved key source, a strict-mode refusal, or a corrupt sidecar.
    pub fn put_entry(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        entry_id: &str,
        metadata: Option<EntryMetadata>,
        set: Vec<(&'static str, Zeroizing<String>)>,
        clear: &[&str],
    ) -> Result<(), ProviderCredentialError> {
        for (field, _) in &set {
            reject_unknown_field(mode, field)?;
        }
        for field in clear {
            reject_unknown_field(mode, field)?;
        }

        // Wrap all fields BEFORE taking the records lock so a strict-mode refusal or key failure never
        // leaves a half-applied record. The AAD binds the entry_id (see secretstore::build_aad).
        let mut wrapped: Vec<(&'static str, StoredCredentialField)> = Vec::with_capacity(set.len());
        let mut write_version = None;
        if !set.is_empty() {
            let store = self.secretstore()?;
            for (field, value) in &set {
                let envelope = store.wrap(
                    mode.as_str(),
                    provider_id,
                    entry_id,
                    field,
                    value.as_bytes(),
                )?;
                // M2: never persist a plaintext `last4` hint. For genuinely-secret fields (passphrase,
                // password, client_secret, access_token, secret, PFX blob) a ≤4-char hint can be the
                // whole secret (e.g. a 4-digit PIN) sitting in cleartext beside the ciphertext. The
                // status/metadata surfaces report a field as configured without any plaintext hint.
                wrapped.push((
                    field,
                    StoredCredentialField {
                        envelope,
                        last4: None,
                    },
                ));
            }
            write_version = Some(store.current_key_version());
        }

        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        self.with_records(|records| {
            let mut next = records.clone();
            let mut record = next
                .get(&key)
                .cloned()
                .unwrap_or_else(|| EncryptedCredentialRecord::empty(mode, provider_id));
            let now = now_rfc3339();

            let idx = match record.entries.iter().position(|e| e.id == entry_id) {
                Some(i) => i,
                None => {
                    record.entries.push(CredentialEntry {
                        id: entry_id.to_owned(),
                        label: String::new(),
                        priority: 0,
                        enabled: true,
                        endpoint: None,
                        selectors: EntrySelectors::new(),
                        fields: BTreeMap::new(),
                        created_at: now.clone(),
                        updated_at: now.clone(),
                    });
                    record.entries.len() - 1
                }
            };
            {
                let entry = &mut record.entries[idx];
                if let Some(meta) = metadata {
                    entry.label = meta.label;
                    entry.priority = meta.priority;
                    entry.enabled = meta.enabled;
                    entry.endpoint = meta.endpoint;
                    entry.selectors = meta.selectors;
                }
                for field in clear {
                    entry.fields.remove(*field);
                }
                for (field, stored) in wrapped {
                    entry.fields.insert(field.to_owned(), stored);
                }
                entry.updated_at = now;
            }

            record.entries.retain(|e| !e.fields.is_empty());
            if let Some(version) = write_version {
                record.key_version = version;
            }
            record.sort_entries();
            if record.entries.is_empty() {
                next.remove(&key);
            } else {
                next.insert(key.clone(), record);
            }
            self.persist(&next)?;
            *records = next;
            Ok(())
        })
    }

    /// Flat convenience write: set/clear fields on the single [`DEFAULT_ENTRY_ID`] entry of
    /// `(mode, provider_id)`. Metadata is left untouched. Kept for callers that do not need the
    /// multi-entry surface.
    pub fn put(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        set: Vec<(&'static str, Zeroizing<String>)>,
        clear: &[&str],
    ) -> Result<(), ProviderCredentialError> {
        self.put_entry(mode, provider_id, DEFAULT_ENTRY_ID, None, set, clear)
    }

    /// Remove one entry from `(mode, provider_id)`. Returns whether an entry was present. A record left
    /// with no entries is dropped. Needs no key material; still fails closed on a corrupt sidecar.
    pub fn delete_entry(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        entry_id: &str,
    ) -> Result<bool, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        self.with_records(|records| {
            let mut next = records.clone();
            let Some(record) = next.get_mut(&key) else {
                return Ok(false);
            };
            let before = record.entries.len();
            record.entries.retain(|e| e.id != entry_id);
            if record.entries.len() == before {
                return Ok(false);
            }
            if record.entries.is_empty() {
                next.remove(&key);
            }
            self.persist(&next)?;
            *records = next;
            Ok(true)
        })
    }

    /// Atomically re-prioritise the entries of `(mode, provider_id)`: each id in `order` receives its
    /// position as its new priority, applied under a **single** records-lock acquisition and persisted
    /// once, so a reorder is all-or-nothing (L2). This replaces a per-entry write loop that could leave
    /// a partially-applied ordering if a later write failed. Ids in `order` absent from the record are
    /// ignored and entries not named keep their priority; callers validate the permutation up-front.
    /// Metadata-only: needs no key material, but still fails closed on a poisoned lock or persist error.
    pub fn reorder_entries(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        order: &[String],
    ) -> Result<(), ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        self.with_records(|records| {
            let mut next = records.clone();
            let Some(record) = next.get_mut(&key) else {
                return Ok(());
            };
            let now = now_rfc3339();
            for (index, id) in order.iter().enumerate() {
                if let Some(entry) = record.entries.iter_mut().find(|e| &e.id == id) {
                    entry.priority = index as i32;
                    entry.updated_at = now.clone();
                }
            }
            record.sort_entries();
            self.persist(&next)?;
            *records = next;
            Ok(())
        })
    }

    /// Decrypt the flat [`DEFAULT_ENTRY_ID`] entry of `(mode, provider_id)`, or `Ok(None)` when no
    /// such entry exists. Administrative/test read path: it authenticates ciphertext but does not
    /// apply the runtime strict/protection guard. Runtime callers must use [`Self::read_runtime`].
    pub fn read(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Option<DecryptedCredentialRecord>, ProviderCredentialError> {
        self.read_inner(mode, provider_id, false)
    }

    /// Runtime provider-assembly read of the flat entry. It refuses plaintext use before decrypting
    /// any field when strict credential storage is enabled and the resolved protection level is not
    /// confidential. A corrupt sidecar or key failure also fails closed; callers must not fall back to
    /// env/DI after an error from this method.
    pub fn read_runtime(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Option<DecryptedCredentialRecord>, ProviderCredentialError> {
        self.read_inner(mode, provider_id, true)
    }

    fn read_inner(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        enforce_runtime_guard: bool,
    ) -> Result<Option<DecryptedCredentialRecord>, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        let record = self.with_records(|records| Ok(records.get(&key).cloned()))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let Some(entry) = record.default_entry().cloned() else {
            return Ok(None);
        };
        let store = self.secretstore()?;
        if enforce_runtime_guard
            && self.strict
            && store.protection_level() != ProtectionLevel::Confidential
        {
            return Err(ProviderCredentialError::RuntimeStrictModeUnprotected {
                level: store.protection_level(),
            });
        }
        let mut fields = BTreeMap::new();
        for (name, stored) in &entry.fields {
            let plaintext = store.unwrap(
                mode.as_str(),
                provider_id,
                &entry.id,
                name,
                &stored.envelope,
            )?;
            fields.insert(name.clone(), plaintext);
        }
        Ok(Some(DecryptedCredentialRecord {
            mode,
            provider_id: provider_id.to_owned(),
            fields,
        }))
    }

    /// Decrypt every entry of the `(mode, provider_id)` record in priority order, or an empty vec when
    /// no record exists. Administrative read path (no runtime guard); it authenticates every field, so
    /// a relocated/tampered ciphertext fails closed with [`SecretStoreError::Crypto`]. Runtime signing
    /// callers must use [`Self::read_entries_runtime`] so the strict-mode protection guard applies.
    pub fn read_entries(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Vec<DecryptedCredentialEntry>, ProviderCredentialError> {
        self.read_entries_inner(mode, provider_id, false)
    }

    /// Runtime multi-entry read for the credential-resolution/failover driver. Mirrors
    /// [`Self::read_runtime`]: it refuses plaintext use — before decrypting **any** field — when strict
    /// credential storage is enabled and the resolved protection level has degraded below confidential
    /// (e.g. to obfuscation). A corrupt sidecar or key failure also fails closed; callers must not fall
    /// back to env/DI after an error from this method.
    pub fn read_entries_runtime(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Vec<DecryptedCredentialEntry>, ProviderCredentialError> {
        self.read_entries_inner(mode, provider_id, true)
    }

    fn read_entries_inner(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        enforce_runtime_guard: bool,
    ) -> Result<Vec<DecryptedCredentialEntry>, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        let record = self.with_records(|records| Ok(records.get(&key).cloned()))?;
        let Some(record) = record else {
            return Ok(Vec::new());
        };
        let store = self.secretstore()?;
        if enforce_runtime_guard
            && self.strict
            && store.protection_level() != ProtectionLevel::Confidential
        {
            return Err(ProviderCredentialError::RuntimeStrictModeUnprotected {
                level: store.protection_level(),
            });
        }
        let mut out = Vec::with_capacity(record.entries.len());
        for entry in &record.entries {
            let mut fields = BTreeMap::new();
            for (name, stored) in &entry.fields {
                let plaintext = store.unwrap(
                    mode.as_str(),
                    provider_id,
                    &entry.id,
                    name,
                    &stored.envelope,
                )?;
                fields.insert(name.clone(), plaintext);
            }
            out.push(DecryptedCredentialEntry {
                entry_id: entry.id.clone(),
                label: entry.label.clone(),
                priority: entry.priority,
                enabled: entry.enabled,
                endpoint: entry.endpoint.clone(),
                selectors: entry.selectors.clone(),
                fields,
            });
        }
        Ok(out)
    }

    /// Remove the entire `(mode, provider_id)` record. Returns whether a record was present. Needs no
    /// key material (it only deletes ciphertext), but still fails closed on a corrupt sidecar.
    pub fn clear_record(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<bool, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        self.with_records(|records| {
            let mut next = records.clone();
            let removed = next.remove(&key).is_some();
            if removed {
                self.persist(&next)?;
                *records = next;
            }
            Ok(removed)
        })
    }

    /// Non-secret status of every stored record (the flat entry's configured field names), for the
    /// status API (S4). Never decrypts and never returns ciphertext or any plaintext hint.
    pub fn statuses(&self) -> Result<Vec<CredentialRecordStatus>, ProviderCredentialError> {
        self.with_records(|records| {
            Ok(records
                .values()
                .filter_map(|record| {
                    let mode = CredentialMode::from_wire(&record.mode)?;
                    let fields = record
                        .default_entry()
                        .map(|entry| {
                            entry
                                .fields
                                .iter()
                                .map(|(name, stored)| (name.clone(), stored.last4.clone()))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(CredentialRecordStatus {
                        mode,
                        provider_id: record.provider_id.clone(),
                        key_version: record.key_version,
                        fields,
                    })
                })
                .collect())
        })
    }

    /// Non-secret, **non-decrypting** metadata for every entry of `(mode, provider_id)`, in the
    /// stored priority order (plan §3 management list / write-response bodies). Returns an empty vec
    /// when no record exists. Never decrypts and never returns ciphertext or plaintext, so it needs
    /// no key source; still fails closed on a corrupt sidecar.
    pub fn entry_metadata(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Vec<CredentialEntryMetadataView>, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        self.with_records(|records| {
            let Some(record) = records.get(&key) else {
                return Ok(Vec::new());
            };
            Ok(record
                .entries
                .iter()
                .map(|entry| CredentialEntryMetadataView {
                    entry_id: entry.id.clone(),
                    label: entry.label.clone(),
                    priority: entry.priority,
                    enabled: entry.enabled,
                    endpoint: entry.endpoint.clone(),
                    selectors: entry.selectors.clone(),
                    fields: entry
                        .fields
                        .iter()
                        .map(|(name, stored)| (name.clone(), stored.last4.clone()))
                        .collect(),
                    created_at: entry.created_at.clone(),
                    updated_at: entry.updated_at.clone(),
                })
                .collect())
        })
    }

    fn persist(&self, records: &RecordMap) -> Result<(), ProviderCredentialError> {
        match &self.backing {
            Backing::DataDir { sidecar, .. } => write_sidecar_atomic(sidecar, records),
            // wp16 P3b: reconcile the encrypted blobs into the shared `provider_credentials` table.
            Backing::Db { store, .. } => write_records_to_db(store, records),
            Backing::InMemory => Ok(()),
        }
    }

    /// wp16 P3b — re-read the encrypted credential records from the shared DB table into memory (a
    /// follower reloading after a leader's credential write). A no-op for the file / in-memory
    /// backings. A read failure fails the store closed (records ⇒ the error reason) rather than
    /// silently emptying it, matching the corrupt-sidecar discipline. Only the Postgres follower
    /// change-feed calls this.
    #[cfg(feature = "postgres")]
    pub(crate) fn reload_from_db(&self) {
        let Backing::Db { store, .. } = &self.backing else {
            return;
        };
        let refreshed = match load_records_from_db(store) {
            Ok(records) => Ok(records),
            Err(reason) => {
                eprintln!(
                    "warning: {reason}; the provider-credential store is failing closed until the \
                     durable records are repaired"
                );
                Err(reason)
            }
        };
        if let Ok(mut guard) = self.records.lock() {
            *guard = refreshed;
        }
    }

    /// Test-only constructor that pre-seeds the DB key so the derived-root source resolves
    /// deterministically on hosts without an OS key store.
    #[cfg(test)]
    pub(crate) fn load_with_db_key(data_dir: &Path, db_key: &[u8], strict: bool) -> Self {
        Self::load_inner(data_dir, Some(Zeroizing::new(db_key.to_vec())), strict)
    }

    /// Test-only DB-backed constructor that pre-seeds the derived-root DB key so the crypto core
    /// resolves deterministically on hosts without an OS key store — the DB-blob analogue of
    /// [`load_with_db_key`](Self::load_with_db_key). Used by the `#[ignore]` live-Postgres credential
    /// round-trip so the wp13 envelope is exercised against the real `provider_credentials` table.
    #[cfg(all(test, feature = "postgres"))]
    pub(crate) fn load_db_backed_with_db_key(
        store: Store,
        data_dir: &Path,
        db_key: &[u8],
        strict: bool,
    ) -> Self {
        let records = load_records_from_db(&store).unwrap_or_else(|_| RecordMap::new());
        Self {
            backing: Backing::Db {
                store,
                data_dir: data_dir.to_path_buf(),
                db_key: Some(Zeroizing::new(db_key.to_vec())),
            },
            strict,
            records: Mutex::new(Ok(records)),
            secretstore: Mutex::new(None),
        }
    }

    /// Test-only in-memory store with an explicit strict flag and no key source.
    #[cfg(test)]
    pub(crate) fn in_memory_with_strict(strict: bool) -> Self {
        Self {
            backing: Backing::InMemory,
            strict,
            records: Mutex::new(Ok(RecordMap::new())),
            secretstore: Mutex::new(None),
        }
    }
}

fn reject_unknown_field(mode: CredentialMode, field: &str) -> Result<(), ProviderCredentialError> {
    if mode.is_valid_field(field) {
        Ok(())
    } else {
        Err(ProviderCredentialError::UnknownField {
            mode: mode.as_str(),
            field: field.to_owned(),
        })
    }
}

/// The current UTC time as an RFC 3339 string, or empty on the (unreachable) formatting failure.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// serde default for [`CredentialEntry::enabled`].
fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let seq = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "chancela-credpersist-{name}-{}-{seq}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    // A fixed DB key so every store built over the same dir derives (on non-Windows) an identical
    // root, and reload sees the same CMK. On Windows the OS DPAPI protector wins and persists the
    // root to the dir, so reload is deterministic there too.
    const TEST_DB_KEY: &[u8] = b"t77-s2-unit-test-db-key-0123456789";

    fn store(dir: &Path) -> ProviderCredentialStore {
        ProviderCredentialStore::load_with_db_key(dir, TEST_DB_KEY, false)
    }

    fn in_memory_store_with_source(
        source: CredentialKeySource,
        db_encrypted: bool,
        strict: bool,
    ) -> ProviderCredentialStore {
        ProviderCredentialStore {
            backing: Backing::InMemory,
            strict,
            records: Mutex::new(Ok(RecordMap::new())),
            secretstore: Mutex::new(Some(CredentialSecretStore::for_test_source(
                source,
                db_encrypted,
                strict,
            ))),
        }
    }

    fn zeroizing(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    fn metadata(
        label: &str,
        priority: i32,
        enabled: bool,
        endpoint: Option<&str>,
    ) -> EntryMetadata {
        EntryMetadata {
            label: label.to_owned(),
            priority,
            enabled,
            endpoint: endpoint.map(str::to_owned),
            selectors: EntrySelectors::new(),
        }
    }

    #[test]
    fn put_reload_round_trip_unwraps_original_secret() {
        let dir = TempDir::new("round-trip");
        let secret = "sk_live_amelia_marques_9f8e7d6c5b4a";
        let client_id = "client-encosto-estrategico";
        {
            let store = store(dir.path());
            store
                .put(
                    CredentialMode::CscQtsp,
                    "encosto-estrategico",
                    CscCredentialFields {
                        client_id: Some(zeroizing(client_id)),
                        client_secret: Some(zeroizing(secret)),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put");
        }

        // A fresh store instance reloads purely from the sidecar on disk.
        let reloaded = store(dir.path());
        let record = reloaded
            .read(CredentialMode::CscQtsp, "encosto-estrategico")
            .expect("read")
            .expect("record present");
        assert_eq!(
            record.fields.get(FIELD_CLIENT_SECRET).map(|z| z.as_str()),
            Some(secret)
        );
        assert_eq!(
            record.fields.get(FIELD_CLIENT_ID).map(|z| z.as_str()),
            Some(client_id)
        );
    }

    #[test]
    fn sidecar_never_contains_plaintext_secret() {
        let dir = TempDir::new("no-plaintext");
        let secret = "top-secret-value-abc123xyz789";
        let store = store(dir.path());
        store
            .put(
                CredentialMode::Scap,
                "",
                ScapCredentialFields {
                    application_id: Some(zeroizing("app-42")),
                    secret: Some(zeroizing(secret)),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");

        let bytes = std::fs::read(dir.path().join(CREDENTIAL_SIDECAR_FILE)).expect("sidecar bytes");
        let text = String::from_utf8(bytes).expect("utf8 sidecar");
        assert!(
            !text.contains(secret),
            "the sidecar must not contain the plaintext secret"
        );
        assert!(!text.contains("app-42"), "identifiers are encrypted too");
        // M2: no plaintext `last4` hint is persisted — not even the secret's last 4 chars.
        assert!(
            !text.contains("z789"),
            "the sidecar must not persist any plaintext hint of the secret"
        );
        assert!(!text.contains("last4"), "no last4 field is written at all");
    }

    #[test]
    fn multiple_entries_are_ordered_by_priority_with_distinct_secrets() {
        let dir = TempDir::new("ordering");
        let store = store(dir.path());
        // Insert out of priority order; entries sort ascending by (priority, id).
        store
            .put_entry(
                CredentialMode::CscQtsp,
                "p",
                "z-entry",
                Some(metadata("", 5, true, None)),
                CscCredentialFields {
                    client_secret: Some(zeroizing("secret-five")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put z");
        store
            .put_entry(
                CredentialMode::CscQtsp,
                "p",
                "a-entry",
                Some(metadata("primary", 1, false, Some("https://csc.example/a"))),
                CscCredentialFields {
                    client_secret: Some(zeroizing("secret-one")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put a");

        let entries = store
            .read_entries(CredentialMode::CscQtsp, "p")
            .expect("read entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_id, "a-entry", "priority 1 sorts first");
        assert_eq!(entries[1].entry_id, "z-entry");
        assert_eq!(entries[0].priority, 1);
        assert!(!entries[0].enabled);
        assert_eq!(entries[0].label, "primary");
        assert_eq!(
            entries[0].endpoint.as_deref(),
            Some("https://csc.example/a")
        );
        assert_eq!(
            entries[0]
                .fields
                .get(FIELD_CLIENT_SECRET)
                .map(|z| z.as_str()),
            Some("secret-one")
        );
        assert_eq!(
            entries[1]
                .fields
                .get(FIELD_CLIENT_SECRET)
                .map(|z| z.as_str()),
            Some("secret-five")
        );
    }

    #[test]
    fn relocating_a_ciphertext_between_entries_fails_authentication() {
        let dir = TempDir::new("relocate");
        {
            let store = store(dir.path());
            store
                .put_entry(
                    CredentialMode::CscQtsp,
                    "p",
                    "entry-a",
                    Some(metadata("A", 0, true, None)),
                    CscCredentialFields {
                        client_secret: Some(zeroizing("secret-a-1111")),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put a");
            store
                .put_entry(
                    CredentialMode::CscQtsp,
                    "p",
                    "entry-b",
                    Some(metadata("B", 1, true, None)),
                    CscCredentialFields {
                        client_secret: Some(zeroizing("secret-b-2222")),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put b");
        }

        // Tamper the on-disk sidecar: copy entry-a's client_secret envelope into entry-b's slot.
        let path = dir.path().join(CREDENTIAL_SIDECAR_FILE);
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read sidecar")).expect("parse");
        let records = file["records"].as_array_mut().expect("records array");
        let record = records
            .iter_mut()
            .find(|r| r["provider_id"] == "p")
            .expect("record p");
        let entries = record["entries"].as_array_mut().expect("entries array");
        let a_secret = entries
            .iter()
            .find(|e| e["id"] == "entry-a")
            .expect("entry-a")["fields"]["client_secret"]
            .clone();
        for entry in entries.iter_mut() {
            if entry["id"] == "entry-b" {
                entry["fields"]["client_secret"] = a_secret.clone();
            }
        }
        std::fs::write(&path, serde_json::to_vec_pretty(&file).expect("serialize")).expect("write");

        // Reloading + decrypting must fail authentication for the relocated ciphertext.
        // (`read_entries` yields non-`Debug` plaintext, so match rather than `expect_err`.)
        let reloaded = store(dir.path());
        let err = match reloaded.read_entries(CredentialMode::CscQtsp, "p") {
            Err(err) => err,
            Ok(_) => panic!("a relocated ciphertext must fail authentication"),
        };
        assert!(
            matches!(
                err,
                ProviderCredentialError::Secret(SecretStoreError::Crypto(_))
            ),
            "expected a crypto auth failure, got {err:?}"
        );
    }

    #[test]
    fn pkcs12_entry_round_trips_binary_pfx_via_base64() {
        let dir = TempDir::new("pkcs12");
        // Arbitrary non-UTF-8 binary "PFX" bytes (0..=255 twice).
        let pfx: Vec<u8> = (0u16..512).map(|i| (i % 256) as u8).collect();
        let pfx_b64 = B64.encode(&pfx);
        let passphrase = "pfx-pass-amelia-9931";
        {
            let store = store(dir.path());
            store
                .put_entry(
                    CredentialMode::LocalPkcs12,
                    "local",
                    "signer-1",
                    Some(metadata("Signer", 0, true, None)),
                    Pkcs12CredentialFields {
                        pfx_der_b64: Some(zeroizing(&pfx_b64)),
                        passphrase: Some(zeroizing(passphrase)),
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put pkcs12");
        }

        // Neither the base64 PFX nor the passphrase appears in plaintext on disk.
        let bytes = std::fs::read(dir.path().join(CREDENTIAL_SIDECAR_FILE)).expect("sidecar bytes");
        let text = String::from_utf8(bytes).expect("utf8 sidecar");
        assert!(!text.contains(&pfx_b64), "encrypted PFX must not leak");
        assert!(!text.contains(passphrase), "passphrase must not leak");

        let reloaded = store(dir.path());
        let entries = reloaded
            .read_entries(CredentialMode::LocalPkcs12, "local")
            .expect("read entries");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.entry_id, "signer-1");
        let recovered_b64 = entry
            .fields
            .get(FIELD_PKCS12_PFX)
            .expect("pfx field")
            .as_str();
        let recovered = B64.decode(recovered_b64).expect("valid base64");
        assert_eq!(recovered, pfx, "binary PFX round-trips exactly");
        assert_eq!(
            entry
                .fields
                .get(FIELD_PKCS12_PASSPHRASE)
                .map(|z| z.as_str()),
            Some(passphrase)
        );
    }

    #[test]
    fn delete_entry_removes_only_the_named_entry() {
        let dir = TempDir::new("delete-entry");
        let store = store(dir.path());
        for id in ["keep", "drop"] {
            store
                .put_entry(
                    CredentialMode::CscQtsp,
                    "p",
                    id,
                    Some(metadata(id, 0, true, None)),
                    CscCredentialFields {
                        client_secret: Some(zeroizing("s")),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put");
        }
        assert!(
            store
                .delete_entry(CredentialMode::CscQtsp, "p", "drop")
                .expect("delete")
        );
        assert!(
            !store
                .delete_entry(CredentialMode::CscQtsp, "p", "missing")
                .expect("delete missing")
        );
        let entries = store
            .read_entries(CredentialMode::CscQtsp, "p")
            .expect("read");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_id, "keep");
    }

    #[test]
    fn key_version_is_recorded_on_write() {
        let dir = TempDir::new("key-version");
        let store = store(dir.path());
        store
            .put(
                CredentialMode::Scap,
                "",
                ScapCredentialFields {
                    secret: Some(zeroizing("x")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");
        let statuses = store.statuses().expect("statuses");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].key_version, 1);
    }

    #[test]
    fn provider_credential_runtime_read_refuses_strict_non_confidential_protection() {
        let writer = in_memory_store_with_source(CredentialKeySource::OperatorEnv, false, false);
        writer
            .put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(zeroizing("cmd-runtime-fixture")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted record");
        let records = writer.records.lock().expect("records").clone();
        let reader = ProviderCredentialStore {
            backing: Backing::InMemory,
            strict: true,
            records: Mutex::new(records),
            secretstore: Mutex::new(Some(CredentialSecretStore::for_test_source(
                CredentialKeySource::OperatorEnv,
                false,
                true,
            ))),
        };

        let err = match reader.read_runtime(CredentialMode::Cmd, "") {
            Err(err) => err,
            Ok(_) => panic!("strict runtime read must refuse obfuscation protection"),
        };
        assert!(matches!(
            err,
            ProviderCredentialError::RuntimeStrictModeUnprotected {
                level: ProtectionLevel::Obfuscation
            }
        ));
    }

    #[test]
    fn read_entries_runtime_refuses_strict_non_confidential_protection() {
        // M1: the multi-entry failover read used by the credential-resolution driver must apply the
        // same strict-mode protection guard as the flat runtime read — refusing to decrypt any stored
        // entry when strict storage is on but protection has degraded to obfuscation.
        let writer = in_memory_store_with_source(CredentialKeySource::OperatorEnv, false, false);
        writer
            .put_entry(
                CredentialMode::CscQtsp,
                "prov",
                "primary",
                None,
                CscCredentialFields {
                    client_secret: Some(zeroizing("csc-failover-fixture")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("seed encrypted entry");
        let records = writer.records.lock().expect("records").clone();
        let reader = ProviderCredentialStore {
            backing: Backing::InMemory,
            strict: true,
            records: Mutex::new(records),
            secretstore: Mutex::new(Some(CredentialSecretStore::for_test_source(
                CredentialKeySource::OperatorEnv,
                false,
                true,
            ))),
        };

        let err = match reader.read_entries_runtime(CredentialMode::CscQtsp, "prov") {
            Err(err) => err,
            Ok(_) => panic!("strict runtime entries read must refuse obfuscation protection"),
        };
        assert!(matches!(
            err,
            ProviderCredentialError::RuntimeStrictModeUnprotected {
                level: ProtectionLevel::Obfuscation
            }
        ));

        // The administrative (unguarded) read still authenticates and returns the entry, proving the
        // refusal is the runtime guard and not a decrypt failure.
        let entries = reader
            .read_entries(CredentialMode::CscQtsp, "prov")
            .expect("admin read is unguarded");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn none_field_leaves_existing_unchanged_and_clear_removes_it() {
        let dir = TempDir::new("partial-update");
        let store = store(dir.path());
        // Seed client_id + client_secret.
        store
            .put(
                CredentialMode::CscQtsp,
                "p",
                CscCredentialFields {
                    client_id: Some(zeroizing("id-1")),
                    client_secret: Some(zeroizing("secret-1")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put seed");

        // Write ONLY access_token (client_id/client_secret are None → untouched).
        store
            .put(
                CredentialMode::CscQtsp,
                "p",
                CscCredentialFields {
                    access_token: Some(zeroizing("tok-1")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put token");

        let record = store
            .read(CredentialMode::CscQtsp, "p")
            .expect("read")
            .expect("present");
        assert_eq!(
            record.fields.get(FIELD_CLIENT_ID).map(|z| z.as_str()),
            Some("id-1")
        );
        assert_eq!(
            record.fields.get(FIELD_CLIENT_SECRET).map(|z| z.as_str()),
            Some("secret-1")
        );
        assert_eq!(
            record.fields.get(FIELD_ACCESS_TOKEN).map(|z| z.as_str()),
            Some("tok-1")
        );

        // Clear just client_secret; the other two survive.
        store
            .put(
                CredentialMode::CscQtsp,
                "p",
                Vec::new(),
                &[FIELD_CLIENT_SECRET],
            )
            .expect("clear field");
        let record = store
            .read(CredentialMode::CscQtsp, "p")
            .expect("read")
            .expect("present");
        assert!(!record.fields.contains_key(FIELD_CLIENT_SECRET));
        assert!(record.fields.contains_key(FIELD_CLIENT_ID));
        assert!(record.fields.contains_key(FIELD_ACCESS_TOKEN));
    }

    #[test]
    fn clearing_all_fields_drops_the_record() {
        let dir = TempDir::new("drop-record");
        let store = store(dir.path());
        store
            .put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(zeroizing("app")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");
        store
            .put(CredentialMode::Cmd, "", Vec::new(), &[FIELD_APPLICATION_ID])
            .expect("clear");
        assert!(store.read(CredentialMode::Cmd, "").expect("read").is_none());

        // And the whole-record delete is a no-op that reports absence now.
        assert!(
            !store
                .clear_record(CredentialMode::Cmd, "")
                .expect("clear record")
        );
    }

    #[test]
    fn clear_record_removes_and_persists() {
        let dir = TempDir::new("clear-record");
        {
            let store = store(dir.path());
            store
                .put(
                    CredentialMode::Cmd,
                    "",
                    CmdCredentialFields {
                        application_id: Some(zeroizing("app")),
                        http_basic_password: Some(zeroizing("pw")),
                        ..Default::default()
                    }
                    .into_set_pairs(),
                    &[],
                )
                .expect("put");
            assert!(store.clear_record(CredentialMode::Cmd, "").expect("clear"));
        }
        let reloaded = store(dir.path());
        assert!(
            reloaded
                .read(CredentialMode::Cmd, "")
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn corrupt_sidecar_fails_closed_not_empty() {
        let dir = TempDir::new("corrupt");
        std::fs::write(
            dir.path().join(CREDENTIAL_SIDECAR_FILE),
            b"{ not valid json ",
        )
        .expect("write corrupt");
        let store = store(dir.path());
        // Reads, writes, clears, and status all refuse rather than reporting an empty config.
        assert!(matches!(
            store.read(CredentialMode::Cmd, ""),
            Err(ProviderCredentialError::CorruptSidecar(_))
        ));
        assert!(matches!(
            store.put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(zeroizing("app")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            ),
            Err(ProviderCredentialError::CorruptSidecar(_))
        ));
        assert!(matches!(
            store.statuses(),
            Err(ProviderCredentialError::CorruptSidecar(_))
        ));
    }

    #[test]
    fn failed_sidecar_write_does_not_update_in_memory_records() {
        let dir = TempDir::new("write-fail");
        let store = store(dir.path());
        let sidecar = dir.path().join(CREDENTIAL_SIDECAR_FILE);
        std::fs::create_dir(&sidecar).expect("block sidecar install with directory");

        let err = store
            .put(
                CredentialMode::Scap,
                "",
                ScapCredentialFields {
                    secret: Some(zeroizing("should-not-stick")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect_err("installing over a directory must fail");
        assert!(matches!(err, ProviderCredentialError::Io { .. }));
        assert!(store.statuses().expect("statuses").is_empty());
        assert!(
            store
                .read(CredentialMode::Scap, "")
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn failed_sidecar_clear_does_not_remove_in_memory_record() {
        let dir = TempDir::new("clear-fail");
        let store = store(dir.path());
        store
            .put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(zeroizing("app")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");
        let sidecar = dir.path().join(CREDENTIAL_SIDECAR_FILE);
        std::fs::remove_file(&sidecar).expect("remove sidecar file");
        std::fs::create_dir(&sidecar).expect("block sidecar install with directory");

        let err = store
            .clear_record(CredentialMode::Cmd, "")
            .expect_err("installing over a directory must fail");
        assert!(matches!(err, ProviderCredentialError::Io { .. }));
        assert_eq!(store.statuses().expect("statuses").len(), 1);
        assert!(store.read(CredentialMode::Cmd, "").expect("read").is_some());
    }

    #[test]
    fn unknown_schema_sidecar_fails_closed() {
        let dir = TempDir::new("old-schema");
        std::fs::write(
            dir.path().join(CREDENTIAL_SIDECAR_FILE),
            br#"{"schema_version":99,"type":"provider-credentials","purpose":"signing_provider_credentials_encrypted","records":[]}"#,
        )
        .expect("write");
        let store = store(dir.path());
        assert!(matches!(
            store.statuses(),
            Err(ProviderCredentialError::CorruptSidecar(_))
        ));
    }

    #[test]
    fn missing_sidecar_reads_empty() {
        let dir = TempDir::new("missing");
        let store = store(dir.path());
        assert!(store.read(CredentialMode::Cmd, "").expect("read").is_none());
        assert!(store.statuses().expect("statuses").is_empty());
    }

    #[test]
    fn in_memory_store_fails_closed_on_write() {
        let store = ProviderCredentialStore::default();
        // No persistence, no key source: reads are empty, writes fail closed.
        assert!(store.read(CredentialMode::Cmd, "").expect("read").is_none());
        let err = store
            .put(
                CredentialMode::Cmd,
                "",
                CmdCredentialFields {
                    application_id: Some(zeroizing("app")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect_err("must fail closed");
        assert!(matches!(
            err,
            ProviderCredentialError::Secret(SecretStoreError::NoKeySource)
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let dir = TempDir::new("unknown-field");
        let store = store(dir.path());
        // "secret" is a SCAP field, not a CMD field.
        let err = store
            .put(
                CredentialMode::Cmd,
                "",
                vec![(FIELD_SECRET, zeroizing("x"))],
                &[],
            )
            .expect_err("unknown field");
        assert!(matches!(err, ProviderCredentialError::UnknownField { .. }));
    }

    #[test]
    fn statuses_report_configured_fields_without_plaintext_hint() {
        let dir = TempDir::new("statuses");
        let store = store(dir.path());
        store
            .put(
                CredentialMode::Scap,
                "",
                ScapCredentialFields {
                    secret: Some(zeroizing("abcdef123456")),
                    ..Default::default()
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");
        let statuses = store.statuses().expect("statuses");
        assert_eq!(statuses.len(), 1);
        let status = &statuses[0];
        assert_eq!(status.mode, CredentialMode::Scap);
        let (name, last4) = &status.fields[0];
        // M2: the field is reported as configured, but with NO plaintext last4 hint.
        assert_eq!(name, FIELD_SECRET);
        assert_eq!(last4.as_deref(), None);
    }

    #[test]
    fn short_passphrase_plaintext_absent_from_sidecar() {
        // A 4-char PIN-style passphrase: its entire plaintext must not appear anywhere in the sidecar,
        // including as a last4 hint (which would once have leaked the whole secret).
        let dir = TempDir::new("short-passphrase");
        let store = store(dir.path());
        let pin = "1234";
        store
            .put(
                CredentialMode::LocalPkcs12,
                "amelia",
                Pkcs12CredentialFields {
                    pfx_der_b64: Some(zeroizing(&B64.encode([0xDE, 0xAD, 0xBE, 0xEF]))),
                    passphrase: Some(zeroizing(pin)),
                }
                .into_set_pairs(),
                &[],
            )
            .expect("put");
        let bytes = std::fs::read(dir.path().join(CREDENTIAL_SIDECAR_FILE)).expect("sidecar bytes");
        let text = String::from_utf8(bytes).expect("utf8 sidecar");
        assert!(
            !text.contains(pin),
            "a short passphrase's plaintext must never appear in the sidecar"
        );
        assert!(!text.contains("last4"), "no last4 hint is persisted");
    }
}
