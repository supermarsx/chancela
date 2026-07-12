//! Provider-credential **model** + encrypted **sidecar** persistence (plan t77 §1/§2, slice S2).
//!
//! This module sits on top of the [`crate::secretstore`] crypto core (S1). It owns:
//!
//! - the per-mode credential **model** ([`CmdCredentialFields`] / [`CscCredentialFields`] /
//!   [`ScapCredentialFields`]) whose secret fields are `Option<Zeroizing<String>>` — `None` on a
//!   write means *leave unchanged*, an explicit clear-list removes a field;
//! - the at-rest **record** ([`EncryptedCredentialRecord`]) that stores ONLY
//!   [`SecretEnvelope`](crate::secretstore::SecretEnvelope)s (nonce + ciphertext + key version) plus
//!   non-secret selectors (mode / provider id) and a ≤4-char `last4` hint — **never** a plaintext
//!   secret;
//! - the encrypted **sidecar** file `provider-credentials.enc.json` in the data dir, written with the
//!   same schema-versioned, atomic temp+rename discipline as `attestation::write_seed_file`, plus the
//!   [`ProviderCredentialStore`] read/put/clear operations that wrap/unwrap through the S1 secretstore.
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

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secretstore::{
    CredentialKeySource, CredentialSecretStore, ProtectionLevel, SecretEnvelope, SecretStoreError,
};

/// File name of the encrypted credential sidecar in the data dir.
pub const CREDENTIAL_SIDECAR_FILE: &str = "provider-credentials.enc.json";

/// Schema version of the sidecar envelope. A mismatch fails closed rather than guessing.
const SIDECAR_SCHEMA_VERSION: u32 = 1;
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
}

impl CredentialMode {
    /// The stable wire/AAD string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cmd => "cmd",
            Self::CscQtsp => "csc",
            Self::Scap => "scap",
        }
    }

    /// Parse a mode back from its [`as_str`](Self::as_str) wire form.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "cmd" => Some(Self::Cmd),
            "csc" => Some(Self::CscQtsp),
            "scap" => Some(Self::Scap),
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
        }
    }

    fn is_valid_field(self, field: &str) -> bool {
        self.field_names().contains(&field)
    }
}

// --- Per-mode credential field model -------------------------------------------------------

/// A per-mode set of secret fields to write. Each field is `Some(value)` to set/replace it or `None`
/// to leave the stored value unchanged (removal is a separate clear-list on
/// [`ProviderCredentialStore::put`]). Implemented by the three mode structs below.
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

/// One encrypted credential field on disk: the AEAD [`SecretEnvelope`] plus a non-secret `last4`
/// hint (≤4 chars) surfaced by the status API. Never carries the plaintext.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCredentialField {
    /// The AEAD envelope wrapping this field's secret value.
    #[serde(flatten)]
    pub envelope: SecretEnvelope,
    /// Up to the last 4 characters of the plaintext, kept as a non-secret display hint.
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

/// The at-rest form of one provider's credentials (plan §1): a per-field map of encrypted envelopes,
/// keyed by field name, tagged with the mode/provider selector and the key version last written.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedCredentialRecord {
    /// The [`CredentialMode::as_str`] this record belongs to.
    pub mode: String,
    /// The provider id (empty for the single-instance CMD/SCAP modes; the QTSP id for CSC).
    pub provider_id: String,
    /// The key version the most recent write used. Each envelope also carries its own version, which
    /// is the authoritative one for decryption; this is an informational/rotation marker.
    pub key_version: u32,
    /// Encrypted fields keyed by field name (sorted for a stable on-disk form).
    pub fields: BTreeMap<String, StoredCredentialField>,
}

impl EncryptedCredentialRecord {
    fn empty(mode: CredentialMode, provider_id: &str) -> Self {
        Self {
            mode: mode.as_str().to_owned(),
            provider_id: provider_id.to_owned(),
            key_version: 0,
            fields: BTreeMap::new(),
        }
    }
}

/// A non-secret status view of one stored record for the credential status API (plan §4). Carries
/// configured field names + `last4` hints only, never ciphertext or plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecordStatus {
    /// The mode this record belongs to.
    pub mode: CredentialMode,
    /// The provider id (empty for CMD/SCAP).
    pub provider_id: String,
    /// The key version the record was last written under.
    pub key_version: u32,
    /// Per configured field: `(field_name, last4)`.
    pub fields: Vec<(String, Option<String>)>,
}

/// The decrypted fields of one record, returned by [`ProviderCredentialStore::read`] for the
/// provider-assembly path (S3). Every value is held in a [`Zeroizing`] buffer.
pub struct DecryptedCredentialRecord {
    /// The mode this record belongs to.
    pub mode: CredentialMode,
    /// The provider id (empty for CMD/SCAP).
    pub provider_id: String,
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

    /// Whether strict credential storage is enabled for this store.
    pub fn strict(&self) -> bool {
        self.strict
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

    /// Write a set of secret fields for `(mode, provider_id)`, removing every field named in `clear`.
    /// Fields not present in `set` and not in `clear` are left unchanged. When the resulting record
    /// has no fields it is dropped entirely. Fails closed (nothing persisted) on an unresolved key
    /// source, a strict-mode refusal, or a corrupt sidecar.
    pub fn put(
        &self,
        mode: CredentialMode,
        provider_id: &str,
        set: Vec<(&'static str, Zeroizing<String>)>,
        clear: &[&str],
    ) -> Result<(), ProviderCredentialError> {
        for (field, _) in &set {
            reject_unknown_field(mode, field)?;
        }
        for field in clear {
            reject_unknown_field(mode, field)?;
        }

        // Only resolve the crypto core (and create the root file) when there is something to encrypt;
        // a clear-only write needs no key material. Wrap all fields BEFORE taking the records lock so
        // a strict-mode refusal or key failure never leaves a half-applied record.
        let mut wrapped: Vec<(&'static str, StoredCredentialField)> = Vec::with_capacity(set.len());
        let mut write_version = None;
        if !set.is_empty() {
            let store = self.secretstore()?;
            for (field, value) in &set {
                let envelope = store.wrap(mode.as_str(), provider_id, field, value.as_bytes())?;
                wrapped.push((
                    field,
                    StoredCredentialField {
                        envelope,
                        last4: Some(last4(value)),
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
            for field in clear {
                record.fields.remove(*field);
            }
            for (field, stored) in wrapped {
                record.fields.insert(field.to_owned(), stored);
            }
            if let Some(version) = write_version {
                record.key_version = version;
            }
            if record.fields.is_empty() {
                next.remove(&key);
            } else {
                next.insert(key.clone(), record);
            }
            self.persist(&next)?;
            *records = next;
            Ok(())
        })
    }

    /// Decrypt every field of the `(mode, provider_id)` record, or `Ok(None)` when no record exists.
    /// Used by the provider-assembly path (S3). Fails closed on a corrupt sidecar or key failure.
    pub fn read(
        &self,
        mode: CredentialMode,
        provider_id: &str,
    ) -> Result<Option<DecryptedCredentialRecord>, ProviderCredentialError> {
        let key = (mode.as_str().to_owned(), provider_id.to_owned());
        let record = self.with_records(|records| Ok(records.get(&key).cloned()))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let store = self.secretstore()?;
        let mut fields = BTreeMap::new();
        for (name, stored) in &record.fields {
            let plaintext = store.unwrap(mode.as_str(), provider_id, name, &stored.envelope)?;
            fields.insert(name.clone(), plaintext);
        }
        Ok(Some(DecryptedCredentialRecord {
            mode,
            provider_id: provider_id.to_owned(),
            fields,
        }))
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

    /// Non-secret status of every stored record (configured field names + `last4` hints), for the
    /// status API (S4). Never decrypts and never returns ciphertext.
    pub fn statuses(&self) -> Result<Vec<CredentialRecordStatus>, ProviderCredentialError> {
        self.with_records(|records| {
            Ok(records
                .values()
                .filter_map(|record| {
                    let mode = CredentialMode::from_wire(&record.mode)?;
                    Some(CredentialRecordStatus {
                        mode,
                        provider_id: record.provider_id.clone(),
                        key_version: record.key_version,
                        fields: record
                            .fields
                            .iter()
                            .map(|(name, stored)| (name.clone(), stored.last4.clone()))
                            .collect(),
                    })
                })
                .collect())
        })
    }

    fn persist(&self, records: &RecordMap) -> Result<(), ProviderCredentialError> {
        match &self.backing {
            Backing::DataDir { sidecar, .. } => write_sidecar_atomic(sidecar, records),
            Backing::InMemory => Ok(()),
        }
    }

    /// Test-only constructor that pre-seeds the DB key so the derived-root source resolves
    /// deterministically on hosts without an OS key store.
    #[cfg(test)]
    fn load_with_db_key(data_dir: &Path, db_key: &[u8], strict: bool) -> Self {
        Self::load_inner(data_dir, Some(Zeroizing::new(db_key.to_vec())), strict)
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

/// The last up to 4 characters of `value`, as a non-secret display hint.
fn last4(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn zeroizing(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
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
        // The last4 hint is present and is at most 4 chars (a display hint, not the secret).
        assert!(text.contains("z789"));
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
        assert!(store.read(CredentialMode::Scap, "").expect("read").is_none());
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
        assert!(
            store
                .read(CredentialMode::Cmd, "")
                .expect("read")
                .is_some()
        );
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
    fn statuses_expose_last4_not_ciphertext() {
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
        assert_eq!(name, FIELD_SECRET);
        assert_eq!(last4.as_deref(), Some("3456"));
    }

    #[test]
    fn last4_handles_short_and_unicode_values() {
        assert_eq!(last4("ab"), "ab");
        assert_eq!(last4("abcdef"), "cdef");
        assert_eq!(last4(""), "");
        // Multi-byte chars are counted by char, never split mid-codepoint.
        assert_eq!(last4("aéîø"), "aéîø");
        assert_eq!(last4("xaéîø"), "aéîø");
    }
}
