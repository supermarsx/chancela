//! Credential **secretstore** crypto core (plan t77 §2, slice S1).
//!
//! Signature-provider credentials (API keys, client secrets, HTTP-Basic passwords, …) are
//! encrypted at rest with an **internally-derived** key so operators never have to manage a
//! separate credential passphrase. This module owns only the crypto core: AEAD wrap/unwrap of
//! individual secret fields, HKDF derivation of the credential master key (CMK) from a 32-byte
//! root, the fail-closed root-key resolver, and the honest protection-level/strict-mode logic.
//! Persistence of the encrypted records, the API surface, and the provider assembly live in
//! later slices (S2–S4) and consume this module.
//!
//! ## Honest boundaries (plan §2 threat model — stated here so the guarantee is not oversold)
//!
//! The default Chancela deployment stores its SQLite database **in plaintext** (SQLCipher is
//! optional). If the credential root key sits in a file next to a plaintext database, both
//! readable by the *same* OS principal, then at-rest credential encryption is **defense-in-depth
//! / obfuscation** — it defeats casual disk theft, backups, and log/observer leakage, but it is
//! **not** confidentiality against an attacker who already has full filesystem access as the app
//! user. It becomes real **confidentiality** only when the root is either (a) sealed by an OS
//! current-user secret store (Windows DPAPI here) scoped to a principal distinct from whoever can
//! read the DB, or (b) derived from a SQLCipher key supplied out-of-band. The store computes this
//! distinction as [`ProtectionLevel`] and surfaces it truthfully; it never describes the
//! plaintext-DB default as unconditional confidentiality.
//!
//! ## Crypto choices (mirrors `attestation.rs`, pinned)
//!
//! - **XChaCha20-Poly1305** AEAD per secret field, with a fresh random 24-byte `XNonce` per wrap
//!   (the 24-byte nonce space makes random nonces safe without a counter). The **AAD binds
//!   `mode ‖ provider_id ‖ entry_id ‖ field_name ‖ key_version`** so a ciphertext cannot be
//!   relocated between fields, entries, providers, or key versions.
//! - **HKDF-SHA256** (RFC 5869), implemented over the in-tree `sha2` crate (no new dependency),
//!   derives the 32-byte CMK from the root and derives a 32-byte root from operator/DB key
//!   material. Correctness is pinned to an RFC 5869 test vector.
//! - **Zeroize** for every plaintext and key buffer: the CMK/root live in [`Zeroizing`], and
//!   decrypted plaintext is wiped on every path.

// This module is the crypto core; S2 (`secretstore_persist`) is its first in-crate consumer, wiring
// `resolve`/`wrap`/`unwrap`/`protection_level`/`strict_from_env` into the credential store. A few
// items are still consumed only by later slices (S3 assembly / S4 endpoints); those carry a targeted
// `#[allow(dead_code)]` with a note rather than a blanket module-level allow.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Environment variable carrying an operator-supplied credential root key directly.
pub const CREDENTIAL_KEY_ENV: &str = "CHANCELA_CREDENTIAL_KEY";
/// Environment variable pointing at a file containing the operator-supplied credential root key.
pub const CREDENTIAL_KEY_FILE_ENV: &str = "CHANCELA_CREDENTIAL_KEY_FILE";
/// Environment variable that forces strict credential storage on (fail closed unless confidential).
pub const CREDENTIAL_STRICT_ENV: &str = "CHANCELA_CREDENTIAL_STRICT";

/// File name of the OS-sealed credential root envelope in the data dir.
const ROOT_FILE_NAME: &str = "provider-credentials-root.json";
/// Schema tag for the sealed-root envelope; a mismatch fails closed rather than guessing.
const ROOT_FILE_FORMAT: &str = "chancela-provider-credentials-root/v1";
/// Size in bytes of the credential root and the derived CMK.
const KEY_BYTES: usize = 32;
/// Size in bytes of the XChaCha20-Poly1305 nonce.
const NONCE_BYTES: usize = 24;
/// The initial key version stamped on freshly generated roots/envelopes.
const INITIAL_KEY_VERSION: u32 = 1;

// HKDF domain-separation constants. Salts are non-secret (RFC 5869 §3.1) and fixed per purpose.
const ROOT_SALT: &[u8] = b"chancela.provider-credentials.rootkey.salt.v1";
const ROOT_FROM_DBKEY_INFO: &[u8] = b"chancela.provider-credentials.rootkey.from-dbkey.v1";
const ROOT_FROM_OPERATOR_INFO: &[u8] =
    b"chancela.provider-credentials.rootkey.from-operator-env.v1";
const CMK_SALT: &[u8] = b"chancela.provider-credentials.cmk.salt.v1";
const CMK_INFO: &[u8] = b"chancela.provider-credentials.cmk.v1";
const AAD_DOMAIN: &[u8] = b"chancela.provider-credentials.aad.v1";

// --- Errors --------------------------------------------------------------------------------

/// A credential secretstore failure. `Display`/`Debug` never carry secret or key material.
#[derive(Debug)]
pub enum SecretStoreError {
    /// No credential root key could be resolved from any source. The store fails closed rather
    /// than persisting plaintext.
    NoKeySource,
    /// Strict credential storage is enabled but the resolved protection level is not confidential,
    /// so a write is refused before any encryption or persistence happens.
    StrictModeUnprotected {
        /// The (non-confidential) protection level that triggered the refusal.
        level: ProtectionLevel,
    },
    /// Both [`CREDENTIAL_KEY_ENV`] and [`CREDENTIAL_KEY_FILE_ENV`] were set. Only one may be used.
    AmbiguousOperatorKey,
    /// The operator credential-key env var contained non-Unicode data.
    NonUnicodeOperatorKey,
    /// The [`CREDENTIAL_KEY_FILE_ENV`] path was present but empty.
    EmptyOperatorKeyFilePath,
    /// A configured operator key source resolved to empty material.
    EmptyOperatorKey,
    /// The operator credential-key file could not be read.
    ReadOperatorKeyFile {
        /// The path configured by [`CREDENTIAL_KEY_FILE_ENV`].
        path: PathBuf,
        /// The filesystem or UTF-8 error returned while reading the key file.
        source: std::io::Error,
    },
    /// An envelope referenced a key version that this store's key ring does not hold.
    UnknownKeyVersion(u32),
    /// A symmetric crypto operation failed (bad key length, AEAD auth failure, corrupt base64).
    /// For decrypt this signals a wrong key/AAD or tampered ciphertext, not a caller mistake.
    Crypto(&'static str),
    /// A filesystem operation on the sealed-root envelope failed.
    Io {
        /// What was being attempted (e.g. `"read"`, `"install"`).
        action: &'static str,
        /// The envelope path.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The sealed-root envelope on disk is structurally invalid or mismatched.
    Envelope {
        /// The envelope path.
        path: PathBuf,
        /// Why it was rejected. Never contains key material.
        reason: String,
    },
    /// The OS-backed root-key protector failed to seal or unseal the root.
    Provider {
        /// The protector provider name.
        provider: &'static str,
        /// The operation that failed (`"seal"` / `"unseal"`).
        operation: &'static str,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// The OS RNG failed while generating a root or nonce.
    Random(std::io::Error),
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeySource => write!(
                f,
                "refusing to store the credential: no credential root key is available. Provide an \
                 OS-backed current-user key store, enable SQLCipher database encryption, or set \
                 {CREDENTIAL_KEY_ENV} / {CREDENTIAL_KEY_FILE_ENV}; the store never persists \
                 plaintext"
            ),
            Self::StrictModeUnprotected { level } => write!(
                f,
                "refusing to store the credential: strict credential storage is enabled but the \
                 current protection level is {level} (not confidential). Enable SQLCipher database \
                 encryption or run on a host with an OS-backed current-user key store, or disable \
                 strict credential storage ({CREDENTIAL_STRICT_ENV})"
            ),
            Self::AmbiguousOperatorKey => write!(
                f,
                "{CREDENTIAL_KEY_ENV} and {CREDENTIAL_KEY_FILE_ENV} are both set; configure only \
                 one operator credential-key source"
            ),
            Self::NonUnicodeOperatorKey => write!(
                f,
                "{CREDENTIAL_KEY_ENV} contains non-Unicode data; the credential key must be UTF-8"
            ),
            Self::EmptyOperatorKeyFilePath => {
                write!(f, "{CREDENTIAL_KEY_FILE_ENV} is set but empty")
            }
            Self::EmptyOperatorKey => {
                write!(
                    f,
                    "the configured operator credential key resolved to empty material"
                )
            }
            Self::ReadOperatorKeyFile { path, source } => write!(
                f,
                "failed to read the operator credential-key file configured by \
                 {CREDENTIAL_KEY_FILE_ENV} at {}: {source}",
                path.display()
            ),
            Self::UnknownKeyVersion(version) => write!(
                f,
                "the stored credential references key version {version}, which is not in this \
                 store's key ring"
            ),
            Self::Crypto(reason) => write!(f, "credential crypto failure: {reason}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(f, "failed to {action} {}: {source}", path.display()),
            Self::Envelope { path, reason } => write!(
                f,
                "credential root envelope {} is invalid: {reason}",
                path.display()
            ),
            Self::Provider {
                provider,
                operation,
                source,
            } => write!(
                f,
                "credential root-key protector {provider} failed to {operation} the root key: \
                 {source}"
            ),
            Self::Random(source) => {
                write!(
                    f,
                    "failed to generate random credential key material: {source}"
                )
            }
        }
    }
}

impl std::error::Error for SecretStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadOperatorKeyFile { source, .. }
            | Self::Io { source, .. }
            | Self::Provider { source, .. }
            | Self::Random(source) => Some(source),
            _ => None,
        }
    }
}

// --- Protection level & key source ---------------------------------------------------------

/// The honest at-rest protection level the store can offer for a given deployment (plan §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    /// The root is OS-sealed to the current user OR the database itself is SQLCipher-encrypted:
    /// real confidentiality against a same-host filesystem reader.
    Confidential,
    /// The root is a plaintext-readable file/operator-env next to a plaintext database:
    /// defense-in-depth only, not confidentiality against the app-user principal.
    Obfuscation,
}

impl ProtectionLevel {
    fn compute(source: &CredentialKeySource, db_encrypted: bool) -> Self {
        match source {
            CredentialKeySource::OsProtected { .. } | CredentialKeySource::DerivedFromDbKey => {
                Self::Confidential
            }
            CredentialKeySource::OperatorEnv => {
                if db_encrypted {
                    Self::Confidential
                } else {
                    Self::Obfuscation
                }
            }
        }
    }
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confidential => f.write_str("confidential"),
            Self::Obfuscation => f.write_str("obfuscation"),
        }
    }
}

/// Where the credential root key came from. Carries no key material — safe to log/serialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CredentialKeySource {
    /// A random root sealed by an OS current-user secret store (Windows DPAPI today).
    OsProtected {
        /// The protector provider name.
        provider: &'static str,
    },
    /// A root derived (HKDF-SHA256) from the SQLCipher database key when DB encryption is on.
    DerivedFromDbKey,
    /// A root derived from operator-supplied key material ([`CREDENTIAL_KEY_ENV`] /
    /// [`CREDENTIAL_KEY_FILE_ENV`]) for headless hosts without an OS keyring.
    OperatorEnv,
}

/// Read-only availability of the credential root key. This is intentionally metadata-only: it does
/// not create an OS-sealed root, decrypt credential fields, or return key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialKeyReadOnlyStatus {
    pub available: bool,
    pub failure: Option<CredentialKeyStatusFailure>,
    pub protection_level: Option<ProtectionLevel>,
    pub key_source: Option<CredentialKeySource>,
    pub key_version: Option<u32>,
}

impl CredentialKeyReadOnlyStatus {
    pub(crate) fn available(
        protection_level: ProtectionLevel,
        key_source: CredentialKeySource,
        key_version: u32,
    ) -> Self {
        Self {
            available: true,
            failure: None,
            protection_level: Some(protection_level),
            key_source: Some(key_source),
            key_version: Some(key_version),
        }
    }

    pub(crate) fn unavailable(failure: CredentialKeyStatusFailure) -> Self {
        Self {
            available: false,
            failure: Some(failure),
            protection_level: None,
            key_source: None,
            key_version: None,
        }
    }

    fn unavailable_with_source(
        failure: CredentialKeyStatusFailure,
        key_source: CredentialKeySource,
    ) -> Self {
        Self {
            available: false,
            failure: Some(failure),
            protection_level: None,
            key_source: Some(key_source),
            key_version: None,
        }
    }
}

/// Sanitized reason a read-only key-status probe could not establish an available key source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialKeyStatusFailure {
    NoKeySource,
    AmbiguousOperatorKey,
    InvalidOperatorKey,
    MissingRootEnvelope,
    InvalidRootEnvelope,
    StoreUnavailable,
}

// --- HKDF-SHA256 (RFC 5869) over the in-tree `sha2` crate -----------------------------------

/// SHA-256 block size in bytes (HMAC key-padding length).
const SHA256_BLOCK: usize = 64;

/// HMAC-SHA256 (RFC 2104) implemented directly over `sha2::Sha256` — avoids adding an `hmac`
/// dependency for the single HKDF use site.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let mut digest: [u8; 32] = Sha256::digest(key).into();
        block[..32].copy_from_slice(&digest);
        digest.zeroize();
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK];
    let mut opad = [0x5cu8; SHA256_BLOCK];
    for (b, k) in ipad.iter_mut().zip(block.iter()) {
        *b ^= k;
    }
    for (b, k) in opad.iter_mut().zip(block.iter()) {
        *b ^= k;
    }
    block.zeroize();

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    ipad.zeroize();
    let mut inner_digest: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    opad.zeroize();
    inner_digest.zeroize();
    outer.finalize().into()
}

/// HKDF-Extract (RFC 5869 §2.2): PRK = HMAC-SHA256(salt, IKM).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3), filling `out` (which must be ≤ 255·32 bytes).
fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    debug_assert!(out.len() <= 255 * 32, "HKDF-Expand length out of range");
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    let mut filled = 0;
    while filled < out.len() {
        let mut data = Vec::with_capacity(prev.len() + info.len() + 1);
        data.extend_from_slice(&prev);
        data.extend_from_slice(info);
        data.push(counter);
        let mut block = hmac_sha256(prk, &data);
        data.zeroize();
        let take = (out.len() - filled).min(32);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
        prev.zeroize();
        prev = block.to_vec();
        block.zeroize();
        counter = counter.wrapping_add(1);
    }
    prev.zeroize();
}

/// HKDF-SHA256(salt, IKM, info) → `out`.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let mut prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, out);
    prk.zeroize();
}

/// Derive the 32-byte credential master key from the 32-byte root.
fn derive_cmk(root: &[u8; KEY_BYTES]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut cmk = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf_sha256(CMK_SALT, &root[..], CMK_INFO, &mut cmk[..]);
    cmk
}

/// Derive a 32-byte root from arbitrary operator/DB key material via HKDF.
fn derive_root_from(material: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut root = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf_sha256(ROOT_SALT, material, info, &mut root[..]);
    root
}

// --- The encrypted field envelope ----------------------------------------------------------

/// The at-rest form of one encrypted credential field (plan §1/§2). Holds only ciphertext, its
/// nonce, and the key version — never plaintext. `Debug` is redacted defensively.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretEnvelope {
    /// Which key-ring version wrapped this field (bound into the AAD).
    pub key_version: u32,
    /// Base64 of the 24-byte XChaCha20-Poly1305 nonce.
    pub nonce_b64: String,
    /// Base64 of the AEAD ciphertext (plaintext + Poly1305 tag).
    pub ciphertext_b64: String,
}

impl fmt::Debug for SecretEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEnvelope")
            .field("key_version", &self.key_version)
            .field("nonce_b64", &"<redacted>")
            .field(
                "ciphertext_b64",
                &format_args!("<{} b64 chars redacted>", self.ciphertext_b64.len()),
            )
            .finish()
    }
}

/// Build the AEAD associated data binding `mode ‖ provider_id ‖ entry_id ‖ field_name ‖
/// key_version`. Each string part is length-prefixed so distinct tuples can never produce the same
/// AAD bytes (so a ciphertext cannot be relocated between a provider's entries).
fn build_aad(
    mode: &str,
    provider_id: &str,
    entry_id: &str,
    field_name: &str,
    key_version: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        AAD_DOMAIN.len()
            + 4 * 8
            + mode.len()
            + provider_id.len()
            + entry_id.len()
            + field_name.len()
            + 4,
    );
    aad.extend_from_slice(AAD_DOMAIN);
    for part in [mode, provider_id, entry_id, field_name] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

// --- The store -----------------------------------------------------------------------------

/// The credential secretstore: a resolved key ring plus the honest protection level and strict
/// flag. Wraps/unwraps individual secret fields; never persists plaintext.
///
/// Cloning is cheap (shared `Arc`). `Debug` never prints key material.
#[derive(Clone)]
pub struct CredentialSecretStore {
    inner: Arc<Inner>,
}

struct Inner {
    key_source: CredentialKeySource,
    protection_level: ProtectionLevel,
    strict: bool,
    current_version: u32,
    /// key_version → CMK. A single entry today; the map is the rotation seam (retired roots kept
    /// read-only until records are re-wrapped).
    keys: HashMap<u32, Zeroizing<[u8; KEY_BYTES]>>,
}

impl fmt::Debug for CredentialSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSecretStore")
            .field("key_source", &self.inner.key_source)
            .field("protection_level", &self.inner.protection_level)
            .field("strict", &self.inner.strict)
            .field("current_key_version", &self.inner.current_version)
            .field(
                "key_ring",
                &format_args!("<{} redacted key(s)>", self.inner.keys.len()),
            )
            .finish()
    }
}

impl CredentialSecretStore {
    /// Resolve the credential root key with fail-closed precedence and build the store.
    ///
    /// Precedence (plan §2): (1) OS-sealed root file (default when an OS protector is available)
    /// → (2) HKDF from the SQLCipher DB key when `db_key` is `Some` → (3) operator env
    /// ([`CREDENTIAL_KEY_ENV`] / [`CREDENTIAL_KEY_FILE_ENV`]) → (4) none ⇒ [`SecretStoreError::NoKeySource`].
    ///
    /// `db_key` is the raw SQLCipher key bytes when the durable store is encrypted, else `None`;
    /// it drives both the derived-root source and the confidential protection level. `strict`
    /// makes the store fail closed on writes whenever the protection level is not confidential.
    pub fn resolve(
        data_dir: &Path,
        db_key: Option<&[u8]>,
        strict: bool,
    ) -> Result<Self, SecretStoreError> {
        let protector = platform_protector();
        let operator_env = read_operator_env()?;
        let (root, source) = resolve_root(
            protector.as_deref(),
            data_dir,
            db_key,
            operator_env.as_ref().map(|material| material.as_slice()),
        )?;
        Ok(Self::from_root(root, source, db_key.is_some(), strict))
    }

    /// Build a store from an already-resolved 32-byte root and its provenance.
    fn from_root(
        root: Zeroizing<[u8; KEY_BYTES]>,
        source: CredentialKeySource,
        db_encrypted: bool,
        strict: bool,
    ) -> Self {
        let protection_level = ProtectionLevel::compute(&source, db_encrypted);
        let cmk = derive_cmk(&root);
        let mut keys = HashMap::new();
        keys.insert(INITIAL_KEY_VERSION, cmk);
        Self {
            inner: Arc::new(Inner {
                key_source: source,
                protection_level,
                strict,
                current_version: INITIAL_KEY_VERSION,
                keys,
            }),
        }
    }

    /// The honest at-rest protection level this store can offer.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.inner.protection_level
    }

    /// Where the resolved root key came from.
    pub fn key_source(&self) -> &CredentialKeySource {
        &self.inner.key_source
    }

    /// Whether strict credential storage is enabled.
    ///
    // Consumed by the credential status endpoint (S4); the S2 persistence store tracks the strict
    // flag independently (without forcing key resolution), so there is no live caller yet.
    #[allow(dead_code)]
    pub fn strict(&self) -> bool {
        self.inner.strict
    }

    /// The key version new writes are wrapped under.
    pub fn current_key_version(&self) -> u32 {
        self.inner.current_version
    }

    #[cfg(test)]
    pub(crate) fn for_test_source(
        source: CredentialKeySource,
        db_encrypted: bool,
        strict: bool,
    ) -> Self {
        Self::from_root(
            Zeroizing::new([0x57; KEY_BYTES]),
            source,
            db_encrypted,
            strict,
        )
    }

    /// Metadata-only status of an already-resolved store.
    pub(crate) fn read_only_status(&self) -> CredentialKeyReadOnlyStatus {
        CredentialKeyReadOnlyStatus::available(
            self.inner.protection_level,
            self.inner.key_source.clone(),
            self.inner.current_version,
        )
    }

    /// Encrypt one secret field into a [`SecretEnvelope`].
    ///
    /// The caller owns `plaintext` and should hold it in a [`Zeroizing`] buffer; this method
    /// makes no plaintext copy that outlives the call. Fails closed under strict mode when the
    /// protection level is not confidential, **before** touching the plaintext.
    pub fn wrap(
        &self,
        mode: &str,
        provider_id: &str,
        entry_id: &str,
        field_name: &str,
        plaintext: &[u8],
    ) -> Result<SecretEnvelope, SecretStoreError> {
        if self.inner.strict && self.inner.protection_level != ProtectionLevel::Confidential {
            return Err(SecretStoreError::StrictModeUnprotected {
                level: self.inner.protection_level,
            });
        }

        let version = self.inner.current_version;
        let cmk = self
            .inner
            .keys
            .get(&version)
            .ok_or(SecretStoreError::UnknownKeyVersion(version))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&cmk[..])
            .map_err(|_| SecretStoreError::Crypto("invalid credential master key length"))?;

        let mut nonce = [0u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| SecretStoreError::Random(rng_error(e)))?;
        let aad = build_aad(mode, provider_id, entry_id, field_name, version);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecretStoreError::Crypto("credential field encryption failed"))?;

        Ok(SecretEnvelope {
            key_version: version,
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        })
    }

    /// Decrypt one [`SecretEnvelope`] back to its plaintext, returned in a [`Zeroizing`] buffer.
    ///
    /// The `mode`/`provider_id`/`entry_id`/`field_name` must match those used at wrap time (they are
    /// bound into the AAD): a mismatch, a tampered ciphertext/nonce, or a wrong key fails
    /// authentication and returns [`SecretStoreError::Crypto`].
    pub fn unwrap(
        &self,
        mode: &str,
        provider_id: &str,
        entry_id: &str,
        field_name: &str,
        envelope: &SecretEnvelope,
    ) -> Result<Zeroizing<String>, SecretStoreError> {
        let cmk = self
            .inner
            .keys
            .get(&envelope.key_version)
            .ok_or(SecretStoreError::UnknownKeyVersion(envelope.key_version))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&cmk[..])
            .map_err(|_| SecretStoreError::Crypto("invalid credential master key length"))?;

        let nonce = B64
            .decode(&envelope.nonce_b64)
            .map_err(|_| SecretStoreError::Crypto("credential nonce is not valid base64"))?;
        if nonce.len() != NONCE_BYTES {
            return Err(SecretStoreError::Crypto("credential nonce is not 24 bytes"));
        }
        let ciphertext = B64
            .decode(&envelope.ciphertext_b64)
            .map_err(|_| SecretStoreError::Crypto("credential ciphertext is not valid base64"))?;

        let aad = build_aad(
            mode,
            provider_id,
            entry_id,
            field_name,
            envelope.key_version,
        );
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: &ciphertext, aad: &aad },
            )
            .map_err(|_| {
                SecretStoreError::Crypto("credential field authentication failed (wrong key, wrong binding, or tampered ciphertext)")
            })?;

        let result = match std::str::from_utf8(&plaintext) {
            Ok(text) => Ok(Zeroizing::new(text.to_owned())),
            Err(_) => Err(SecretStoreError::Crypto(
                "decrypted credential is not valid UTF-8",
            )),
        };
        plaintext.zeroize();
        result
    }
}

/// Convert a `rand_core` fill error into an `io::Error` for uniform reporting.
fn rng_error(err: rand_core::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

// --- Root-key resolver ---------------------------------------------------------------------

/// Resolve the 32-byte root and its provenance with fail-closed precedence. Split out from
/// [`CredentialSecretStore::resolve`] so tests can inject a protector and explicit env material.
fn resolve_root(
    protector: Option<&dyn RootKeyProtector>,
    data_dir: &Path,
    db_key: Option<&[u8]>,
    operator_key: Option<&[u8]>,
) -> Result<(Zeroizing<[u8; KEY_BYTES]>, CredentialKeySource), SecretStoreError> {
    if let Some(protector) = protector {
        let path = data_dir.join(ROOT_FILE_NAME);
        let (root, _version) = load_or_create_sealed_root(protector, &path)?;
        return Ok((
            root,
            CredentialKeySource::OsProtected {
                provider: protector.provider(),
            },
        ));
    }

    if let Some(db_key) = db_key {
        let root = derive_root_from(db_key, ROOT_FROM_DBKEY_INFO);
        return Ok((root, CredentialKeySource::DerivedFromDbKey));
    }

    if let Some(material) = operator_key {
        let root = derive_root_from(material, ROOT_FROM_OPERATOR_INFO);
        return Ok((root, CredentialKeySource::OperatorEnv));
    }

    Err(SecretStoreError::NoKeySource)
}

/// Read operator credential-key material from the environment, rejecting an ambiguous or empty
/// configuration. Returns `None` when neither env var is set (so a lower-precedence source or the
/// fail-closed path applies).
fn read_operator_env() -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
    let key = std::env::var_os(CREDENTIAL_KEY_ENV);
    let key_file = std::env::var_os(CREDENTIAL_KEY_FILE_ENV);
    match (key, key_file) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(SecretStoreError::AmbiguousOperatorKey),
        (Some(raw), None) => {
            let value = raw
                .into_string()
                .map_err(|_| SecretStoreError::NonUnicodeOperatorKey)?;
            let material = value.trim().as_bytes().to_vec();
            if material.is_empty() {
                return Err(SecretStoreError::EmptyOperatorKey);
            }
            Ok(Some(Zeroizing::new(material)))
        }
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            if path.as_os_str().is_empty() {
                return Err(SecretStoreError::EmptyOperatorKeyFilePath);
            }
            let raw = std::fs::read_to_string(&path)
                .map_err(|source| SecretStoreError::ReadOperatorKeyFile { path, source })?;
            let material = raw.trim().as_bytes().to_vec();
            if material.is_empty() {
                return Err(SecretStoreError::EmptyOperatorKey);
            }
            Ok(Some(Zeroizing::new(material)))
        }
    }
}

/// Parse the strict-mode override from [`CREDENTIAL_STRICT_ENV`], falling back to `default` when
/// it is unset. Any non-empty, non-falsey value turns strict on.
pub fn strict_from_env(default: bool) -> bool {
    match std::env::var(CREDENTIAL_STRICT_ENV) {
        Ok(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            !(normalized.is_empty()
                || normalized == "0"
                || normalized == "false"
                || normalized == "off"
                || normalized == "no")
        }
        Err(_) => default,
    }
}

/// Probe the credential root-key source without creating, unsealing, or deriving key material.
pub(crate) fn inspect_key_source_read_only(
    data_dir: &Path,
    db_key_configured: bool,
) -> CredentialKeyReadOnlyStatus {
    if let Some(protector) = platform_protector() {
        let source = CredentialKeySource::OsProtected {
            provider: protector.provider(),
        };
        let path = data_dir.join(ROOT_FILE_NAME);
        return inspect_sealed_root_envelope(&*protector, &path)
            .map(|key_version| {
                CredentialKeyReadOnlyStatus::available(
                    ProtectionLevel::Confidential,
                    source.clone(),
                    key_version,
                )
            })
            .unwrap_or_else(|failure| {
                CredentialKeyReadOnlyStatus::unavailable_with_source(failure, source)
            });
    }

    if db_key_configured {
        return CredentialKeyReadOnlyStatus::available(
            ProtectionLevel::Confidential,
            CredentialKeySource::DerivedFromDbKey,
            INITIAL_KEY_VERSION,
        );
    }

    match inspect_operator_key_source_metadata() {
        Ok(true) => CredentialKeyReadOnlyStatus::available(
            ProtectionLevel::Obfuscation,
            CredentialKeySource::OperatorEnv,
            INITIAL_KEY_VERSION,
        ),
        Ok(false) => {
            CredentialKeyReadOnlyStatus::unavailable(CredentialKeyStatusFailure::NoKeySource)
        }
        Err(failure) => CredentialKeyReadOnlyStatus::unavailable(failure),
    }
}

fn inspect_operator_key_source_metadata() -> Result<bool, CredentialKeyStatusFailure> {
    let key = std::env::var_os(CREDENTIAL_KEY_ENV);
    let key_file = std::env::var_os(CREDENTIAL_KEY_FILE_ENV);
    match (key, key_file) {
        (None, None) => Ok(false),
        (Some(_), Some(_)) => Err(CredentialKeyStatusFailure::AmbiguousOperatorKey),
        (Some(raw), None) => {
            let mut value = raw
                .into_string()
                .map_err(|_| CredentialKeyStatusFailure::InvalidOperatorKey)?;
            let available = !value.trim().is_empty();
            value.zeroize();
            if available {
                Ok(true)
            } else {
                Err(CredentialKeyStatusFailure::InvalidOperatorKey)
            }
        }
        (None, Some(path)) => {
            if path.is_empty() {
                return Err(CredentialKeyStatusFailure::InvalidOperatorKey);
            }
            let path = PathBuf::from(path);
            let metadata = std::fs::metadata(path)
                .map_err(|_| CredentialKeyStatusFailure::InvalidOperatorKey)?;
            if metadata.is_file() && metadata.len() > 0 {
                Ok(true)
            } else {
                Err(CredentialKeyStatusFailure::InvalidOperatorKey)
            }
        }
    }
}

// --- OS-sealed root envelope ---------------------------------------------------------------

/// A pluggable OS current-user secret-store protector (generalizes the desktop
/// `DatabaseKeyProtector`). The Windows DPAPI impl is the only one wired today; other platforms
/// report no protector so resolution falls through to the DB-derived / operator-env sources —
/// never to silent plaintext.
trait RootKeyProtector {
    /// A stable provider name recorded in the envelope so a foreign envelope is rejected.
    fn provider(&self) -> &'static str;
    /// Seal `plaintext` to the current-user OS secret store.
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError>;
    /// Unseal a previously sealed blob. The plaintext is returned in a zeroizing buffer.
    fn unprotect(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError>;
}

#[cfg(windows)]
fn platform_protector() -> Option<Box<dyn RootKeyProtector>> {
    Some(Box::new(WindowsCurrentUserDpapi))
}

#[cfg(not(windows))]
fn platform_protector() -> Option<Box<dyn RootKeyProtector>> {
    None
}

#[derive(Serialize, Deserialize)]
struct SealedRootEnvelope {
    format: String,
    provider: String,
    key_version: u32,
    sealed_root_b64: String,
}

/// Load the sealed root from `path`, or generate + seal a fresh random root if the file is
/// absent. Fails closed on any structural/provider mismatch (never silently regenerates over a
/// valid-but-foreign envelope).
fn load_or_create_sealed_root(
    protector: &dyn RootKeyProtector,
    path: &Path,
) -> Result<(Zeroizing<[u8; KEY_BYTES]>, u32), SecretStoreError> {
    if path.is_file() {
        return load_sealed_root(protector, path);
    }

    let mut root = Zeroizing::new([0u8; KEY_BYTES]);
    OsRng
        .try_fill_bytes(&mut root[..])
        .map_err(|e| SecretStoreError::Random(rng_error(e)))?;
    let sealed = protector.protect(&root[..])?;
    let envelope = SealedRootEnvelope {
        format: ROOT_FILE_FORMAT.to_owned(),
        provider: protector.provider().to_owned(),
        key_version: INITIAL_KEY_VERSION,
        sealed_root_b64: B64.encode(&sealed),
    };
    if !write_root_envelope(path, &envelope)? {
        // Another process installed the envelope between our check and write; use theirs.
        return load_sealed_root(protector, path);
    }
    Ok((root, INITIAL_KEY_VERSION))
}

fn inspect_sealed_root_envelope(
    protector: &dyn RootKeyProtector,
    path: &Path,
) -> Result<u32, CredentialKeyStatusFailure> {
    if !path.is_file() {
        return Err(CredentialKeyStatusFailure::MissingRootEnvelope);
    }
    let raw = std::fs::read(path).map_err(|_| CredentialKeyStatusFailure::InvalidRootEnvelope)?;
    let envelope: SealedRootEnvelope = serde_json::from_slice(&raw)
        .map_err(|_| CredentialKeyStatusFailure::InvalidRootEnvelope)?;
    if envelope.format != ROOT_FILE_FORMAT || envelope.provider != protector.provider() {
        return Err(CredentialKeyStatusFailure::InvalidRootEnvelope);
    }
    let sealed = B64
        .decode(&envelope.sealed_root_b64)
        .map_err(|_| CredentialKeyStatusFailure::InvalidRootEnvelope)?;
    if sealed.is_empty() {
        return Err(CredentialKeyStatusFailure::InvalidRootEnvelope);
    }
    Ok(envelope.key_version)
}

fn load_sealed_root(
    protector: &dyn RootKeyProtector,
    path: &Path,
) -> Result<(Zeroizing<[u8; KEY_BYTES]>, u32), SecretStoreError> {
    let raw = std::fs::read(path).map_err(|source| SecretStoreError::Io {
        action: "read",
        path: path.to_path_buf(),
        source,
    })?;
    let envelope: SealedRootEnvelope =
        serde_json::from_slice(&raw).map_err(|source| SecretStoreError::Envelope {
            path: path.to_path_buf(),
            reason: format!("not a valid root envelope: {source}"),
        })?;
    if envelope.format != ROOT_FILE_FORMAT {
        return Err(SecretStoreError::Envelope {
            path: path.to_path_buf(),
            reason: format!("unsupported format {}", envelope.format),
        });
    }
    if envelope.provider != protector.provider() {
        return Err(SecretStoreError::Envelope {
            path: path.to_path_buf(),
            reason: format!(
                "provider {} does not match this host's protector {}",
                envelope.provider,
                protector.provider()
            ),
        });
    }
    let sealed =
        B64.decode(&envelope.sealed_root_b64)
            .map_err(|source| SecretStoreError::Envelope {
                path: path.to_path_buf(),
                reason: format!("sealed_root_b64 is not valid base64: {source}"),
            })?;
    let plaintext = protector.unprotect(&sealed)?;
    if plaintext.len() != KEY_BYTES {
        return Err(SecretStoreError::Envelope {
            path: path.to_path_buf(),
            reason: "unsealed root key is not 32 bytes".to_owned(),
        });
    }
    let mut root = Zeroizing::new([0u8; KEY_BYTES]);
    root.copy_from_slice(&plaintext);
    Ok((root, envelope.key_version))
}

/// Atomically install the envelope with a temp-file + rename, matching the desktop protector.
/// Returns `false` (rather than erroring) when the target already exists, so a lost create race
/// falls back to loading the winner's envelope.
fn write_root_envelope(
    path: &Path,
    envelope: &SealedRootEnvelope,
) -> Result<bool, SecretStoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| SecretStoreError::Io {
                action: "create directory for",
                path: path.to_path_buf(),
                source,
            })?;
        }
    }

    let bytes =
        serde_json::to_vec_pretty(envelope).map_err(|source| SecretStoreError::Envelope {
            path: path.to_path_buf(),
            reason: format!("failed to serialize root envelope: {source}"),
        })?;

    let mut random = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|e| SecretStoreError::Random(rng_error(e)))?;
    let mut tmp_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| ROOT_FILE_NAME.into());
    tmp_name.push(format!(".{:016x}.tmp", u64::from_be_bytes(random)));
    let tmp_path = path.with_file_name(tmp_name);

    {
        use std::io::Write as _;
        let mut tmp = match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(source) => {
                return Err(SecretStoreError::Io {
                    action: "create temporary root envelope",
                    path: tmp_path,
                    source,
                });
            }
        };
        if let Err(source) = tmp.write_all(&bytes) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SecretStoreError::Io {
                action: "write temporary root envelope",
                path: tmp_path,
                source,
            });
        }
        if let Err(source) = tmp.sync_all() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SecretStoreError::Io {
                action: "flush temporary root envelope",
                path: tmp_path,
                source,
            });
        }
    }

    if path.exists() {
        let _ = std::fs::remove_file(&tmp_path);
        return Ok(false);
    }
    match std::fs::rename(&tmp_path, path) {
        Ok(()) => Ok(true),
        Err(source) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(SecretStoreError::Io {
                action: "install root envelope",
                path: path.to_path_buf(),
                source,
            })
        }
    }
}

// --- Windows DPAPI current-user protector --------------------------------------------------
//
// Minimal manual FFI to `CryptProtectData`/`CryptUnprotectData` (crypt32) so no `windows-sys`
// dependency has to be added to this crate; the calls mirror the desktop protector exactly.

#[cfg(windows)]
const WINDOWS_DPAPI_PROVIDER: &str = "windows-current-user-dpapi";

#[cfg(windows)]
struct WindowsCurrentUserDpapi;

#[cfg(windows)]
impl RootKeyProtector for WindowsCurrentUserDpapi {
    fn provider(&self) -> &'static str {
        WINDOWS_DPAPI_PROVIDER
    }

    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        windows_dpapi::protect(plaintext)
    }

    fn unprotect(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        windows_dpapi::unprotect(sealed).map(Zeroizing::new)
    }
}

#[cfg(windows)]
mod windows_dpapi {
    use core::ffi::c_void;
    use core::ptr;

    use zeroize::Zeroize;

    use super::{SecretStoreError, WINDOWS_DPAPI_PROVIDER};

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *const c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            pp_sz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *const c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    fn blob_len(len: usize, operation: &'static str) -> Result<u32, SecretStoreError> {
        u32::try_from(len).map_err(|_| SecretStoreError::Provider {
            provider: WINDOWS_DPAPI_PROVIDER,
            operation,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential root blob is too large for DPAPI",
            ),
        })
    }

    pub(super) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let input = DataBlob {
            cb_data: blob_len(plaintext.len(), "seal")?,
            pb_data: plaintext.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretStoreError::Provider {
                provider: WINDOWS_DPAPI_PROVIDER,
                operation: "seal",
                source: std::io::Error::last_os_error(),
            });
        }

        let sealed =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }.to_vec();
        unsafe {
            LocalFree(output.pb_data.cast());
        }
        Ok(sealed)
    }

    pub(super) fn unprotect(sealed: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let input = DataBlob {
            cb_data: blob_len(sealed.len(), "unseal")?,
            pb_data: sealed.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(SecretStoreError::Provider {
                provider: WINDOWS_DPAPI_PROVIDER,
                operation: "unseal",
                source: std::io::Error::last_os_error(),
            });
        }

        let plaintext =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }.to_vec();
        // L1 hardening: the decrypted plaintext lives in an OS `LocalAlloc` buffer. Copy it out (above),
        // then wipe the OS buffer before returning it to `LocalFree`, so a secret does not linger in
        // freed heap memory that a later allocation could read back.
        unsafe {
            if !output.pb_data.is_null() && output.cb_data > 0 {
                std::slice::from_raw_parts_mut(output.pb_data, output.cb_data as usize).zeroize();
            }
            LocalFree(output.pb_data.cast());
        }
        Ok(plaintext)
    }
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
                "chancela-secretstore-{name}-{}-{seq}-{nanos}",
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

    /// A deterministic, cross-platform protector for exercising the OS-sealed root path without a
    /// real OS keyring (a reversible XOR mask — NOT secure, tests only).
    struct TestProtector;

    impl RootKeyProtector for TestProtector {
        fn provider(&self) -> &'static str {
            "test-protector"
        }

        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
            let mut sealed = b"sealed:".to_vec();
            sealed.extend(plaintext.iter().map(|b| b ^ 0x5a));
            Ok(sealed)
        }

        fn unprotect(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
            let body = sealed
                .strip_prefix(b"sealed:")
                .ok_or(SecretStoreError::Crypto("test protector prefix missing"))?;
            Ok(Zeroizing::new(body.iter().map(|b| b ^ 0x5a).collect()))
        }
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn store_with(
        source: CredentialKeySource,
        db_encrypted: bool,
        strict: bool,
    ) -> CredentialSecretStore {
        CredentialSecretStore::from_root(
            Zeroizing::new([7u8; KEY_BYTES]),
            source,
            db_encrypted,
            strict,
        )
    }

    #[test]
    fn aead_round_trips_a_secret_field() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        let secret = "sk_live_amelia_marques_0xdeadbeef";
        let env = store
            .wrap(
                "csc",
                "encosto-estrategico",
                "entry-1",
                "client_secret",
                secret.as_bytes(),
            )
            .expect("wrap");
        assert_eq!(env.key_version, 1);
        assert!(!env.ciphertext_b64.contains(secret));

        let recovered = store
            .unwrap(
                "csc",
                "encosto-estrategico",
                "entry-1",
                "client_secret",
                &env,
            )
            .expect("unwrap");
        assert_eq!(&*recovered, secret);
    }

    #[test]
    fn wrong_aad_binding_fails_to_decrypt() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        let env = store
            .wrap(
                "csc",
                "provider-a",
                "entry-1",
                "client_secret",
                b"top-secret",
            )
            .expect("wrap");

        // Swapped field, provider, and mode each break authentication.
        assert!(
            store
                .unwrap("csc", "provider-a", "entry-1", "client_id", &env)
                .is_err()
        );
        assert!(
            store
                .unwrap("csc", "provider-b", "entry-1", "client_secret", &env)
                .is_err()
        );
        assert!(
            store
                .unwrap("cmd", "provider-a", "entry-1", "client_secret", &env)
                .is_err()
        );
        // And the correct binding still works.
        assert!(
            store
                .unwrap("csc", "provider-a", "entry-1", "client_secret", &env)
                .is_ok()
        );
    }

    #[test]
    fn wrong_entry_id_binding_fails_to_decrypt() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        let env = store
            .wrap(
                "csc",
                "provider-a",
                "entry-primary",
                "client_secret",
                b"top-secret",
            )
            .expect("wrap");
        assert!(
            store
                .unwrap("csc", "provider-a", "entry-fallback", "client_secret", &env)
                .is_err(),
            "a ciphertext must not decrypt under a different entry_id"
        );
        assert_eq!(
            &*store
                .unwrap("csc", "provider-a", "entry-primary", "client_secret", &env)
                .unwrap(),
            "top-secret"
        );
    }

    #[test]
    fn tampered_ciphertext_or_nonce_fails_to_decrypt() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        let env = store
            .wrap("scap", "ama", "entry-1", "secret", b"ama-api-key")
            .expect("wrap");

        let mut ct_tampered = env.clone();
        let mut ct = B64.decode(&ct_tampered.ciphertext_b64).unwrap();
        ct[0] ^= 0x01;
        ct_tampered.ciphertext_b64 = B64.encode(&ct);
        assert!(
            store
                .unwrap("scap", "ama", "entry-1", "secret", &ct_tampered)
                .is_err()
        );

        let mut nonce_tampered = env.clone();
        let mut nonce = B64.decode(&nonce_tampered.nonce_b64).unwrap();
        nonce[0] ^= 0x01;
        nonce_tampered.nonce_b64 = B64.encode(&nonce);
        assert!(
            store
                .unwrap("scap", "ama", "entry-1", "secret", &nonce_tampered)
                .is_err()
        );
    }

    #[test]
    fn wrong_key_version_is_rejected() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        let mut env = store
            .wrap("cmd", "", "entry-1", "http_basic_password", b"pw")
            .expect("wrap");
        env.key_version = 99;
        assert!(matches!(
            store.unwrap("cmd", "", "entry-1", "http_basic_password", &env),
            Err(SecretStoreError::UnknownKeyVersion(99))
        ));
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        // RFC 5869 Appendix A, Test Case 1 (SHA-256).
        let ikm = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_bytes("000102030405060708090a0b0c");
        let info = hex_bytes("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk =
            hex_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex_bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let mut okm = vec![0u8; 42];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn resolver_fails_closed_with_no_source() {
        let dir = TempDir::new("no-source");
        let err = resolve_root(None, dir.path(), None, None).expect_err("must fail closed");
        assert!(matches!(err, SecretStoreError::NoKeySource));
        // Nothing was written.
        assert!(!dir.path().join(ROOT_FILE_NAME).exists());
    }

    #[test]
    fn resolver_precedence_os_over_db_over_env() {
        let dir = TempDir::new("precedence");
        // OS protector present → OsProtected wins even when db/env are available.
        let (_root, source) = resolve_root(
            Some(&TestProtector),
            dir.path(),
            Some(b"db-key"),
            Some(b"operator-key"),
        )
        .expect("os wins");
        assert_eq!(
            source,
            CredentialKeySource::OsProtected {
                provider: "test-protector"
            }
        );

        // No OS protector, db key present → derived-from-db wins over env.
        let (_root, source) =
            resolve_root(None, dir.path(), Some(b"db-key"), Some(b"operator-key"))
                .expect("db wins over env");
        assert_eq!(source, CredentialKeySource::DerivedFromDbKey);

        // Only operator env remains.
        let (_root, source) =
            resolve_root(None, dir.path(), None, Some(b"operator-key")).expect("operator env");
        assert_eq!(source, CredentialKeySource::OperatorEnv);
    }

    #[test]
    fn os_sealed_root_persists_reuses_and_hides_plaintext() {
        let dir = TempDir::new("sealed-root");
        let path = dir.path().join(ROOT_FILE_NAME);

        let (first, version) =
            load_or_create_sealed_root(&TestProtector, &path).expect("create sealed root");
        assert_eq!(version, INITIAL_KEY_VERSION);
        assert!(path.is_file());

        // The raw envelope never contains the root bytes in the clear.
        let raw = std::fs::read(&path).expect("read envelope");
        assert!(
            raw.windows(KEY_BYTES).all(|w| w != &first[..]),
            "sealed envelope must not contain the plaintext root"
        );
        let text = String::from_utf8(raw).expect("utf8 envelope");
        assert!(text.contains("test-protector"));

        // A second load returns the identical root (stable across restarts).
        let (second, _) =
            load_or_create_sealed_root(&TestProtector, &path).expect("reload sealed root");
        assert_eq!(&first[..], &second[..]);

        // A foreign provider envelope is rejected, not silently regenerated.
        struct OtherProtector;
        impl RootKeyProtector for OtherProtector {
            fn provider(&self) -> &'static str {
                "other-protector"
            }
            fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
                Ok(plaintext.to_vec())
            }
            fn unprotect(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
                Ok(Zeroizing::new(sealed.to_vec()))
            }
        }
        let err = load_or_create_sealed_root(&OtherProtector, &path)
            .expect_err("provider mismatch must be rejected");
        assert!(matches!(err, SecretStoreError::Envelope { .. }));
    }

    #[test]
    fn strict_mode_refuses_wrap_when_not_confidential() {
        let store = store_with(CredentialKeySource::OperatorEnv, false, true);
        assert_eq!(store.protection_level(), ProtectionLevel::Obfuscation);

        let err = store
            .wrap("csc", "p", "entry-1", "client_secret", b"secret")
            .expect_err("strict + obfuscation must refuse");
        match err {
            SecretStoreError::StrictModeUnprotected { level } => {
                assert_eq!(level, ProtectionLevel::Obfuscation);
                let message = SecretStoreError::StrictModeUnprotected { level }.to_string();
                assert!(message.contains("SQLCipher"));
                assert!(message.contains("OS-backed"));
                assert!(!message.contains("secret"));
            }
            other => panic!("expected StrictModeUnprotected, got {other:?}"),
        }
    }

    #[test]
    fn strict_mode_accepts_wrap_when_confidential() {
        for source in [
            CredentialKeySource::OsProtected {
                provider: "test-protector",
            },
            CredentialKeySource::DerivedFromDbKey,
        ] {
            let db_encrypted = matches!(source, CredentialKeySource::DerivedFromDbKey);
            let store = store_with(source, db_encrypted, true);
            assert_eq!(store.protection_level(), ProtectionLevel::Confidential);
            let env = store
                .wrap("csc", "p", "entry-1", "client_secret", b"secret")
                .expect("strict + confidential accepts");
            assert_eq!(
                &*store
                    .unwrap("csc", "p", "entry-1", "client_secret", &env)
                    .unwrap(),
                "secret"
            );
        }
    }

    #[test]
    fn permissive_mode_accepts_and_reports_obfuscation() {
        let store = store_with(CredentialKeySource::OperatorEnv, false, false);
        assert_eq!(store.protection_level(), ProtectionLevel::Obfuscation);
        assert!(!store.strict());
        assert_eq!(store.key_source(), &CredentialKeySource::OperatorEnv);
        let env = store
            .wrap("scap", "ama", "entry-1", "secret", b"ama-key")
            .expect("permissive accepts");
        assert_eq!(
            &*store
                .unwrap("scap", "ama", "entry-1", "secret", &env)
                .unwrap(),
            "ama-key"
        );
    }

    #[test]
    fn protection_level_and_key_source_across_sources() {
        let cases = [
            (
                CredentialKeySource::OsProtected {
                    provider: "test-protector",
                },
                false,
                ProtectionLevel::Confidential,
            ),
            (
                CredentialKeySource::DerivedFromDbKey,
                true,
                ProtectionLevel::Confidential,
            ),
            (
                CredentialKeySource::OperatorEnv,
                false,
                ProtectionLevel::Obfuscation,
            ),
            // Operator env alongside an encrypted DB is confidential (DB protects the material).
            (
                CredentialKeySource::OperatorEnv,
                true,
                ProtectionLevel::Confidential,
            ),
        ];
        for (source, db_encrypted, expected) in cases {
            let store = store_with(source.clone(), db_encrypted, false);
            assert_eq!(store.protection_level(), expected, "source {source:?}");
            assert_eq!(store.key_source(), &source);
        }
    }

    #[test]
    fn debug_never_prints_key_material() {
        let store = store_with(CredentialKeySource::DerivedFromDbKey, true, false);
        // Recompute the CMK the store holds and confirm it is absent from Debug output.
        let cmk = derive_cmk(&[7u8; KEY_BYTES]);
        let cmk_hex: String = cmk.iter().map(|b| format!("{b:02x}")).collect();
        let debug = format!("{store:?}");
        assert!(debug.contains("CredentialSecretStore"));
        assert!(debug.contains("redacted key"));
        assert!(!debug.contains(&cmk_hex));

        // And the envelope's Debug hides the ciphertext.
        let env = store
            .wrap("csc", "p", "entry-1", "client_secret", b"s3cr3t-value")
            .expect("wrap");
        let env_debug = format!("{env:?}");
        assert!(!env_debug.contains(&env.ciphertext_b64));
        assert!(env_debug.contains("redacted"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_seals_and_unseals_the_root() {
        // Exercises the real manual-FFI DPAPI path end-to-end (this host is Windows).
        let protector = WindowsCurrentUserDpapi;
        let root = [0xA5u8; KEY_BYTES];
        let sealed = protector.protect(&root).expect("dpapi seal");
        assert_ne!(sealed.as_slice(), &root[..]);
        let unsealed = protector.unprotect(&sealed).expect("dpapi unseal");
        assert_eq!(&unsealed[..], &root[..]);

        // And the full sealed-root round trip through a data-dir envelope.
        let dir = TempDir::new("dpapi-root");
        let path = dir.path().join(ROOT_FILE_NAME);
        let (a, _) = load_or_create_sealed_root(&protector, &path).expect("create");
        let (b, _) = load_or_create_sealed_root(&protector, &path).expect("reload");
        assert_eq!(&a[..], &b[..]);
    }
}
