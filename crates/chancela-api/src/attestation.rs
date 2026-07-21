//! Optional per-user PKI **audit attestation** and the crypto behind optional passwords
//! (plan t29 §4.3/§4.4).
//!
//! ## Honest boundaries (plan t29 §0/§6 — repeated here so the guarantee is not oversold)
//!
//! - A **password** gates `POST /v1/session` and unlocks the attestation key. It is a *tamper
//!   speed-bump for a shared machine*, **not at-rest encryption**: entities, books, acts,
//!   `users.json` and the ledger remain readable and editable on disk regardless of any password
//!   (the ARC-30 gap — out of scope here).
//! - An **attestation** proves an action was performed inside a session unlocked by the
//!   password-holder → per-user cryptographic **accountability / tamper-evidence** in the audit
//!   trail. It is **NOT** legal non-repudiation or a qualified electronic signature: the server
//!   holds the decrypted key in memory during the session (trust-on-the-local-process, not a
//!   smartcard the server never sees). Qualified signatures on the sealed acts (CC/CMD →
//!   CAdES/PAdES) remain the legal mechanism; this is an internal layer on the DAT-11 hash chain.
//!
//! ## Crypto choices (plan t29 §3, pinned)
//!
//! - **argon2id** (`argon2::Argon2::default()` params) for both the sign-in **verification hash**
//!   and, separately, a 32-byte **KEK** derived from the password + a per-key salt via
//!   `hash_password_into`. New sign-in/recovery verifiers keep argon2's random PHC salt and add a
//!   file-backed application seed (argon2 secret input) plus a per-verifier pepper. The stored
//!   per-verifier pepper is not a classical hidden pepper once an attacker has `users.json`; it is
//!   extra verifier material kept off API/ledger surfaces, while the app seed lives in its own seed
//!   config sidecar.
//! - **XChaCha20-Poly1305** wraps the 32-byte P-256 secret scalar under the KEK — pure-Rust, no
//!   AES-NI-detection surface, and its 24-byte random nonce removes all nonce-management burden.
//! - **P-256** ECDSA (ES256 semantics) signs each ledger event's chain `hash` via
//!   `sign_prehash` (the event hash *is* the prehash); verified with `verify_prehash`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock as StdRwLock};

use argon2::password_hash::rand_core::OsRng as SaltRng;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use chancela_ledger::Event;

/// Minimum sign-in-secret length (plan §4.2: length over composition rules).
pub const MIN_SECRET_LEN: usize = 8;
/// Maximum sign-in-secret length — bounds the argon2 cost of a hostile giant input.
pub const MAX_SECRET_LEN: usize = 256;
/// The signature algorithm recorded on every attestation (ES256 = ECDSA P-256 / SHA-256).
pub const ALGORITHM: &str = "ES256";

/// A crypto operation failed. These are internal faults (a corrupt stored blob, an RNG or
/// serialization failure) — never a wrong password, which the caller checks via
/// [`verify_secret`] and maps to `401` itself. Maps to `500` at the API boundary.
#[derive(Debug)]
pub struct AttestationError(pub String);

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attestation crypto failure: {}", self.0)
    }
}

impl std::error::Error for AttestationError {}

fn crypto<E: std::fmt::Display>(e: E) -> AttestationError {
    AttestationError(e.to_string())
}

// --- Password (sign-in secret) hashing ----------------------------------------------------

/// The file-backed seed config used by hardened password/recovery verifiers.
pub const VERIFIER_SEED_FILE: &str = "password-verifier-seed.json";

/// Prefix for the v1 Chancela verifier envelope stored in `User.password_hash` /
/// `User.recovery_hash`: `chancela-secret-v1$<seed-id>$<pepper-b64>$<argon2id-phc>`.
pub(crate) const HARDENED_VERIFIER_PREFIX: &str = "chancela-secret-v1$";

const VERIFIER_SEED_BYTES: usize = 32;
const VERIFIER_PEPPER_BYTES: usize = 32;
const VERIFIER_SEED_KIND: &str = "seed";
const VERIFIER_SEED_PURPOSE: &str = "password_verifier_app_seed";

#[derive(Clone)]
pub struct VerifierSeed {
    inner: Arc<VerifierSeedInner>,
}

struct VerifierSeedInner {
    id: String,
    bytes: [u8; VERIFIER_SEED_BYTES],
    path: Option<PathBuf>,
    saved: Mutex<bool>,
}

#[derive(Serialize, Deserialize)]
struct VerifierSeedFile {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: String,
    purpose: String,
    seed_id: String,
    seed_b64: String,
}

impl Default for VerifierSeed {
    fn default() -> Self {
        Self::generate(None, true)
    }
}

impl VerifierSeed {
    /// Load the app verifier seed from a data-dir sidecar if present; otherwise generate a seed that
    /// will be saved lazily before the first hardened verifier is committed. Startup stays
    /// read-only-friendly, while credential mutation fails closed if the seed cannot be persisted.
    pub(crate) fn load_or_generate(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<VerifierSeedFile>(&bytes)
                .ok()
                .and_then(|file| decode_seed_file(&file))
            {
                Some(seed) => Self::from_bytes(seed, Some(path), true),
                None => {
                    eprintln!(
                        "warning: {} is not a valid password verifier seed config; generating a new seed",
                        path.display()
                    );
                    Self::generate(Some(path), false)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::generate(Some(path), false),
            Err(e) => {
                eprintln!(
                    "warning: failed to read password verifier seed config {} ({e}); generating a new seed",
                    path.display()
                );
                Self::generate(Some(path), false)
            }
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.inner.id
    }

    fn bytes(&self) -> &[u8; VERIFIER_SEED_BYTES] {
        &self.inner.bytes
    }

    pub(crate) fn ensure_saved(&self) -> Result<(), AttestationError> {
        let Some(path) = &self.inner.path else {
            return Ok(());
        };
        let mut saved = self
            .inner
            .saved
            .lock()
            .map_err(|_| AttestationError("verifier seed state lock poisoned".to_owned()))?;
        if *saved {
            return Ok(());
        }
        write_seed_file(path, self)?;
        *saved = true;
        Ok(())
    }

    fn generate(path: Option<PathBuf>, saved: bool) -> Self {
        let mut bytes = [0u8; VERIFIER_SEED_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes, path, saved)
    }

    fn from_bytes(bytes: [u8; VERIFIER_SEED_BYTES], path: Option<PathBuf>, saved: bool) -> Self {
        let id = seed_id(&bytes);
        register_seed(&id, bytes);
        VerifierSeed {
            inner: Arc::new(VerifierSeedInner {
                id,
                bytes,
                path,
                saved: Mutex::new(saved),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecretVerification {
    pub verified: bool,
    pub needs_upgrade: bool,
}

/// Hash a sign-in secret into a legacy argon2id PHC string. New user/recovery credential storage
/// should use [`hash_secret_with_seed`]; this helper remains for legacy tests and constant-work
/// dummy verifiers.
pub fn hash_secret(secret: &str) -> Result<String, AttestationError> {
    let salt = SaltString::generate(&mut SaltRng);
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(crypto)?
        .to_string())
}

/// Hash a sign-in/recovery secret into the hardened v1 verifier envelope.
pub(crate) fn hash_secret_with_seed(
    secret: &str,
    seed: &VerifierSeed,
) -> Result<String, AttestationError> {
    seed.ensure_saved()?;
    let mut pepper = [0u8; VERIFIER_PEPPER_BYTES];
    OsRng.fill_bytes(&mut pepper);
    let salt = SaltString::generate(&mut SaltRng);
    let input = verifier_input(secret, &pepper);
    let phc = seeded_argon2(seed.bytes())?
        .hash_password(&input, &salt)
        .map_err(crypto)?
        .to_string();
    Ok(format!(
        "{HARDENED_VERIFIER_PREFIX}{}${}${phc}",
        seed.id(),
        B64.encode(pepper)
    ))
}

/// Verify a sign-in/recovery secret and report whether the stored verifier should be rewritten to
/// the current hardened format. Legacy PHC strings remain readable and are marked for upgrade after
/// a successful proof.
pub(crate) fn verify_secret_with_seed(
    secret: &str,
    stored: &str,
    seed: &VerifierSeed,
) -> SecretVerification {
    if let Some(parsed) = parse_hardened_verifier(stored) {
        let verified = if parsed.seed_id == seed.id() {
            verify_hardened_parts(secret, &parsed, seed.bytes())
        } else {
            lookup_seed(parsed.seed_id)
                .map(|bytes| verify_hardened_parts(secret, &parsed, &bytes))
                .unwrap_or(false)
        };
        return SecretVerification {
            verified,
            needs_upgrade: verified && parsed.seed_id != seed.id(),
        };
    }

    let verified = verify_legacy_phc(secret, stored);
    SecretVerification {
        verified,
        needs_upgrade: verified,
    }
}

/// Verify a sign-in secret against a stored verifier. Supports legacy PHC strings and hardened v1
/// verifiers whose seed has been registered by a [`VerifierSeed`] loaded into this process. A
/// malformed stored hash verifies as `false` rather than erroring — the caller treats it as "wrong".
pub fn verify_secret(secret: &str, stored: &str) -> bool {
    if let Some(parsed) = parse_hardened_verifier(stored) {
        return lookup_seed(parsed.seed_id)
            .map(|bytes| verify_hardened_parts(secret, &parsed, &bytes))
            .unwrap_or(false);
    }
    verify_legacy_phc(secret, stored)
}

fn verify_legacy_phc(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => {
            #[cfg(test)]
            verify_probe::record("legacy", &parsed);
            Argon2::default()
                .verify_password(secret.as_bytes(), &parsed)
                .is_ok()
        }
        Err(_) => false,
    }
}

/// Test-only instrumentation over the argon2 password verifications this module actually performs.
///
/// It exists so the sign-in enumeration guarantee can be asserted *structurally* instead of with a
/// stopwatch: the unknown-identifier path must run the same number of argon2 verifications, at the
/// same cost parameters, as a wrong password against a real account. A wall-clock ratio would prove
/// the same thing but flakes under load, and a test that flakes gets deleted — taking the guarantee
/// with it.
///
/// The log is **thread-local**: `#[tokio::test]` runs a current-thread runtime, so a request driven
/// through `Router::oneshot` verifies on the calling test's own thread, and parallel tests cannot
/// contaminate each other's counts. Compiled only under `cfg(test)`, so production sign-in carries
/// no counter.
#[cfg(test)]
pub(crate) mod verify_probe {
    use std::cell::RefCell;

    use super::{Params, PasswordHash};

    /// One argon2 verification: which stored-verifier format it read, and the cost parameters that
    /// were really run (`0` if the PHC string did not carry them).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Verification {
        pub kind: &'static str,
        pub m_cost: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    thread_local! {
        static LOG: RefCell<Vec<Verification>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(kind: &'static str, hash: &PasswordHash<'_>) {
        let params = Params::try_from(hash).ok();
        LOG.with_borrow_mut(|log| {
            log.push(Verification {
                kind,
                m_cost: params.as_ref().map(Params::m_cost).unwrap_or(0),
                t_cost: params.as_ref().map(Params::t_cost).unwrap_or(0),
                p_cost: params.as_ref().map(Params::p_cost).unwrap_or(0),
            })
        });
    }

    /// Drain and return the verifications performed on this thread since the last drain.
    pub(crate) fn take() -> Vec<Verification> {
        LOG.with_borrow_mut(std::mem::take)
    }
}

struct ParsedHardenedVerifier<'a> {
    seed_id: &'a str,
    pepper: [u8; VERIFIER_PEPPER_BYTES],
    phc: &'a str,
}

fn parse_hardened_verifier(stored: &str) -> Option<ParsedHardenedVerifier<'_>> {
    let rest = stored.strip_prefix(HARDENED_VERIFIER_PREFIX)?;
    let (seed_id, rest) = rest.split_once('$')?;
    let (pepper_b64, phc) = rest.split_once('$')?;
    let pepper = decode_fixed::<VERIFIER_PEPPER_BYTES>(pepper_b64)?;
    Some(ParsedHardenedVerifier {
        seed_id,
        pepper,
        phc,
    })
}

fn verify_hardened_parts(
    secret: &str,
    parsed: &ParsedHardenedVerifier<'_>,
    seed: &[u8; VERIFIER_SEED_BYTES],
) -> bool {
    let Ok(phc) = PasswordHash::new(parsed.phc) else {
        return false;
    };
    #[cfg(test)]
    verify_probe::record("hardened", &phc);
    let input = verifier_input(secret, &parsed.pepper);
    seeded_argon2(seed)
        .and_then(|argon2| {
            argon2
                .verify_password(&input, &phc)
                .map_err(|e| AttestationError(e.to_string()))
        })
        .is_ok()
}

fn verifier_input(secret: &str, pepper: &[u8; VERIFIER_PEPPER_BYTES]) -> Vec<u8> {
    let secret = secret.as_bytes();
    let mut input = Vec::with_capacity(32 + 8 + secret.len() + 8 + pepper.len());
    input.extend_from_slice(b"chancela.secret.verifier.v1");
    input.extend_from_slice(&(secret.len() as u64).to_be_bytes());
    input.extend_from_slice(secret);
    input.extend_from_slice(&(pepper.len() as u64).to_be_bytes());
    input.extend_from_slice(pepper);
    input
}

fn seeded_argon2(seed: &[u8]) -> Result<Argon2<'_>, AttestationError> {
    Argon2::new_with_secret(seed, Algorithm::Argon2id, Version::V0x13, Params::default())
        .map_err(crypto)
}

fn seed_registry() -> &'static StdRwLock<HashMap<String, [u8; VERIFIER_SEED_BYTES]>> {
    static REGISTRY: OnceLock<StdRwLock<HashMap<String, [u8; VERIFIER_SEED_BYTES]>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| StdRwLock::new(HashMap::new()))
}

fn register_seed(id: &str, bytes: [u8; VERIFIER_SEED_BYTES]) {
    seed_registry()
        .write()
        .expect("verifier seed registry lock poisoned")
        .insert(id.to_owned(), bytes);
}

fn lookup_seed(id: &str) -> Option<[u8; VERIFIER_SEED_BYTES]> {
    seed_registry()
        .read()
        .expect("verifier seed registry lock poisoned")
        .get(id)
        .copied()
}

fn seed_id(seed: &[u8; VERIFIER_SEED_BYTES]) -> String {
    let digest: [u8; 32] = Sha256::digest(seed).into();
    crate::hex::hex(&digest)[..32].to_owned()
}

fn decode_seed_file(file: &VerifierSeedFile) -> Option<[u8; VERIFIER_SEED_BYTES]> {
    if file.schema_version != 1
        || file.kind != VERIFIER_SEED_KIND
        || file.purpose != VERIFIER_SEED_PURPOSE
    {
        return None;
    }
    let seed = decode_fixed::<VERIFIER_SEED_BYTES>(&file.seed_b64)?;
    let computed = seed_id(&seed);
    if file.seed_id != computed {
        eprintln!(
            "warning: password verifier seed config id mismatch; using the id derived from the seed"
        );
    }
    Some(seed)
}

fn decode_fixed<const N: usize>(b64: &str) -> Option<[u8; N]> {
    let bytes = B64.decode(b64).ok()?;
    bytes.try_into().ok()
}

fn write_seed_file(path: &Path, seed: &VerifierSeed) -> Result<(), AttestationError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(crypto)?;
    }
    let file = VerifierSeedFile {
        schema_version: 1,
        kind: VERIFIER_SEED_KIND.to_owned(),
        purpose: VERIFIER_SEED_PURPOSE.to_owned(),
        seed_id: seed.id().to_owned(),
        seed_b64: B64.encode(seed.bytes()),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(crypto)?;
    let tmp = seed_tmp_path(path);
    std::fs::write(&tmp, &json).map_err(crypto)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(crypto(e))
        }
    }
}

fn seed_tmp_path(path: &Path) -> PathBuf {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| VERIFIER_SEED_FILE.into());
    name.push(format!(".{:016x}.tmp", u64::from_be_bytes(random)));
    path.with_file_name(name)
}

// --- Recovery phrase (independent reset credential, t51 Phase B) ----------------------------

/// Bytes of entropy behind a recovery phrase: 20 bytes = **160 bits**, far beyond any offline
/// brute-force even before the argon2id verifier is considered.
const RECOVERY_ENTROPY_BYTES: usize = 20;

/// Crockford base32 alphabet (excludes `I`, `L`, `O`, `U` to avoid transcription ambiguity).
const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a fresh, human-transcribable recovery phrase: 160 bits of OS entropy encoded as
/// Crockford base32 (32 chars, no ambiguous letters, no padding) grouped `XXXXXXXX-XXXXXXXX-…`.
///
/// The phrase is an **independent** credential — it is NOT derived from, nor does it wrap, the
/// password. The server stores only its verifier ([`hash_secret_with_seed`] for new writes; legacy
/// PHC strings remain readable); the plaintext is shown to the user exactly once, at issuance, and
/// is unrecoverable thereafter.
pub fn generate_recovery_phrase() -> String {
    let mut bytes = [0u8; RECOVERY_ENTROPY_BYTES];
    OsRng.fill_bytes(&mut bytes);
    // 20 bytes = 160 bits, an exact multiple of 5, so base32 yields 32 chars with no leftover.
    let mut chars = String::with_capacity(32);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            chars.push(CROCKFORD_BASE32[idx] as char);
        }
    }
    chars
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).expect("base32 chars are ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Derive a 32-byte key-encryption key from the password and a per-key salt (separate from the
/// verification hash — plan §3). argon2id with the default params.
fn derive_kek(secret: &str, salt: &[u8]) -> Result<[u8; 32], AttestationError> {
    let mut kek = [0u8; 32];
    Argon2::default()
        .hash_password_into(secret.as_bytes(), salt, &mut kek)
        .map_err(crypto)?;
    Ok(kek)
}

// --- The wrapped attestation key ----------------------------------------------------------

/// The at-rest form of a user's attestation key, persisted in `users.json` (never on the wire).
///
/// Holds the **public** key (SEC1, base64) and its fingerprint in the clear, plus the 32-byte
/// P-256 secret scalar **wrapped** with XChaCha20-Poly1305 under a KEK derived from the user's
/// password + [`kdf_salt`](Self::kdf_salt). Without the password the scalar is unrecoverable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationKeyBlob {
    /// Base64 of the uncompressed SEC1 public key.
    pub public_key_sec1: String,
    /// Lowercase hex of `sha256(SEC1 public key)[..16]` — the 32-hex key fingerprint.
    pub fingerprint: String,
    /// Base64 of the per-key argon2 KEK salt (16 random bytes).
    pub kdf_salt: String,
    /// Base64 of the 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Base64 of the AEAD ciphertext wrapping the 32-byte secret scalar.
    pub ciphertext: String,
}

impl AttestationKeyBlob {
    /// Generate a fresh P-256 keypair and wrap its secret scalar under `secret`.
    pub fn generate(secret: &str) -> Result<Self, AttestationError> {
        let signing_key = SigningKey::random(&mut OsRng);
        let sec1 = sec1_bytes(signing_key.verifying_key());
        let fingerprint = fingerprint(&sec1);
        let scalar = signing_key.to_bytes();
        Self::wrap(secret, &sec1, &fingerprint, scalar.as_slice())
    }

    /// Wrap a known scalar/public-key pair under `secret` (used by [`generate`] and [`rewrap`]).
    fn wrap(
        secret: &str,
        sec1: &[u8],
        fingerprint: &str,
        scalar: &[u8],
    ) -> Result<Self, AttestationError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_kek(secret, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&kek).map_err(crypto)?;
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, scalar).map_err(crypto)?;
        Ok(AttestationKeyBlob {
            public_key_sec1: B64.encode(sec1),
            fingerprint: fingerprint.to_owned(),
            kdf_salt: B64.encode(salt),
            nonce: B64.encode(nonce_bytes),
            ciphertext: B64.encode(ciphertext),
        })
    }

    /// Decrypt the secret scalar with `secret` and reconstruct the in-memory signing key. The
    /// caller must have already verified `secret` against the user's PHC hash; an AEAD failure
    /// here therefore signals a corrupt blob (→ `500`), not a wrong password.
    pub fn unlock(&self, secret: &str) -> Result<SigningKey, AttestationError> {
        let salt = B64.decode(&self.kdf_salt).map_err(crypto)?;
        let kek = derive_kek(secret, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&kek).map_err(crypto)?;
        let nonce_bytes = B64.decode(&self.nonce).map_err(crypto)?;
        if nonce_bytes.len() != 24 {
            return Err(AttestationError("stored nonce is not 24 bytes".to_owned()));
        }
        let nonce = <&XNonce>::try_from(nonce_bytes.as_slice())
            .map_err(|_| AttestationError("stored nonce is not 24 bytes".to_owned()))?;
        let ciphertext = B64.decode(&self.ciphertext).map_err(crypto)?;
        let scalar = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(crypto)?;
        SigningKey::from_slice(&scalar).map_err(crypto)
    }

    /// Re-wrap the same keypair under a new password (verify-old happens at the call site). The
    /// public key and fingerprint are preserved, so previously-issued attestations still verify.
    pub fn rewrap(&self, old_secret: &str, new_secret: &str) -> Result<Self, AttestationError> {
        let signing_key = self.unlock(old_secret)?;
        let sec1 = B64.decode(&self.public_key_sec1).map_err(crypto)?;
        Self::wrap(
            new_secret,
            &sec1,
            &self.fingerprint,
            signing_key.to_bytes().as_slice(),
        )
    }

    /// The raw SEC1 public-key bytes, or `None` if the stored base64 is corrupt.
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        B64.decode(&self.public_key_sec1).ok()
    }

    /// The public half of this key, kept so the attestations it signed keep verifying once it is
    /// superseded (t92). See [`RetiredAttestationKey`].
    pub fn retire(&self, retired_at: String) -> RetiredAttestationKey {
        RetiredAttestationKey {
            public_key_sec1: self.public_key_sec1.clone(),
            fingerprint: self.fingerprint.clone(),
            retired_at,
        }
    }
}

/// The **public half only** of a superseded attestation key, retained so a rotation or a removal
/// stops destroying the account's attestation history (t92).
///
/// Verification needs exactly two things — the SEC1 public key and the fingerprint the attestation
/// records — and both are already public: they are stored in the clear in `users.json` and
/// published on the wire in `UserView`. The three fields of [`AttestationKeyBlob`] that constitute
/// the secret (`kdf_salt`, `nonce`, `ciphertext`, which together wrap the P-256 scalar) are
/// deliberately NOT carried over: a retired key can verify the past and can never sign again.
/// `retire_attestation_key_retains_no_secret_material` in `crates/chancela-api/tests` asserts the
/// stored shape rather than trusting this comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredAttestationKey {
    /// Base64 of the uncompressed SEC1 public key. No private component.
    pub public_key_sec1: String,
    /// The 32-hex fingerprint attestations signed by this key carry.
    pub fingerprint: String,
    /// RFC 3339 instant the key stopped being the user's current key.
    pub retired_at: String,
}

impl RetiredAttestationKey {
    /// The raw SEC1 public-key bytes, or `None` if the stored base64 is corrupt.
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        B64.decode(&self.public_key_sec1).ok()
    }
}

/// Uncompressed SEC1 encoding of a P-256 public key.
fn sec1_bytes(vk: &VerifyingKey) -> Vec<u8> {
    vk.to_encoded_point(false).as_bytes().to_vec()
}

/// The 32-hex key fingerprint: lowercase hex of `sha256(SEC1 public key)[..16]` (plan §4.3,
/// frozen so the UI and the verify endpoint agree).
pub fn fingerprint(sec1: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(sec1).into();
    crate::hex::hex(&digest)[..32].to_owned()
}

/// The fingerprint of an in-memory signing key (its public key's [`fingerprint`]).
pub fn key_fingerprint(key: &SigningKey) -> String {
    fingerprint(&sec1_bytes(key.verifying_key()))
}

// --- The attestation record ---------------------------------------------------------------

/// A per-event signature binding a ledger event's chain hash to the user who was signed in with
/// an unlocked attestation key when the event was recorded (plan §4.4). Lives in the in-memory
/// sidecar keyed by `event_seq`; never touches the `chancela-ledger` crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The ledger `seq` of the attested event (the sidecar key).
    pub event_seq: u64,
    /// The attested event's id (uuid).
    pub event_id: String,
    /// The attested event's chain hash (64-hex) — what was actually signed.
    pub event_hash: String,
    /// The username of the session that produced the signature.
    pub username: String,
    /// The signing key's fingerprint (32-hex).
    pub fingerprint: String,
    /// The signature algorithm ([`ALGORITHM`]).
    pub algorithm: String,
    /// Base64 of the DER-encoded ECDSA signature over `event_hash`.
    pub signature: String,
    /// When the attestation was produced (RFC 3339 UTC).
    pub created_at: String,
}

/// Sign a just-appended ledger event's chain `hash` with an unlocked key, producing an
/// [`Attestation`]. Returns `None` on a signing failure — attestation is best-effort enrichment
/// and must never block the mutation it accompanies (plan §4.4).
pub fn sign_event(key: &SigningKey, username: &str, event: &Event) -> Option<Attestation> {
    let sig: Signature = key.sign_prehash(&event.hash).ok()?;
    Some(Attestation {
        event_seq: event.seq,
        event_id: event.id.to_string(),
        event_hash: crate::hex::hex(&event.hash),
        username: username.to_owned(),
        fingerprint: key_fingerprint(key),
        algorithm: ALGORITHM.to_owned(),
        signature: B64.encode(sig.to_der().as_bytes()),
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
    })
}

/// Verify an attestation's signature over its stored `event_hash` with a SEC1 public key. Does
/// **not** check that the hash matches the live ledger — that binding is the caller's job (plan
/// §4.6). Returns `false` on any decode/parse/verify failure.
pub fn verify_signature(att: &Attestation, sec1_pubkey: &[u8]) -> bool {
    let Some(hash) = crate::hex::parse_hex32(&att.event_hash) else {
        return false;
    };
    let Ok(der) = B64.decode(&att.signature) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(&der) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_sec1_bytes(sec1_pubkey) else {
        return false;
    };
    vk.verify_prehash(&hash, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(hash: [u8; 32]) -> Event {
        // Build a real event via the ledger so `hash`/`seq`/`id` are populated the same way
        // production does, then override the hash for the tamper test.
        let mut ledger = chancela_ledger::Ledger::new();
        ledger.append("amelia", "book:1", "act.sealed", None, b"payload");
        let mut ev = ledger.events()[0].clone();
        ev.hash = hash;
        ev
    }

    #[test]
    fn secret_hash_round_trips_and_rejects_wrong() {
        let phc = hash_secret("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2"));
        assert!(verify_secret("correct horse battery", &phc));
        assert!(!verify_secret("wrong", &phc));
    }

    #[test]
    fn hardened_secret_verifier_uses_seed_pepper_and_salt() {
        let seed = VerifierSeed::default();
        let first = hash_secret_with_seed("same-password", &seed).unwrap();
        let second = hash_secret_with_seed("same-password", &seed).unwrap();

        assert!(first.starts_with(HARDENED_VERIFIER_PREFIX));
        assert!(first.contains("$argon2id$"));
        assert_ne!(first, second, "salt and pepper make each verifier unique");
        assert!(!first.contains("same-password"));

        let ok = verify_secret_with_seed("same-password", &first, &seed);
        assert!(ok.verified);
        assert!(!ok.needs_upgrade);
        assert!(!verify_secret_with_seed("wrong", &first, &seed).verified);

        let other_seed = VerifierSeed::default();
        let (_, rest) = first
            .strip_prefix(HARDENED_VERIFIER_PREFIX)
            .expect("hardened prefix")
            .split_once('$')
            .expect("seed id separator");
        let forged_seed_id = format!("{HARDENED_VERIFIER_PREFIX}{}${rest}", other_seed.id());
        assert!(
            !verify_secret_with_seed("same-password", &forged_seed_id, &other_seed).verified,
            "the app seed is part of the argon2 verifier input"
        );
    }

    #[test]
    fn legacy_phc_verifier_still_verifies_but_requests_upgrade() {
        let legacy = hash_secret("old-password").unwrap();
        let seed = VerifierSeed::default();

        let ok = verify_secret_with_seed("old-password", &legacy, &seed);
        assert!(ok.verified);
        assert!(ok.needs_upgrade);
        assert!(!verify_secret_with_seed("wrong", &legacy, &seed).verified);
    }

    #[test]
    fn recovery_phrase_is_high_entropy_and_hashes_independently() {
        let a = generate_recovery_phrase();
        let b = generate_recovery_phrase();
        // Shape: 32 base32 chars in four 8-char groups joined by '-'.
        assert_eq!(a.len(), 32 + 3);
        assert_eq!(a.split('-').count(), 4);
        assert!(a.split('-').all(|g| g.len() == 8));
        assert!(
            a.chars()
                .all(|c| c == '-' || CROCKFORD_BASE32.contains(&(c as u8))),
            "only Crockford base32 + separators: {a}"
        );
        // Two draws never collide (160 bits of entropy).
        assert_ne!(a, b);
        // Stored only as an argon2id verifier; the plaintext round-trips, a wrong guess fails.
        let phc = hash_secret(&a).unwrap();
        assert!(verify_secret(&a, &phc));
        assert!(!verify_secret(&b, &phc));
    }

    #[test]
    fn key_wraps_unlocks_and_signs() {
        let blob = AttestationKeyBlob::generate("s3cret-pass").unwrap();
        assert_eq!(blob.fingerprint.len(), 32);
        // Wrong password cannot unwrap the scalar.
        assert!(blob.unlock("nope").is_err());
        let key = blob.unlock("s3cret-pass").unwrap();

        let event = sample_event([9u8; 32]);
        let att = sign_event(&key, "amelia", &event).unwrap();
        assert_eq!(att.algorithm, "ES256");
        assert_eq!(att.event_seq, event.seq);
        // The signature carries the key's own fingerprint.
        assert_eq!(att.fingerprint, blob.fingerprint);
        // Verifies against the public key…
        let pk = blob.public_key_bytes().unwrap();
        assert!(verify_signature(&att, &pk));
        // …but not against a different key.
        let other = AttestationKeyBlob::generate("other").unwrap();
        assert!(!verify_signature(&att, &other.public_key_bytes().unwrap()));
    }

    #[test]
    fn tampered_event_hash_fails_verification() {
        let blob = AttestationKeyBlob::generate("pw").unwrap();
        let key = blob.unlock("pw").unwrap();
        let event = sample_event([1u8; 32]);
        let mut att = sign_event(&key, "u", &event).unwrap();
        // Flip the recorded hash: the signature no longer matches.
        att.event_hash = crate::hex::hex(&[2u8; 32]);
        assert!(!verify_signature(&att, &blob.public_key_bytes().unwrap()));
    }

    #[test]
    fn rewrap_preserves_key_identity() {
        let blob = AttestationKeyBlob::generate("old").unwrap();
        let rewrapped = blob.rewrap("old", "new").unwrap();
        // Same public key + fingerprint; a signature under the new password still verifies.
        assert_eq!(blob.fingerprint, rewrapped.fingerprint);
        assert_eq!(blob.public_key_sec1, rewrapped.public_key_sec1);
        assert!(rewrapped.unlock("old").is_err());
        let key = rewrapped.unlock("new").unwrap();
        let event = sample_event([7u8; 32]);
        let att = sign_event(&key, "u", &event).unwrap();
        assert!(verify_signature(
            &att,
            &rewrapped.public_key_bytes().unwrap()
        ));
    }
}
