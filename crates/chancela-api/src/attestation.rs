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
//!   (a PHC string) and, separately, a 32-byte **KEK** derived from the password + a per-key salt
//!   via `hash_password_into`.
//! - **XChaCha20-Poly1305** wraps the 32-byte P-256 secret scalar under the KEK — pure-Rust, no
//!   AES-NI-detection surface, and its 24-byte random nonce removes all nonce-management burden.
//! - **P-256** ECDSA (ES256 semantics) signs each ledger event's chain `hash` via
//!   `sign_prehash` (the event hash *is* the prehash); verified with `verify_prehash`.

use argon2::password_hash::rand_core::OsRng as SaltRng;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
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

/// Hash a sign-in secret into an argon2id PHC string for storage in `users.json`.
pub fn hash_secret(secret: &str) -> Result<String, AttestationError> {
    let salt = SaltString::generate(&mut SaltRng);
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(crypto)?
        .to_string())
}

/// Verify a sign-in secret against a stored argon2id PHC string. A malformed stored hash (should
/// never happen) verifies as `false` rather than erroring — the caller treats it as "wrong".
pub fn verify_secret(secret: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
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
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), scalar)
            .map_err(crypto)?;
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
        let ciphertext = B64.decode(&self.ciphertext).map_err(crypto)?;
        let scalar = cipher
            .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_slice())
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
