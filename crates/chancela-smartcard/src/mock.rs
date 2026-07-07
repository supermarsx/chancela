//! In-memory [`MockToken`] driving all offline unit tests.
//!
//! It stands in for a real Cartão de Cidadão so cert selection, RSA vs P-256
//! branching, ECDSA DER re-encoding, and error surfaces run in CI with no reader
//! (plan §3). The certificates are real DER fixtures (public certs only — no
//! private keys are checked in), so [`crate::crypto::algorithm_from_cert_der`]
//! assigns each token cert its algorithm exactly as the real token does.
//!
//! **The produced signature values are deterministic placeholders of the correct
//! shape, not cryptographically valid signatures** — the mock owns no private
//! key. Cryptographic round-trip verification is `chancela-cades`'s job (its
//! tests mint ephemeral keys). See `TESTING.md`.

use chancela_cades::{RawSignature, SignatureAlgorithm};
use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::SmartcardError;
use crate::token::{
    CertUsage, CryptoToken, LABEL_AUTH_CERT, LABEL_SIGNATURE_CERT, TokenCertificate,
};

/// A CC v1 (RSA-2048) signature certificate, DER (self-signed test fixture).
const FIXTURE_RSA_CERT: &[u8] = include_bytes!("../fixtures/cc_v1_signature_rsa2048.der");
/// A CC v2 (P-256) authentication certificate, DER (self-signed test fixture).
const FIXTURE_EC_CERT: &[u8] = include_bytes!("../fixtures/cc_v2_authentication_p256.der");

/// An in-memory [`CryptoToken`] for offline tests.
#[derive(Debug, Clone)]
pub struct MockToken {
    certificates: Vec<TokenCertificate>,
    /// When set, signing with the qualified-signature cert fails, simulating a
    /// card whose qualified signature was never activated (plan §1.2).
    signature_activated: bool,
}

impl MockToken {
    /// Build a mock from an explicit certificate list.
    #[must_use]
    pub fn with_certificates(certificates: Vec<TokenCertificate>) -> Self {
        Self {
            certificates,
            signature_activated: true,
        }
    }

    /// A CC **v1** card: RSA-2048 signature + authentication certificates
    /// (`CKM_RSA_PKCS` path).
    #[must_use]
    pub fn cartao_de_cidadao_v1() -> Self {
        Self::with_certificates(vec![
            token_cert(LABEL_SIGNATURE_CERT, FIXTURE_RSA_CERT),
            token_cert(LABEL_AUTH_CERT, FIXTURE_RSA_CERT),
        ])
    }

    /// A CC **v2** card (June 2024+): P-256 signature + authentication
    /// certificates (`CKM_ECDSA` path, DER re-encoding).
    #[must_use]
    pub fn cartao_de_cidadao_v2() -> Self {
        Self::with_certificates(vec![
            token_cert(LABEL_SIGNATURE_CERT, FIXTURE_EC_CERT),
            token_cert(LABEL_AUTH_CERT, FIXTURE_EC_CERT),
        ])
    }

    /// Simulate a card whose qualified signature has not been activated: signing
    /// with the signature cert then fails (auth still works).
    #[must_use]
    pub fn without_signature_activation(mut self) -> Self {
        self.signature_activated = false;
        self
    }
}

/// Parse a fixture into a [`TokenCertificate`], detecting its algorithm the same
/// way the real token does. Panics only on a broken build-time fixture.
fn token_cert(label: &str, der: &[u8]) -> TokenCertificate {
    let algorithm = crypto::algorithm_from_cert_der(der)
        .expect("bundled fixture certificate must have a supported key algorithm");
    TokenCertificate {
        label: label.to_owned(),
        cert_der: der.to_vec(),
        algorithm,
    }
}

impl CryptoToken for MockToken {
    fn list_certificates(&self) -> Result<Vec<TokenCertificate>, SmartcardError> {
        Ok(self.certificates.clone())
    }

    fn sign_digest(
        &self,
        cert: &TokenCertificate,
        digest: &[u8; 32],
    ) -> Result<RawSignature, SmartcardError> {
        // The cert must be one this card exposes (mimics "object not found").
        if !self.certificates.iter().any(|c| c.label == cert.label) {
            return Err(SmartcardError::CertificateNotFound(cert.label.clone()));
        }
        // Un-activated qualified signature fails at sign time, like real cards.
        if !self.signature_activated && cert.usage() == CertUsage::QualifiedSignature {
            return Err(SmartcardError::Pkcs11(
                "CKR_FUNCTION_FAILED: qualified signature not activated".to_owned(),
            ));
        }

        let signature = match cert.algorithm {
            SignatureAlgorithm::RsaPkcs1Sha256 => {
                // Shape of an RSA-2048 signature (256 bytes), derived from the
                // DigestInfo so different digests give different values.
                let digest_info = crypto::sha256_digest_info(digest);
                deterministic_bytes(&digest_info, 256)
            }
            SignatureAlgorithm::EcdsaP256Sha256 => {
                // Produce IEEE-P1363 r‖s and run it through the real re-encoder,
                // so the ECDSA DER path is exercised end to end.
                let raw = deterministic_p1363(digest);
                crypto::ecdsa_signature_to_der(&raw)?
            }
            other => {
                return Err(SmartcardError::UnsupportedKeyAlgorithm(format!(
                    "{other:?}"
                )));
            }
        };

        Ok(RawSignature::new(
            cert.algorithm,
            signature,
            cert.cert_der.clone(),
            Vec::new(),
        ))
    }
}

/// Deterministically expand `seed` into `n` bytes via chained SHA-256.
fn deterministic_bytes(seed: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut block = Sha256::digest(seed);
    while out.len() < n {
        out.extend_from_slice(&block);
        block = Sha256::digest(block);
    }
    out.truncate(n);
    out
}

/// Deterministic 64-byte IEEE-P1363 `r‖s` block for a P-256 mock signature.
fn deterministic_p1363(digest: &[u8; 32]) -> [u8; 64] {
    let r = Sha256::digest([digest.as_slice(), b"r"].concat());
    let s = Sha256::digest([digest.as_slice(), b"s"].concat());
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    out
}
