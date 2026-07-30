//! Field encryption hook (spec 04 §1.3 / risk #6).
//!
//! The newer SCMD spec requires the mobile number, PIN, and OTP to be RSA-encrypted
//! with AMA's public certificate before being placed in the request. This is
//! config-gated: preprod runs cleartext; PROD requires the AMA cert. Because the
//! RSA PKCS#1 v1.5 encryption padding needs randomness and this crate does not pull
//! a `getrandom`-enabled RNG, the encryption entry points take a caller-supplied
//! [`CryptoRngCore`] (re-exported as [`crate::rand_core`]).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::DecodePem;
use der::Encode;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::CryptoRngCore;
use x509_cert::Certificate;

use crate::error::CmdError;

/// How sensitive request fields (phone, PIN, OTP) are represented on the wire.
///
/// - [`FieldEncryptor::Cleartext`] passes the value through unchanged (preprod only).
/// - [`FieldEncryptor::AmaRsa`] RSA-PKCS#1v1.5-encrypts the value with AMA's public key
///   and base64-encodes the ciphertext (required for PROD).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FieldEncryptor {
    /// No encryption — the field is sent as-is. Allowed only in preprod.
    Cleartext,
    /// Encrypt with AMA's RSA public key, then base64-encode.
    AmaRsa(RsaPublicKey),
}

impl FieldEncryptor {
    /// Build an [`FieldEncryptor::AmaRsa`] from AMA's field-encryption certificate (PEM).
    ///
    /// Extracts the RSA public key from the certificate's `SubjectPublicKeyInfo`.
    /// Returns [`CmdError::Encryption`] if the PEM is not a valid X.509 cert carrying
    /// an RSA key.
    ///
    /// The text goes through [`crate::normalize_certificate_pem`] first, so this accepts what an
    /// operator actually pasted — CRLF, a BOM, trailing spaces, a one-line block — while a
    /// difference that would change the decoded bytes is still refused, by name. The credential
    /// write path already stores the canonical form, so for a panel-configured deployment this is
    /// a no-op; it matters for `CHANCELA_CMD_AMA_CERT_PEM`, which reads a file straight off disk.
    pub fn from_ama_cert_pem(pem: &str) -> Result<Self, CmdError> {
        let normalized = crate::normalize_certificate_pem(pem)
            .map_err(|e| CmdError::Encryption(format!("invalid AMA certificate PEM: {e}")))?;
        let cert = Certificate::from_pem(normalized.pem().as_bytes())
            .map_err(|e| CmdError::Encryption(format!("invalid AMA certificate PEM: {e}")))?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CmdError::Encryption(format!("cannot encode AMA SPKI: {e}")))?;
        let key = RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| {
            CmdError::Encryption(format!("AMA certificate does not carry an RSA key: {e}"))
        })?;
        Ok(FieldEncryptor::AmaRsa(key))
    }

    /// Encrypt (or pass through) a single sensitive field.
    ///
    /// For [`FieldEncryptor::Cleartext`] the `rng` is unused and the plaintext is returned.
    /// For [`FieldEncryptor::AmaRsa`] the value is RSA-PKCS#1v1.5-encrypted and base64-encoded.
    pub fn encrypt<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        plaintext: &str,
    ) -> Result<String, CmdError> {
        match self {
            FieldEncryptor::Cleartext => Ok(plaintext.to_string()),
            FieldEncryptor::AmaRsa(key) => {
                let ct = key
                    .encrypt(rng, Pkcs1v15Encrypt, plaintext.as_bytes())
                    .map_err(|e| CmdError::Encryption(format!("RSA encryption failed: {e}")))?;
                Ok(STANDARD.encode(ct))
            }
        }
    }

    /// Whether this encryptor actually protects fields (true for [`FieldEncryptor::AmaRsa`]).
    pub fn is_encrypting(&self) -> bool {
        matches!(self, FieldEncryptor::AmaRsa(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::rand_core::{CryptoRng, RngCore, impls};

    /// A tiny deterministic xorshift RNG for offline crypto tests (NOT for production).
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    const AMA_CERT_PEM: &str = include_str!("../fixtures/ama_encryption_cert.pem");

    #[test]
    fn cleartext_passes_through() {
        let mut rng = TestRng(0x1234_5678_9abc_def0);
        let enc = FieldEncryptor::Cleartext;
        assert!(!enc.is_encrypting());
        assert_eq!(enc.encrypt(&mut rng, "123456").unwrap(), "123456");
    }

    #[test]
    fn ama_cert_pem_builds_encryptor() {
        let enc = FieldEncryptor::from_ama_cert_pem(AMA_CERT_PEM).unwrap();
        assert!(enc.is_encrypting());
        let mut rng = TestRng(0xdead_beef_0bad_f00d);
        // A 2048-bit key yields a 256-byte ciphertext -> 344 base64 chars (with padding).
        let out = enc.encrypt(&mut rng, "1234").unwrap();
        let decoded = STANDARD.decode(&out).unwrap();
        assert_eq!(decoded.len(), 256);
    }

    /// The signing path must accept the same dirt the admin panel does, and reach the same key.
    ///
    /// `CHANCELA_CMD_AMA_CERT_PEM` reads a file off the server's disk with no normalisation upstream
    /// of it, so this is the path where a CRLF checkout or a BOM would otherwise take production
    /// down with "invalid AMA certificate PEM".
    #[test]
    fn a_filthily_pasted_certificate_builds_the_same_key() {
        use rsa::traits::PublicKeyParts;

        let clean = match FieldEncryptor::from_ama_cert_pem(AMA_CERT_PEM).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => panic!("the fixture carries an RSA key, got {other:?}"),
        };
        let filthy = format!("\u{feff}{}", AMA_CERT_PEM.replace('\n', "  \r\n"));
        let dirty = match FieldEncryptor::from_ama_cert_pem(&filthy).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => {
                panic!("normalisation must not change what the certificate carries: {other:?}")
            }
        };
        assert_eq!(clean.n(), dirty.n());
        assert_eq!(clean.e(), dirty.e());
    }

    /// A defect that would change the bytes is still refused, and the message names it.
    #[test]
    fn a_corrupt_certificate_is_still_refused_with_a_reason() {
        let err = FieldEncryptor::from_ama_cert_pem(
            "-----BEGIN PRIVATE KEY-----\nMAoCAQE=\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("PRIVATE KEY"), "{message}");
    }

    #[test]
    fn rsa_encrypt_round_trips_with_private_key() {
        let mut rng = TestRng(0x00c0_ffee_00c0_ffee);
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let enc = FieldEncryptor::AmaRsa(RsaPublicKey::from(&priv_key));
        let ct_b64 = enc.encrypt(&mut rng, "990211").unwrap();
        let ct = STANDARD.decode(&ct_b64).unwrap();
        let pt = priv_key.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        assert_eq!(pt, b"990211");
    }
}
