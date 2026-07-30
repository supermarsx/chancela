//! Field encryption hook (spec 04 §1.3 / risk #6).
//!
//! The newer SCMD spec requires the mobile number, PIN, and OTP to be RSA-encrypted
//! with AMA's public key before being placed in the request. That key may be handed to an operator
//! inside an X.509 certificate or on its own as a `PUBLIC KEY` block; both are accepted and both
//! reduce to the same key, because the key is the only part of either artefact this uses. This is
//! config-gated: preprod runs cleartext; PROD requires the AMA cert. Because the
//! RSA PKCS#1 v1.5 encryption padding needs randomness and this crate does not pull
//! a `getrandom`-enabled RNG, the encryption entry points take a caller-supplied
//! [`CryptoRngCore`] (re-exported as [`crate::rand_core`]).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::CryptoRngCore;

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
    /// Build a [`FieldEncryptor::AmaRsa`] from AMA's field-encryption key material (PEM).
    ///
    /// Accepts **either** armour AMA's key can arrive in:
    ///
    /// - `-----BEGIN CERTIFICATE-----` — the RSA key is taken from the certificate's
    ///   `SubjectPublicKeyInfo`, as it always was;
    /// - `-----BEGIN PUBLIC KEY-----` — that `SubjectPublicKeyInfo` on its own.
    ///
    /// Both reach [`crate::NormalizedAmaKeyPem::spki_der`], so the two forms of one key provably
    /// build the same encryptor: the certificate around the key is never consulted here. Nothing on
    /// this path verifies a certificate, checks a signature, builds a chain or looks at the validity
    /// window — it never did, and widening the accepted armour does not change that. A caller that
    /// needs those facts stated must ask the inspection for them.
    ///
    /// Returns [`CmdError::Encryption`] if the PEM is not one of those two things carrying an RSA
    /// key, with a message naming which.
    ///
    /// The text goes through [`crate::normalize_ama_key_pem`] first, so this accepts what an
    /// operator actually pasted — CRLF, a BOM, trailing spaces, a one-line block — while a
    /// difference that would change the decoded bytes is still refused, by name. The credential
    /// write path already stores the canonical form, so for a panel-configured deployment this is
    /// a no-op; it matters for `CHANCELA_CMD_AMA_CERT_PEM`, which reads a file straight off disk.
    pub fn from_ama_key_pem(pem: &str) -> Result<Self, CmdError> {
        let normalized = crate::normalize_ama_key_pem(pem)
            .map_err(|e| CmdError::Encryption(format!("invalid AMA key material: {e}")))?;
        // The label is in the message because "does not carry an RSA key" is acted on differently
        // depending on which artefact the operator is holding.
        let label = normalized.kind().label();
        let key = RsaPublicKey::from_public_key_der(normalized.spki_der()).map_err(|e| {
            CmdError::Encryption(format!(
                "the AMA {label} block does not carry an RSA key: {e}"
            ))
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

    /// The fixture's key as a bare `PUBLIC KEY` block, built WITHOUT the code under test.
    ///
    /// This is the artefact an operator is handed when AMA sends the key rather than the
    /// certificate. It is derived here with `x509_cert`'s own reader and `der`'s own encoder, so the
    /// equivalence proof below does not lean on the normaliser to produce its own input.
    fn ama_public_key_pem() -> String {
        use der::DecodePem;
        use der::Encode;

        let spki = x509_cert::Certificate::from_pem(AMA_CERT_PEM.as_bytes())
            .expect("the fixture is a certificate")
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("its spki re-encodes");
        let body = STANDARD.encode(spki);
        let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PUBLIC KEY-----\n");
        out
    }

    #[test]
    fn cleartext_passes_through() {
        let mut rng = TestRng(0x1234_5678_9abc_def0);
        let enc = FieldEncryptor::Cleartext;
        assert!(!enc.is_encrypting());
        assert_eq!(enc.encrypt(&mut rng, "123456").unwrap(), "123456");
    }

    #[test]
    fn ama_cert_pem_builds_encryptor() {
        let enc = FieldEncryptor::from_ama_key_pem(AMA_CERT_PEM).unwrap();
        assert!(enc.is_encrypting());
        let mut rng = TestRng(0xdead_beef_0bad_f00d);
        // A 2048-bit key yields a 256-byte ciphertext -> 344 base64 chars (with padding).
        let out = enc.encrypt(&mut rng, "1234").unwrap();
        let decoded = STANDARD.decode(&out).unwrap();
        assert_eq!(decoded.len(), 256);
    }

    /// A bare `PUBLIC KEY` block is accepted, and is the SAME encryptor as the certificate.
    ///
    /// This is the claim the whole widening rests on. It is proved three ways over, because any one
    /// of them alone could pass while the encryptor still differed:
    ///
    /// 1. the public-key DER matches byte for byte;
    /// 2. modulus and exponent match;
    /// 3. the two encrypt a fixed plaintext to the identical ciphertext under an identically seeded
    ///    RNG — the only one of the three that exercises the value actually put on the wire.
    #[test]
    fn a_bare_public_key_builds_the_same_encryptor_as_the_certificate_it_came_from() {
        use rsa::pkcs8::EncodePublicKey;
        use rsa::traits::PublicKeyParts;

        let key_of = |pem: &str| match FieldEncryptor::from_ama_key_pem(pem).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => panic!("the fixture carries an RSA key, got {other:?}"),
        };
        let from_certificate = key_of(AMA_CERT_PEM);
        let from_public_key = key_of(&ama_public_key_pem());

        assert_eq!(
            from_certificate.to_public_key_der().unwrap().as_bytes(),
            from_public_key.to_public_key_der().unwrap().as_bytes(),
            "the two armours produced different public-key DER"
        );
        assert_eq!(from_certificate.n(), from_public_key.n());
        assert_eq!(from_certificate.e(), from_public_key.e());

        // Same seed, same plaintext, same ciphertext: PKCS#1 v1.5 padding is randomised, so this
        // holds only if the key AND the randomness are identical — which is exactly the claim.
        const SEED: u64 = 0x5eed_0f00_d5ee_d1e5;
        let ct_from_certificate = FieldEncryptor::AmaRsa(from_certificate)
            .encrypt(&mut TestRng(SEED), "912345678")
            .unwrap();
        let ct_from_public_key = FieldEncryptor::AmaRsa(from_public_key)
            .encrypt(&mut TestRng(SEED), "912345678")
            .unwrap();
        assert_eq!(ct_from_certificate, ct_from_public_key);
        assert_eq!(STANDARD.decode(&ct_from_certificate).unwrap().len(), 256);
    }

    /// A `PUBLIC KEY` block gets the same dirt tolerance as a certificate — one paste, one email.
    #[test]
    fn a_filthily_pasted_public_key_builds_the_same_key() {
        use rsa::traits::PublicKeyParts;

        let clean_pem = ama_public_key_pem();
        let key_of = |pem: &str| match FieldEncryptor::from_ama_key_pem(pem).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => panic!("expected an RSA key, got {other:?}"),
        };
        let clean = key_of(&clean_pem);
        let dirty = key_of(&format!("\u{feff}{}", clean_pem.replace('\n', "  \r\n")));
        assert_eq!(clean.n(), dirty.n());
        assert_eq!(clean.e(), dirty.e());
    }

    /// PKCS#1 is refused, and the refusal survives the wrapping this constructor puts around it.
    #[test]
    fn a_pkcs1_public_key_is_refused_with_the_conversion_stated() {
        let err = FieldEncryptor::from_ama_key_pem(
            "-----BEGIN RSA PUBLIC KEY-----\nMAoCAQE=\n-----END RSA PUBLIC KEY-----\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("RSA PUBLIC KEY"), "{message}");
        assert!(message.contains("SubjectPublicKeyInfo"), "{message}");
        assert!(message.contains("openssl"), "{message}");
    }

    /// The signing path must accept the same dirt the admin panel does, and reach the same key.
    ///
    /// `CHANCELA_CMD_AMA_CERT_PEM` reads a file off the server's disk with no normalisation upstream
    /// of it, so this is the path where a CRLF checkout or a BOM would otherwise take production
    /// down with "invalid AMA certificate PEM".
    #[test]
    fn a_filthily_pasted_certificate_builds_the_same_key() {
        use rsa::traits::PublicKeyParts;

        let clean = match FieldEncryptor::from_ama_key_pem(AMA_CERT_PEM).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => panic!("the fixture carries an RSA key, got {other:?}"),
        };
        let filthy = format!("\u{feff}{}", AMA_CERT_PEM.replace('\n', "  \r\n"));
        let dirty = match FieldEncryptor::from_ama_key_pem(&filthy).unwrap() {
            FieldEncryptor::AmaRsa(key) => key,
            other => {
                panic!("normalisation must not change what the certificate carries: {other:?}")
            }
        };
        assert_eq!(clean.n(), dirty.n());
        assert_eq!(clean.e(), dirty.e());
    }

    /// A defect that would change the bytes is still refused, and the message names it.
    ///
    /// A private key gets the loud refusal, unchanged by the wrapping this constructor puts around
    /// it: the text reached the server, and the sentence says so rather than filing it as a typo.
    #[test]
    fn a_corrupt_certificate_is_still_refused_with_a_reason() {
        let err = FieldEncryptor::from_ama_key_pem(
            "-----BEGIN PRIVATE KEY-----\nMAoCAQE=\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("PRIVATE KEY"), "{message}");
        assert!(message.contains("not stored"), "{message}");
        assert!(message.contains("rotate"), "{message}");
    }

    /// Something that is neither armour, and is not a private key, gets the plain refusal —
    /// which names both things this field DOES take and says nothing about private keys.
    #[test]
    fn an_unaccepted_label_names_both_armours_without_mentioning_private_keys() {
        let err = FieldEncryptor::from_ama_key_pem(
            "-----BEGIN DH PARAMETERS-----\nMAoCAQE=\n-----END DH PARAMETERS-----\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("DH PARAMETERS"), "{message}");
        assert!(message.contains("CERTIFICATE"), "{message}");
        assert!(message.contains("PUBLIC KEY"), "{message}");
        assert!(!message.contains("PRIVATE"), "{message}");
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
