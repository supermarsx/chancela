//! Offline, deterministic unit tests for the CAdES-B build/validate round-trip.
//!
//! Test certificates and keys are generated ephemerally in-test (no private keys are checked in,
//! per `.orchestration/plans/t4.md` §6). Both supported profiles are exercised:
//! RSA-PKCS1-SHA256 (Cartão de Cidadão v1 / Chave Móvel Digital) and ECDSA-P256-SHA256 (CC v2).
//!
//! These tests live in-crate (not under `tests/`) so they can reach the crate's own crypto
//! dependencies (`rsa`, `p256`, `x509-cert`, `der`) — integration tests only see dev-dependencies.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::asn1::{Any, BitString};
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::attrs::{SigningCertificateV2, sha256};
use crate::oids;
use crate::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest, validate_cades_b,
};

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// A test signer bundling an ephemeral key and its self-signed certificate.
enum TestSigner {
    Rsa {
        // Boxed: an `RsaPrivateKey` is much larger than the ECDSA key (clippy large_enum_variant).
        key: Box<rsa::RsaPrivateKey>,
        cert_der: Vec<u8>,
    },
    Ecdsa {
        key: p256::ecdsa::SigningKey,
        cert_der: Vec<u8>,
    },
}

impl TestSigner {
    fn new_rsa(cn: &str, serial: u8) -> Self {
        use rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&key);
        let spki = SubjectPublicKeyInfoOwned::from_key(public).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: oids::SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        };
        let signer_key = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer_key, &sha256(tbs))
        });
        Self::Rsa {
            key: Box::new(key),
            cert_der,
        }
    }

    fn new_ecdsa(cn: &str, serial: u8) -> Self {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use rsa::rand_core::OsRng;
        let key = SigningKey::random(&mut OsRng);
        let verifying = *key.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(verifying).expect("ec spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: oids::ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signer_key = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            let sig: p256::ecdsa::Signature = signer_key.sign(tbs);
            sig.to_der().as_bytes().to_vec()
        });
        Self::Ecdsa { key, cert_der }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            TestSigner::Rsa { .. } => SignatureAlgorithm::RsaPkcs1Sha256,
            TestSigner::Ecdsa { .. } => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }

    fn cert_der(&self) -> Vec<u8> {
        match self {
            TestSigner::Rsa { cert_der, .. } | TestSigner::Ecdsa { cert_der, .. } => {
                cert_der.clone()
            }
        }
    }

    /// Sign a 32-byte digest exactly as the real token/remote signer would:
    /// RSA → PKCS#1 v1.5 over `DigestInfo(sha256, digest)`; ECDSA → raw over the prehash,
    /// DER-encoded (r, s).
    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        match self {
            TestSigner::Rsa { key, .. } => sign_rsa_digest_info(key, digest),
            TestSigner::Ecdsa { key, .. } => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature =
                    key.sign_prehash(digest).expect("ecdsa prehash sign");
                sig.to_der().as_bytes().to_vec()
            }
        }
    }

    fn raw_signature(&self, digest: &[u8; 32]) -> RawSignature {
        RawSignature::new(
            self.algorithm(),
            self.sign_digest(digest),
            self.cert_der(),
            vec![],
        )
    }
}

fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

/// Hand-build and self-sign a minimal X.509 v3 certificate. We construct the TBS directly and
/// sign it with the raw primitive rather than going through `x509-cert`'s `CertificateBuilder`,
/// which would require `sha2/oid` (not enabled in this workspace) for the RSA signer.
fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let name = Name::from_str(&format!("CN={cn}")).expect("name");
    let validity = Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature = sign(&tbs_der);
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    };
    cert.to_der().expect("cert der")
}

fn fixed_time() -> time::OffsetDateTime {
    // 2025-06-15T14:26:40Z — inside the UTCTime window, whole seconds (round-trips exactly).
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

fn roundtrip(signer: &TestSigner) {
    let content = b"Chancela: livro de atas, ato numero 42";
    let content_digest = sha256(content);
    let signing_time = fixed_time();

    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), signing_time)
        .expect("signed attrs digest");
    let raw = signer.raw_signature(&digest);
    let cms = assemble_cades_b(&raw, &content_digest, signing_time).expect("assemble");

    let validation = validate_cades_b(&cms, &content_digest).expect("validate");
    assert!(validation.attrs_ok);
    assert!(
        validation.signing_certificate_v2_present,
        "CAdES-B requires signing-certificate-v2"
    );
    assert_eq!(
        validation
            .signing_time
            .expect("signing time")
            .unix_timestamp(),
        1_750_000_000
    );
    assert_eq!(validation.signer_cert_der, signer.cert_der());
}

#[test]
fn rsa_roundtrip_validates() {
    roundtrip(&TestSigner::new_rsa("Chancela RSA Test", 1));
}

#[test]
fn ecdsa_roundtrip_validates() {
    roundtrip(&TestSigner::new_ecdsa("Chancela P256 Test", 2));
}

#[test]
fn signed_attributes_digest_is_deterministic() {
    let signer = TestSigner::new_ecdsa("Determinism", 3);
    let content_digest = sha256(b"same content");
    let t = fixed_time();
    let a = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();
    let b = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();
    assert_eq!(
        a, b,
        "identical inputs must yield identical signed-attrs digest"
    );
}

#[test]
fn tampered_content_digest_is_rejected() {
    let signer = TestSigner::new_rsa("Tamper Content", 4);
    let content_digest = sha256(b"original content");
    let t = fixed_time();
    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();
    let raw = signer.raw_signature(&digest);
    let cms = assemble_cades_b(&raw, &content_digest, t).unwrap();

    // Validate against a *different* content digest → message-digest attribute mismatch.
    let other_digest = sha256(b"a different document entirely");
    let err = validate_cades_b(&cms, &other_digest).unwrap_err();
    assert!(
        matches!(err, crate::CadesError::MessageDigestMismatch),
        "got {err:?}"
    );
}

#[test]
fn corrupted_signature_is_rejected() {
    let signer = TestSigner::new_rsa("Corrupt Sig", 5);
    let content_digest = sha256(b"content");
    let t = fixed_time();
    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();

    let mut raw = signer.raw_signature(&digest);
    let last = raw.signature.len() - 1;
    raw.signature[last] ^= 0xff; // flip bits in the signature value
    let cms = assemble_cades_b(&raw, &content_digest, t).unwrap();

    assert!(validate_cades_b(&cms, &content_digest).is_err());
}

#[test]
fn signing_time_mismatch_breaks_signature() {
    // If the signer signs attributes for time T but the CMS is assembled with time T', the
    // embedded attributes no longer hash to what was signed → signature must fail.
    let signer = TestSigner::new_ecdsa("Time Mismatch", 6);
    let content_digest = sha256(b"content");
    let signed_at = fixed_time();
    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), signed_at).unwrap();
    let raw = signer.raw_signature(&digest);

    let assembled_at = time::OffsetDateTime::from_unix_timestamp(1_750_000_999).unwrap();
    let cms = assemble_cades_b(&raw, &content_digest, assembled_at).unwrap();

    assert!(validate_cades_b(&cms, &content_digest).is_err());
}

#[test]
fn signer_cert_mismatch_is_rejected() {
    // Signature produced by signer A's key, but the embedded certificate is signer B's.
    let signer_a = TestSigner::new_rsa("Signer A", 7);
    let signer_b = TestSigner::new_rsa("Signer B", 8);
    let content_digest = sha256(b"content");
    let t = fixed_time();

    // Attributes digest is computed over B's certificate (so ESSCertIDv2/sid reference B), and
    // signed with A's key → B's public key cannot verify it.
    let digest = signed_attributes_digest(&content_digest, &signer_b.cert_der(), t).unwrap();
    let raw = RawSignature::new(
        signer_a.algorithm(),
        signer_a.sign_digest(&digest),
        signer_b.cert_der(),
        vec![],
    );
    let cms = assemble_cades_b(&raw, &content_digest, t).unwrap();

    assert!(matches!(
        validate_cades_b(&cms, &content_digest).unwrap_err(),
        crate::CadesError::SignatureVerification
    ));
}

#[test]
fn ess_certid_v2_binds_the_signing_certificate() {
    // The signing-certificate-v2 attribute must carry SHA-256(signing cert).
    let signer = TestSigner::new_ecdsa("ESS Bind", 9);
    let content_digest = sha256(b"content");
    let t = fixed_time();
    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();
    let raw = signer.raw_signature(&digest);
    let cms = assemble_cades_b(&raw, &content_digest, t).unwrap();

    // Re-parse and pull the ESSCertIDv2 out of the signed attributes.
    let ci = cms::content_info::ContentInfo::from_der(&cms).unwrap();
    let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
    let si = sd.signer_infos.0.iter().next().unwrap();
    let attrs = si.signed_attrs.as_ref().unwrap();
    let ess_value = attrs
        .iter()
        .find(|a| a.oid == oids::ID_AA_SIGNING_CERTIFICATE_V2)
        .and_then(|a| a.values.iter().next().cloned())
        .expect("signing-certificate-v2 present");
    let ess = SigningCertificateV2::from_der(&ess_value.to_der().unwrap()).unwrap();
    let cert_hash = ess.certs[0].cert_hash.as_bytes();
    assert_eq!(cert_hash, sha256(&signer.cert_der()).as_slice());
    assert!(
        ess.certs[0].hash_algorithm.is_none(),
        "SHA-256 is the default and must be omitted (canonical DER)"
    );
}

#[test]
fn outer_content_type_is_signed_data() {
    let signer = TestSigner::new_rsa("Outer", 10);
    let content_digest = sha256(b"content");
    let t = fixed_time();
    let digest = signed_attributes_digest(&content_digest, &signer.cert_der(), t).unwrap();
    let raw = signer.raw_signature(&digest);
    let cms = assemble_cades_b(&raw, &content_digest, t).unwrap();

    let ci = cms::content_info::ContentInfo::from_der(&cms).unwrap();
    assert_eq!(ci.content_type, oids::ID_SIGNED_DATA);
}
