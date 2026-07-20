//! Shared in-test helpers: an ephemeral RSA signer + a base PDF + CSC config/secrets, so the
//! offline tests produce a **cryptographically real** signature over the digest the client sends.
//!
//! Mirrors `chancela-signing/tests/remote_source.rs`. Fixtures use the fictional
//! "Encosto Estratégico Lda" / "Amélia Marques" — never a real entity.

#![allow(dead_code)]

use std::str::FromStr;
use std::time::Duration as StdDuration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{Any, BitString, ObjectIdentifier};
use der::pem::LineEnding;
use der::{Encode, EncodePem};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use chancela_csc::{CscAuthorization, CscConfig, CscSecrets};

pub const OID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
pub const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub const PROVIDER_ID: &str = "encosto-qtsp";
pub const CREDENTIAL_ID: &str = "cred-encosto-amelia-01";
pub const USER_REF: &str = "amelia.marques@encosto.example";
pub const PIN: &str = "271828";
pub const OTP: &str = "314159";

/// 2025-06-15T14:26:40Z — whole seconds, inside the CAdES UTCTime window.
pub fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

/// A sandbox CSC config for the fictional provider, service authorization.
pub fn test_config() -> CscConfig {
    CscConfig {
        provider_id: PROVIDER_ID.to_string(),
        display_name: "Encosto QTSP".to_string(),
        base_url: "https://sandbox.encosto.example/csc/v2".to_string(),
        authorization: CscAuthorization::Service,
        sandbox: true,
        credential_id: None,
        scope: chancela_csc::DEFAULT_SCOPE.to_string(),
    }
}

/// Service-authorization secrets (never real).
pub fn test_secrets() -> CscSecrets {
    CscSecrets::new("csc-client-id-test", "csc-client-secret-test")
}

/// An ephemeral in-test RSA signer + self-signed certificate.
pub struct RsaSigner {
    key: rsa::RsaPrivateKey,
    cert: Certificate,
}

impl RsaSigner {
    pub fn new(cn: &str, serial: u8) -> Self {
        use rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer = key.clone();
        let cert = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &Sha256::digest(tbs).into())
        });
        Self { key, cert }
    }

    pub fn cert_pem(&self) -> String {
        self.cert.to_pem(LineEnding::LF).expect("cert pem")
    }

    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.to_der().expect("cert der")
    }

    /// Base64-encoded DER, the shape a CSC `credentials/info` returns.
    pub fn cert_der_b64(&self) -> String {
        STANDARD.encode(self.cert_der())
    }

    /// Raw PKCS#1 v1.5 signature over the SHA-256 DigestInfo of `digest`.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        sign_rsa_digest_info(&self.key, digest)
    }
}

pub fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(digest);
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

fn build_self_signed(
    cn: &str,
    serial: u8,
    spki: SubjectPublicKeyInfoOwned,
    sig_alg: AlgorithmIdentifierOwned,
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Certificate {
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
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&signature).expect("bitstring"),
    }
}

/// A minimal classic-xref PDF that `chancela_pades::prepare_signature` accepts.
pub fn base_pdf() -> Vec<u8> {
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    )
}

fn assemble_pdf(objects: &[(u32, &str)], root: u32) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = buf.len();
    let max_id = objects.iter().map(|(id, _)| *id).max().unwrap();
    buf.extend_from_slice(format!("xref\n0 {}\n", max_id + 1).as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f\r\n");
    for id in 1..=max_id {
        let off = offsets
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, o)| *o)
            .unwrap();
        buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root {root} 0 R >>\n", max_id + 1).as_bytes(),
    );
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}
