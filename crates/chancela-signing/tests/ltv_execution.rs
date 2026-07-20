//! End-to-end PAdES-LT / LTA *execution* tests (t67-e5).
//!
//! These drive the real long-term-validation pipeline, not caller-supplied-evidence passthrough:
//! sign a PDF (B-B), fetch validated CRL revocation evidence over a mock transport, embed it as a
//! `/DSS` + `/VRI` revision (LT), produce a `/DocTimeStamp` archive timestamp over that revision
//! (LTA), and then renew — appending a second `/DSS` + `/DocTimeStamp` revision. Every assertion is
//! about evidence that was actually embedded; no legal sufficiency is claimed.
//!
//! The signer/issuer certificates and the CRL are minted ephemerally in-test (no private keys are
//! checked in, plan §6). The archive timestamp is produced by a mock TSA that replays the bundled
//! `chancela-tsa` OpenSSL fixture with its message imprint rewritten to the revision digest, so the
//! embedded `/DocTimeStamp` imprint validates against the revision it covers (mirrors the technique
//! in `chancela-pades/src/tests.rs`).

use std::str::FromStr;
use std::time::{Duration as StdDuration, SystemTime};

use der::asn1::{Any, BitString, Ia5String, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, rand_core::OsRng};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::crl::{CertificateList, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::crl::CrlDistributionPoints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use chancela_signing::pipeline::{execute_pdf_lta, renew_pdf_ltv};
use chancela_signing::{
    EvidentiaryLevel, MockProvider, RevocationError, RevocationEvidenceProvider,
    RevocationFetchLimits, RevocationHttpResponse, RevocationHttpTransport, SignOptions,
    SignatureAlgorithm, SigningError, SigningFamily, Timestamp, TimestampProvider, sign_pdf_pades,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Validation time and CRL freshness window: this_update = T-1h, nextUpdate = T+1h.
const VALIDATION_UNIX: i64 = 1_750_000_000;
const CRL_URL: &str = "http://crl.chancela.example/test.crl";

// --- Certificate + CRL minting -------------------------------------------------------------------

fn sha256_rsa_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA,
        parameters: Some(Any::null()),
    }
}

fn spki_of(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(
        RsaPublicKey::from(key)
            .to_public_key_der()
            .expect("public key der")
            .as_bytes(),
    )
    .expect("spki")
}

fn rsa_sign_sha256(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
    digest_info.extend_from_slice(&Sha256::digest(message));
    key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info)
        .expect("rsa sign")
}

fn crl_dp_extension(url: &str) -> Extension {
    let cdp = CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(Ia5String::new(url).expect("ia5 uri")),
        ])),
        reasons: None,
        crl_issuer: None,
    }]);
    Extension {
        extn_id: OID_CRL_DISTRIBUTION_POINTS,
        critical: false,
        extn_value: OctetString::new(cdp.to_der().expect("cdp der")).expect("ext value"),
    }
}

fn build_cert(
    subject: &Name,
    issuer: &Name,
    serial: u8,
    key: &RsaPrivateKey,
    extensions: Option<Vec<Extension>>,
) -> Vec<u8> {
    let sig_alg = sha256_rsa_alg();
    let validity = Validity::from_now(StdDuration::from_secs(3650 * 24 * 3600)).expect("validity");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: sig_alg.clone(),
        issuer: issuer.clone(),
        validity,
        subject: subject.clone(),
        subject_public_key_info: spki_of(key),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };
    // Self-signed shape: the certificate signature is not validated by the CRL/DSS path, so any
    // well-formed signature bytes suffice for parsing (mirrors the crate's other in-test certs).
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&[0u8; 256]).expect("signature"),
    }
    .to_der()
    .expect("cert der")
}

fn crl_time(unix: i64) -> Time {
    let secs = u64::try_from(unix).expect("non-negative unix time");
    Time::try_from(SystemTime::UNIX_EPOCH + StdDuration::from_secs(secs)).expect("crl time")
}

/// Build a CRL issued by `issuer_name` and signed by `issuer_key`, revoking nothing, fresh at the
/// validation time. This passes every check in `RevocationEvidenceProvider` (issuer match,
/// freshness, empty revoked list, RSA-SHA256 signature).
fn build_signed_crl(issuer_name: &Name, issuer_key: &RsaPrivateKey) -> Vec<u8> {
    let tbs = TbsCertList {
        version: Version::V2,
        signature: sha256_rsa_alg(),
        issuer: issuer_name.clone(),
        this_update: crl_time(VALIDATION_UNIX - 3600),
        next_update: Some(crl_time(VALIDATION_UNIX + 3600)),
        revoked_certificates: None,
        crl_extensions: None,
    };
    let tbs_der = tbs.to_der().expect("crl tbs der");
    let signature = rsa_sign_sha256(issuer_key, &tbs_der);
    CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: sha256_rsa_alg(),
        signature: BitString::from_bytes(&signature).expect("crl signature"),
    }
    .to_der()
    .expect("crl der")
}

/// The full signer material: an RSA key, its certificate (carrying a CRL distribution point), the
/// issuer certificate, and a valid CRL fetched by URL.
struct SignerFixture {
    signer_key: RsaPrivateKey,
    signer_cert_der: Vec<u8>,
    issuer_cert_der: Vec<u8>,
    crl_der: Vec<u8>,
}

fn signer_fixture() -> SignerFixture {
    let issuer_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("issuer key");
    let signer_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("signer key");
    let issuer_name = Name::from_str("CN=Chancela Test CA").expect("issuer name");
    let signer_name = Name::from_str("CN=Chancela Test Signer").expect("signer name");

    let issuer_cert_der = build_cert(&issuer_name, &issuer_name, 1, &issuer_key, None);
    let signer_cert_der = build_cert(
        &signer_name,
        &issuer_name,
        7,
        &signer_key,
        Some(vec![crl_dp_extension(CRL_URL)]),
    );
    let crl_der = build_signed_crl(&issuer_name, &issuer_key);

    SignerFixture {
        signer_key,
        signer_cert_der,
        issuer_cert_der,
        crl_der,
    }
}

// --- Mock CRL transport --------------------------------------------------------------------------

struct MockCrlTransport {
    crl_der: Vec<u8>,
}

impl RevocationHttpTransport for MockCrlTransport {
    fn get_crl(
        &self,
        _url: &str,
        _limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError> {
        Ok(RevocationHttpResponse {
            status: 200,
            body: self.crl_der.clone(),
        })
    }

    fn post_ocsp(
        &self,
        _url: &str,
        _request_der: &[u8],
        _limits: &RevocationFetchLimits,
    ) -> Result<RevocationHttpResponse, RevocationError> {
        panic!("signer certificate has no OCSP AIA; the CRL path must be taken")
    }
}

// --- Mock TSA that stamps an arbitrary digest ----------------------------------------------------

/// The bundled `chancela-tsa` fixture token with its message imprint rewritten to `digest`, so the
/// produced `/DocTimeStamp` imprint binds the revision it covers.
fn patched_timestamp(digest: &[u8; 32]) -> Timestamp {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let request = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    let mut ts = tsa.stamp(&request).expect("fixture timestamp");
    let pos = ts
        .token_der
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present in token");
    ts.token_der[pos..pos + digest.len()].copy_from_slice(digest);
    ts
}

struct PatchingTsa;

impl TimestampProvider for PatchingTsa {
    fn timestamp_digest(&self, digest: &[u8; 32]) -> Result<Timestamp, SigningError> {
        Ok(patched_timestamp(digest))
    }

    fn timestamp_data(&self, data: &[u8]) -> Result<Timestamp, SigningError> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        Ok(patched_timestamp(&digest))
    }
}

// --- Base PDF (classic xref, mirrors the crate's other PDF tests) --------------------------------

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

fn base_pdf() -> Vec<u8> {
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

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(VALIDATION_UNIX).unwrap()
}

fn signer_provider(fixture: &SignerFixture) -> MockProvider {
    // CAdES hands the closure the signed-attributes digest to sign directly (RSA over its
    // DigestInfo — no re-hash), matching the crate's other RSA `MockProvider`s.
    let key = fixture.signer_key.clone();
    MockProvider::new(
        SigningFamily::CartaoDeCidadao,
        EvidentiaryLevel::Qualified,
        SignatureAlgorithm::RsaPkcs1Sha256,
        fixture.signer_cert_der.clone(),
        move |digest| {
            let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
            digest_info.extend_from_slice(digest);
            key.sign(Pkcs1v15Sign::new_unprefixed(), &digest_info)
                .map_err(|e| SigningError::Provider(e.to_string()))
        },
    )
}

// --- Tests ---------------------------------------------------------------------------------------

#[test]
fn execute_pdf_lta_embeds_revocation_and_archive_timestamp() {
    let fixture = signer_fixture();
    let provider = signer_provider(&fixture);
    let signed = sign_pdf_pades(
        &provider,
        &base_pdf(),
        fixed_time(),
        &SignOptions::default(),
    )
    .expect("sign PAdES B-B");

    let revocation = RevocationEvidenceProvider::new(
        MockCrlTransport {
            crl_der: fixture.crl_der.clone(),
        },
        RevocationFetchLimits::default(),
    );
    let tsa = PatchingTsa;

    let lta = execute_pdf_lta(
        &signed,
        &fixture.signer_cert_der,
        &fixture.issuer_cert_der,
        &revocation,
        fixed_time(),
        &tsa,
    )
    .expect("execute PAdES-LTA");

    // The fetched CRL landed in /DSS, keyed to the signature by a /VRI entry with /TU freshness.
    assert!(lta.dss.present, "DSS revision present");
    assert_eq!(lta.dss.crl_count(), 1, "one fetched CRL embedded");
    assert_eq!(lta.dss.ocsp_count(), 0, "CRL path, no OCSP");
    assert_eq!(
        lta.dss.certificate_count(),
        2,
        "signer + issuer certs embedded"
    );
    assert!(lta.dss.has_revocation_evidence());
    assert_eq!(lta.dss.vri_count, 1, "one VRI entry keyed to the signature");
    assert!(
        lta.dss.has_vri_tu(),
        "VRI carries /TU validation-time metadata"
    );

    // The CRL came back through validation, not passthrough.
    assert_eq!(lta.revocation.sources.len(), 1);
    assert_eq!(lta.revocation.sources[0].url, CRL_URL);
    assert!(lta.revocation.ocsp_sources.is_empty());

    // The archive /DocTimeStamp is present and its imprint binds the timestamped revision.
    assert!(lta.doc_timestamps.present, "archive timestamp present");
    assert_eq!(lta.doc_timestamps.count, 1);
    assert!(
        lta.doc_timestamps.all_imprints_valid(),
        "DocTimeStamp imprint binds the DSS revision"
    );
    assert!(!lta.archive_timestamp_token_der.is_empty());

    // Renewal appends a *second* DSS + DocTimeStamp revision, preserving the first.
    let renewal = renew_pdf_ltv(
        &lta.pdf,
        &fixture.signer_cert_der,
        &fixture.issuer_cert_der,
        &revocation,
        fixed_time(),
        &tsa,
    )
    .expect("renew PAdES LTV");

    assert!(renewal.pdf.len() > lta.pdf.len(), "renewal appended bytes");
    assert!(renewal.execution.embedded_dss_revocation_evidence());
    assert!(
        renewal.execution.embedded_valid_document_timestamp(),
        "renewal archive timestamp imprint is valid"
    );
    assert_eq!(
        renewal.execution.doc_timestamps.count, 2,
        "both archive timestamps are present after renewal"
    );
    assert!(
        renewal.execution.doc_timestamps.all_imprints_valid(),
        "the earlier archive timestamp still binds its revision after renewal"
    );
    assert!(!renewal.archive_timestamp_token_der.is_empty());
}

#[test]
fn execute_pdf_lta_reports_revoked_signer_honestly() {
    // A CRL that lists the signer's serial must abort LT execution with a revoked-signer error,
    // never silently produce "long-term" evidence.
    let fixture = signer_fixture();
    let issuer_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("issuer key");
    let issuer_name = Name::from_str("CN=Chancela Revoking CA").expect("issuer name");
    let revoking_issuer_cert = build_cert(&issuer_name, &issuer_name, 1, &issuer_key, None);

    // CRL that revokes serial 7 (the signer) and is signed by this issuer.
    let tbs = TbsCertList {
        version: Version::V2,
        signature: sha256_rsa_alg(),
        issuer: issuer_name.clone(),
        this_update: crl_time(VALIDATION_UNIX - 3600),
        next_update: Some(crl_time(VALIDATION_UNIX + 3600)),
        revoked_certificates: Some(vec![x509_cert::crl::RevokedCert {
            serial_number: SerialNumber::new(&[7]).expect("serial"),
            revocation_date: crl_time(VALIDATION_UNIX - 1800),
            crl_entry_extensions: None,
        }]),
        crl_extensions: None,
    };
    let tbs_der = tbs.to_der().expect("crl tbs der");
    let signature = rsa_sign_sha256(&issuer_key, &tbs_der);
    let crl_der = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: sha256_rsa_alg(),
        signature: BitString::from_bytes(&signature).expect("crl signature"),
    }
    .to_der()
    .expect("crl der");

    let provider = signer_provider(&fixture);
    let signed = sign_pdf_pades(
        &provider,
        &base_pdf(),
        fixed_time(),
        &SignOptions::default(),
    )
    .expect("sign PAdES B-B");
    let revocation = RevocationEvidenceProvider::new(
        MockCrlTransport { crl_der },
        RevocationFetchLimits::default(),
    );

    let err = execute_pdf_lta(
        &signed,
        &fixture.signer_cert_der,
        &revoking_issuer_cert,
        &revocation,
        fixed_time(),
        &PatchingTsa,
    )
    .unwrap_err();

    assert!(
        matches!(err, SigningError::Pades(ref msg) if msg.contains("revoked")),
        "revoked signer must fail LT execution honestly, got {err:?}"
    );
}
