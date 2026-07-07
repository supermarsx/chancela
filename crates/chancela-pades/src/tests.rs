//! Offline, deterministic round-trip tests for PAdES-B-B / B-T signing and validation.
//!
//! Signing keys and certificates are generated ephemerally in-test (no private keys are checked
//! in, per `.orchestration/plans/t4.md` §6), mirroring `chancela-cades/src/tests.rs`. Both CAdES
//! profiles are exercised: RSA-PKCS1-SHA256 and ECDSA-P256-SHA256. B-T uses the bundled
//! `chancela-tsa` OpenSSL fixture via `MockTsaTransport::from_fixture()`.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use sha2::{Digest, Sha256};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};

use crate::error::PadesError;
use crate::sign::MAX_CONTENTS_BYTES;
use crate::{SignOptions, add_signature_timestamp, sign_pdf, validate_pdf_signature};

// --- OIDs used only for the in-test self-signed certificates -------------------------------------

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn fixed_time() -> time::OffsetDateTime {
    // 2025-06-15T14:26:40Z — whole seconds, inside the UTCTime window.
    time::OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap()
}

// --- In-test signer (mirrors chancela-cades/src/tests.rs) ----------------------------------------

enum TestSigner {
    Rsa {
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
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            sign_rsa_digest_info(&signer, &sha256(tbs))
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
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("ec spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signer = key.clone();
        let cert_der = build_self_signed(cn, serial, spki, sig_alg, |tbs| {
            let sig: p256::ecdsa::Signature = signer.sign(tbs);
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

// --- Minimal base PDF (classic cross-reference table) --------------------------------------------

/// Assemble a minimal classic-xref PDF from `(id, dict-body)` object bodies (ids 1..=max, contiguous).
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

/// Sign `pdf` with `signer`, wiring the CAdES assembly into the signing callback.
fn sign_with(pdf: &[u8], signer: &TestSigner, opts: &SignOptions) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf(pdf, opts, |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf")
}

// --- Tests ---------------------------------------------------------------------------------------

#[test]
fn base_pdf_is_parseable() {
    let pdf = base_pdf();
    let doc = lopdf::Document::load_mem(&pdf).expect("base parses");
    assert_eq!(doc.max_id, 3);
}

#[test]
fn rsa_sign_validates() {
    let signer = TestSigner::new_rsa("PAdES RSA", 1);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
    assert!(report.cades.signing_certificate_v2_present);
    assert!(!report.has_signature_timestamp);
    assert_eq!(
        report.cades.signing_time.map(|t| t.unix_timestamp()),
        Some(1_750_000_000)
    );
}

#[test]
fn ecdsa_sign_validates() {
    let signer = TestSigner::new_ecdsa("PAdES P256", 2);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

#[test]
fn byte_range_excludes_exactly_the_contents_placeholder() {
    let signer = TestSigner::new_rsa("PAdES Range", 3);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // The excluded gap is exactly the `<` + hex placeholder + `>`.
    let report = validate_pdf_signature(&signed).unwrap();
    let excluded = report.total_len - report.covered_len;
    assert_eq!(excluded, MAX_CONTENTS_BYTES * 2 + 2, "gap = <..> inclusive");

    // ByteRange starts at 0 and its second range ends exactly at EOF.
    let [s1, l1, s2, l2] = report.byte_range;
    assert_eq!(s1, 0);
    assert_eq!((s2 + l2) as usize, report.total_len);
    // The gap boundary lines up with the '<' / '>' of /Contents.
    let lt = crate_find(&signed, b"/Contents <").unwrap() + b"/Contents ".len();
    assert_eq!(l1 as usize, lt, "range1 ends at the '<'");
    assert_eq!(
        s2 as usize,
        lt + 1 + MAX_CONTENTS_BYTES * 2 + 1,
        "range2 starts after '>'"
    );
}

#[test]
fn tampered_byte_in_range_fails_validation() {
    let signer = TestSigner::new_rsa("PAdES Tamper", 4);
    let mut signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // Flip a byte in the binary comment (offset 11) — inside ByteRange range1, keeps the PDF
    // parseable, so the failure is a digest mismatch (not a parse error).
    signed[11] ^= 0xff;
    let err = validate_pdf_signature(&signed).unwrap_err();
    assert!(
        matches!(
            err,
            PadesError::Cades(chancela_cades::CadesError::MessageDigestMismatch)
        ),
        "got {err:?}"
    );
}

#[test]
fn tampered_byte_after_gap_fails_validation() {
    let signer = TestSigner::new_ecdsa("PAdES Tamper2", 5);
    let mut signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // Flip a byte in the trailing incremental section (the last '%%EOF' region is in range2).
    let idx = signed.len() - 3;
    signed[idx] ^= 0xff;
    assert!(validate_pdf_signature(&signed).is_err());
}

#[test]
fn sign_options_are_emitted() {
    let signer = TestSigner::new_rsa("PAdES Opts", 6);
    let opts = SignOptions {
        field_name: Some("Assinatura".into()),
        signing_time: Some("D:20260706142640Z".into()),
        reason: Some("Ata aprovada".into()),
        location: Some("Lisboa".into()),
        contact_info: None,
    };
    let signed = sign_with(&base_pdf(), &signer, &opts);
    // Still valid, and the field name / reason are present in the bytes.
    validate_pdf_signature(&signed).expect("validate");
    assert!(crate_find(&signed, b"(Assinatura)").is_some());
    assert!(crate_find(&signed, b"(Ata aprovada)").is_some());
    assert!(crate_find(&signed, b"D:20260706142640Z").is_some());
}

#[test]
fn b_t_signature_timestamp_embeds_and_validates() {
    let signer = TestSigner::new_rsa("PAdES BT", 7);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    // Drive B-T from the bundled chancela-tsa OpenSSL fixture. The fixture covers a fixed digest;
    // the embedding logic under test is independent of which digest the token attests, so the
    // callback ignores the CMS-signature digest and stamps the fixture digest+nonce.
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    let with_ts = add_signature_timestamp(&signed, |_sig_digest| tsa.stamp(&req)).expect("B-T");

    let report = validate_pdf_signature(&with_ts).expect("validate B-T");
    assert!(
        report.has_signature_timestamp,
        "signature timestamp present"
    );
    // Adding the unsigned attribute must not disturb the ByteRange / B-B signature.
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

#[test]
fn validation_rejects_unsigned_pdf() {
    let err = validate_pdf_signature(&base_pdf()).unwrap_err();
    assert!(matches!(err, PadesError::NoSignature), "got {err:?}");
}

#[test]
fn signing_non_pdf_input_is_a_parse_error() {
    // Garbage bytes cannot be loaded as a PDF; signing must fail up front (before the callback).
    let err = sign_pdf(
        b"this is definitely not a PDF",
        &SignOptions::default(),
        |_| Ok::<_, std::io::Error>(Vec::new()),
    )
    .unwrap_err();
    assert!(matches!(err, PadesError::PdfParse(_)), "got {err:?}");
}

#[test]
fn a_failing_signing_callback_surfaces_as_signer_error() {
    // The ByteRange is computed successfully, then the caller's signing callback fails: the error
    // is carried through the boxed `Signer` variant rather than swallowed.
    let err = sign_pdf(&base_pdf(), &SignOptions::default(), |_digest| {
        Err(std::io::Error::other("card removed mid-sign"))
    })
    .unwrap_err();
    match err {
        PadesError::Signer(source) => {
            assert!(source.to_string().contains("card removed"));
        }
        other => panic!("expected Signer, got {other:?}"),
    }
}

#[test]
fn a_cms_larger_than_the_placeholder_is_rejected() {
    // A CMS exceeding the fixed 16 KiB `/Contents` placeholder cannot be embedded; the produced /
    // capacity sizes are reported so the caller can diagnose the overflow.
    let oversized = MAX_CONTENTS_BYTES + 1;
    let err = sign_pdf(&base_pdf(), &SignOptions::default(), move |_digest| {
        Ok::<_, std::io::Error>(vec![0u8; oversized])
    })
    .unwrap_err();
    match err {
        PadesError::ContentsPlaceholderTooSmall { produced, capacity } => {
            assert_eq!(produced, oversized);
            assert_eq!(capacity, MAX_CONTENTS_BYTES);
        }
        other => panic!("expected ContentsPlaceholderTooSmall, got {other:?}"),
    }
}

#[test]
fn a_pdf_with_an_existing_acroform_is_rejected() {
    // Phase-1 does not merge into a pre-existing form; a catalog already carrying an /AcroForm is a
    // `MalformedStructure` rejection, not a silent double-form.
    let pdf = assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
            (4, "<< /Fields [] /SigFlags 3 >>"),
        ],
        1,
    );
    let err = sign_pdf(&pdf, &SignOptions::default(), |_| {
        Ok::<_, std::io::Error>(Vec::new())
    })
    .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => assert!(msg.contains("AcroForm"), "got {msg}"),
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

/// Tiny helper: first occurrence of `needle` in `haystack` (tests avoid depending on `pdf` internals).
fn crate_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
