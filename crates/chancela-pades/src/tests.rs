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
use crate::renewal::{LtvRenewalDeadlineStatus, LtvRenewalPolicy, plan_ltv_renewal_with_policy};
use crate::sign::MAX_CONTENTS_BYTES;
use crate::validate::PdfSignatureCoverage;
use crate::{
    DocTimeStampFailureReason, DocTimeStampReport, DocTimeStampSemanticStatus, DssEvidence,
    DssReport, ImageSeal, LtvRenewalPlanAction, LtvRenewalPlanInput, LtvRenewalPlanScope,
    SealAppearance, SealContent, SealImageFormat, SealPlacement, SignOptions, TextSeal,
    add_doc_timestamp_revision, add_dss_revision, add_dss_revision_with_validation_time,
    add_signature_timestamp, inspect_doc_timestamps, inspect_dss,
    prepare_signature_with_appearance, sign_pdf, sign_pdf_with_appearance, validate_pdf_signature,
};

// --- OIDs used only for the in-test self-signed certificates -------------------------------------

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2).
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Public, synthetic DER fixture used as caller-supplied OCSP bytes in DSS tests. The PAdES layer
/// preserves DER blobs but does not semantically validate revocation protocol payloads.
const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];

/// Public, synthetic DER fixture used as caller-supplied CRL bytes in DSS tests.
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];

/// Public, synthetic complete DER fixture used as caller-supplied `/DocTimeStamp` token bytes.
const DOC_TIMESTAMP_TOKEN_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x07];

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

/// Sign `pdf` with `signer` placing a visible seal `appearance`.
fn sign_with_appearance(
    pdf: &[u8],
    signer: &TestSigner,
    opts: &SignOptions,
    appearance: &SealAppearance,
) -> Vec<u8> {
    let signing_time = fixed_time();
    let cert = signer.cert_der();
    sign_pdf_with_appearance(pdf, opts, Some(appearance), |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf_with_appearance")
}

/// A two-page classic-xref PDF (page objects 3 and 4; page index 1 = object 4).
fn base_pdf_two_pages() -> Vec<u8> {
    assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
            (
                4,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    )
}

/// Encode a 2×2 RGBA PNG (one fully transparent pixel, one semi-transparent) so the decode path
/// exercises the alpha → `/SMask` split.
fn tiny_rgba_png() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, 2, 2);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("png header");
        let data: [u8; 16] = [
            255, 0, 0, 255, // opaque red
            0, 255, 0, 128, // semi-transparent green
            0, 0, 255, 255, // opaque blue
            0, 0, 0, 0, // fully transparent
        ];
        writer.write_image_data(&data).expect("png data");
    }
    out
}

/// The signature widget annotation (the merged `/FT /Sig` + `/Subtype /Widget` field) of a signed
/// PDF, cloned out of the parsed document.
fn signature_widget(pdf: &[u8]) -> lopdf::Dictionary {
    let doc = lopdf::Document::load_mem(pdf).expect("parse signed PDF");
    doc.objects
        .values()
        .find_map(|obj| {
            let dict = obj.as_dict().ok()?;
            let is_widget = matches!(dict.get(b"Subtype").ok()?.as_name().ok(), Some(b"Widget"));
            let is_sig = matches!(
                dict.get(b"FT").ok().and_then(|o| o.as_name().ok()),
                Some(b"Sig")
            );
            (is_widget && is_sig).then(|| dict.clone())
        })
        .expect("signature widget present")
}

/// The four `/Rect` numbers of the signature widget.
fn widget_rect(widget: &lopdf::Dictionary) -> [f32; 4] {
    let arr = widget
        .get(b"Rect")
        .and_then(|o| o.as_array())
        .expect("Rect");
    assert_eq!(arr.len(), 4, "Rect has four numbers");
    // Whole-number coordinates serialize without a decimal point, so lopdf reparses them as
    // Integer; `as_float` accepts both Integer and Real.
    [
        arr[0].as_float().unwrap(),
        arr[1].as_float().unwrap(),
        arr[2].as_float().unwrap(),
        arr[3].as_float().unwrap(),
    ]
}

/// Assert the widget's `/AP /N` references a `/Subtype /Form` XObject in `pdf`, returning the
/// referenced object id.
fn assert_ap_is_form_xobject(pdf: &[u8], widget: &lopdf::Dictionary) -> (u32, u16) {
    let ap = widget
        .get(b"AP")
        .and_then(|o| o.as_dict())
        .expect("/AP dictionary present");
    let n_ref = ap
        .get(b"N")
        .and_then(|o| o.as_reference())
        .expect("/AP /N reference");
    let doc = lopdf::Document::load_mem(pdf).expect("parse signed PDF");
    let form = doc
        .get_object(n_ref)
        .and_then(|o| o.as_stream())
        .expect("/AP /N is a stream");
    assert_eq!(
        form.dict.get(b"Subtype").and_then(|o| o.as_name()).ok(),
        Some(b"Form".as_ref()),
        "appearance stream is a form XObject"
    );
    n_ref
}

fn add_fixture_timestamp(signed: &[u8]) -> Vec<u8> {
    // Drive B-T from the bundled chancela-tsa OpenSSL fixture. The fixture covers a fixed digest;
    // the embedding logic under test is independent of which digest the token attests, so the
    // callback ignores the CMS-signature digest and stamps the fixture digest+nonce.
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    add_signature_timestamp(signed, |_sig_digest| tsa.stamp(&req)).expect("B-T")
}

fn fixture_timestamp_token() -> Vec<u8> {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let req = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    tsa.stamp(&req).expect("fixture token").token_der
}

fn token_with_replaced_fixture_imprint(imprint: &[u8; 32]) -> Vec<u8> {
    let mut token = fixture_timestamp_token();
    let pos = token
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present");
    token[pos..pos + imprint.len()].copy_from_slice(imprint);
    token
}

fn doc_timestamp_token_for_revision(pdf: &[u8]) -> Vec<u8> {
    let placeholder =
        add_doc_timestamp_revision(pdf, &fixture_timestamp_token()).expect("placeholder DTS");
    let report = inspect_doc_timestamps(&placeholder).expect("inspect placeholder DTS");
    let digest = report.validations[0]
        .document_digest
        .expect("DocTimeStamp ByteRange digest");
    token_with_replaced_fixture_imprint(&digest)
}

fn fixture_dss_evidence(signer: &TestSigner) -> DssEvidence {
    let issuer = TestSigner::new_rsa("PAdES DSS Issuer", 42);
    DssEvidence {
        certificates: vec![signer.cert_der(), issuer.cert_der()],
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: vec![CRL_DER_FIXTURE.to_vec()],
    }
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
    assert!(!report.doc_timestamps.present);
    assert_eq!(
        report.ltv_renewal_plan.scope,
        LtvRenewalPlanScope::LocalTechnicalEvidenceOnly
    );
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::SignatureTimestamp,
            LtvRenewalPlanInput::DssRevocationEvidence,
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddSignatureTimestamp
    );
    assert!(report.ltv_renewal_plan.has_local_evidence_gap());
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
fn coverage_verdicts_distinguish_rendered_document_binding() {
    let signer = TestSigner::new_rsa("PAdES Coverage", 24);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let report = validate_pdf_signature(&signed).expect("validate whole-document signature");
    assert_eq!(report.coverage, PdfSignatureCoverage::WholeDocument);
    assert!(report.coverage.covers_rendered_document());

    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");
    let report = validate_pdf_signature(&with_dss).expect("validate LTV-augmented signature");
    assert_eq!(
        report.coverage,
        PdfSignatureCoverage::LtvAugmentedSignedRevision
    );
    assert!(report.coverage.covers_rendered_document());

    let content_override = append_object_override(
        &signed,
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
    );
    let report = validate_pdf_signature(&content_override).expect("validate altered PDF");
    assert_eq!(report.coverage, PdfSignatureCoverage::AlteredAfterSigning);
    assert!(!report.coverage.covers_rendered_document());
    assert!(report.covers_signed_revision_except_contents);
    assert!(report.has_later_incremental_updates);

    let overwide_gap = sign_with_overwide_gap(&signer);
    let report = validate_pdf_signature(&overwide_gap).expect("validate overwide ByteRange gap");
    assert_eq!(report.coverage, PdfSignatureCoverage::Malformed);
    assert!(!report.coverage.covers_rendered_document());
    assert!(!report.covers_signed_revision_except_contents);
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

    let with_ts = add_fixture_timestamp(&signed);

    let report = validate_pdf_signature(&with_ts).expect("validate B-T");
    assert!(
        report.has_signature_timestamp,
        "signature timestamp present"
    );
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::DssRevocationEvidence,
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::EmbedDssRevocationEvidence
    );
    // Adding the unsigned attribute must not disturb the ByteRange / B-B signature.
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());
}

#[test]
fn dss_revision_appends_to_b_t_and_reports_counts_hashes() {
    let signer = TestSigner::new_rsa("PAdES DSS", 8);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);

    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");
    let repeated = add_dss_revision(&with_ts, &evidence).expect("deterministic DSS append");

    assert_ne!(with_dss, with_ts);
    assert!(with_dss.starts_with(&with_ts));
    assert_eq!(with_dss, repeated);

    let report = validate_pdf_signature(&with_dss).expect("validate B-T + DSS");
    assert!(report.has_signature_timestamp);
    assert!(report.covers_signed_revision_except_contents);
    assert!(!report.covers_whole_file_except_contents);
    assert!(report.has_later_incremental_updates);
    assert_eq!(report.signed_revision_len, with_ts.len());
    assert_eq!(report.total_len, with_dss.len());
    assert!(report.dss.present);
    assert_eq!(report.dss.vri_count, 1);
    assert_eq!(report.dss.vri_keys.len(), 1);
    assert_eq!(report.dss.vri_keys[0].len(), 64);
    assert_eq!(report.dss.vri_tu_count, 0);
    assert!(report.dss.vri_tu_keys.is_empty());
    assert!(!report.dss.has_vri_tu());
    assert_eq!(report.dss.certificate_count(), 2);
    assert_eq!(report.dss.ocsp_count(), 1);
    assert_eq!(report.dss.crl_count(), 1);
    assert_eq!(report.dss.ocsp_hashes, vec![sha256(OCSP_DER_FIXTURE)]);
    assert_eq!(report.dss.crl_hashes, vec![sha256(CRL_DER_FIXTURE)]);
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![
            LtvRenewalPlanInput::DssValidationTime,
            LtvRenewalPlanInput::DocumentTimestamp,
        ]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::RecordDssValidationTime
    );

    let direct_dss = inspect_dss(&with_dss).expect("inspect DSS");
    assert_eq!(direct_dss, report.dss);
}

#[test]
fn doc_timestamp_revision_appends_and_reports_without_lta_claim() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp", 13);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");

    let with_doc_ts =
        add_doc_timestamp_revision(&with_dss, DOC_TIMESTAMP_TOKEN_DER_FIXTURE).expect("DTS append");
    let repeated =
        add_doc_timestamp_revision(&with_dss, DOC_TIMESTAMP_TOKEN_DER_FIXTURE).expect("repeat DTS");

    assert_ne!(with_doc_ts, with_dss);
    assert!(with_doc_ts.starts_with(&with_dss));
    assert_eq!(with_doc_ts, repeated);
    assert!(crate_find(&with_doc_ts, b"/Type /DocTimeStamp").is_some());
    assert!(crate_find(&with_doc_ts, b"/SubFilter /ETSI.RFC3161").is_some());

    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS revision");
    assert!(report.has_signature_timestamp);
    assert!(report.dss.present);
    assert!(report.covers_signed_revision_except_contents);
    assert!(!report.covers_whole_file_except_contents);
    assert!(report.has_later_incremental_updates);
    assert_eq!(report.total_len, with_doc_ts.len());
    assert_eq!(report.signed_revision_len, with_ts.len());
    assert!(report.doc_timestamps.present);
    assert_eq!(report.doc_timestamps.count, 1);
    assert_eq!(report.doc_timestamps.token_count(), 1);
    assert_eq!(
        report.doc_timestamps.token_hashes,
        vec![sha256(DOC_TIMESTAMP_TOKEN_DER_FIXTURE)]
    );
    assert_eq!(
        report.doc_timestamps.validations[0].status,
        DocTimeStampSemanticStatus::Failed
    );
    assert_eq!(
        report.doc_timestamps.validations[0].failure_reason,
        Some(DocTimeStampFailureReason::MalformedToken)
    );
    assert!(!report.doc_timestamps.all_imprints_valid());
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::ReviewDocumentTimestamp
    );
    assert!(
        report
            .ltv_renewal_plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::DocumentTimestampImprintBinding)
    );

    let direct = inspect_doc_timestamps(&with_doc_ts).expect("inspect DTS");
    assert_eq!(direct, report.doc_timestamps);
}

#[test]
fn doc_timestamp_reports_valid_rfc3161_imprint_binding() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp Valid", 15);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let token = doc_timestamp_token_for_revision(&signed);

    let with_doc_ts = add_doc_timestamp_revision(&signed, &token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS PDF");

    assert!(report.doc_timestamps.present);
    assert_eq!(report.doc_timestamps.count, 1);
    assert!(report.doc_timestamps.all_imprints_valid());
    let validation = &report.doc_timestamps.validations[0];
    assert_eq!(validation.status, DocTimeStampSemanticStatus::Valid);
    assert_eq!(validation.failure_reason, None);
    assert_eq!(
        validation.token_imprint.as_deref(),
        Some(validation.document_digest.as_ref().unwrap().as_slice())
    );
    assert_eq!(
        validation.token_hash_algorithm.as_deref(),
        Some("2.16.840.1.101.3.4.2.1")
    );
}

#[test]
fn doc_timestamp_reports_tampered_rfc3161_imprint_binding() {
    let signer = TestSigner::new_rsa("PAdES DocTimeStamp Tampered", 16);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let stale_token = fixture_timestamp_token();

    let with_doc_ts = add_doc_timestamp_revision(&signed, &stale_token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate DTS PDF");

    let validation = &report.doc_timestamps.validations[0];
    assert_eq!(validation.status, DocTimeStampSemanticStatus::Failed);
    assert_eq!(
        validation.failure_reason,
        Some(DocTimeStampFailureReason::ImprintMismatch)
    );
    assert_ne!(
        validation.token_imprint.as_deref(),
        Some(validation.document_digest.as_ref().unwrap().as_slice())
    );
    assert!(!report.doc_timestamps.all_imprints_valid());
}

#[test]
fn invalid_doc_timestamp_token_is_rejected() {
    let signer = TestSigner::new_rsa("PAdES Bad DocTimeStamp", 14);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let err = add_doc_timestamp_revision(&signed, b"not der").unwrap_err();
    assert!(
        matches!(err, PadesError::InvalidDocTimeStampToken),
        "got {err:?}"
    );
}

#[test]
fn dss_revision_keeps_signed_revision_tamper_detection() {
    let signer = TestSigner::new_rsa("PAdES DSS Tamper", 9);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let mut with_dss = add_dss_revision(&with_ts, &evidence).expect("DSS append");

    // Flip a byte in the signed revision. The later DSS revision remains parseable, but the
    // ByteRange digest no longer matches the embedded CMS.
    with_dss[11] ^= 0xff;
    let err = validate_pdf_signature(&with_dss).unwrap_err();
    assert!(
        matches!(
            err,
            PadesError::Cades(chancela_cades::CadesError::MessageDigestMismatch)
        ),
        "got {err:?}"
    );
}

#[test]
fn empty_dss_evidence_is_rejected() {
    let signer = TestSigner::new_rsa("PAdES Empty DSS", 10);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());

    let err = add_dss_revision(&signed, &DssEvidence::default()).unwrap_err();
    assert!(matches!(err, PadesError::DssEvidenceEmpty), "got {err:?}");
}

#[test]
fn existing_dss_is_merged_and_deduped() {
    let signer = TestSigner::new_rsa("PAdES Existing DSS", 11);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let mut evidence = fixture_dss_evidence(&signer);
    evidence.certificates.push(evidence.certificates[0].clone());
    evidence.ocsp_responses.push(OCSP_DER_FIXTURE.to_vec());
    evidence.crls.push(CRL_DER_FIXTURE.to_vec());
    let with_dss = add_dss_revision(&signed, &evidence).expect("first DSS append");
    let first_cert_refs = dss_array_refs(&with_dss, b"Certs");
    let first_ocsp_refs = dss_array_refs(&with_dss, b"OCSPs");
    let first_crl_refs = dss_array_refs(&with_dss, b"CRLs");

    let merged = add_dss_revision(&with_dss, &evidence).expect("merged DSS append");
    let report = inspect_dss(&merged).expect("inspect merged DSS");

    assert!(merged.starts_with(&with_dss));
    assert_eq!(report.vri_count, 1);
    assert_eq!(report.certificate_count(), 2);
    assert_eq!(report.ocsp_count(), 1);
    assert_eq!(report.crl_count(), 1);
    assert_eq!(report.ocsp_hashes, vec![sha256(OCSP_DER_FIXTURE)]);
    assert_eq!(report.crl_hashes, vec![sha256(CRL_DER_FIXTURE)]);
    assert_eq!(dss_array_refs(&merged, b"Certs"), first_cert_refs);
    assert_eq!(dss_array_refs(&merged, b"OCSPs"), first_ocsp_refs);
    assert_eq!(dss_array_refs(&merged, b"CRLs"), first_crl_refs);
}

#[test]
fn dss_validation_time_is_written_as_vri_tu_and_reported() {
    let signer = TestSigner::new_rsa("PAdES DSS TU", 12);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);

    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let report = validate_pdf_signature(&with_dss).expect("validate DSS TU");

    assert!(report.has_signature_timestamp);
    assert!(report.dss.present);
    assert_eq!(report.dss.vri_count, 1);
    assert_eq!(report.dss.vri_tu_count, 1);
    assert_eq!(report.dss.vri_tu_keys, report.dss.vri_keys);
    assert!(report.dss.has_vri_tu());
    assert!(report.dss.has_vri_tu_for_key(&report.dss.vri_keys[0]));
    assert!(crate_find(&with_dss, b"/TU (D:20260709120000Z)").is_some());
    assert_eq!(
        report.ltv_renewal_plan.missing_inputs,
        vec![LtvRenewalPlanInput::DocumentTimestamp]
    );
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddDocumentTimestamp
    );
}

#[test]
fn ltv_renewal_plan_monitors_when_local_evidence_inputs_are_present() {
    let signer = TestSigner::new_rsa("PAdES Renewal Plan", 17);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let token = doc_timestamp_token_for_revision(&with_dss);

    let with_doc_ts = add_doc_timestamp_revision(&with_dss, &token).expect("DTS append");
    let report = validate_pdf_signature(&with_doc_ts).expect("validate renewal plan PDF");

    assert!(report.has_signature_timestamp);
    assert!(report.dss.has_revocation_evidence());
    assert!(report.dss.has_vri_tu());
    assert!(report.doc_timestamps.all_imprints_valid());
    assert_eq!(
        report.ltv_renewal_plan.scope,
        LtvRenewalPlanScope::LocalTechnicalEvidenceOnly
    );
    assert!(report.ltv_renewal_plan.missing_inputs.is_empty());
    assert!(!report.ltv_renewal_plan.has_local_evidence_gap());
    assert!(report.ltv_renewal_plan.has_all_local_planning_inputs());
    assert_eq!(
        report.ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::MonitorTimestampRenewal
    );
}

#[test]
fn ltv_renewal_policy_classifies_caller_supplied_deadlines_only() {
    let policy = LtvRenewalPolicy {
        now_unix_seconds: Some(1_750_000_000),
        renewal_deadline_unix_seconds: Some(1_750_000_300),
        due_soon_window_seconds: Some(600),
    };
    let plan = plan_ltv_renewal_with_policy(
        false,
        &DssReport::default(),
        &DocTimeStampReport::default(),
        policy,
    );

    assert_eq!(plan.policy, policy);
    assert_eq!(
        plan.renewal_deadline.status,
        LtvRenewalDeadlineStatus::DueSoon
    );
    assert_eq!(plan.renewal_deadline.seconds_until_deadline, Some(300));
    assert_eq!(
        plan.next_action,
        LtvRenewalPlanAction::AddSignatureTimestamp
    );

    let past_due = plan_ltv_renewal_with_policy(
        true,
        &DssReport::default(),
        &DocTimeStampReport::default(),
        LtvRenewalPolicy {
            now_unix_seconds: Some(1_750_000_000),
            renewal_deadline_unix_seconds: Some(1_749_999_999),
            due_soon_window_seconds: None,
        },
    );
    assert_eq!(
        past_due.renewal_deadline.status,
        LtvRenewalDeadlineStatus::PastDue
    );
    assert_eq!(past_due.renewal_deadline.seconds_until_deadline, Some(-1));
}

#[test]
fn multi_signature_renewal_plan_reports_each_signature_vri_coverage() {
    let signer = TestSigner::new_rsa("PAdES Multi Renewal", 18);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_dss = add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
        .expect("DSS append with TU");
    let token = doc_timestamp_token_for_revision(&with_dss);
    let with_doc_ts = add_doc_timestamp_revision(&with_dss, &token).expect("DTS append");
    let with_second_sig =
        append_synthetic_sig_dictionary(&with_doc_ts, DOC_TIMESTAMP_TOKEN_DER_FIXTURE);

    let report = validate_pdf_signature(&with_second_sig).expect("validate first signature");

    assert_eq!(report.multi_signature_ltv_renewal_plan.signature_count, 2);
    assert_eq!(
        report
            .multi_signature_ltv_renewal_plan
            .signatures_with_local_evidence_gaps,
        vec![1]
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[0].dss_vri_present,
        "real signature has a matching DSS VRI entry"
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[0].dss_vri_validation_time_present,
        "real signature VRI has /TU"
    );
    assert!(
        !report.multi_signature_ltv_renewal_plan.signatures[1].dss_vri_present,
        "synthetic second signature has no matching DSS VRI entry"
    );
    assert!(
        report.multi_signature_ltv_renewal_plan.signatures[1]
            .plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::SignatureDssVri)
    );
    assert_eq!(
        report.multi_signature_ltv_renewal_plan.next_action,
        LtvRenewalPlanAction::AddSignatureDssVri
    );
}

#[test]
fn multi_signature_renewal_plan_matches_tu_to_the_specific_vri_key() {
    let signer = TestSigner::new_rsa("PAdES Multi Renewal TU Key", 19);
    let signed = sign_with(&base_pdf(), &signer, &SignOptions::default());
    let with_ts = add_fixture_timestamp(&signed);
    let evidence = fixture_dss_evidence(&signer);
    let with_first_tu =
        add_dss_revision_with_validation_time(&with_ts, &evidence, "D:20260709120000Z")
            .expect("first DSS append with TU");
    let with_second_sig = append_synthetic_sig_dictionary_with_signed_revision_len(
        &with_first_tu,
        DOC_TIMESTAMP_TOKEN_DER_FIXTURE,
        with_first_tu.len() + 1,
    );

    let with_second_vri =
        add_dss_revision(&with_second_sig, &evidence).expect("second DSS append without TU");
    let report = validate_pdf_signature(&with_second_vri).expect("validate first signature");

    assert_eq!(report.dss.vri_count, 2);
    assert_eq!(report.dss.vri_tu_count, 1);
    assert_eq!(report.dss.vri_tu_keys.len(), 1);
    assert_eq!(report.multi_signature_ltv_renewal_plan.signature_count, 2);

    let first_signature = &report.multi_signature_ltv_renewal_plan.signatures[0];
    assert!(first_signature.dss_vri_present);
    assert!(first_signature.dss_vri_validation_time_present);
    assert!(report.dss.has_vri_tu_for_key(&first_signature.vri_key));

    let second_signature = &report.multi_signature_ltv_renewal_plan.signatures[1];
    assert!(second_signature.dss_vri_present);
    assert!(!second_signature.dss_vri_validation_time_present);
    assert!(!report.dss.has_vri_tu_for_key(&second_signature.vri_key));
    assert!(
        second_signature
            .plan
            .missing_inputs
            .contains(&LtvRenewalPlanInput::SignatureDssValidationTime)
    );
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

// --- Visible-seal (t67-e3) -----------------------------------------------------------------------

#[test]
fn visible_text_seal_places_rect_and_ap_and_still_validates() {
    let signer = TestSigner::new_rsa("PAdES Seal Text", 20);
    let placement = SealPlacement {
        page: 0,
        x: 72.0,
        y: 700.0,
        w: 180.0,
        h: 48.0,
    };
    let seal = SealAppearance {
        placement,
        // memory: fictional example name, never a real person.
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let signed = sign_with_appearance(&base_pdf(), &signer, &SignOptions::default(), &seal);

    // The B-B signature still validates and covers the whole file except /Contents.
    let report = validate_pdf_signature(&signed).expect("validate visible-seal PDF");
    assert!(report.covers_whole_file_except_contents);
    assert_eq!(report.cades.signer_cert_der, signer.cert_der());

    // Real /Rect = [x, y, x+w, y+h] and a form-XObject appearance stream.
    let widget = signature_widget(&signed);
    assert_eq!(widget_rect(&widget), [72.0, 700.0, 252.0, 748.0]);
    assert_ap_is_form_xobject(&signed, &widget);
    // Widget bound to the requested page (object 3 = first page).
    assert_eq!(
        widget.get(b"P").and_then(|o| o.as_reference()).unwrap(),
        (3, 0)
    );
    // The invisible zero-Rect placeholder is gone.
    assert!(crate_find(&signed, b"/Rect [0 0 0 0]").is_none());
}

#[test]
fn visible_image_seal_embeds_png_with_smask_on_requested_page_and_validates() {
    let signer = TestSigner::new_ecdsa("PAdES Seal Image", 21);
    let placement = SealPlacement {
        page: 1, // second page of a two-page document
        x: 100.0,
        y: 120.0,
        w: 96.0,
        h: 64.0,
    };
    let seal = SealAppearance {
        placement,
        content: SealContent::Image(ImageSeal {
            data: tiny_rgba_png(),
            format: SealImageFormat::Png,
        }),
    };
    let signed = sign_with_appearance(
        &base_pdf_two_pages(),
        &signer,
        &SignOptions::default(),
        &seal,
    );

    // Signature integrity preserved.
    let report = validate_pdf_signature(&signed).expect("validate image-seal PDF");
    assert!(report.covers_whole_file_except_contents);

    // /Rect on the requested page and an /AP /N form XObject.
    let widget = signature_widget(&signed);
    assert_eq!(widget_rect(&widget), [100.0, 120.0, 196.0, 184.0]);
    let form_ref = assert_ap_is_form_xobject(&signed, &widget);
    // Widget bound to page index 1 (object 4 = second page).
    assert_eq!(
        widget.get(b"P").and_then(|o| o.as_reference()).unwrap(),
        (4, 0)
    );

    // The appearance form references an image XObject, and the RGBA source produced an /SMask.
    let doc = lopdf::Document::load_mem(&signed).expect("parse");
    let form = doc
        .get_object(form_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    let xobjects = form
        .dict
        .get(b"Resources")
        .and_then(|o| o.as_dict())
        .and_then(|r| r.get(b"XObject"))
        .and_then(|o| o.as_dict())
        .expect("form /Resources /XObject");
    let im_ref = xobjects
        .get(b"Im0")
        .and_then(|o| o.as_reference())
        .expect("/Im0 image reference");
    let image = doc.get_object(im_ref).and_then(|o| o.as_stream()).unwrap();
    assert_eq!(
        image.dict.get(b"Subtype").and_then(|o| o.as_name()).ok(),
        Some(b"Image".as_ref())
    );
    assert_eq!(
        image.dict.get(b"Width").and_then(|o| o.as_i64()).ok(),
        Some(2)
    );
    assert_eq!(
        image.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceRGB".as_ref())
    );
    let smask_ref = image
        .dict
        .get(b"SMask")
        .and_then(|o| o.as_reference())
        .expect("RGBA image carries an /SMask");
    let smask = doc
        .get_object(smask_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    assert_eq!(
        smask.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceGray".as_ref())
    );
}

#[test]
fn visible_jpeg_seal_embeds_verbatim_dctdecode() {
    let signer = TestSigner::new_rsa("PAdES Seal JPEG", 22);
    // A minimal baseline-JPEG header: SOI, an APP0/JFIF stub, then a SOF0 declaring 8×8 3-component,
    // then SOS. Enough for the frame-header scan; the bytes are embedded verbatim as /DCTDecode.
    let jpeg: Vec<u8> = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, 0x00, 0x11, // SOF0, length 17
        0x08, // precision 8
        0x00, 0x08, // height 8
        0x00, 0x08, // width 8
        0x03, // 3 components
        0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // component specs
        0xFF, 0xDA, 0x00, 0x02, // SOS
        0xFF, 0xD9, // EOI
    ];
    let placement = SealPlacement {
        page: 0,
        x: 40.0,
        y: 40.0,
        w: 72.0,
        h: 72.0,
    };
    let seal = SealAppearance {
        placement,
        content: SealContent::Image(ImageSeal {
            data: jpeg.clone(),
            format: SealImageFormat::Jpeg,
        }),
    };
    let signed = sign_with_appearance(&base_pdf(), &signer, &SignOptions::default(), &seal);

    let report = validate_pdf_signature(&signed).expect("validate jpeg-seal PDF");
    assert!(report.covers_whole_file_except_contents);

    let widget = signature_widget(&signed);
    let form_ref = assert_ap_is_form_xobject(&signed, &widget);
    let doc = lopdf::Document::load_mem(&signed).expect("parse");
    let form = doc
        .get_object(form_ref)
        .and_then(|o| o.as_stream())
        .unwrap();
    let im_ref = form
        .dict
        .get(b"Resources")
        .and_then(|o| o.as_dict())
        .and_then(|r| r.get(b"XObject"))
        .and_then(|o| o.as_dict())
        .and_then(|x| x.get(b"Im0"))
        .and_then(|o| o.as_reference())
        .unwrap();
    let image = doc.get_object(im_ref).and_then(|o| o.as_stream()).unwrap();
    assert_eq!(
        image.dict.get(b"Filter").and_then(|o| o.as_name()).ok(),
        Some(b"DCTDecode".as_ref()),
        "JPEG embedded as DCTDecode"
    );
    assert_eq!(image.content, jpeg, "JPEG bytes embedded verbatim");
    assert_eq!(
        image.dict.get(b"ColorSpace").and_then(|o| o.as_name()).ok(),
        Some(b"DeviceRGB".as_ref())
    );
}

#[test]
fn invisible_default_is_unchanged_with_appearance_api() {
    // Driving the appearance-capable path with `None` must reproduce the byte-identical invisible
    // signature the legacy `sign_pdf` produces (backward compatibility).
    let signer = TestSigner::new_rsa("PAdES Invisible Default", 23);
    let opts = SignOptions {
        signing_time: Some("D:20260706142640Z".into()),
        ..SignOptions::default()
    };
    let via_legacy = sign_with(&base_pdf(), &signer, &opts);

    let signing_time = fixed_time();
    let cert = signer.cert_der();
    let via_new = sign_pdf_with_appearance(&base_pdf(), &opts, None, |digest| {
        let attrs = signed_attributes_digest(digest, &cert, signing_time)?;
        let raw = signer.raw_signature(&attrs);
        assemble_cades_b(&raw, digest, signing_time)
    })
    .expect("sign_pdf_with_appearance(None)");

    assert_eq!(via_legacy, via_new);
    assert!(crate_find(&via_new, b"/Rect [0 0 0 0]").is_some());
    assert!(crate_find(&via_new, b"/AP").is_none());
}

#[test]
fn seal_page_out_of_range_is_rejected() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 5, // base_pdf has one page
            x: 10.0,
            y: 10.0,
            w: 50.0,
            h: 20.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(&base_pdf(), &SignOptions::default(), Some(&seal))
        .unwrap_err();
    match err {
        PadesError::MalformedStructure(msg) => assert!(msg.contains("out of range"), "got {msg}"),
        other => panic!("expected MalformedStructure, got {other:?}"),
    }
}

#[test]
fn seal_zero_size_is_rejected() {
    let seal = SealAppearance {
        placement: SealPlacement {
            page: 0,
            x: 10.0,
            y: 10.0,
            w: 0.0,
            h: 20.0,
        },
        content: SealContent::Text(TextSeal::name_date("Amélia Marques", "2026-07-11")),
    };
    let err = prepare_signature_with_appearance(&base_pdf(), &SignOptions::default(), Some(&seal))
        .unwrap_err();
    assert!(
        matches!(err, PadesError::MalformedStructure(_)),
        "got {err:?}"
    );
}

/// Tiny helper: first occurrence of `needle` in `haystack` (tests avoid depending on `pdf` internals).
fn crate_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dss_array_refs(pdf: &[u8], key: &[u8]) -> Vec<(u32, u16)> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let catalog = doc
        .get_object(root)
        .and_then(lopdf::Object::as_dict)
        .expect("catalog");
    let (_, dss_obj) = doc
        .dereference(catalog.get(b"DSS").expect("DSS"))
        .expect("DSS ref");
    let dss = dss_obj.as_dict().expect("DSS dict");
    let (_, array_obj) = doc
        .dereference(dss.get(key).expect("array"))
        .expect("array ref");
    array_obj
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_reference().expect("stream ref"))
        .collect()
}

fn append_synthetic_sig_dictionary(pdf: &[u8], contents_der: &[u8]) -> Vec<u8> {
    append_synthetic_sig_dictionary_with_signed_revision_len(pdf, contents_der, 0)
}

fn append_synthetic_sig_dictionary_with_signed_revision_len(
    pdf: &[u8],
    contents_der: &[u8],
    signed_revision_len: usize,
) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let prev_startxref = crate::pdf::last_startxref(pdf).expect("startxref");
    let sig_id = doc.max_id + 1;
    let mut out = pdf.to_vec();
    let obj_offset = out.len() + 1;
    out.extend_from_slice(b"\n");
    out.extend_from_slice(format!("{sig_id} 0 obj\n").as_bytes());
    out.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ");
    out.extend_from_slice(
        format!("/ByteRange [0 0 {signed_revision_len} 0] /Contents <").as_bytes(),
    );
    out.extend_from_slice(&crate::pdf::to_hex(contents_der));
    out.extend_from_slice(b"> >>\nendobj\n");
    let xref_offset = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{sig_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
            sig_id + 1,
            root.0
        )
        .as_bytes(),
    );
    out
}

/// Append an incremental update that redefines the existing object `obj_id` with `new_body`. Later
/// revisions win, so a viewer (and `lopdf`) renders `new_body` in place of the signed object — a
/// content-bearing tamper the first signature never covered (C3).
fn append_object_override(pdf: &[u8], obj_id: u32, new_body: &str) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let prev_startxref = crate::pdf::last_startxref(pdf).expect("startxref");
    let mut out = pdf.to_vec();
    let obj_offset = out.len() + 1;
    out.extend_from_slice(b"\n");
    out.extend_from_slice(format!("{obj_id} 0 obj\n{new_body}\nendobj\n").as_bytes());
    let xref_offset = out.len();
    out.extend_from_slice(
        format!(
            "xref\n{obj_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {} /Root {} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
            doc.max_id + 1,
            root.0
        )
        .as_bytes(),
    );
    out
}

/// Build a self-contained signed PDF whose signature `/ByteRange` gap deliberately spans **more**
/// than the `/Contents` token (it also excludes the space right after the closing `>`), yet whose
/// CMS is computed over exactly that widened gap so the cryptographic check still passes. Exercises
/// the C3 MEDIUM: a signature whose excluded gap is not exactly `/Contents` must not be reported
/// clean.
fn sign_with_overwide_gap(signer: &TestSigner) -> Vec<u8> {
    // Placeholder hex-byte capacity; a self-signed CAdES-B CMS fits with zero padding.
    const CAPACITY: usize = 4096;
    let signing_time = fixed_time();
    let cert = signer.cert_der();

    let mut sig_body = String::from(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 0000000000 0000000000 0000000000] /Contents <",
    );
    sig_body.push_str(&"0".repeat(CAPACITY * 2));
    sig_body.push_str("> >>");
    let objects: [(u32, &str); 4] = [
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
        ),
        (4, sig_body.as_str()),
    ];

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::new();
    for (id, body) in &objects {
        offsets.push((*id, buf.len()));
        buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let xref_off = buf.len();
    buf.extend_from_slice(b"xref\n0 5\n0000000000 65535 f\r\n");
    for id in 1..=4u32 {
        let off = offsets.iter().find(|(i, _)| *i == id).unwrap().1;
        buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\n");
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());

    let lt = crate_find(&buf, b"/Contents <").unwrap() + b"/Contents ".len();
    let hex_start = lt + 1;
    let gt = hex_start + CAPACITY * 2;
    assert_eq!(buf[gt], b'>', "closing '>' where expected");
    // Widen the excluded gap one byte past '>' (the following space), so it is no longer the lone
    // '<...>' /Contents token.
    let l1 = lt;
    let s2 = gt + 2;
    let range2_len = buf.len() - s2;

    let br_marker = crate_find(&buf, b"/ByteRange [0 ").unwrap() + b"/ByteRange [0 ".len();
    let br = format!("{l1:010} {s2:010} {range2_len:010}");
    buf[br_marker..br_marker + br.len()].copy_from_slice(br.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buf[0..l1]);
    hasher.update(&buf[s2..s2 + range2_len]);
    let digest: [u8; 32] = hasher.finalize().into();

    let attrs = signed_attributes_digest(&digest, &cert, signing_time).expect("signed attrs");
    let raw = signer.raw_signature(&attrs);
    let cms = assemble_cades_b(&raw, &digest, signing_time).expect("cades");
    assert!(cms.len() <= CAPACITY, "CMS must fit the placeholder");

    let hex = crate::pdf::to_hex(&cms);
    buf[hex_start..hex_start + hex.len()].copy_from_slice(&hex);
    buf
}
