//! PAdES-LT / LTA *execution*-mechanics tests at the pades layer (t67-e5).
//!
//! These exercise the produced-token DocTimeStamp path ([`add_doc_timestamp_revision_with`]) and the
//! renewal executor ([`execute_ltv_renewal`]) directly, without the `chancela-signing` revocation
//! fetch. The archive timestamp is produced by replaying the bundled `chancela-tsa` OpenSSL fixture
//! with its imprint rewritten to the revision digest, so the embedded `/DocTimeStamp` imprint
//! validates against the revision it covers.

use std::convert::Infallible;

use chancela_pades::archive_timestamp::{add_doc_timestamp_revision_with, inspect_doc_timestamps};
use chancela_pades::renewal::execute_ltv_renewal;
use chancela_pades::{DssEvidence, SignOptions, inspect_dss, sign_pdf};

/// Public, synthetic complete DER used as caller-supplied revocation bytes (the pades layer embeds
/// DER blobs verbatim; semantic revocation validation lives in `chancela-signing`).
const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
/// A minimal complete DER SEQUENCE used as the embedded CMS placeholder — enough to reserve the
/// signature and give the document an AcroForm; these tests do not validate the CMS itself.
const MINIMAL_CMS: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];

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

fn signed_pdf() -> Vec<u8> {
    let base = assemble_pdf(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ],
        1,
    );
    sign_pdf(&base, &SignOptions::default(), |_digest| {
        Ok::<Vec<u8>, Infallible>(MINIMAL_CMS.to_vec())
    })
    .expect("sign PAdES placeholder")
}

/// The bundled fixture token with its message imprint rewritten to `digest`.
fn patched_token(digest: &[u8; 32]) -> Vec<u8> {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let request = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    let mut token = tsa.stamp(&request).expect("fixture token").token_der;
    let pos = token
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present");
    token[pos..pos + digest.len()].copy_from_slice(digest);
    token
}

#[test]
fn produced_doc_timestamp_binds_the_revision() {
    let signed = signed_pdf();
    let with_dts = add_doc_timestamp_revision_with(&signed, |digest| {
        Ok::<Vec<u8>, Infallible>(patched_token(digest))
    })
    .expect("produce DocTimeStamp");

    let report = inspect_doc_timestamps(&with_dts).expect("inspect DocTimeStamp");
    assert_eq!(report.count, 1);
    assert!(
        report.all_imprints_valid(),
        "the produced token imprint binds the timestamped revision"
    );
}

#[test]
fn execute_ltv_renewal_appends_dss_and_archive_timestamp() {
    let signed = signed_pdf();
    let evidence = DssEvidence {
        certificates: Vec::new(),
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: Vec::new(),
    };

    let (renewed, execution) =
        execute_ltv_renewal(&signed, &evidence, "2025-06-15T14:26:40Z", |digest| {
            Ok::<Vec<u8>, Infallible>(patched_token(digest))
        })
        .expect("execute LTV renewal");

    // The renewal embedded fresh revocation material with /TU metadata and a valid archive stamp.
    assert!(execution.embedded_dss_revocation_evidence());
    assert!(execution.dss.has_vri_tu());
    assert!(execution.embedded_valid_document_timestamp());
    assert_eq!(execution.doc_timestamps.count, 1);

    // The reports reflect the actual bytes in the renewed document.
    let dss = inspect_dss(&renewed).expect("inspect renewed DSS");
    assert_eq!(dss.ocsp_count(), 1);
    assert!(dss.has_vri_tu());
    let dts = inspect_doc_timestamps(&renewed).expect("inspect renewed DocTimeStamp");
    assert!(dts.all_imprints_valid());
}
