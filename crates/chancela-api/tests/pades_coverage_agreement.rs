//! The two PAdES surfaces must return the same verdict for the same file (SIG-24, finding C3).
//!
//! `POST /v1/signature/pdf/validate` and `POST /v1/documents/import/validate` both run
//! `chancela_pades::validate_pdf_signature`, but they map its report to a status independently.
//! A disagreement is not a cosmetic inconsistency: it means one screen certifies as a valid PAdES-B
//! signature the very file the other screen refuses. These tests pin the two together over one
//! incremental-update tamper and one untouched signature, so a future divergence fails here.
//!
//! The tamper is the classic one: an incremental update appended after the signed revision that
//! redefines a page. The embedded CMS still verifies — nothing inside the signed byte range moved —
//! but the page a reader renders is not the page that was signed.

use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};

use common::{TEST_PASSWORD, password_hash};

/// A real PAdES-B-B signed PDF from the validator corpus.
const SIGNED_PDF: &[u8] =
    include_bytes!("../../../docs/fixtures/validator-corpus/cases/bb-basic/input/bb-basic.pdf");

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn owner_session(state: &AppState) -> String {
    let uid = UserId(Uuid::new_v4());
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("created_at");
    state.users.write().await.insert(
        uid,
        User {
            passkeys: Vec::new(),
            id: uid,
            username: format!("coverage-user-{}", uid.0),
            display_name: "Amélia Marques".to_owned(),
            email: None,
            created_at,
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

fn seeded_state() -> AppState {
    AppState {
        roles: std::sync::Arc::new(tokio::sync::RwLock::new(RoleCatalog::seeded_defaults())),
        ..AppState::default()
    }
}

fn post_pdf(uri: &str, token: &str, bytes: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/pdf")
        .header("x-chancela-session", token)
        .body(Body::from(bytes.to_vec()))
        .expect("request builds")
}

/// Append an incremental update redefining object `obj_id`. Later revisions win, so a reader renders
/// `new_body` in place of the object the signature covered.
fn append_object_override(pdf: &[u8], obj_id: u32, new_body: &str) -> Vec<u8> {
    let doc = lopdf::Document::load_mem(pdf).expect("parse PDF");
    let root = doc
        .trailer
        .get(b"Root")
        .and_then(lopdf::Object::as_reference)
        .expect("root");
    let prev_startxref = {
        let marker = pdf
            .windows(b"startxref".len())
            .rposition(|w| w == b"startxref")
            .expect("startxref");
        let mut i = marker + b"startxref".len();
        while i < pdf.len() && pdf[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < pdf.len() && pdf[i].is_ascii_digit() {
            i += 1;
        }
        std::str::from_utf8(&pdf[start..i])
            .expect("utf8")
            .parse::<usize>()
            .expect("startxref offset")
    };
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

#[tokio::test]
async fn both_pades_surfaces_refuse_the_same_incremental_update_tamper() {
    let altered = append_object_override(
        SIGNED_PDF,
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
    );
    // The premise of the disagreement: the CMS itself still verifies over the signed byte range.
    let report = chancela_pades::validate_pdf_signature(&altered).expect("CMS still validates");
    assert!(
        !report.coverage.covers_rendered_document(),
        "the tamper must leave the CMS valid but the coverage broken"
    );

    let state = seeded_state();
    let token = owner_session(&state).await;

    let (status, signature_body) = send(
        &state,
        post_pdf("/v1/signature/pdf/validate", &token, &altered),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signature_body}");
    assert_eq!(signature_body["status"], "invalid");
    assert_eq!(signature_body["signature"]["status"], "invalid");
    assert_eq!(
        signature_body["signature"]["coverage"]["verdict"],
        "altered_after_signing"
    );

    let (status, import_body) = send(
        &state,
        post_pdf("/v1/documents/import/validate", &token, &altered),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{import_body}");
    assert_eq!(
        import_body["signature"]["validation_status"], "altered_after_signing",
        "the import screen must not certify a tampered signature as valid PAdES-B"
    );
    assert_eq!(
        import_body["signature"]["coverage"], signature_body["signature"]["coverage"]["verdict"],
        "both surfaces must name the same coverage verdict"
    );
    assert_eq!(import_body["signature"]["covers_rendered_document"], false);
    assert_eq!(
        import_body["signature_evidence"]["all_claimed_signatures_valid"],
        false
    );
    assert_eq!(
        import_body["signature_evidence"]["cryptographically_valid_count"],
        0
    );
    assert!(
        import_body["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"] == "signed_pdf_altered_after_signing"),
        "{import_body}"
    );
    assert!(
        !import_body["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"] == "valid_pades_b"),
        "a tampered file must not also carry the clean-validation finding: {import_body}"
    );
}

#[tokio::test]
async fn both_pades_surfaces_accept_the_same_untouched_signature() {
    // The other half of agreement: neither surface may turn pessimistic on a clean signature.
    let state = seeded_state();
    let token = owner_session(&state).await;

    let (status, signature_body) = send(
        &state,
        post_pdf("/v1/signature/pdf/validate", &token, SIGNED_PDF),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signature_body}");
    assert_eq!(signature_body["signature"]["status"], "valid");
    assert_eq!(
        signature_body["signature"]["coverage"]["covers_rendered_document"],
        true
    );

    let (status, import_body) = send(
        &state,
        post_pdf("/v1/documents/import/validate", &token, SIGNED_PDF),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{import_body}");
    assert_eq!(
        import_body["signature"]["validation_status"],
        "valid_pades_b"
    );
    assert_eq!(import_body["signature"]["covers_rendered_document"], true);
    assert_eq!(
        import_body["signature_evidence"]["all_claimed_signatures_valid"],
        true
    );
    assert!(
        !import_body["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"] == "signed_pdf_incomplete_byte_range"),
        "a clean signature must not be flagged for an incomplete /ByteRange: {import_body}"
    );
}
