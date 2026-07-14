//! Journey: Arquivo ledger archive exports over the real server binary.
//!
//! Covers the composed, RBAC-gated endpoint that renders the current ledger archive as PDF/A bytes:
//! global `ledger.read` success, accepted chain/scope filters, structured invalid-chain failures,
//! audit/interchange export formats, default newest-first ordering, and the read-only invariant
//! (exporting must not append a ledger event).

mod common;

use common::*;
use serde_json::{Value, json};

const TEST_PASSWORD: &str = "Archive-Safe7!";

/// Fetch raw bytes (not JSON) from the running server. Archive exports are PDF bytes, so the JSON
/// harness helpers would try to parse the body incorrectly.
async fn get_bytes(h: &ServerHarness, path: &str, token: &str) -> (u16, String, Vec<u8>) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}{}", h.base_url, path))
        .header(SESSION_HEADER, token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = resp
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("read body of {path} failed: {e}"))
        .to_vec();
    (status, ctype, bytes)
}

fn assert_archive_pdf(status: u16, ctype: &str, bytes: &[u8], label: &str) {
    assert_eq!(status, 200, "{label} status");
    assert_eq!(ctype, "application/pdf; profile=PDF/A-2u", "{label} ctype");
    assert!(
        bytes.starts_with(b"%PDF-"),
        "{label} should return PDF bytes"
    );
    assert!(!bytes.is_empty(), "{label} should return a nonempty body");
}

async fn bootstrap_archive_session(h: &ServerHarness) -> String {
    let (status, user) = h
        .post_json(
            "/v1/users",
            json!({
                "username": "e2e.operator",
                "display_name": "E2E Operator",
                "password": TEST_PASSWORD,
            }),
        )
        .await;
    assert_eq!(status, 201, "bootstrap archive user: {user}");
    let user_id = user["id"].as_str().expect("user id");

    let (status, session) = h
        .post_json(
            "/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        )
        .await;
    assert_eq!(status, 200, "bootstrap archive session: {session}");
    let token = session["token"].as_str().expect("session token").to_owned();
    h.set_default_token(&token);
    token
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn ledger_archive_document_is_pdf_filterable_structured_and_read_only() {
    let h = ServerHarness::start().await;
    let token = bootstrap_archive_session(&h).await;
    let entity_id = create_entity(
        &h,
        "Encosto Estratégico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;

    // Global ledger-read success: authenticated Owner@Global can export the whole archive.
    let (status, ctype, pdf) = get_bytes(&h, "/v1/ledger/archive/document", &token).await;
    assert_archive_pdf(status, &ctype, &pdf, "global archive export");

    // Current ledger chain + scope filters are accepted by the archive renderer.
    let filtered_path = format!(
        "/v1/ledger/archive/document?chain=book:{book_id}&scope=book:{book_id}&kind=book.opened&limit=1"
    );
    let (status, ctype, filtered_pdf) = get_bytes(&h, &filtered_path, &token).await;
    assert_archive_pdf(status, &ctype, &filtered_pdf, "filtered archive export");

    // The dropdown's non-PDF formats are backed by real server responses, not just UI options.
    let (status, ctype, json_bytes) = get_bytes(
        &h,
        "/v1/ledger/archive/document?format=json&limit=2",
        &token,
    )
    .await;
    assert_eq!(status, 200, "JSON archive export status");
    assert_eq!(ctype, "application/json", "JSON archive export ctype");
    let export: Value = serde_json::from_slice(&json_bytes).expect("JSON archive export parses");
    assert_eq!(export["export_kind"], "audit_interchange");
    assert_eq!(export["canonical_preserved_evidence"], false);
    assert_eq!(export["canonical_evidence_format"], "pdfa");
    assert_eq!(export["order"], "desc");
    assert_eq!(export["event_count"], 2);
    let events = export["events"].as_array().expect("JSON export events");
    assert_eq!(events.len(), 2);
    assert!(
        events[0]["seq"].as_u64().expect("first seq")
            > events[1]["seq"].as_u64().expect("second seq"),
        "JSON archive export defaults to newest-first order: {export}"
    );

    for (format, expected_ctype, expected_marker) in [
        ("txt", "text/plain; charset=utf-8", "kind=book.opened"),
        (
            "csv",
            "text/csv; charset=utf-8",
            "seq,chain_seq,kind,scope,actor,timestamp",
        ),
        ("html", "text/html; charset=utf-8", "<table>"),
    ] {
        let path = format!("{filtered_path}&format={format}");
        let (status, ctype, bytes) = get_bytes(&h, &path, &token).await;
        assert_eq!(status, 200, "{format} archive export status");
        assert_eq!(ctype, expected_ctype, "{format} archive export ctype");
        let body = String::from_utf8(bytes).expect("archive interchange export is UTF-8");
        assert!(
            body.contains("Audit/interchange export only"),
            "{format} archive export carries the non-canonical notice: {body}"
        );
        assert!(
            body.contains(expected_marker),
            "{format} archive export carries expected event data: {body}"
        );
    }

    // Bad chain ids produce the structured 422 JSON envelope used by the ledger API.
    let (status, body) = h
        .get_json_auth("/v1/ledger/archive/document?chain=not-a-chain", &token)
        .await;
    assert_eq!(status, 422, "malformed chain status: {body}");
    let obj = body.as_object().expect("422 body is a JSON object");
    assert_eq!(
        obj.keys().collect::<Vec<_>>(),
        vec!["error"],
        "422 body is the base error envelope: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .expect("422 error string")
            .contains("invalid chain"),
        "422 describes the chain parse failure: {body}"
    );

    // Exporting is read-only: it must not append an archive/document/generated ledger event.
    let (status, before) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger before export: {before}");
    let (status, ctype, pdf) = get_bytes(&h, "/v1/ledger/archive/document?limit=2", &token).await;
    assert_archive_pdf(status, &ctype, &pdf, "read-only archive export");
    let (status, after) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger after export: {after}");
    assert_eq!(
        before, after,
        "archive export should not append or mutate ledger events"
    );
}
