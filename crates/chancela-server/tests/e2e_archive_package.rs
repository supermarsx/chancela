//! Journey: deterministic internal preservation package export.
//!
//! Builds a book with one sealed act, downloads `GET /v1/books/{id}/archive/package` twice, validates
//! the ZIP with `chancela_archive`, and checks that the manifest references the preserved PDF/A
//! document and metadata sidecar without appending ledger events.

mod common;

use std::io::{Cursor, Read};

use chancela_archive::{PackageFileRole, validate_package};
use common::*;
use serde_json::{Value, json};
use zip::ZipArchive;

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

fn package_member_json(bytes: &[u8], path: &str) -> Value {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).expect("archive package is a readable zip");
    let mut member = archive
        .by_name(path)
        .unwrap_or_else(|e| panic!("archive package member {path} missing: {e}"));
    let mut json = String::new();
    member
        .read_to_string(&mut json)
        .unwrap_or_else(|e| panic!("read archive package member {path}: {e}"));
    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("archive package member {path} is not JSON ({e}): {json}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn book_archive_package_is_valid_deterministic_and_read_only() {
    let h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

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
    let act_id = draft_act(&h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    let document_id = sealed["document"]["id"].as_str().expect("document id");

    let (status, before) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger before export: {before}");

    let path = format!("/v1/books/{book_id}/archive/package");
    let (status, ctype, first) = get_bytes(&h, &path, &token).await;
    assert_eq!(status, 200, "archive package status");
    assert_eq!(ctype, "application/zip", "archive package content type");
    assert!(!first.is_empty(), "archive package has bytes");

    let (status, ctype, second) = get_bytes(&h, &path, &token).await;
    assert_eq!(status, 200, "second archive package status");
    assert_eq!(
        ctype, "application/zip",
        "second archive package content type"
    );
    assert_eq!(
        first, second,
        "same inputs produce byte-identical preservation ZIPs"
    );

    let manifest = validate_package(&first).expect("archive package validates");
    assert_eq!(manifest.entity_id.to_string(), entity_id);
    assert_eq!(manifest.book_id.to_string(), book_id);
    assert!(
        manifest.act_ids.iter().any(|id| id.to_string() == act_id),
        "manifest references the sealed act: {manifest:?}"
    );
    assert!(
        manifest
            .document_ids
            .iter()
            .any(|id| id.to_string() == document_id),
        "manifest references the sealed document: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("documents/{document_id}.pdf")
                && file.role == PackageFileRole::PdfA
                && file.content_type == "application/pdf"
                && file.act_id.is_some()
        }),
        "manifest references the act PDF/A document: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("metadata/{document_id}.json")
                && file.role == PackageFileRole::Metadata
                && file.document_id.is_some()
        }),
        "manifest references the document metadata sidecar: {manifest:?}"
    );

    let (status, after) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger after export: {after}");
    assert_eq!(before, after, "package export is read-only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn persisted_legal_hold_survives_restart_and_blocks_partial_disposal() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

    let entity_id = create_entity(
        &h,
        "Arquivo Retencao, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;
    let act_id = draft_act(
        &h,
        &book_id,
        "Ata com retencao sob hold judicial",
        Some(&token),
    )
    .await;
    fill_act_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;
    let (status, sealed) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "seal act before hold: {sealed}");
    let document_id = sealed["document"]["id"].as_str().expect("document id");

    let hold_reason = "court order: suspend scheduled archive destruction";
    let (status, hold) = h
        .put_json_auth(
            &format!("/v1/books/{book_id}/legal-hold"),
            json!({ "reason": hold_reason, "actor": "records.manager" }),
            &token,
        )
        .await;
    assert_eq!(status, 200, "set persisted legal hold: {hold}");
    assert_eq!(hold["legal_hold"], true);
    assert_eq!(hold["reason"], hold_reason);
    assert_eq!(hold["actor"], "e2e.operator");
    let hold_set_at = hold["set_at"].clone();

    let package_path = format!("/v1/books/{book_id}/archive/package");
    let (status, ctype, package_before_restart) = get_bytes(&h, &package_path, &token).await;
    assert_eq!(status, 200, "archive under active hold: {status}");
    assert_eq!(ctype, "application/zip");
    let manifest =
        validate_package(&package_before_restart).expect("pre-restart package validates");
    assert!(manifest.retention.legal_hold);
    assert!(!manifest.retention.is_disposable());
    assert!(
        manifest.files.iter().any(|file| {
            file.path == "evidence/legal-hold.json"
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "manifest declares legal-hold evidence: {manifest:?}"
    );
    let hold_report = package_member_json(&package_before_restart, "evidence/legal-hold.json");
    assert_eq!(hold_report["reason"], hold_reason);
    assert_eq!(hold_report["actor"], "e2e.operator");
    assert_eq!(hold_report["persistence"], "persisted_book_state");

    h.restart().await;
    let token = h
        .current_token()
        .expect("default session was reopened after restart");

    let (status, reloaded_hold) = h
        .get_json_auth(&format!("/v1/books/{book_id}/legal-hold"), &token)
        .await;
    assert_eq!(
        status, 200,
        "legal hold reloaded after restart: {reloaded_hold}"
    );
    assert_eq!(reloaded_hold["legal_hold"], true);
    assert_eq!(reloaded_hold["reason"], hold_reason);
    assert_eq!(reloaded_hold["actor"], "e2e.operator");
    assert_eq!(
        reloaded_hold["set_at"], hold_set_at,
        "hold timestamp is durable, not recreated on boot"
    );

    let (status, disposal_status) = h
        .get_json_auth(&format!("/v1/books/{book_id}/archive/disposal"), &token)
        .await;
    assert_eq!(
        status, 200,
        "disposal status should be readable after restart: {disposal_status}"
    );
    assert_eq!(disposal_status["eligible"], false);
    assert_eq!(disposal_status["blocked"], true);
    assert_eq!(disposal_status["active_persisted_legal_hold"], true);
    assert!(
        disposal_status["reasons"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason["code"] == "active_persisted_legal_hold"
                    && reason["blocking"] == true)),
        "active legal-hold reason blocks disposal: {disposal_status}"
    );

    let (status, before_blocked_disposal) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(
        status, 200,
        "ledger before blocked disposal: {before_blocked_disposal}"
    );
    let (status, rejected) = h
        .post_json_auth(
            &format!("/v1/books/{book_id}/archive/disposal"),
            json!({ "dry_run": true }),
            &token,
        )
        .await;
    assert_eq!(
        status, 409,
        "hold must block disposal simulation after restart: {rejected}"
    );
    assert!(
        rejected["error"]
            .as_str()
            .is_some_and(|error| error.contains("hold legal ativo")),
        "blocked disposal error identifies active hold: {rejected}"
    );
    assert!(
        rejected.get("would_delete").is_none(),
        "blocked destructive retention path must not build a partial deletion manifest: {rejected}"
    );
    let (status, after_blocked_disposal) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(
        status, 200,
        "ledger after blocked disposal: {after_blocked_disposal}"
    );
    assert_eq!(
        before_blocked_disposal, after_blocked_disposal,
        "blocked disposal attempt is read-only"
    );

    let (status, hold_after_rejection) = h
        .get_json_auth(&format!("/v1/books/{book_id}/legal-hold"), &token)
        .await;
    assert_eq!(
        status, 200,
        "legal hold after rejected disposal: {hold_after_rejection}"
    );
    assert_eq!(
        hold_after_rejection, reloaded_hold,
        "rejected disposal did not partially clear or rewrite the hold"
    );
    let (status, book) = h
        .get_json_auth(&format!("/v1/books/{book_id}"), &token)
        .await;
    assert_eq!(status, 200, "book remains after rejected disposal: {book}");
    assert_eq!(book["id"], book_id);
    let (status, act) = h.get_json_auth(&format!("/v1/acts/{act_id}"), &token).await;
    assert_eq!(status, 200, "act remains after rejected disposal: {act}");
    assert_eq!(act["state"], "Sealed");

    let (status, ctype, package_after_rejection) = get_bytes(&h, &package_path, &token).await;
    assert_eq!(status, 200, "archive still exports after blocked disposal");
    assert_eq!(ctype, "application/zip");
    assert_eq!(
        package_after_rejection, package_before_restart,
        "restart plus blocked disposal did not rewrite archive package inputs"
    );
    let manifest =
        validate_package(&package_after_rejection).expect("post-rejection package validates");
    assert!(manifest.retention.legal_hold);
    assert!(
        manifest
            .document_ids
            .iter()
            .any(|id| id.to_string() == document_id),
        "package still references the preserved sealed document: {manifest:?}"
    );
}
