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

const E2E_PASSWORD: &str = "Teste-Forte7!X";

async fn bootstrap_password_session(h: &ServerHarness) -> (String, String) {
    let (status, user) = h
        .post_json(
            "/v1/users",
            json!({
                "username": "e2e.operator",
                "display_name": "E2E Operator",
                "password": E2E_PASSWORD
            }),
        )
        .await;
    assert_eq!(status, 201, "create password-backed e2e user: {user}");
    let user_id = user["id"].as_str().expect("user id").to_owned();
    let token = open_password_session(h, &user_id).await;
    (user_id, token)
}

async fn open_password_session(h: &ServerHarness, user_id: &str) -> String {
    let (status, session) = h
        .post_json(
            "/v1/session",
            json!({ "user_id": user_id, "password": E2E_PASSWORD }),
        )
        .await;
    assert_eq!(status, 200, "open password-backed e2e session: {session}");
    let token = session["token"].as_str().expect("session token").to_owned();
    h.set_default_token(&token);
    token
}

fn package_member_text(bytes: &[u8], path: &str) -> String {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).expect("archive package is a readable zip");
    let mut member = archive
        .by_name(path)
        .unwrap_or_else(|e| panic!("archive package member {path} missing: {e}"));
    let mut text = String::new();
    member
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("read archive package member {path}: {e}"));
    text
}

fn package_has_member(bytes: &[u8], path: &str) -> bool {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).expect("archive package is a readable zip");
    archive.by_name(path).is_ok()
}

struct GeneratedConveningArchiveFixture {
    book_id: String,
    act_id: String,
    ata_document_id: String,
    notice_document_id: String,
}

async fn fill_generated_convening_act_contents(h: &ServerHarness, act_id: &str, token: &str) {
    let (status, body) = h
        .patch_json_auth(
            &format!("/v1/acts/{act_id}"),
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Aprovadas as contas do exercicio.",
                "convening": {
                    "convener": "Ana Presidente",
                    "convener_capacity": "Administrator",
                    "dispatch_date": "2026-03-01",
                    "antecedence_days": 21,
                    "channel": "Email",
                    "evidence_reference": "doc:convocatoria-2026-03-01",
                    "recipients": [
                        {
                            "name": "Ana Sócia",
                            "contact": "ana@example.test",
                            "channel": "Email",
                            "reference": "MSG-1"
                        },
                        {
                            "name": "Bruno Sócio",
                            "contact": "bruno@example.test",
                            "channel": "Email",
                            "reference": "MSG-2"
                        }
                    ]
                }
            }),
            token,
        )
        .await;
    assert_eq!(status, 200, "patch generated-convening act: {body}");
}

async fn seal_generated_convening_notice_act(
    h: &ServerHarness,
    token: &str,
) -> GeneratedConveningArchiveFixture {
    let entity_id = create_entity(
        h,
        "Encosto Estrategico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        token,
    )
    .await;
    let book_id = open_book(h, &entity_id, token).await;
    let act_id = draft_act(h, &book_id, "Ata da AG anual convocada", Some(token)).await;
    fill_generated_convening_act_contents(h, &act_id, token).await;
    advance_to_signing(h, &act_id, Some(token)).await;

    let (status, sealed) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            json!({
                "manual_signature_original_reference": {
                    "storage_reference": "Arquivo A / Pasta 2026 / Ata convocada"
                }
            }),
            token,
        )
        .await;
    assert_eq!(status, 200, "seal generated-convening act: {sealed}");
    assert_eq!(sealed["document"]["template_id"], "csc-ata-ag/v1");
    let ata_document_id = sealed["document"]["id"]
        .as_str()
        .expect("ata document id")
        .to_owned();

    let (status, notice) = h
        .post_json_auth(
            &format!("/v1/acts/{act_id}/document/generate?template_id=csc-convocatoria-ag/v1"),
            json!({}),
            token,
        )
        .await;
    assert_eq!(status, 201, "generated convening notice: {notice}");
    assert_eq!(notice["template_id"], "csc-convocatoria-ag/v1");
    assert_eq!(
        notice["dispatch_evidence_status"]["status"],
        "required_pending"
    );
    let notice_document_id = notice["id"].as_str().expect("notice id").to_owned();
    assert_ne!(notice_document_id, ata_document_id);

    GeneratedConveningArchiveFixture {
        book_id,
        act_id,
        ata_document_id,
        notice_document_id,
    }
}

fn assert_generated_dispatch_sidecar_no_claim_flags(sidecar: &Value) {
    assert_eq!(sidecar["status_scope"], "technical_metadata_only");
    for flag in [
        "sending_performed_by_chancela",
        "delivery_confirmed",
        "dispatch_completed",
        "legal_notice_completion_claimed",
        "legal_sufficiency_claimed",
        "provider_execution_claimed",
        "registry_filing_claimed",
        "bundle_readiness_claimed",
        "dglab_certification_claimed",
        "legal_archive_acceptance_claimed",
        "proof_bytes_included",
        "operator_note_included",
    ] {
        assert_eq!(sidecar[flag], false, "{flag} must remain false: {sidecar}");
    }
    assert_eq!(sidecar["completion_basis"], "none");
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
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Export package ata"),
            &token,
        )
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
async fn archive_package_indexes_generated_convening_notice_dispatch_evidence_metadata_only() {
    let mut h = ServerHarness::start().await;
    let (user_id, token) = bootstrap_password_session(&h).await;
    let sealed = seal_generated_convening_notice_act(&h, &token).await;
    let operator_note = "unique generated convening archive e2e note 2026-07-15T10:10:00Z sentinel";

    let (status, evidence) = h
        .post_json_auth(
            &format!(
                "/v1/documents/generated/{}/dispatch-evidence",
                sealed.notice_document_id
            ),
            json!({
                "actor": "archive.operator",
                "dispatched_at": "2026-03-01T09:00:00Z",
                "channel": "Email",
                "reference": "MSG-1",
                "recipients": ["Ana Sócia", "Bruno Sócio"],
                "evidence_reference": "archive:generated-convening-notice-dispatch",
                "operator_note": operator_note
            }),
            &token,
        )
        .await;
    assert_eq!(status, 201, "dispatch evidence: {evidence}");
    assert_eq!(
        evidence["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    assert_eq!(
        evidence["dispatch_evidence_status"]["dispatch_completed"],
        false
    );
    assert_eq!(
        evidence["dispatch_evidence_status"]["completion_basis"],
        "none"
    );
    let idempotency_key = evidence["evidence"]["idempotency_key"]
        .as_str()
        .expect("dispatch evidence idempotency key")
        .to_owned();

    let (status, before) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger before package export: {before}");

    let package_path = format!("/v1/books/{}/archive/package", sealed.book_id);
    let (status, ctype, first) = get_bytes(&h, &package_path, &token).await;
    assert_eq!(status, 200, "archive package status");
    assert_eq!(ctype, "application/zip");
    let (status, ctype, second) = get_bytes(&h, &package_path, &token).await;
    assert_eq!(status, 200, "second archive package status");
    assert_eq!(ctype, "application/zip");
    assert_eq!(
        first, second,
        "same generated-dispatch metadata inputs produce byte-identical packages"
    );

    let manifest = validate_package(&first).expect("archive package validates");
    assert_eq!(manifest.book_id.to_string(), sealed.book_id);
    assert!(
        manifest
            .act_ids
            .iter()
            .any(|id| id.to_string() == sealed.act_id),
        "manifest references the sealed act: {manifest:?}"
    );
    assert!(
        manifest
            .document_ids
            .iter()
            .any(|id| id.to_string() == sealed.ata_document_id),
        "manifest keeps the canonical Ata document id: {manifest:?}"
    );
    assert!(
        manifest
            .document_ids
            .iter()
            .all(|id| id.to_string() != sealed.notice_document_id),
        "generated notice id must not be promoted into manifest.document_ids: {manifest:?}"
    );

    let sidecar_path = format!(
        "evidence/generated-dispatch/{}.json",
        sealed.notice_document_id
    );
    let sidecar_file = manifest
        .files
        .iter()
        .find(|file| file.path == sidecar_path)
        .expect("generated convening dispatch sidecar in manifest");
    assert_eq!(sidecar_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(sidecar_file.content_type, "application/json");
    assert_eq!(
        sidecar_file.act_id.map(|id| id.to_string()).as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(
        sidecar_file.document_id, None,
        "generated notice metadata sidecar must not claim a canonical package document"
    );
    assert!(
        !package_has_member(
            &first,
            &format!("documents/{}.pdf", sealed.notice_document_id)
        ),
        "metadata-only generated dispatch evidence must not include generated notice PDF bytes"
    );

    let sidecar = package_member_json(&first, &sidecar_path);
    assert_eq!(
        sidecar["evidence_kind"],
        "generated_document_dispatch_evidence_metadata"
    );
    assert_eq!(
        sidecar["metadata_schema"],
        "chancela-generated-document-dispatch-evidence-metadata/v1"
    );
    assert_eq!(sidecar["generated_document_id"], sealed.notice_document_id);
    assert_eq!(sidecar["act_id"], sealed.act_id);
    assert!(
        sidecar.get("document_id").is_none(),
        "sidecar should not expose a package document_id: {sidecar}"
    );
    assert_eq!(sidecar["template_id"], "csc-convocatoria-ag/v1");
    assert_eq!(
        sidecar["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["dispatch_completed"],
        false
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["completion_basis"],
        "none"
    );
    assert_eq!(
        sidecar["coverage"]["required_recipients"],
        json!(["Ana Sócia", "Bruno Sócio"])
    );
    assert_eq!(
        sidecar["coverage"]["recorded_recipients"],
        json!(["Ana Sócia", "Bruno Sócio"])
    );
    assert_eq!(sidecar["coverage"]["missing_recipients"], json!([]));
    assert_eq!(sidecar["coverage"]["all_required_recipients_covered"], true);
    assert_generated_dispatch_sidecar_no_claim_flags(&sidecar);

    let record = &sidecar["records"].as_array().expect("records")[0];
    assert_eq!(record["dispatched_at"], "2026-03-01T09:00:00Z");
    assert_eq!(record["channel"], "Email");
    assert_eq!(record["reference"], "MSG-1");
    assert_eq!(
        record["evidence_reference"],
        "archive:generated-convening-notice-dispatch"
    );
    assert_eq!(record["recipients"], json!(["Ana Sócia", "Bruno Sócio"]));
    assert_eq!(record["dispatch_completed"], false);
    assert_eq!(record["completion_basis"], "none");
    assert_eq!(record["bytes_included"], false);
    assert_eq!(record["operator_note_included"], false);
    assert!(
        record.get("idempotency_key").is_none() && record.get("fingerprint").is_none(),
        "stable identifiers must not leak into sidecar records: {record}"
    );

    let evidence_index = package_member_json(&first, "evidence/index.json");
    let generated_dispatch = &evidence_index["generated_dispatch_evidence"];
    assert_eq!(
        generated_dispatch["attachment_status"],
        "generated_dispatch_evidence_metadata_attached"
    );
    assert_eq!(
        generated_dispatch["attachments"],
        json!([{
            "generated_document_id": sealed.notice_document_id.clone(),
            "act_id": sealed.act_id.clone(),
            "template_id": "csc-convocatoria-ag/v1",
            "path": sidecar_path.clone(),
            "content_type": "application/json",
            "generated_document_download": format!(
                "/v1/documents/generated/{}",
                sealed.notice_document_id
            ),
            "dispatch_evidence_status": {
                "status": "operator_evidence_covered",
                "required": true,
                "evidence_attached": true,
                "dispatch_completed": false,
                "completion_basis": "none",
                "required_recipients": ["Ana Sócia", "Bruno Sócio"],
                "recorded_recipients": ["Ana Sócia", "Bruno Sócio"],
                "missing_recipients": [],
                "note": "operator-recorded dispatch evidence covers all generated convening notice recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
            },
            "proof_bytes_included": false,
            "operator_note_included": false
        }])
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical documents")
            .iter()
            .any(|entry| entry["document_id"] == sealed.ata_document_id),
        "canonical Ata remains indexed as the package document: {evidence_index}"
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical documents")
            .iter()
            .all(|entry| entry["document_id"] != sealed.notice_document_id),
        "generated notice remains dispatch metadata only: {evidence_index}"
    );

    let sidecar_text = package_member_text(&first, &sidecar_path);
    let index_text = package_member_text(&first, "evidence/index.json");
    assert!(
        !sidecar_text.contains(operator_note)
            && !sidecar_text.contains("\"operator_note\":")
            && !index_text.contains(operator_note)
            && !index_text.contains("\"operator_note\":"),
        "free-form operator notes are excluded from preservation output"
    );
    assert!(
        !sidecar_text.contains(&idempotency_key)
            && !sidecar_text.contains("\"idempotency_key\":")
            && !sidecar_text.contains("\"fingerprint\":")
            && !index_text.contains(&idempotency_key)
            && !index_text.contains("\"idempotency_key\":")
            && !index_text.contains("\"fingerprint\":"),
        "note-derived stable identifiers are excluded from preservation output"
    );

    let (status, after) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(status, 200, "ledger after package export: {after}");
    assert_eq!(before, after, "package export is read-only");

    h.restart().await;
    let token = open_password_session(&h, &user_id).await;
    let (status, ctype, after_restart) = get_bytes(&h, &package_path, &token).await;
    assert_eq!(status, 200, "archive package after restart");
    assert_eq!(ctype, "application/zip");
    assert_eq!(
        after_restart, first,
        "restarted server exports byte-identical generated-dispatch package"
    );
    validate_package(&after_restart).expect("post-restart archive package validates");
    let (status, after_restart_ledger) = h
        .get_json_auth("/v1/ledger/events?limit=1000", &token)
        .await;
    assert_eq!(
        status, 200,
        "ledger after restart package export: {after_restart_ledger}"
    );
    assert_eq!(
        after_restart_ledger, before,
        "package export remains read-only after restart"
    );
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
        .post_json_auth(
            &format!("/v1/acts/{act_id}/seal"),
            manual_signature_seal_body("Arquivo E2E / Legal hold ata"),
            &token,
        )
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
    assert_eq!(
        rejected["error"],
        "disposição bloqueada; consulte os motivos de elegibilidade antes de executar"
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
