//! Archive package evidence reports.
//!
//! These tests exercise the package endpoint through the API router, then inspect the ZIP members
//! directly. The signed case seeds the already-existing `signed_documents` row shape so this stays
//! focused on archive packaging rather than signing routes.

mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, router};
use chancela_archive::{PackageFileRole, PreservationLevel, validate_package};
use chancela_core::ActId;
use chancela_signing::{
    DssEvidence, MockProvider, SignOptions, SignerProvider, SigningFamily, attach_pdf_dss,
    sign_pdf_pades, timestamp_pdf_with_url,
};
use chancela_store::{StoredDocument, StoredSignedDocument};
use common::tsa_http::MockTsaServer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::macros::datetime;
use tower::ServiceExt;
use uuid::Uuid;

const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("chancela-api-archive-package-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("temp dir created");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct SealedAct {
    book_id: String,
    act_id: String,
    document_id: String,
}

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

async fn send_bytes(state: &AppState, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, ctype, bytes)
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

async fn bootstrap(state: &AppState) -> String {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "username": "archive.owner", "display_name": "Archive Owner" }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create owner: {user}");
    let user_id = user["id"].as_str().expect("user id");

    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "user_id": user_id }).to_string()))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

async fn seal_act(state: &AppState, token: &str) -> SealedAct {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Encosto Estrategico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    let book_id = book["id"].as_str().expect("book id").to_owned();

    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "act: {act}");
    let act_id = act["id"].as_str().expect("act id").to_owned();

    let (status, body) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Aprovadas as contas do exercicio."
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch act: {body}");

    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        let (status, body) = send(
            state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/advance"),
                token,
                json!({ "to": to }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
    }

    let (status, sealed) = send(
        state,
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    let document_id = sealed["document"]["id"]
        .as_str()
        .expect("document id")
        .to_owned();

    SealedAct {
        book_id,
        act_id,
        document_id,
    }
}

async fn archive_package_bytes(state: &AppState, book_id: &str, token: &str) -> Vec<u8> {
    archive_package_bytes_at(
        state,
        &format!("/v1/books/{book_id}/archive/package"),
        token,
    )
    .await
}

async fn archive_package_bytes_at(state: &AppState, uri: &str, token: &str) -> Vec<u8> {
    let (status, content_type, bytes) = send_bytes(state, get_req(uri, token)).await;
    assert_eq!(status, StatusCode::OK, "archive package status");
    assert_eq!(content_type, "application/zip");
    assert!(!bytes.is_empty(), "archive package has bytes");
    bytes
}

fn zip_members(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip readable");
    let mut out = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).expect("zip member");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("member bytes");
        out.insert(file.name().to_owned(), bytes);
    }
    out
}

fn member_json(members: &BTreeMap<String, Vec<u8>>, path: &str) -> Value {
    serde_json::from_slice(
        members
            .get(path)
            .unwrap_or_else(|| panic!("missing zip member {path}")),
    )
    .unwrap_or_else(|e| panic!("{path} is valid JSON: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_act_id(value: &str) -> ActId {
    ActId(Uuid::parse_str(value).expect("act uuid"))
}

fn stored_document(state: &AppState, act_id: ActId, document_id: &str) -> StoredDocument {
    state
        .store
        .as_ref()
        .expect("store")
        .documents_for_act(act_id)
        .expect("documents for act")
        .into_iter()
        .find(|doc| doc.id == document_id)
        .unwrap_or_else(|| panic!("document {document_id} for {act_id}"))
}

fn upsert_document(state: &AppState, document: &StoredDocument) {
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_document(document))
        .expect("document upserted");
}

async fn ledger_events(state: &AppState, token: &str) -> Value {
    let (status, body) = send(state, get_req("/v1/ledger/events?limit=1000", token)).await;
    assert_eq!(status, StatusCode::OK, "ledger events: {body}");
    body
}

#[tokio::test]
async fn archive_package_legal_hold_marks_manifest_and_blocks_disposal() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let reason = "litigation preservation request";
    let encoded_reason = "litigation%20preservation%20request";

    let bytes = archive_package_bytes_at(
        &state,
        &format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason={}",
            sealed.book_id, encoded_reason
        ),
        &token,
    )
    .await;

    let manifest = validate_package(&bytes).expect("archive package validates");
    assert!(manifest.retention.legal_hold);
    assert!(
        !manifest.retention.is_disposable(),
        "legal hold must block retention-driven disposal"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == "evidence/legal-hold.json"
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "legal hold evidence is declared in manifest: {manifest:?}"
    );

    let members = zip_members(&bytes);
    let report = member_json(&members, "evidence/legal-hold.json");
    assert_eq!(report["report_kind"], "retention_legal_hold_evidence");
    assert_eq!(report["status"], "active");
    assert_eq!(report["legal_hold"], true);
    assert_eq!(report["reason"], reason);
    assert_eq!(report["scope"], "book_archive_package_export");
    assert_eq!(
        report["persistence"],
        "export_time_only; this endpoint does not persist legal-hold state"
    );
}

#[tokio::test]
async fn archive_package_legal_hold_rejects_missing_or_empty_reason() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    for uri in [
        format!(
            "/v1/books/{}/archive/package?legal_hold=true",
            sealed.book_id
        ),
        format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason=%20%20",
            sealed.book_id
        ),
    ] {
        let (status, body) = send(&state, get_req(&uri, &token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(
            body["error"],
            "legal_hold_reason is required when legal_hold=true"
        );
    }
}

#[tokio::test]
async fn persisted_book_legal_hold_round_trips_and_archive_uses_it() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let reason = "court preservation order";

    let (status, hold) = send(
        &state,
        json_req(
            "PUT",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "reason": reason, "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set legal hold: {hold}");
    assert_eq!(hold["legal_hold"], true);
    assert_eq!(hold["reason"], reason);
    assert_eq!(hold["actor"], "archive.owner");
    assert!(
        hold["set_at"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let persisted = state.store.as_ref().expect("store").load().expect("load");
    let book_id = Uuid::parse_str(&sealed.book_id).expect("book uuid");
    let stored_hold = persisted
        .books
        .get(&chancela_core::BookId(book_id))
        .and_then(|book| book.legal_hold.as_ref())
        .expect("legal hold persisted");
    assert_eq!(stored_hold.reason, reason);
    assert_eq!(stored_hold.actor, "archive.owner");

    let (status, hold) = send(
        &state,
        get_req(&format!("/v1/books/{}/legal-hold", sealed.book_id), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read legal hold: {hold}");
    assert_eq!(hold["legal_hold"], true);
    assert_eq!(hold["reason"], reason);

    let bytes = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&bytes).expect("archive package validates");
    assert!(manifest.retention.legal_hold);
    assert!(!manifest.retention.is_disposable());
    let members = zip_members(&bytes);
    let report = member_json(&members, "evidence/legal-hold.json");
    assert_eq!(report["report_kind"], "retention_legal_hold_evidence");
    assert_eq!(report["status"], "active");
    assert_eq!(report["legal_hold"], true);
    assert_eq!(report["reason"], reason);
    assert_eq!(report["actor"], "archive.owner");
    assert_eq!(report["persistence"], "persisted_book_state");
    assert!(
        report["set_at"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let (status, hold) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clear legal hold: {hold}");
    assert_eq!(hold["legal_hold"], false);
    assert!(hold["reason"].is_null());
    let persisted = state.store.as_ref().expect("store").load().expect("load");
    assert!(
        persisted
            .books
            .get(&chancela_core::BookId(book_id))
            .and_then(|book| book.legal_hold.as_ref())
            .is_none(),
        "legal hold cleared durably"
    );
}

#[tokio::test]
async fn disposal_status_blocks_active_persisted_legal_hold() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let (status, hold) = send(
        &state,
        json_req(
            "PUT",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "reason": "court order", "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set legal hold: {hold}");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disposal status: {body}");
    assert_eq!(body["book_id"], sealed.book_id);
    assert_eq!(body["book_state"], "Open");
    assert_eq!(body["eligible"], false);
    assert_eq!(body["blocked"], true);
    assert_eq!(body["active_persisted_legal_hold"], true);
    assert_eq!(body["export_time_legal_hold_persisted"], false);
    assert!(
        body["reasons"].as_array().is_some_and(|reasons| reasons
            .iter()
            .any(|reason| reason["code"] == "active_persisted_legal_hold"
                && reason["blocking"] == true)),
        "legal hold reason is reported: {body}"
    );

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": true }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "dry-run disposal is blocked by hold: {body}"
    );
}

#[tokio::test]
async fn disposal_dry_run_allowed_without_persisted_hold_after_export_time_hold() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let _package = archive_package_bytes_at(
        &state,
        &format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason=export%20only",
            sealed.book_id
        ),
        &token,
    )
    .await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run disposal: {body}");
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["status"]["eligible"], true);
    assert_eq!(body["status"]["blocked"], false);
    assert_eq!(body["status"]["active_persisted_legal_hold"], false);
    assert_eq!(body["status"]["export_time_legal_hold_persisted"], false);
    assert_eq!(
        body["status"]["reasons"].as_array().expect("reasons").len(),
        0
    );
    assert!(
        body["status"]["signed_evidence"]["documents_total"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "document evidence summary is present: {body}"
    );
    assert_eq!(
        body["would_delete"]["package_profile"],
        "chancela-internal-preservation-package/v1"
    );
    assert!(
        body["would_delete"]["package_members"]
            .as_array()
            .is_some_and(|members| members
                .iter()
                .any(|member| member["path"] == format!("documents/{}.pdf", sealed.document_id))),
        "dry-run manifest names package members: {body}"
    );
}

#[tokio::test]
async fn disposal_non_dry_run_is_refused_without_deleting_data() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": false }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "non-dry-run refused: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("dry_run=true")),
        "refusal tells clients to use dry_run=true: {body}"
    );

    let (status, book) = send(
        &state,
        get_req(&format!("/v1/books/{}", sealed.book_id), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "book still exists: {book}");
    assert_eq!(book["id"], sealed.book_id);
}

#[tokio::test]
async fn archive_package_rejects_stored_pdf_digest_mismatch_without_mutating_ledger() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let before = ledger_events(&state, &token).await;

    let mut document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    document.pdf_digest = "0".repeat(64);
    upsert_document(&state, &document);

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "corrupt export: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("pdf_digest mismatch")),
        "digest mismatch is explicit: {body}"
    );

    let after = ledger_events(&state, &token).await;
    assert_eq!(before, after, "failed archive validation is read-only");
}

#[tokio::test]
async fn archive_package_rejects_missing_preserved_pdf_bytes() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let mut document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    document.pdf_bytes.clear();
    document.pdf_digest = sha256_hex(&document.pdf_bytes);
    upsert_document(&state, &document);

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "missing PDF bytes: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("no preserved PDF bytes")),
        "missing content is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_duplicate_document_ids_before_manifest_build() {
    let dir = TempDir::new();
    let mut state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let book_owner = parse_act_id(&sealed.book_id);
    state.store = None;

    {
        let mut documents = state.documents.write().await;
        let book_document = documents
            .get_mut(&book_owner)
            .expect("book opening document exists");
        book_document.id = sealed.document_id.clone();
    }

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate doc id: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("appears more than once")),
        "duplicate document id is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_path_traversal_like_document_id_metadata() {
    let dir = TempDir::new();
    let mut state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let book_owner = parse_act_id(&sealed.book_id);
    state.store = None;

    {
        let mut documents = state.documents.write().await;
        let book_document = documents
            .get_mut(&book_owner)
            .expect("book opening document exists");
        book_document.id = "../metadata.json".to_owned();
    }

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "path-like doc id: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("stored document id is not a UUID")),
        "path-like id is rejected before it can become a package path: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_signed_metadata_for_the_wrong_document() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);
    let wrong_document_id = Uuid::new_v4().to_string();
    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: wrong_document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:01:00 UTC),
        signer_cert_der: b"fixture signer certificate DER".to_vec(),
        timestamp_token_der: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "wrong signed doc: {body}");
    assert!(
        body["error"].as_str().is_some_and(|error| {
            error.contains("references document")
                && error.contains(&wrong_document_id)
                && error.contains(&sealed.document_id)
        }),
        "wrong signed document link is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_signed_metadata_with_impossible_dates() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);
    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:01:00 UTC),
        signed_at: datetime!(2026-04-01 12:00:00 UTC),
        signer_cert_der: b"fixture signer certificate DER".to_vec(),
        timestamp_token_der: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "impossible dates: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("signed_at before signing_time")),
        "impossible signature chronology is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_reports_unsigned_documents_without_placeholder() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let first = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let second = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(first, second, "archive output stays deterministic");

    let manifest = validate_package(&first).expect("archive package validates");
    let preservation = &manifest.preservation_interchange;
    assert_eq!(
        preservation.profile,
        "chancela-internal-dglab-aligned-preservation-metadata/v1"
    );
    assert!(!preservation.official_dglab_interchange);
    assert!(!preservation.dglab_certification_claimed);
    assert_eq!(preservation.producer.name, "Encosto Estrategico, S.A.");
    assert_eq!(preservation.producer.system, "Chancela");
    assert_eq!(
        preservation.package_type,
        "chancela-internal-preservation-package"
    );
    assert_eq!(preservation.package_version, "1");
    assert_eq!(preservation.preservation_level, PreservationLevel::Managed);
    assert!(preservation.classification.scheme.is_none());
    assert!(preservation.classification.code.is_none());
    assert!(preservation.classification.title.is_none());
    assert!(preservation.classification.sensitivity.is_none());
    assert_eq!(preservation.retention, manifest.retention);
    assert_eq!(
        preservation.rights.holder.as_deref(),
        Some("Encosto Estrategico, S.A.")
    );
    assert_eq!(
        preservation.rights.access_note.as_deref(),
        Some("Chancela internal preservation package")
    );
    assert_eq!(preservation.languages, vec!["pt-PT".to_owned()]);
    assert_eq!(preservation.provenance.source_system, "Chancela");
    assert_eq!(
        preservation.provenance.record_count,
        manifest.provenance.len()
    );
    assert_eq!(preservation.fixity.algorithm, "sha256");
    assert_eq!(preservation.fixity.manifest_path, "manifest.json");
    assert_eq!(preservation.fixity.file_count, manifest.files.len());
    let total_byte_len: u64 = manifest.files.iter().map(|file| file.byte_len).sum();
    assert_eq!(preservation.fixity.total_byte_len, total_byte_len);

    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    let evidence_file = manifest
        .files
        .iter()
        .find(|file| file.path == evidence_path)
        .expect("act evidence report in manifest");
    assert_eq!(evidence_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(evidence_file.content_type, "application/json");
    assert_eq!(
        evidence_file.act_id.map(|id| id.to_string()).as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(
        evidence_file
            .document_id
            .map(|id| id.to_string())
            .as_deref(),
        Some(sealed.document_id.as_str())
    );

    let members = zip_members(&first);
    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "not_signed");
    assert_eq!(report["source"], "documents");
    assert_eq!(report["archive_export_revalidated"], false);
    assert_eq!(
        report["reason"],
        "no stored signature metadata matched this act document at export time"
    );
    assert!(
        report.get("signature").is_none(),
        "unsigned report must not claim signature evidence: {report}"
    );
    assert!(
        !String::from_utf8_lossy(members.get(&evidence_path).expect("evidence bytes"))
            .contains("placeholder"),
        "report must not contain placeholder evidence"
    );
}

#[tokio::test]
async fn archive_package_reports_persisted_signature_metadata_as_evidence() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = ActId(Uuid::parse_str(&sealed.act_id).expect("act uuid"));

    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signer_cert_der = b"fixture signer certificate DER".to_vec();
    let timestamp_token_der = b"fixture timestamp token DER".to_vec();
    let signed_pdf_digest = sha256_hex(&signed_pdf_bytes);
    let signer_cert_digest = sha256_hex(&signer_cert_der);
    let timestamp_token_digest = sha256_hex(&timestamp_token_der);
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:01:00 UTC),
        signer_cert_der: signer_cert_der.clone(),
        timestamp_token_der: Some(timestamp_token_der.clone()),
        signed_pdf_bytes: signed_pdf_bytes.clone(),
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let first = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let second = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(first, second, "signed archive output stays deterministic");

    let manifest = validate_package(&first).expect("archive package validates");
    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("signed/{}.pdf", sealed.document_id)
                && file.role == PackageFileRole::Other
                && file.content_type == "application/pdf; profile=PAdES-B-T"
        }),
        "signed PDF sidecar has timestamp-aware profile: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == evidence_path
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "signature evidence JSON is declared: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| file.path
            == format!("signing/{}.json", sealed.document_id)
            && file.role == PackageFileRole::SigningReport),
        "signing metadata sidecar remains declared: {manifest:?}"
    );

    let members = zip_members(&first);
    assert_eq!(
        members
            .get(&format!("signed/{}.pdf", sealed.document_id))
            .expect("signed PDF member"),
        &signed_pdf_bytes
    );
    assert_eq!(
        members
            .get(&format!("evidence/{}-signer-cert.der", sealed.document_id))
            .expect("signer cert member"),
        &signer_cert_der
    );
    assert_eq!(
        members
            .get(&format!(
                "evidence/{}-timestamp-token.tsr",
                sealed.document_id
            ))
            .expect("timestamp member"),
        &timestamp_token_der
    );

    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "signed");
    assert_eq!(report["source"], "signed_documents");
    assert_eq!(report["archive_export_revalidated"], false);
    assert!(
        report.get("reason").is_none(),
        "signed report has no absence reason"
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["path"],
        format!("signed/{}.pdf", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["content_type"],
        "application/pdf; profile=PAdES-B-T"
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["sha256"],
        signed_pdf_digest
    );
    assert_eq!(
        report["signature"]["signature"]["family"],
        "CartaoDeCidadao"
    );
    assert_eq!(
        report["signature"]["signature"]["evidentiary_level"],
        "Qualified"
    );
    assert_eq!(
        report["signature"]["signature"]["trusted_list_status"],
        "Granted"
    );
    assert_eq!(
        report["signature"]["signature"]["signing_time"],
        "2026-04-01T12:00:00Z"
    );
    assert_eq!(
        report["signature"]["signature"]["signed_at"],
        "2026-04-01T12:01:00Z"
    );
    assert_eq!(
        report["signature"]["signer_certificate"]["path"],
        format!("evidence/{}-signer-cert.der", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["signer_certificate"]["sha256"],
        signer_cert_digest
    );
    assert_eq!(report["signature"]["timestamp_token"]["present"], true);
    assert_eq!(
        report["signature"]["timestamp_token"]["path"],
        format!("evidence/{}-timestamp-token.tsr", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["timestamp_token"]["sha256"],
        timestamp_token_digest
    );
    assert_eq!(
        report["signature"]["persisted_validation"]["byte_range_covers_whole_file_except_contents"],
        "validated_before_persistence"
    );
    assert_eq!(
        report["signature"]["persisted_validation"]["cryptographic_revalidation_at_export"],
        "not_performed"
    );
    assert!(
        !String::from_utf8_lossy(members.get(&evidence_path).expect("evidence bytes"))
            .contains("placeholder"),
        "report must not contain placeholder evidence"
    );
}

#[tokio::test]
async fn archive_package_reports_embedded_dss_without_legal_b_lt_claim() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = ActId(Uuid::parse_str(&sealed.act_id).expect("act uuid"));
    let unsigned = state
        .store
        .as_ref()
        .expect("store")
        .document_for_act(act_id)
        .expect("document lookup")
        .expect("sealed document");

    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let signer_cert_der = provider
        .signing_certificate_der()
        .expect("signer certificate");
    let signing_time = datetime!(2026-04-01 12:00:00 UTC);
    let signed_pdf = sign_pdf_pades(
        &provider,
        &unsigned.pdf_bytes,
        signing_time,
        &SignOptions::default(),
    )
    .expect("PAdES signing");
    let tsa = MockTsaServer::granted();
    let tsa_url = tsa.url().to_owned();
    let (timestamped_pdf, timestamp_token_der) = tokio::task::spawn_blocking(move || {
        timestamp_pdf_with_url(&signed_pdf, &tsa_url).expect("timestamped PDF")
    })
    .await
    .expect("timestamp task");
    let dss_evidence = DssEvidence {
        certificates: vec![signer_cert_der.clone()],
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: vec![CRL_DER_FIXTURE.to_vec()],
    };
    let (signed_pdf_with_dss, dss_report) =
        attach_pdf_dss(&timestamped_pdf, &dss_evidence).expect("DSS append");
    assert!(dss_report.present);
    assert_eq!(dss_report.vri_count, 1);
    assert_eq!(dss_report.ocsp_count(), 1);
    assert_eq!(dss_report.crl_count(), 1);

    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_with_dss),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Chancela mock signer".to_owned()),
        signing_time,
        signed_at: datetime!(2026-04-01 12:02:00 UTC),
        signer_cert_der: signer_cert_der.clone(),
        timestamp_token_der: Some(timestamp_token_der),
        signed_pdf_bytes: signed_pdf_with_dss,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&package).expect("archive package validates");
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("signed/{}.pdf", sealed.document_id)
                && file.content_type == "application/pdf; profile=PAdES-B-T"
        }),
        "signed PDF remains timestamp-profiled, not advertised as legal B-LT: {manifest:?}"
    );

    let members = zip_members(&package);
    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "signed");
    assert_eq!(report["archive_export_revalidated"], false);
    let dss = &report["signature"]["dss"];
    assert_eq!(dss["basis"], "embedded_pdf_dss_catalog_inspection_only");
    assert_eq!(dss["present"], true);
    assert_eq!(dss["vri_count"], 1);
    assert_eq!(dss["certificate_count"], 1);
    assert_eq!(dss["ocsp_count"], 1);
    assert_eq!(dss["crl_count"], 1);
    assert_eq!(dss["revocation_evidence_present"], true);
    assert_eq!(dss["local_b_lt_style_evidence_present"], true);
    assert_eq!(dss["live_revocation_fetching"], false);
    assert_eq!(dss["production_b_lt_status"], "not_claimed");
    assert_eq!(dss["legal_b_lt_claimed"], false);
    assert_eq!(dss["inspection_status"], "inspected_from_signed_pdf");
    assert_eq!(
        dss["certificate_sha256"],
        json!([sha256_hex(&signer_cert_der)])
    );
    assert_eq!(dss["ocsp_sha256"], json!([sha256_hex(OCSP_DER_FIXTURE)]));
    assert_eq!(dss["crl_sha256"], json!([sha256_hex(CRL_DER_FIXTURE)]));
    assert!(
        report["signature"].get("legal_qualification").is_none(),
        "archive evidence must not claim legal qualification: {report}"
    );
}
