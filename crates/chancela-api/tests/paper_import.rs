use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chancela-paper-import-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
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
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

async fn send_bytes(
    state: &AppState,
    req: Request<Body>,
) -> (StatusCode, Vec<u8>, header::HeaderMap) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, bytes.to_vec(), headers)
}

fn json_req(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

fn patch_req(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

async fn bootstrap(state: &AppState) -> String {
    *state.roles.write().await = chancela_authz::RoleCatalog::seeded_defaults();

    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "username": "paper.owner", "display_name": "Paper Owner" }).to_string(),
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

fn valid_candidate() -> Value {
    json!({
        "entity_ref": "entity-legacy-001",
        "entity_name": "Encosto Estrategico, S.A.",
        "entity_nipc": "503004642",
        "book_ref": "ag-book-1968-1971",
        "date_from": "1968-01-01",
        "date_to": "1971-12-31",
        "page_count": 240,
        "page_from": 1,
        "page_to": 48,
        "original_ata_number_from": 101,
        "original_ata_number_to": 119,
        "source_filename": "ag-1968-1971.pdf",
        "digest": "abababababababababababababababababababababababababababababababab",
        "notes": "Scanned from bound paper minute book."
    })
}

fn package_bytes() -> Vec<u8> {
    b"%PDF-1.7\nhistorical paper book scan package\n%%EOF".to_vec()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn preserve_body(bytes: &[u8]) -> Value {
    let digest = hex(&Sha256::digest(bytes));
    let mut body = valid_candidate();
    body["digest"] = json!(digest);
    body["content_base64"] = json!(B64.encode(bytes));
    body["content_type"] = json!("application/pdf");
    body["declared_sha256"] = json!(digest);
    body["size_bytes"] = json!(bytes.len());
    body
}

fn preflight_blocker_codes(body: &Value) -> Vec<String> {
    body["canonical_conversion_preflight"]["blockers"]
        .as_array()
        .expect("preflight blockers array")
        .iter()
        .map(|blocker| {
            blocker["code"]
                .as_str()
                .expect("preflight blocker code")
                .to_owned()
        })
        .collect()
}

async fn validate(state: &AppState, token: &str, body: Value) -> (StatusCode, Value) {
    send(
        state,
        json_req("/v1/books/paper-import/validate", token, body),
    )
    .await
}

async fn preserve(state: &AppState, token: &str, body: Value) -> (StatusCode, Value) {
    send(state, json_req("/v1/books/paper-import", token, body)).await
}

async fn enqueue_ocr(state: &AppState, token: &str, import_id: &str) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            &format!("/v1/books/paper-import/{import_id}/ocr/enqueue"),
            token,
            json!({}),
        ),
    )
    .await
}

async fn update_ocr_status(
    state: &AppState,
    token: &str,
    import_id: &str,
    status: &str,
) -> (StatusCode, Value) {
    send(
        state,
        patch_req(
            &format!("/v1/books/paper-import/{import_id}/ocr-status"),
            token,
            json!({ "status": status }),
        ),
    )
    .await
}

async fn create_ocr_draft(
    state: &AppState,
    token: &str,
    import_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            &format!("/v1/books/paper-import/{import_id}/ocr-drafts"),
            token,
            body,
        ),
    )
    .await
}

async fn review_ocr_draft(
    state: &AppState,
    token: &str,
    import_id: &str,
    draft_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    send(
        state,
        patch_req(
            &format!("/v1/books/paper-import/{import_id}/ocr-drafts/{draft_id}/review"),
            token,
            body,
        ),
    )
    .await
}

async fn list_imports(state: &AppState, token: &str, query: &str) -> (StatusCode, Value) {
    send(
        state,
        get_req(&format!("/v1/books/paper-import{query}"), token),
    )
    .await
}

async fn list_ocr_drafts(state: &AppState, token: &str, import_id: &str) -> (StatusCode, Value) {
    send(
        state,
        get_req(
            &format!("/v1/books/paper-import/{import_id}/ocr-drafts"),
            token,
        ),
    )
    .await
}

#[tokio::test]
async fn valid_paper_book_import_validation_returns_non_canonical_dry_run_report() {
    let state = AppState::default();
    let token = bootstrap(&state).await;

    let (status, body) = validate(&state, &token, valid_candidate()).await;

    assert_eq!(status, StatusCode::OK, "validation report: {body}");
    assert_eq!(body["report_kind"], "paper_book_import_validation");
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["identity"]["book_ref"], "ag-book-1968-1971");
    assert_eq!(body["package"]["page_count"], 240);
    assert_eq!(body["package"]["source_page_range"]["from"], 1);
    assert_eq!(body["package"]["source_page_range"]["to"], 48);
    assert_eq!(body["linking_evidence"]["source_page_range"]["from"], 1);
    assert_eq!(body["linking_evidence"]["source_page_range"]["to"], 48);
    assert_eq!(
        body["linking_evidence"]["original_ata_number_range"]["from"],
        101
    );
    assert_eq!(
        body["linking_evidence"]["original_ata_number_range"]["to"],
        119
    );
    assert_eq!(body["linking_evidence"]["planning_evidence_only"], true);
    assert_eq!(body["linking_evidence"]["canonical_act_created"], false);
    assert_eq!(
        body["linking_evidence"]["canonical_document_created"],
        false
    );
    assert_eq!(body["linking_evidence"]["signature_created"], false);
    assert_eq!(body["linking_evidence"]["legal_acceptance_claimed"], false);
    assert_eq!(
        body["continuation"]["recommendation"],
        "continue_after_operator_review_of_original_numbering"
    );
    assert_eq!(
        body["continuation"]["recommended_action"],
        "prepare_next_digital_ata_using_recommended_next_ata_number"
    );
    assert_eq!(body["continuation"]["recommended_next_ata_number"], 120);
    assert_eq!(body["continuation"]["requires_operator_review"], true);
    assert_eq!(body["continuation"]["canonical_act_created"], false);
    assert_eq!(body["continuation"]["canonical_document_created"], false);
    assert_eq!(body["continuation"]["signature_created"], false);
    assert_eq!(body["continuation"]["legal_acceptance_claimed"], false);
    assert_eq!(
        body["canonical_conversion_preflight"]["status"],
        "not_attempted"
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["scope"],
        "ocr_to_canonical_conversion_preflight"
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["evidence_source"],
        "not_supplied"
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["preflight_requested"],
        false
    );
    assert!(
        body["canonical_conversion_preflight"]["blockers"]
            .as_array()
            .expect("default preflight blockers")
            .is_empty()
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["evidence"]["candidate_digest_present"],
        true
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["evidence"]["source_page_range_valid"],
        true
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["canonical_act_created"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["canonical_document_created"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["signature_created"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["signing_requested"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["signature_validity_claimed"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["qualified_signature_claimed"],
        false
    );
    assert_eq!(
        body["candidate_classification"]["classification"],
        "historical_paper_book_non_canonical_evidence"
    );
    assert_eq!(body["candidate_classification"]["non_canonical"], true);
    assert_eq!(
        body["candidate_classification"]["canonical_minutes_claimed"],
        false
    );
    assert_eq!(
        body["candidate_classification"]["qualified_signature_claimed"],
        false
    );
    assert_eq!(
        body["candidate_classification"]["legal_validity_claimed"],
        false
    );
    assert_eq!(body["can_accept_as_import_candidate"], true);
}

#[tokio::test]
async fn paper_book_import_validation_blocks_requested_canonical_conversion_without_evidence() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let mut candidate = valid_candidate();
    candidate["digest"] = Value::Null;
    candidate["canonical_conversion_preflight"] = json!({});

    let (status, body) = validate(&state, &token, candidate).await;

    assert_eq!(status, StatusCode::OK, "validation report: {body}");
    let preflight = &body["canonical_conversion_preflight"];
    assert_eq!(preflight["status"], "blocked");
    assert_eq!(preflight["preflight_requested"], true);
    assert_eq!(preflight["evidence"]["ocr_text_present"], false);
    assert_eq!(preflight["evidence"]["candidate_digest_present"], false);
    assert_eq!(preflight["evidence"]["operator_review_recorded"], false);
    assert_eq!(preflight["evidence"]["package_fixity_recorded"], false);
    assert_eq!(preflight["evidence"]["page_range_reviewed"], false);
    assert_eq!(preflight["evidence"]["legal_acceptance_recorded"], false);
    let codes = preflight_blocker_codes(&body);
    assert!(codes.contains(&"missing_ocr_text".to_owned()));
    assert!(codes.contains(&"missing_operator_review".to_owned()));
    assert!(codes.contains(&"missing_candidate_digest".to_owned()));
    assert!(codes.contains(&"package_fixity_not_recorded".to_owned()));
    assert!(codes.contains(&"page_range_not_reviewed".to_owned()));
    assert!(codes.contains(&"legal_acceptance_not_recorded".to_owned()));
    assert_eq!(preflight["canonical_act_created"], false);
    assert_eq!(preflight["canonical_document_created"], false);
    assert_eq!(preflight["signature_created"], false);
    assert_eq!(preflight["signing_requested"], false);
    assert_eq!(preflight["signature_validity_claimed"], false);
    assert_eq!(preflight["qualified_signature_claimed"], false);
    assert_eq!(preflight["legal_validity_claimed"], false);
}

#[tokio::test]
async fn paper_book_import_validation_allows_preflight_only_with_explicit_evidence() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let mut candidate = valid_candidate();
    candidate["canonical_conversion_preflight"] = json!({
        "ocr_text_digest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "operator_review_recorded": true,
        "package_fixity_recorded": true,
        "page_range_reviewed": true,
        "legal_acceptance_recorded": true
    });

    let (status, body) = validate(&state, &token, candidate).await;

    assert_eq!(status, StatusCode::OK, "validation report: {body}");
    let preflight = &body["canonical_conversion_preflight"];
    assert_eq!(preflight["status"], "allowed");
    assert_eq!(preflight["preflight_requested"], true);
    assert_eq!(
        preflight["evidence_source"],
        "operator_supplied_preflight_evidence"
    );
    assert_eq!(
        preflight["allowed_next_action"],
        "prepare_canonical_conversion_draft_after_preservation"
    );
    assert_eq!(preflight["evidence"]["ocr_text_present"], true);
    assert_eq!(
        preflight["evidence"]["ocr_text_digest"],
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    );
    assert_eq!(preflight["evidence"]["operator_review_recorded"], true);
    assert_eq!(preflight["evidence"]["candidate_digest_present"], true);
    assert_eq!(preflight["evidence"]["package_fixity_recorded"], true);
    assert_eq!(preflight["evidence"]["source_page_range"]["from"], 1);
    assert_eq!(preflight["evidence"]["source_page_range"]["to"], 48);
    assert_eq!(preflight["evidence"]["page_range_reviewed"], true);
    assert_eq!(preflight["evidence"]["legal_acceptance_recorded"], true);
    assert!(
        preflight["blockers"]
            .as_array()
            .expect("blockers")
            .is_empty()
    );
    assert_eq!(preflight["raw_ocr_text_in_report"], false);
    assert_eq!(preflight["canonical_act_created"], false);
    assert_eq!(preflight["canonical_document_created"], false);
    assert_eq!(preflight["signature_created"], false);
    assert_eq!(preflight["signing_requested"], false);
    assert_eq!(preflight["signature_validity_claimed"], false);
    assert_eq!(preflight["qualified_signature_claimed"], false);
    assert_eq!(preflight["legal_validity_claimed"], false);
}

#[tokio::test]
async fn paper_book_import_validation_rejects_bad_source_or_original_ranges() {
    let state = AppState::default();
    let token = bootstrap(&state).await;

    let mut bad_pages = valid_candidate();
    bad_pages["page_from"] = json!(49);
    bad_pages["page_to"] = json!(48);
    let (status, body) = validate(&state, &token, bad_pages).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad source pages: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("source page range")),
        "error names source page range: {body}"
    );

    let mut missing_original_to = valid_candidate();
    missing_original_to["original_ata_number_to"] = Value::Null;
    let (status, body) = validate(&state, &token, missing_original_to).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "partial original range: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("supplied together")),
        "error names paired original ata-number fields: {body}"
    );
}

#[tokio::test]
async fn paper_book_import_validation_rejects_bad_date_range() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let mut body = valid_candidate();
    body["date_from"] = json!("1971-12-31");
    body["date_to"] = json!("1968-01-01");

    let (status, body) = validate(&state, &token, body).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad range: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("date range")),
        "error names date range: {body}"
    );
}

#[tokio::test]
async fn paper_book_import_validation_rejects_path_like_inputs() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let mut body = valid_candidate();
    body["source_filename"] = json!("scans/ag-1968-1971.pdf");

    let (status, body) = validate(&state, &token, body).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "path-like input: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("not a path")),
        "error names path-like input: {body}"
    );
}

#[tokio::test]
async fn paper_book_import_validation_does_not_mutate_ledger() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let before = state.ledger.read().await.events().len();

    let (status, body) = validate(&state, &token, valid_candidate()).await;

    assert_eq!(status, StatusCode::OK, "validation report: {body}");
    assert_eq!(
        state.ledger.read().await.events().len(),
        before,
        "read-only paper import validation must not append ledger events"
    );
}

#[tokio::test]
async fn paper_book_import_preserves_package_bytes_and_appends_metadata_only_event() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let before = state.ledger.read().await.events().len();
    let bytes = package_bytes();

    let (status, body) = preserve(&state, &token, preserve_body(&bytes)).await;

    assert_eq!(status, StatusCode::CREATED, "preservation report: {body}");
    assert_eq!(body["report_kind"], "paper_book_import_preservation");
    assert_eq!(body["dry_run"], false);
    assert_eq!(body["candidate_classification"]["non_canonical"], true);
    assert_eq!(
        body["candidate_classification"]["legal_validity_claimed"],
        false
    );
    assert_eq!(body["package"]["source_page_range"]["from"], 1);
    assert_eq!(body["package"]["source_page_range"]["to"], 48);
    assert_eq!(
        body["linking_evidence"]["original_ata_number_range"]["from"],
        101
    );
    assert_eq!(
        body["linking_evidence"]["original_ata_number_range"]["to"],
        119
    );
    assert_eq!(body["linking_evidence"]["planning_evidence_only"], true);
    assert_eq!(body["linking_evidence"]["canonical_act_created"], false);
    assert_eq!(
        body["linking_evidence"]["canonical_document_created"],
        false
    );
    assert_eq!(body["linking_evidence"]["signature_created"], false);
    assert_eq!(body["linking_evidence"]["legal_acceptance_claimed"], false);
    assert_eq!(body["continuation"]["recommended_next_ata_number"], 120);
    assert_eq!(body["continuation"]["canonical_act_created"], false);
    assert_eq!(body["continuation"]["canonical_document_created"], false);
    assert_eq!(body["continuation"]["signature_created"], false);
    assert_eq!(body["continuation"]["legal_acceptance_claimed"], false);
    assert_eq!(
        body["canonical_conversion_preflight"]["status"],
        "not_attempted"
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["canonical_act_created"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["canonical_document_created"],
        false
    );
    assert_eq!(
        body["canonical_conversion_preflight"]["signature_created"],
        false
    );
    assert_eq!(body["preservation"]["bytes_in_ledger_event"], false);
    assert_eq!(body["preservation"]["ocr_status"], "not_run");
    let import_id = body["import_id"].as_str().expect("import id");

    let ledger = state.ledger.read().await;
    assert_eq!(
        ledger.events().len(),
        before + 1,
        "preservation appends exactly one ledger event"
    );
    let event = ledger.events().last().expect("paper import event");
    assert_eq!(event.kind, "paper_book_import.preserved");
    assert_eq!(event.scope, format!("paper-book-import:{import_id}"));
    drop(ledger);

    let stored = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_import(import_id)
        .expect("store read")
        .expect("paper import row");
    assert_eq!(stored.bytes, bytes);
    assert_eq!(stored.meta.sha256, body["preservation"]["sha256"]);
    assert_eq!(stored.meta.page_from, 1);
    assert_eq!(stored.meta.page_to, 48);
    assert_eq!(stored.meta.original_number_from, Some(101));
    assert_eq!(stored.meta.original_number_to, Some(119));
    assert_eq!(stored.meta.ocr_status.as_str(), "not_run");
}

#[tokio::test]
async fn paper_book_import_ocr_status_lifecycle_is_metadata_only() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let (status, created) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");
    let before = state.ledger.read().await.events().len();

    let (status, queued) = enqueue_ocr(&state, &token, import_id).await;
    assert_eq!(status, StatusCode::OK, "enqueue: {queued}");
    assert_eq!(queued["previous_ocr_status"], "not_run");
    assert_eq!(queued["ocr_status"], "queued");
    assert_eq!(queued["ocr_text_stored"], false);
    assert_eq!(queued["authoritative_text_claimed"], false);
    assert_eq!(queued["legal_validity_claimed"], false);
    assert!(
        queued["status_notice"]
            .as_str()
            .is_some_and(|notice| notice.contains("metadata only")),
        "status notice is non-authoritative: {queued}"
    );

    let (status, running) = update_ocr_status(&state, &token, import_id, "running").await;
    assert_eq!(status, StatusCode::OK, "running: {running}");
    assert_eq!(running["previous_ocr_status"], "queued");
    assert_eq!(running["ocr_status"], "running");

    let (status, completed) = update_ocr_status(&state, &token, import_id, "completed").await;
    assert_eq!(status, StatusCode::OK, "completed: {completed}");
    assert_eq!(completed["previous_ocr_status"], "running");
    assert_eq!(completed["ocr_status"], "completed");

    let ledger = state.ledger.read().await;
    assert_eq!(
        ledger.events().len(),
        before + 3,
        "each OCR status mutation appends one metadata event"
    );
    assert_eq!(
        ledger.events().last().expect("last event").kind,
        "paper_book_import.ocr_status_updated"
    );
    drop(ledger);

    let stored = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_import(import_id)
        .expect("store read")
        .expect("paper import row");
    assert_eq!(stored.meta.ocr_status.as_str(), "completed");
    assert_eq!(stored.bytes, package_bytes());

    let (status, meta) = send(
        &state,
        get_req(&format!("/v1/books/paper-import/{import_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "metadata: {meta}");
    assert_eq!(meta["ocr_status"], "completed");
    assert_eq!(meta["ocr_text_stored"], false);
    assert_eq!(meta["authoritative_text_claimed"], false);
    assert!(meta.get("ocr_text").is_none());
}

#[tokio::test]
async fn paper_book_import_ocr_status_rejects_unknown_status_without_mutation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let (status, created) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");
    let before = state.ledger.read().await.events().len();

    let (status, body) = update_ocr_status(&state, &token, import_id, "verified").await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown OCR status: {body}"
    );
    assert!(
        body["error"].as_str().is_some_and(
            |error| error.contains("disabled, not_run, queued, running, completed, or failed")
        ),
        "error names allowed lifecycle: {body}"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        before,
        "bad OCR status must not append ledger events"
    );
    let stored = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_import(import_id)
        .expect("store read")
        .expect("paper import row");
    assert_eq!(stored.meta.ocr_status.as_str(), "not_run");
}

#[tokio::test]
async fn paper_book_import_ocr_draft_results_are_non_authoritative_and_reviewable() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let bytes = package_bytes();
    let (status, created) = preserve(&state, &token, preserve_body(&bytes)).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");
    let before = state.ledger.read().await.events().len();
    let digest = hex(&Sha256::digest("Livro de atas digitalizado."));

    let (status, draft) = create_ocr_draft(
        &state,
        &token,
        import_id,
        json!({
            "extracted_text": "Livro de atas digitalizado.",
            "text_digest": digest,
            "page_spans": [
                { "start_page": 1, "end_page": 2 },
                { "start_page": 5, "end_page": 5 }
            ],
            "confidence": 0.87,
            "engine_name": "operator-supplied-ocr",
            "engine_version": "0.1.0"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "create OCR draft: {draft}");
    assert_eq!(draft["import_id"], import_id);
    assert_eq!(draft["extracted_text"], "Livro de atas digitalizado.");
    assert_eq!(draft["text_digest"], digest);
    assert_eq!(draft["page_spans"][0]["start_page"], 1);
    assert_eq!(draft["page_spans"][0]["end_page"], 2);
    assert_eq!(draft["confidence"], 0.87);
    assert_eq!(draft["engine"]["name"], "operator-supplied-ocr");
    assert_eq!(draft["review_status"], "unreviewed");
    assert_eq!(draft["non_canonical"], true);
    assert_eq!(draft["authoritative_text_claimed"], false);
    assert_eq!(draft["canonical_minutes_claimed"], false);
    assert_eq!(draft["canonical_act_created"], false);
    assert_eq!(draft["canonical_document_created"], false);
    assert_eq!(draft["signature_created"], false);
    assert_eq!(draft["legal_validity_claimed"], false);
    assert!(
        draft["draft_notice"]
            .as_str()
            .is_some_and(|notice| notice.contains("non-authoritative")),
        "draft notice is explicit: {draft}"
    );
    let draft_id = draft["draft_id"].as_str().expect("draft id");

    let (status, listed) = list_ocr_drafts(&state, &token, import_id).await;
    assert_eq!(status, StatusCode::OK, "list drafts: {listed}");
    let rows = listed.as_array().expect("draft list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["draft_id"], draft_id);
    assert_eq!(rows[0]["canonical_act_created"], false);
    assert_eq!(rows[0]["canonical_document_created"], false);
    assert_eq!(rows[0]["signature_created"], false);

    let (status, reviewed) = review_ocr_draft(
        &state,
        &token,
        import_id,
        draft_id,
        json!({ "review_status": "accepted", "review_note": "Checked against the scan." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "review OCR draft: {reviewed}");
    assert_eq!(reviewed["review_status"], "accepted");
    assert_eq!(reviewed["review_note"], "Checked against the scan.");
    assert!(reviewed["reviewed_at"].as_str().is_some());
    assert!(reviewed["reviewed_by"].as_str().is_some());
    assert_eq!(reviewed["authoritative_text_claimed"], false);
    assert_eq!(reviewed["canonical_act_created"], false);
    assert_eq!(reviewed["canonical_document_created"], false);
    assert_eq!(reviewed["signature_created"], false);
    assert_eq!(reviewed["legal_validity_claimed"], false);

    let ledger = state.ledger.read().await;
    assert_eq!(
        ledger.events().len(),
        before + 2,
        "draft create and review each append one metadata event"
    );
    assert_eq!(
        ledger.events()[ledger.events().len() - 2].kind,
        "paper_book_import.ocr_draft_created"
    );
    assert_eq!(
        ledger.events().last().expect("last event").kind,
        "paper_book_import.ocr_draft_reviewed"
    );
    drop(ledger);

    let stored_import = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_import(import_id)
        .expect("store read")
        .expect("paper import row");
    assert_eq!(stored_import.bytes, bytes);
    assert_eq!(stored_import.meta.ocr_status.as_str(), "not_run");

    let stored_draft = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_ocr_draft(draft_id)
        .expect("draft read")
        .expect("draft row");
    assert_eq!(stored_draft.import_id, import_id);
    assert_eq!(stored_draft.review_status.as_str(), "accepted");
}

#[tokio::test]
async fn paper_book_import_ocr_draft_superseded_review_requires_successor_without_failed_mutation()
{
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let (status, created) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");

    let (status, first) = create_ocr_draft(
        &state,
        &token,
        import_id,
        json!({
            "text_digest": "ab".repeat(32),
            "page_spans": [{ "start_page": 1, "end_page": 1 }],
            "confidence": 0.70,
            "engine_name": "operator-supplied-ocr"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "first draft: {first}");
    let first_id = first["draft_id"].as_str().expect("first draft id");

    let (status, successor) = create_ocr_draft(
        &state,
        &token,
        import_id,
        json!({
            "text_digest": "cd".repeat(32),
            "page_spans": [{ "start_page": 1, "end_page": 1 }],
            "confidence": 0.91,
            "engine_name": "operator-supplied-ocr"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "successor draft: {successor}");
    let successor_id = successor["draft_id"].as_str().expect("successor draft id");
    let before_review = state.ledger.read().await.events().len();

    let (status, body) = review_ocr_draft(
        &state,
        &token,
        import_id,
        first_id,
        json!({ "review_status": "superseded" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing superseded_by refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("superseded_by")),
        "error names superseded_by requirement: {body}"
    );

    let (status, body) = review_ocr_draft(
        &state,
        &token,
        import_id,
        first_id,
        json!({ "review_status": "accepted", "superseded_by": successor_id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "superseded_by on accepted refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("only valid")),
        "error names superseded_by status constraint: {body}"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        before_review,
        "invalid review transitions must not append ledger events"
    );
    let unchanged = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_ocr_draft(first_id)
        .expect("draft read")
        .expect("draft row");
    assert_eq!(unchanged.review_status.as_str(), "unreviewed");
    assert!(unchanged.superseded_by.is_none());

    let (status, reviewed) = review_ocr_draft(
        &state,
        &token,
        import_id,
        first_id,
        json!({
            "review_status": "superseded",
            "superseded_by": successor_id,
            "review_note": "Replaced by a higher-confidence OCR draft."
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superseded review: {reviewed}");
    assert_eq!(reviewed["review_status"], "superseded");
    assert_eq!(reviewed["superseded_by"], successor_id);
    assert_eq!(reviewed["canonical_act_created"], false);
    assert_eq!(reviewed["canonical_document_created"], false);
    assert_eq!(reviewed["signature_created"], false);
    assert_eq!(reviewed["authoritative_text_claimed"], false);

    assert_eq!(
        state.ledger.read().await.events().len(),
        before_review + 1,
        "valid superseded review appends one metadata event"
    );
    let stored = state
        .store
        .as_ref()
        .expect("store")
        .paper_book_ocr_draft(first_id)
        .expect("draft read")
        .expect("draft row");
    assert_eq!(stored.review_status.as_str(), "superseded");
    assert_eq!(stored.superseded_by.as_deref(), Some(successor_id));
}

#[tokio::test]
async fn paper_book_import_ocr_draft_rejects_missing_text_and_bad_page_span_without_mutation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let (status, created) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");
    let before = state.ledger.read().await.events().len();

    let (status, body) = create_ocr_draft(
        &state,
        &token,
        import_id,
        json!({
            "page_spans": [{ "start_page": 1, "end_page": 1 }],
            "engine_name": "operator-supplied-ocr"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing text/digest refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("extracted_text or text_digest")),
        "error names text/digest requirement: {body}"
    );

    let (status, body) = create_ocr_draft(
        &state,
        &token,
        import_id,
        json!({
            "text_digest": "ab".repeat(32),
            "page_spans": [{ "start_page": 1, "end_page": 999 }],
            "confidence": 0.7,
            "engine_name": "operator-supplied-ocr"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad page span refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("page_count")),
        "error names page_count bound: {body}"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        before,
        "invalid OCR draft requests must not append ledger events"
    );
}

#[tokio::test]
async fn paper_book_import_list_and_read_are_metadata_only_and_download_returns_bytes() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let bytes = package_bytes();
    let (status, created) = preserve(&state, &token, preserve_body(&bytes)).await;
    assert_eq!(status, StatusCode::CREATED, "preserve: {created}");
    let import_id = created["import_id"].as_str().expect("import id");

    let (status, list) = list_imports(&state, &token, "").await;
    assert_eq!(status, StatusCode::OK, "list: {list}");
    let rows = list.as_array().expect("list array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["import_id"], import_id);
    assert_eq!(rows[0]["book_ref"], "ag-book-1968-1971");
    assert_eq!(rows[0]["page_from"], 1);
    assert_eq!(rows[0]["page_to"], 48);
    assert_eq!(rows[0]["original_ata_number_from"], 101);
    assert_eq!(rows[0]["original_ata_number_to"], 119);
    assert_eq!(rows[0]["linking_evidence"]["source_page_range"]["from"], 1);
    assert_eq!(rows[0]["linking_evidence"]["source_page_range"]["to"], 48);
    assert_eq!(
        rows[0]["linking_evidence"]["original_ata_number_range"]["from"],
        101
    );
    assert_eq!(
        rows[0]["linking_evidence"]["original_ata_number_range"]["to"],
        119
    );
    assert_eq!(rows[0]["linking_evidence"]["planning_evidence_only"], true);
    assert_eq!(rows[0]["continuation"]["recommended_next_ata_number"], 120);
    assert_eq!(rows[0]["non_canonical"], true);
    assert_eq!(rows[0]["legal_validity_claimed"], false);
    assert_eq!(rows[0]["signature_validity_claimed"], false);
    assert_eq!(rows[0]["qualified_signature_claimed"], false);
    assert_eq!(
        rows[0]["bytes_download"],
        format!("/v1/books/paper-import/{import_id}/bytes")
    );
    assert!(
        rows[0].get("bytes").is_none() && rows[0].get("content_base64").is_none(),
        "metadata list must not expose retained bytes: {list}"
    );

    let (status, filtered) = list_imports(&state, &token, "?book_ref=ag-book-1968-1971").await;
    assert_eq!(status, StatusCode::OK, "filtered list: {filtered}");
    assert_eq!(filtered.as_array().expect("filtered").len(), 1);

    let (status, empty) = list_imports(&state, &token, "?book_ref=other-book").await;
    assert_eq!(status, StatusCode::OK, "empty filtered list: {empty}");
    assert!(empty.as_array().expect("empty").is_empty());

    let (status, meta) = send(
        &state,
        get_req(&format!("/v1/books/paper-import/{import_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "metadata: {meta}");
    assert_eq!(meta["import_id"], import_id);
    assert_eq!(meta["page_from"], 1);
    assert_eq!(meta["page_to"], 48);
    assert_eq!(meta["original_ata_number_from"], 101);
    assert_eq!(meta["original_ata_number_to"], 119);
    assert_eq!(meta["linking_evidence"]["planning_evidence_only"], true);
    assert_eq!(meta["continuation"]["recommended_next_ata_number"], 120);
    assert!(meta.get("bytes").is_none() && meta.get("content_base64").is_none());

    let (status, downloaded, headers) = send_bytes(
        &state,
        get_req(&format!("/v1/books/paper-import/{import_id}/bytes"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "download status");
    assert_eq!(downloaded, bytes);
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok()),
        Some("application/pdf")
    );
    assert!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.contains("ag-1968-1971.pdf")),
        "download uses sanitized source filename: {headers:?}"
    );
}

#[tokio::test]
async fn paper_book_import_reads_reject_path_like_or_non_uuid_ids() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;

    let (status, body) = send(
        &state,
        get_req("/v1/books/paper-import/not-a-uuid/bytes", &token),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad id refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("paper-book import id")),
        "error names import id: {body}"
    );
}

#[tokio::test]
async fn paper_book_import_preservation_rejects_digest_mismatch_without_mutation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    let before = state.ledger.read().await.events().len();
    let bytes = package_bytes();
    let mut body = preserve_body(&bytes);
    body["declared_sha256"] = json!("cd".repeat(32));

    let (status, body) = preserve(&state, &token, body).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad digest: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("sha256")),
        "error names sha256: {body}"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        before,
        "digest mismatch must not append ledger events"
    );
}

#[tokio::test]
async fn paper_book_import_preservation_requires_store_and_is_blocked_while_degraded() {
    let state = AppState::default();
    let token = bootstrap(&state).await;
    let (status, body) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "in-memory preserve refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("on-disk persistence")),
        "error names persistence requirement: {body}"
    );

    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.path());
    let token = bootstrap(&state).await;
    *state.degraded.write().await = true;

    let (status, body) = validate(&state, &token, valid_candidate()).await;
    assert_eq!(status, StatusCode::OK, "dry-run stays available: {body}");

    let (status, body) = preserve(&state, &token, preserve_body(&package_bytes())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "degraded: {body}");
    assert_eq!(body["read_only"], true);
}
