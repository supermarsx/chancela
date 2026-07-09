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

fn json_req(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
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
    assert_eq!(body["preservation"]["bytes_in_ledger_event"], false);
    assert_eq!(body["preservation"]["ocr_status"], "not_started");
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
    assert_eq!(stored.meta.ocr_status.as_str(), "not_started");
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
