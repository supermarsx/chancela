use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;

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

async fn validate(state: &AppState, token: &str, body: Value) -> (StatusCode, Value) {
    send(
        state,
        json_req("/v1/books/paper-import/validate", token, body),
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
