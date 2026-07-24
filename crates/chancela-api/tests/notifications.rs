use crate::common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, UserId, router};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-notifications-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn send(state: AppState, req: Request<Body>) -> (StatusCode, Value) {
    let response = router(state).oneshot(req).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    json_request("POST", uri, body)
}

fn patch_json(uri: &str, body: Value) -> Request<Body> {
    json_request("PATCH", uri, body)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        "x-chancela-session",
        token.parse().expect("valid session header"),
    );
    req
}

async fn create_user(state: &AppState, token: Option<&str>, username: &str) -> UserId {
    let req = post_json(
        "/v1/users",
        json!({
            "username": username,
            "display_name": username,
            "password": TEST_PASSWORD,
        }),
    );
    let req = match token {
        Some(token) => with_session(req, token),
        None => req,
    };
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::CREATED, "user created: {body}");
    UserId(Uuid::parse_str(body["id"].as_str().expect("id")).expect("uuid"))
}

async fn open_session(state: &AppState, user_id: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post_json(
            "/v1/session",
            json!({ "user_id": user_id.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn patch_triage(state: &AppState, token: &str, notification_id: &str, status: &str) -> Value {
    let uri = format!("/v1/notifications/triage/{}", notification_id);
    let (status_code, body) = send(
        state.clone(),
        with_session(patch_json(&uri, json!({ "status": status })), token),
    )
    .await;
    assert_eq!(status_code, StatusCode::OK, "triage patched: {body}");
    body
}

#[tokio::test]
async fn notification_triage_persists_for_actor_across_restart() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let owner = create_user(&state, None, "owner").await;
    let owner_token = open_session(&state, owner).await;

    let patched = patch_triage(
        &state,
        &owner_token,
        "alert%3Aregistry.provenance.expired%3Aentity-1",
        "dismissed",
    )
    .await;
    assert_eq!(patched["status"], "dismissed");
    assert_eq!(
        patched["entry"]["notification_id"],
        "alert:registry.provenance.expired:entity-1"
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, body) = send(
        restarted,
        with_session(get("/v1/notifications/triage"), &restarted_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "triage lists after restart: {body}");
    assert_eq!(body["durable"], true);
    assert_eq!(body["entries"].as_array().expect("entries").len(), 1);
    assert_eq!(body["entries"][0]["status"], "dismissed");
    assert_eq!(
        body["entries"][0]["notification_id"],
        "alert:registry.provenance.expired:entity-1"
    );
}

#[tokio::test]
async fn notification_triage_is_scoped_per_actor() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let owner = create_user(&state, None, "owner").await;
    let owner_token = open_session(&state, owner).await;
    let bruno = create_user(&state, Some(&owner_token), "bruno").await;
    let bruno_token = open_session(&state, bruno).await;

    patch_triage(
        &state,
        &owner_token,
        "reminder%3Aentity-1%3Acsc-art376-annual",
        "acknowledged",
    )
    .await;

    let (owner_status, owner_body) = send(
        state.clone(),
        with_session(get("/v1/notifications/triage"), &owner_token),
    )
    .await;
    assert_eq!(owner_status, StatusCode::OK);
    assert_eq!(
        owner_body["entries"]
            .as_array()
            .expect("owner entries")
            .len(),
        1
    );

    let (bruno_status, bruno_body) = send(
        state,
        with_session(get("/v1/notifications/triage"), &bruno_token),
    )
    .await;
    assert_eq!(bruno_status, StatusCode::OK);
    assert!(
        bruno_body["entries"]
            .as_array()
            .expect("bruno entries")
            .is_empty(),
        "another actor must not inherit the owner triage state: {bruno_body}"
    );
}
