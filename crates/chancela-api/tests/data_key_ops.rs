use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{LEITOR_ROLE_ID, OWNER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

const PREFLIGHT_PATH: &str = "/v1/data/key-rotation/preflight";
const EXECUTE_PATH: &str = "/v1/data/key-rotation";

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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        "x-chancela-session",
        token.parse().expect("valid header value"),
    );
    req
}

async fn seed_user(state: &AppState, username: &str, role_id: RoleId) -> UserId {
    let uid = UserId(Uuid::new_v4());
    let user = User {
        id: uid,
        username: username.to_owned(),
        display_name: username.to_owned(),
        email: None,
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        active: true,
        password_hash: None,
        attestation_key: None,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
    };
    state.users.write().await.insert(uid, user);
    uid
}

async fn open_session(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post_json("/v1/session", json!({ "user_id": uid.0 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn owner_session(state: &AppState) -> String {
    let uid = seed_user(state, "owner", OWNER_ROLE_ID).await;
    open_session(state, uid).await
}

fn assert_secret_free(body: &Value, secrets: &[&str]) {
    let rendered = body.to_string();
    for secret in secrets {
        assert!(
            !rendered.contains(secret),
            "response leaked secret {secret:?}: {rendered}"
        );
    }
}

fn state_for_header_only_data_dir(dir: PathBuf) -> AppState {
    AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        persist_path: Some(Arc::new(dir.join("settings.json"))),
        ..AppState::default()
    }
}

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("chancela-data-key-ops-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn preflight_requires_settings_manage_permission() {
    let tmp = TempDir::new("permission-denied");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let uid = seed_user(&state, "reader", LEITOR_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let current_key = "current-key-denied";
    let new_key = "replacement-key-denied";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "new_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "permission denial: {body}");
    assert_secret_free(&body, &[current_key, new_key]);
}

#[tokio::test]
async fn execution_requires_settings_manage_permission_without_leaking_keys() {
    let tmp = TempDir::new("execute-permission-denied");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let uid = seed_user(&state, "reader", LEITOR_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let new_key = "replacement-key-execute-denied";

    let (status, body) = send(
        state,
        with_session(
            post_json(EXECUTE_PATH, json!({ "new_key": new_key })),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "permission denial: {body}");
    assert_secret_free(&body, &[new_key]);
}

#[tokio::test]
async fn execution_refuses_plaintext_store_without_leaking_key_or_migrating() {
    let tmp = TempDir::new("execute-plaintext");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let new_key = "replacement-key-for-execute-plaintext";

    let (status, body) = send(
        state,
        with_session(
            post_json(EXECUTE_PATH, json!({ "new_key": new_key })),
            &token,
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "plaintext refused: {body}"
    );
    assert!(
        body["error"].as_str().expect("error string").contains(
            "plaintext stores must use the supported backup/export-restore migration plan"
        ),
        "plaintext refusal explains non-destructive migration boundary: {body}"
    );
    assert_secret_free(&body, &[new_key]);

    let db =
        std::fs::read(tmp.dir.join(chancela_store::DB_FILE)).expect("database remains readable");
    assert!(
        db.starts_with(b"SQLite format 3\0"),
        "execution must not rewrite a plaintext SQLite store"
    );
}

#[tokio::test]
async fn preflight_reports_empty_and_missing_replacement_key_without_leaking_keys() {
    let tmp = TempDir::new("empty-new-key");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-empty-new-key";

    for body in [
        json!({ "current_key": current_key, "new_key": " \n\t " }),
        json!({ "current_key": current_key }),
    ] {
        let (status, body) = send(
            state.clone(),
            with_session(post_json(PREFLIGHT_PATH, body), &token),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "empty replacement report: {body}");
        assert_eq!(body["ready"], false);
        assert_eq!(body["status"], "reject_empty_new_key");
        assert_eq!(body["evidence"]["requested_key_config"], "empty");
        assert_secret_free(&body, &[current_key]);
    }
}

#[tokio::test]
async fn preflight_reports_plaintext_store_not_rotatable_without_leaking_keys() {
    let tmp = TempDir::new("plaintext");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-plaintext";
    let new_key = "replacement-key-for-plaintext";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "new_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "plaintext report: {body}");
    assert_eq!(body["ready"], false);
    assert_eq!(body["status"], "plaintext_store_not_rotatable");
    assert_eq!(body["evidence"]["database_format"], "plaintext_sqlite");
    assert_eq!(body["evidence"]["current_key_config"], "configured");
    assert_eq!(body["evidence"]["requested_key_config"], "configured");
    assert_secret_free(&body, &[current_key, new_key]);
}

#[cfg(not(feature = "sqlcipher"))]
#[tokio::test]
async fn preflight_reports_sqlcipher_build_required_without_leaking_keys() {
    let tmp = TempDir::new("no-sqlcipher");
    std::fs::write(
        tmp.dir.join(chancela_store::DB_FILE),
        b"not a plaintext sqlite header",
    )
    .expect("fake non-plaintext database header");
    let state = state_for_header_only_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-no-sqlcipher";
    let new_key = "replacement-key-for-no-sqlcipher";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "replacement_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "no-sqlcipher report: {body}");
    assert_eq!(body["ready"], false);
    assert_eq!(body["status"], "sqlcipher_build_required");
    assert_eq!(
        body["evidence"]["database_format"],
        "non_plaintext_or_encrypted"
    );
    assert_eq!(body["evidence"]["current_key_config"], "configured");
    assert_eq!(body["evidence"]["requested_key_config"], "configured");
    assert_eq!(body["evidence"]["sqlcipher_available"], false);
    assert_secret_free(&body, &[current_key, new_key]);
}
