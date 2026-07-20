//! First-run bootstrap: the first user of a genuinely fresh instance is the **maximal** principal
//! (protected Owner role @ Global — every verb in the catalog, instance-wide, covering every tenant
//! present or future), and the unauthenticated bootstrap can never be re-triggered to escalate on an
//! instance that already has a user directory.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_authz::{OWNER_ROLE_ID, Permission};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

/// A private data directory for one test (removed on the way out).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-t20-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("test data dir");
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_with_session(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

fn create_first_user(username: &str) -> Request<Body> {
    post_json(
        "/api/v1/users",
        json!({ "username": username, "password": TEST_PASSWORD }),
    )
}

#[tokio::test]
async fn the_first_user_of_a_fresh_instance_holds_every_permission_at_global() {
    let dir = TempDir::new("fresh");
    let state = AppState::with_data_dir(&dir.0);

    let (status, created) = send(state.clone(), create_first_user("amelia.marques")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "first user bootstraps: {created}"
    );
    let user_id = created["id"].as_str().expect("id").to_owned();

    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first user signs in: {session}");
    let token = session["token"].as_str().expect("token").to_owned();

    let (status, view) = send(
        state.clone(),
        get_with_session("/api/v1/session/permissions", &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "permissions read: {view}");

    // The maximal role, at the broadest scope the model has.
    let assignments = view["role_assignments"].as_array().expect("assignments");
    assert_eq!(assignments.len(), 1, "exactly one assignment: {view}");
    assert_eq!(assignments[0]["role_id"], OWNER_ROLE_ID.0.to_string());
    assert_eq!(assignments[0]["scope"]["kind"], "global");

    // Global scope ⇒ every verb in the catalog, held instance-wide (so it covers the default tenant
    // AND any tenant created later — a tenant-scoped grant never could).
    let grants = view["permissions"].as_array().expect("grants");
    for permission in Permission::ALL {
        assert!(
            grants.iter().any(|g| {
                g["permission"] == permission.as_str() && g["scope"]["kind"] == "global"
            }),
            "the first user is missing {permission}@global"
        );
    }
}

#[tokio::test]
async fn a_second_user_created_by_the_owner_is_not_an_owner() {
    let dir = TempDir::new("second");
    let state = AppState::with_data_dir(&dir.0);

    let (status, created) = send(state.clone(), create_first_user("amelia.marques")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "first user bootstraps: {created}"
    );
    let user_id = created["id"].as_str().expect("id").to_owned();
    let (_, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    let token = session["token"].as_str().expect("token").to_owned();

    // Unauthenticated: the bootstrap window is closed the moment a user exists.
    let (status, body) = send(state.clone(), create_first_user("segundo")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a second create needs a session: {body}"
    );

    // With the Owner's session it succeeds — but as Gestor@Global, not a second super-user.
    let mut req = post_json(
        "/api/v1/users",
        json!({ "username": "segundo", "password": TEST_PASSWORD }),
    );
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    let (status, second) = send(state.clone(), req).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "owner creates a user: {second}"
    );

    let users = state.users.read().await;
    let second_id = second["id"].as_str().expect("id");
    let second_user = users
        .values()
        .find(|u| u.id.0.to_string() == second_id)
        .expect("second user stored");
    assert!(
        !second_user
            .role_assignments
            .iter()
            .any(chancela_authz::RoleAssignment::is_owner_admin),
        "only the first user is the Owner"
    );
}

/// **Re-trigger guard.** `load_users` is malformed-tolerant: an unreadable/corrupt `users.json`
/// boots as ZERO users. Without a durable-evidence check that would present an already-initialised
/// instance as a fresh install and let an unauthenticated caller mint themselves an Owner@Global
/// (and clobber the real directory on the next persist). An existing users document means
/// "initialised", whatever the in-memory map says.
#[tokio::test]
async fn a_corrupt_user_directory_does_not_reopen_the_unauthenticated_bootstrap() {
    let dir = TempDir::new("corrupt");
    std::fs::write(dir.0.join("users.json"), b"{ not a users document")
        .expect("write a corrupt users document");

    let state = AppState::with_data_dir(&dir.0);
    assert!(
        state.users.read().await.is_empty(),
        "the corrupt document loads as zero users (the pre-condition this guards)"
    );

    let (status, body) = send(state.clone(), create_first_user("atacante")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an initialised-but-broken instance never bootstraps: {body}"
    );
    assert!(
        state.users.read().await.is_empty(),
        "no user was created by the refused bootstrap"
    );
}

/// The complement of the guard: a data dir with no users document at all IS a fresh install and must
/// still bootstrap — a factory reset removes the sidecars, so a reset instance is never bricked.
#[tokio::test]
async fn an_instance_with_no_user_document_still_bootstraps() {
    let dir = TempDir::new("nodoc");
    assert!(!dir.0.join("users.json").exists());
    let state = AppState::with_data_dir(&dir.0);

    let (status, body) = send(state.clone(), create_first_user("amelia.marques")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "fresh install bootstraps: {body}"
    );
}
