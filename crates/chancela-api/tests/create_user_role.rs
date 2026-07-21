//! t71 — assigning a role **at creation** (`POST /v1/users` with a `role`).
//!
//! Creation-time role assignment is an escalation surface: it is the one place where "create a
//! user" and "grant authority" happen in the same request. These tests pin the three properties
//! that make it safe:
//!
//!  1. the subset ceiling applies exactly as it does on `POST /v1/users/{id}/roles` — a creator
//!     cannot grant authority they do not themselves hold, not even by naming a fat seeded role;
//!  2. a refused grant is **atomic**: no user is left created-but-roleless;
//!  3. the first-run bootstrap is untouched — the first user is still Owner\@Global, and a `role`
//!     on a bootstrap create is refused rather than silently honoured.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_authz::OWNER_ROLE_ID;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

/// A private data directory for one test (removed on the way out).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-t71-{tag}-{}", Uuid::new_v4()));
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
    // A rejection from the `Json` extractor itself (a malformed body, or a value serde refuses —
    // e.g. an unsupported language tag) is plain text, not the JSON `ApiError` envelope. Keep it
    // as a string rather than panicking, so a test can still assert on the status and the text.
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
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

fn post_as(uri: &str, body: Value, token: &str) -> Request<Body> {
    let mut req = post_json(uri, body);
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    req
}

/// Bootstrap an Owner and return `(user_id, session_token)`.
async fn bootstrap_owner(state: &AppState) -> (String, String) {
    let (status, created) = send(
        state.clone(),
        post_json(
            "/api/v1/users",
            json!({ "username": "amelia.marques", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner bootstraps: {created}");
    let user_id = created["id"].as_str().expect("id").to_owned();

    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": user_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner signs in: {session}");
    let token = session["token"].as_str().expect("token").to_owned();
    (user_id, token)
}

/// Whether a user with `username` exists in the durable directory.
async fn user_exists(state: &AppState, username: &str) -> bool {
    state
        .users
        .read()
        .await
        .values()
        .any(|u| u.username.eq_ignore_ascii_case(username))
}

#[tokio::test]
async fn an_explicit_role_is_assigned_in_the_same_request_as_the_create() {
    let dir = TempDir::new("explicit");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    // A narrow role the Owner may certainly grant.
    let (status, role) = send(
        state.clone(),
        post_as(
            "/api/v1/roles",
            json!({ "name": "Leitor de entidades", "permissions": ["entity.read"] }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "role created: {role}");
    let role_id = role["id"].as_str().expect("role id").to_owned();

    let (status, created) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "bruno.dias",
                "password": TEST_PASSWORD,
                "role": { "role_id": role_id, "scope": { "kind": "global" } },
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user created: {created}");

    // Exactly the requested grant — NOT the historical silent Gestor@Global default.
    let users = state.users.read().await;
    let user = users
        .values()
        .find(|u| u.username == "bruno.dias")
        .expect("created user stored");
    assert_eq!(user.role_assignments.len(), 1, "one assignment");
    assert_eq!(user.role_assignments[0].role_id.0.to_string(), role_id);
    assert_eq!(
        user.role_assignments[0].scope,
        chancela_authz::Scope::Global
    );
}

#[tokio::test]
async fn a_role_above_the_creators_ceiling_is_refused_and_no_user_is_written() {
    let dir = TempDir::new("ceiling");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    // A delegate who may create users and assign roles, but holds nothing else. Their ceiling is
    // therefore {user.manage, role.assign, entity.read} — far below Owner.
    let (status, role) = send(
        state.clone(),
        post_as(
            "/api/v1/roles",
            json!({
                "name": "Gestor de contas",
                "permissions": ["user.manage", "role.assign", "entity.read"],
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "delegate role created: {role}");
    let delegate_role = role["id"].as_str().expect("role id").to_owned();

    let (status, delegate) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "carla.nunes",
                "password": TEST_PASSWORD,
                "role": { "role_id": delegate_role, "scope": { "kind": "global" } },
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "delegate created: {delegate}");
    let delegate_id = delegate["id"].as_str().expect("id").to_owned();

    let (status, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": delegate_id, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delegate signs in: {session}");
    let delegate_token = session["token"].as_str().expect("token").to_owned();

    // The delegate tries to mint an Owner. `role.assign`@Global passes; the SUBSET invariant does
    // not — Owner carries every verb, and the delegate holds three.
    let (status, refusal) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "escalada",
                "password": TEST_PASSWORD,
                "role": {
                    "role_id": OWNER_ROLE_ID.0.to_string(),
                    "scope": { "kind": "global" },
                },
            }),
            &delegate_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "escalation refused: {refusal}"
    );

    // ATOMICITY: the refusal happened before any write, so there is no created-but-roleless user.
    assert!(
        !user_exists(&state, "escalada").await,
        "a refused role must leave NO user behind"
    );
}

#[tokio::test]
async fn a_role_carrying_one_verb_the_creator_lacks_is_refused() {
    let dir = TempDir::new("perverb");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    let (_, delegate_role) = send(
        state.clone(),
        post_as(
            "/api/v1/roles",
            json!({
                "name": "Gestor de contas",
                "permissions": ["user.manage", "role.assign", "entity.read"],
            }),
            &owner,
        ),
    )
    .await;
    let delegate_role = delegate_role["id"].as_str().expect("id").to_owned();

    // Everything the delegate holds, PLUS one verb it does not. The ceiling is evaluated per
    // permission inside the role, so a single excess verb is enough to refuse the whole grant.
    let (_, fat_role) = send(
        state.clone(),
        post_as(
            "/api/v1/roles",
            json!({
                "name": "Quase igual",
                "permissions": ["user.manage", "role.assign", "entity.read", "entity.create"],
            }),
            &owner,
        ),
    )
    .await;
    let fat_role = fat_role["id"].as_str().expect("id").to_owned();

    let (_, delegate) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "carla.nunes",
                "password": TEST_PASSWORD,
                "role": { "role_id": delegate_role, "scope": { "kind": "global" } },
            }),
            &owner,
        ),
    )
    .await;
    let (_, session) = send(
        state.clone(),
        post_json(
            "/api/v1/session",
            json!({ "user_id": delegate["id"], "password": TEST_PASSWORD }),
        ),
    )
    .await;
    let delegate_token = session["token"].as_str().expect("token").to_owned();

    let (status, refusal) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "quase",
                "password": TEST_PASSWORD,
                "role": { "role_id": fat_role, "scope": { "kind": "global" } },
            }),
            &delegate_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "one excess verb refuses the grant: {refusal}"
    );
    assert!(!user_exists(&state, "quase").await, "nothing written");
}

#[tokio::test]
async fn a_role_on_the_bootstrap_create_is_refused_and_the_first_user_is_still_owner() {
    let dir = TempDir::new("boot");
    let state = AppState::with_data_dir(&dir.0);

    // The unauthenticated bootstrap may not choose its own role — that would let an anonymous
    // caller pick a *narrower* first principal and strand the instance without an Owner.
    let (status, refusal) = send(
        state.clone(),
        post_json(
            "/api/v1/users",
            json!({
                "username": "amelia.marques",
                "password": TEST_PASSWORD,
                "role": {
                    "role_id": OWNER_ROLE_ID.0.to_string(),
                    "scope": { "kind": "global" },
                },
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a role on the bootstrap create is refused: {refusal}"
    );
    assert!(
        !user_exists(&state, "amelia.marques").await,
        "the refused bootstrap wrote nothing"
    );

    // And the ordinary bootstrap still yields Owner@Global, by the same path it always took.
    let (status, created) = send(
        state.clone(),
        post_json(
            "/api/v1/users",
            json!({ "username": "amelia.marques", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap succeeds: {created}");

    let users = state.users.read().await;
    let first = users.values().next().expect("first user");
    assert_eq!(first.role_assignments.len(), 1);
    assert_eq!(first.role_assignments[0].role_id, OWNER_ROLE_ID);
}

#[tokio::test]
async fn a_language_preference_round_trips_and_auto_is_stored_as_auto() {
    let dir = TempDir::new("lang");
    let state = AppState::with_data_dir(&dir.0);
    let (owner_id, owner) = bootstrap_owner(&state).await;

    // The bootstrap user chose nothing ⇒ "auto", the standing instruction to keep detecting.
    let (status, view) = send(
        state.clone(),
        Request::builder()
            .uri(format!("/api/v1/users/{owner_id}"))
            .header("x-chancela-session", &owner)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner read: {view}");
    assert_eq!(view["language"], json!("auto"), "default is auto");

    // A concrete locale at creation.
    let (status, created) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "bruno.dias",
                "password": TEST_PASSWORD,
                "language": "de-DE",
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "created: {created}");
    assert_eq!(created["language"], json!("de-DE"));

    // "auto" is a real value that PATCH can set BACK to — undoing a fixed choice, not clearing it.
    let user_id = created["id"].as_str().expect("id").to_owned();
    let mut req = post_json(
        &format!("/api/v1/users/{user_id}"),
        json!({ "language": "auto" }),
    );
    *req.method_mut() = axum::http::Method::PATCH;
    let (status, patched) = send(state.clone(), {
        req.headers_mut()
            .insert("x-chancela-session", owner.parse().expect("header"));
        req
    })
    .await;
    assert_eq!(status, StatusCode::OK, "patched: {patched}");
    assert_eq!(patched["language"], json!("auto"));

    // And it is stored as `Auto`, never resolved to a detected tag behind the user's back.
    let users = state.users.read().await;
    let stored = users
        .values()
        .find(|u| u.username == "bruno.dias")
        .expect("stored");
    assert!(stored.language.fixed().is_none(), "auto stays auto");
}

#[tokio::test]
async fn an_unknown_language_is_refused_rather_than_silently_defaulted() {
    let dir = TempDir::new("badlang");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    // A tag we do not ship must not quietly become pt-PT at creation — the operator chose
    // something, and being told it was ignored is the only honest outcome.
    let (status, refusal) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "bruno.dias",
                "password": TEST_PASSWORD,
                "language": "kl-GL",
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown locale refused: {refusal}"
    );
    // The refusal names the offending tag, so the operator knows WHICH field was rejected.
    assert!(
        refusal.to_string().contains("kl-GL"),
        "the refusal should name the tag it rejected: {refusal}"
    );
    assert!(!user_exists(&state, "bruno.dias").await, "nothing written");
}

#[tokio::test]
async fn the_create_response_never_echoes_the_password() {
    let dir = TempDir::new("nopw");
    let state = AppState::with_data_dir(&dir.0);
    let (_, owner) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        post_as(
            "/api/v1/users",
            json!({
                "username": "bruno.dias",
                "password": TEST_PASSWORD,
                "send_welcome_email": true,
            }),
            &owner,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "created: {created}");

    // Neither the secret nor its hash appears anywhere in the response document.
    let body = created.to_string();
    assert!(
        !body.contains(TEST_PASSWORD),
        "the response echoed the password: {body}"
    );
    assert!(
        !body.contains("password_hash") && !body.contains("\"password\""),
        "the response carries a password field: {body}"
    );
    // It reports only *whether* a secret exists.
    assert_eq!(created["has_secret"], json!(true));
}
