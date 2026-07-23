//! t95 session backend over the wire: the self-scoped active-sign-ins list, self-revoke, and
//! revoke-all-others.
//!
//! The property that must hold and is easy to get wrong: a **revoked token is rejected on its next
//! request**, not merely dropped from the list. `revoking_a_session_rejects_its_token_on_the_next_request`
//! proves it by using the revoked token afterward and asserting 401.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-sessions-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
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
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, value)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("header"));
    req
}
fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("req")
}

async fn seed_user(state: &AppState, username: &str, role: RoleId) -> UserId {
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(password_hash()),
            attestation_key: None,
            retired_attestation_keys: Vec::new(),
            totp: None,
            two_factor_required: false,
            force_password_change: false,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(role, Scope::Global)],
            language: Default::default(),
        },
    );
    uid
}

/// Sign in, optionally sending a `User-Agent` (for the device label) and an `X-Forwarded-For` (for
/// the IP, when the instance trusts forwarded headers). Returns the token.
async fn sign_in(
    state: &AppState,
    uid: UserId,
    user_agent: Option<&str>,
    xff: Option<&str>,
) -> String {
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/session")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(ua) = user_agent {
        req = req.header(header::USER_AGENT, ua);
    }
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    let req = req
        .body(Body::from(
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
        ))
        .unwrap();
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "sign-in: {body}");
    body["token"].as_str().expect("token").to_owned()
}

// =================================================================================================

#[tokio::test]
async fn the_list_is_self_scoped_and_flags_the_current_session_with_device() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let alice = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let bob = seed_user(&state, "bruno.dias", OWNER_ROLE_ID).await;

    // Alice signs in on two "devices"; Bob on one.
    let chrome =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";
    let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
    let alice_a = sign_in(&state, alice, Some(chrome), None).await;
    let _alice_b = sign_in(&state, alice, Some(firefox), None).await;
    let _bob = sign_in(&state, bob, Some(chrome), None).await;

    let (status, body) = send(state.clone(), with_session(get("/v1/sessions"), &alice_a)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sessions = body["sessions"].as_array().expect("sessions");
    // Alice sees her TWO sessions and not Bob's — self-scoped.
    assert_eq!(
        sessions.len(),
        2,
        "self-scoped list must show only the caller's sessions: {body}"
    );

    let current: Vec<&Value> = sessions.iter().filter(|s| s["current"] == true).collect();
    assert_eq!(
        current.len(),
        1,
        "exactly one session is the caller's current one"
    );
    assert_eq!(current[0]["device"], "Chrome on Windows");
    // The handle is opaque and is NOT the token.
    let handle = current[0]["session_id"].as_str().unwrap();
    assert_ne!(handle, alice_a, "the handle must not be the token");
    assert!(
        !body.to_string().contains(&alice_a),
        "the token must never appear in the list"
    );
}

#[tokio::test]
async fn a_trusted_forwarded_ip_is_stored_truncated() {
    let temp = TempDir::new();
    let mut state = AppState::with_data_dir(&temp.0);
    // Trust forwarded headers so the in-process test can supply an IP (there is no ConnectInfo).
    state.rate_limit.trust_forwarded_for = true;
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;

    let token = sign_in(&state, uid, None, Some("198.51.100.37")).await;
    let (status, body) = send(state.clone(), with_session(get("/v1/sessions"), &token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The full host is never stored — only its /24 network.
    assert_eq!(body["sessions"][0]["ip"], "198.51.100.0");
}

#[tokio::test]
async fn revoking_a_session_rejects_its_token_on_the_next_request() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;

    let keep = sign_in(&state, uid, None, None).await;
    let victim = sign_in(&state, uid, None, None).await;

    // Find the victim's handle from `keep`'s self-scoped list (both are Alice's).
    let (_, list) = send(state.clone(), with_session(get("/v1/sessions"), &keep)).await;
    let victim_digest_handle = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["current"] == false)
        .expect("the other session")["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The victim token works right now.
    let (status, _) = send(state.clone(), with_session(get("/v1/session"), &victim)).await;
    assert_eq!(status, StatusCode::OK);

    // Revoke it by handle.
    let (status, revoked) = send(
        state.clone(),
        with_session(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/sessions/{victim_digest_handle}"))
                .body(Body::empty())
                .unwrap(),
            &keep,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");

    // THE PROPERTY: the revoked token is rejected on its NEXT request, not merely delisted.
    let (status, _) = send(state.clone(), with_session(get("/v1/session"), &victim)).await;
    // `GET /v1/session` returns `{user: null}` for an unknown session rather than 401, so assert the
    // session no longer resolves to a user.
    let (_, sess) = send(state.clone(), with_session(get("/v1/session"), &victim)).await;
    assert!(
        sess["user"].is_null(),
        "the revoked token still authenticates: {sess}"
    );
    // And on a gated endpoint the revoked token is a hard 401.
    let (status_gated, _) = send(state.clone(), with_session(get("/v1/users"), &victim)).await;
    assert_eq!(
        status_gated,
        StatusCode::UNAUTHORIZED,
        "revoked token must be rejected"
    );
    let _ = status;

    // `keep` still works.
    let (status, _) = send(state.clone(), with_session(get("/v1/users"), &keep)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn revoke_others_keeps_the_current_session_and_drops_the_rest() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;

    let current = sign_in(&state, uid, None, None).await;
    let other_a = sign_in(&state, uid, None, None).await;
    let other_b = sign_in(&state, uid, None, None).await;

    let (status, revoked) = send(
        state.clone(),
        with_session(
            Request::builder()
                .method("POST")
                .uri("/v1/sessions/revoke-others")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            &current,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(
        revoked["revoked"], 2,
        "both other sessions revoked: {revoked}"
    );

    // The current session survives.
    let (status, _) = send(state.clone(), with_session(get("/v1/users"), &current)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the current session must survive revoke-others"
    );

    // The others are rejected on their next request.
    for token in [&other_a, &other_b] {
        let (status, _) = send(state.clone(), with_session(get("/v1/users"), token)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a revoked-other token must be rejected"
        );
    }

    // And the list now shows only the current one.
    let (_, list) = send(state.clone(), with_session(get("/v1/sessions"), &current)).await;
    assert_eq!(list["sessions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn revoking_another_users_session_handle_is_a_404() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let alice = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let bob = seed_user(&state, "bruno.dias", OWNER_ROLE_ID).await;
    let alice_token = sign_in(&state, alice, None, None).await;
    let bob_token = sign_in(&state, bob, None, None).await;

    // Bob's own handle.
    let (_, bob_list) = send(state.clone(), with_session(get("/v1/sessions"), &bob_token)).await;
    let bob_handle = bob_list["sessions"][0]["session_id"].as_str().unwrap();

    // Alice tries to revoke Bob's session by his handle → 404, never revealing it exists.
    let (status, _) = send(
        state.clone(),
        with_session(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/sessions/{bob_handle}"))
                .body(Body::empty())
                .unwrap(),
            &alice_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one user must not revoke another's session"
    );

    // Bob's session is untouched.
    let (status, _) = send(state.clone(), with_session(get("/v1/users"), &bob_token)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_list_requires_a_session() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let (status, _) = send(state.clone(), get("/v1/sessions")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
