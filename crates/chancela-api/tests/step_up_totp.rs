//! Step-up re-auth accepts a live TOTP code as an equal-strength alternative to the password
//! (author lane: the "prove identity with whichever method you hold" work).
//!
//! The gate under test is [`chancela_api`]'s `require_step_up`, reached here through the self-service
//! `POST /v1/me/suspend` route — the lightest step-up-gated surface that needs only a session. The
//! invariants asserted:
//!
//! - a user with a **confirmed** TOTP factor satisfies step-up with a live code (200, not 403);
//! - a wrong code is the same uniform `403` as offering nothing;
//! - a user who holds only a password is NOT let through on a `totp_code` field — they still must
//!   supply the password (the TOTP arm resolves to "not proved", the account stays non-vacuous).
//!
//! Codes are computed one step **ahead** of the confirm step: confirming the factor consumes the
//! current step (the replay guard advances `last_accepted_step`), so a same-step code would be
//! refused as a replay. The ±1 verification window accepts the next step.

use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::totp::{STEP_SECONDS, code_for_secret};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use crate::common::{TEST_PASSWORD, password_hash};

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        common::ensure_credential_key();
        let dir = std::env::temp_dir().join(format!("chancela-stepup-totp-{}", Uuid::new_v4()));
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
        .expect("body collects");
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
fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

async fn seed_user(state: &AppState, username: &str, role: RoleId) -> UserId {
    let uid = UserId(Uuid::new_v4());
    state.users.write().await.insert(
        uid,
        User {
            passkeys: Vec::new(),
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

async fn open_session(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post(
            "/v1/session",
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// Enrol and confirm a TOTP factor for `uid` over the wire, returning the base32 secret the enrol
/// response shows once. Confirming consumes the current step.
async fn enrol_and_confirm(state: &AppState, uid: UserId, token: &str) -> String {
    let (status, started) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/two-factor/totp/enrol", uid.0),
                Value::Null,
            ),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "enrol: {started}");
    let secret = started["secret"].as_str().expect("secret").to_owned();

    let code = code_for_secret(&secret, OffsetDateTime::now_utc().unix_timestamp()).expect("code");
    let (status, confirmed) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/two-factor/totp/confirm", uid.0),
                json!({ "code": code }),
            ),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {confirmed}");
    secret
}

/// A code for the step AFTER `now`, so it clears the replay guard the confirm step advanced while
/// staying inside the verifier's ±1 window.
fn next_step_code(secret: &str) -> String {
    code_for_secret(
        secret,
        OffsetDateTime::now_utc().unix_timestamp() + STEP_SECONDS,
    )
    .expect("code")
}

/// A confirmed-TOTP user proves step-up with a live code — the destructive self-suspend goes
/// through (200), so the gate accepted the code as an equal-strength alternative to the password.
#[tokio::test]
async fn step_up_accepts_a_live_totp_code() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    // A second active user who is also an Owner, so suspending the acting Reader is not blocked as
    // the sole active user / sole active Owner.
    let _admin = seed_user(&state, "owner.admin", OWNER_ROLE_ID).await;
    let uid = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let secret = enrol_and_confirm(&state, uid, &token).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post(
                "/v1/me/suspend",
                json!({ "reauth": { "totp_code": next_step_code(&secret) } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "step-up should accept a live TOTP code: {body}"
    );
}

/// A wrong TOTP code is the same uniform `403` as offering nothing — the account is not suspended.
#[tokio::test]
async fn step_up_refuses_a_wrong_totp_code() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let _admin = seed_user(&state, "owner.admin", OWNER_ROLE_ID).await;
    let uid = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let _secret = enrol_and_confirm(&state, uid, &token).await;

    let (status, _body) = send(
        state.clone(),
        with_session(
            post(
                "/v1/me/suspend",
                json!({ "reauth": { "totp_code": "000000" } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a wrong code must not satisfy step-up"
    );
}

/// A user who holds only a password is NOT let through on a `totp_code` field: they hold a
/// credential, so the gate stays non-vacuous and the TOTP arm resolves to "not proved". The
/// password still works.
#[tokio::test]
async fn a_password_only_user_still_must_use_the_password() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let _admin = seed_user(&state, "owner.admin", OWNER_ROLE_ID).await;
    let uid = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;

    // A TOTP field on an account with no TOTP factor proves nothing.
    let (status, _body) = send(
        state.clone(),
        with_session(
            post(
                "/v1/me/suspend",
                json!({ "reauth": { "totp_code": "123456" } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a password-holder must not pass step-up via a TOTP field they cannot satisfy"
    );

    // The password they actually hold does satisfy it.
    let (status, body) = send(
        state.clone(),
        with_session(
            post(
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the password must still satisfy step-up: {body}"
    );
}

/// The whole safety claim, stated as a test: making TOTP an option a *holder* can choose did not
/// open a path an *attacker* can take. An account that holds a confirmed TOTP factor (so the TOTP
/// arm is present) AND a password is non-vacuous; a caller riding the session token alone — no
/// password, no TOTP code, no passkey — is refused with the uniform `403`, exactly as before the arm
/// existed. The session is not a proof; the arm is a choice offered to whoever can satisfy it.
#[tokio::test]
async fn a_session_alone_still_fails_with_the_totp_arm_present() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let _admin = seed_user(&state, "owner.admin", OWNER_ROLE_ID).await;
    let uid = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    // The account now holds a confirmed TOTP factor — the arm is offerable — and still holds its
    // password, so it is non-vacuous and the t69 session-is-enough exemption does not apply.
    let _secret = enrol_and_confirm(&state, uid, &token).await;

    // An empty proof: no password, no totp_code, no passkey.
    let (status, _body) = send(
        state.clone(),
        with_session(post("/v1/me/suspend", json!({ "reauth": {} })), &token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a session token alone must never satisfy step-up once the account holds a credential"
    );
}
