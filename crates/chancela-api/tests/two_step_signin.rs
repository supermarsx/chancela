//! t95 P2 over the wire: the two-step sign-in (TOTP challenge carrying the unlocked key), the
//! enrol-on-next-sign-in wall, and the forced-password-change wall.
//!
//! The property that bites hardest, and the reason this flow exists: the attestation key unlocked
//! from the password must **survive the challenge without a session existing** and reach the minted
//! session, so a 2FA sign-in attests exactly as a one-step sign-in does. `an_attested_act_after_a_two_step_sign_in`
//! proves that end to end.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::totp::code_for_secret;
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const NEW_PASSWORD: &str = "Trocada-Forte8!Q";

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-p2-{}", Uuid::new_v4()));
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
    Request::builder().method("GET").uri(uri).body(Body::empty()).expect("req")
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
            id: uid,
            username: username.to_owned(),
            display_name: username.to_owned(),
            email: None,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
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

/// Sign in (single-step) and return the token.
async fn sign_in(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign-in: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// Enrol + confirm a TOTP factor for `uid`, returning the base32 secret.
async fn enrol_totp(state: &AppState, uid: UserId, token: &str) -> String {
    let (status, started) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "enrol: {started}");
    let secret = started["secret"].as_str().unwrap().to_owned();
    let code = current_code(&secret);
    let (status, _) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/two-factor/totp/confirm", uid.0), json!({ "code": code })),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm");
    // Confirmation consumes the current step in the replay guard. A real sign-in presents a code
    // from a LATER window; in a test, confirm and the challenge happen within the same 30s step, so
    // reset the guard to simulate elapsed time — otherwise the challenge's same-step code is
    // (correctly) refused as a replay. The replay guard itself is covered by the totp unit tests.
    state
        .users
        .write()
        .await
        .get_mut(&uid)
        .unwrap()
        .totp
        .as_mut()
        .unwrap()
        .last_accepted_step = None;
    secret
}

fn current_code(secret: &str) -> String {
    code_for_secret(secret, OffsetDateTime::now_utc().unix_timestamp()).expect("decodable secret")
}

/// A code guaranteed NOT to be the current one (real code + 1, mod 10^6), so a "wrong code" assertion
/// can never flake on a 1-in-a-million collision with the live code.
fn wrong_code(secret: &str) -> String {
    let real: u32 = current_code(secret).parse().expect("6 digits");
    format!("{:06}", (real + 1) % 1_000_000)
}

// =================================================================================================
// THE TWO-STEP CHALLENGE
// =================================================================================================

#[tokio::test]
async fn a_password_sign_in_with_a_confirmed_factor_returns_a_challenge_not_a_token() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = sign_in(&state, uid).await;
    let secret = enrol_totp(&state, uid, &token).await;

    // Now a fresh password sign-in must NOT mint a token — it returns a challenge.
    let (status, body) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("token").is_none(), "a confirmed factor must gate the token: {body}");
    let challenge = &body["two_factor_challenge"];
    assert!(challenge["challenge_id"].is_string(), "{body}");
    assert_eq!(challenge["methods"][0], "totp");

    // A wrong password never even reaches the challenge — same uniform 401 as before.
    let (status, _) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": "wrong-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Completing the challenge with a live code mints the session.
    let challenge_id = challenge["challenge_id"].as_str().unwrap();
    let code = current_code(&secret);
    let (status, minted) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": challenge_id, "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert!(minted["token"].is_string(), "the completed challenge mints a token: {minted}");

    // And that token is a real, working session.
    let (status, sess) = send(
        state.clone(),
        with_session(get("/v1/session"), minted["token"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sess}");
    assert_eq!(sess["user"]["username"], "amelia.marques");
}

/// THE INVARIANT: the attestation key unlocked from the password survives the challenge and reaches
/// the minted session — a two-step sign-in can attest, exactly like a one-step one. We prove it by
/// performing an attested act (creating a user) and checking the resulting ledger event is attested.
#[tokio::test]
async fn an_attested_act_after_a_two_step_sign_in_is_actually_attested() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    // Bootstrap the first Owner through the real endpoint, so it gets an attestation key generated
    // and wrapped under its password exactly as production does (t88) — a fabricated key would not
    // unlock from the password at sign-in.
    let (status, created) = send(
        state.clone(),
        post("/v1/users", json!({ "username": "amelia.marques", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap owner: {created}");
    assert_eq!(created["has_attestation_key"], true, "{created}");
    let uid = UserId(Uuid::parse_str(created["id"].as_str().unwrap()).unwrap());
    let bootstrap_token = sign_in(&state, uid).await;
    let secret = enrol_totp(&state, uid, &bootstrap_token).await;

    // Two-step sign in afresh.
    let (_, challenge) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    let challenge_id = challenge["two_factor_challenge"]["challenge_id"].as_str().unwrap();
    let code = current_code(&secret);
    let (status, minted) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": challenge_id, "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let token = minted["token"].as_str().unwrap().to_owned();

    // Perform an attesting act with the two-step session: create another user.
    let (status, created) = send(
        state.clone(),
        with_session(
            post(
                "/v1/users",
                json!({ "username": "bruno.dias", "password": TEST_PASSWORD }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    // The last ledger event must be attested — the two-step session held the unlocked key. The
    // attestation is stored in `state.attestations`, keyed by the event's seq.
    let seq = {
        let ledger = state.ledger.read().await;
        let last = ledger.events().last().expect("an event");
        assert_eq!(last.kind, "user.created");
        last.seq
    };
    assert!(
        state.attestations.read().await.contains_key(&seq),
        "a two-step sign-in produced an UNATTESTED act — the key did not survive the challenge"
    );
}

#[tokio::test]
async fn a_challenge_is_single_use_and_capped_and_a_wrong_code_is_uniform() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = sign_in(&state, uid).await;
    let secret = enrol_totp(&state, uid, &token).await;

    let new_challenge = |state: AppState| async move {
        let (_, body) = send(
            state,
            post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
        )
        .await;
        body["two_factor_challenge"]["challenge_id"].as_str().unwrap().to_owned()
    };

    // Unknown challenge id → uniform 401.
    let (status, _) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": "made-up", "code": "000000" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Single use: a completed challenge cannot be completed again.
    let cid = new_challenge(state.clone()).await;
    let code = current_code(&secret);
    let (status, _) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": cid, "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code2 = current_code(&secret);
    let (status, _) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": cid, "code": code2 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent challenge must not be reusable");

    // Attempt cap: five wrong codes discard the challenge; a subsequent correct code fails because
    // the challenge is gone.
    let cid = new_challenge(state.clone()).await;
    for _ in 0..5 {
        let (status, _) = send(
            state.clone(),
            post("/v1/session/challenge", json!({ "challenge_id": &cid, "code": wrong_code(&secret) })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let code = current_code(&secret);
    let (status, _) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": &cid, "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a challenge discarded after the cap is gone");
}

/// A backup code satisfies the challenge when the authenticator is unavailable, and is single-use.
#[tokio::test]
async fn a_backup_code_completes_the_challenge_and_is_consumed() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = sign_in(&state, uid).await;
    // Enrol + capture the backup codes from the confirm response.
    let (_, started) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), &token),
    )
    .await;
    let secret = started["secret"].as_str().unwrap().to_owned();
    let (_, confirmed) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/two-factor/totp/confirm", uid.0), json!({ "code": current_code(&secret) })),
            &token,
        ),
    )
    .await;
    let backup = confirmed["backup_codes"][0].as_str().unwrap().to_owned();

    let (_, challenge) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(challenge["two_factor_challenge"]["methods"][1], "backup_code");
    let cid = challenge["two_factor_challenge"]["challenge_id"].as_str().unwrap().to_owned();
    let (status, minted) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": cid, "code": backup })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a backup code should complete the challenge: {minted}");

    // The same backup code is now spent.
    let (_, challenge) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    let cid = challenge["two_factor_challenge"]["challenge_id"].as_str().unwrap().to_owned();
    let (status, _) = send(
        state.clone(),
        post("/v1/session/challenge", json!({ "challenge_id": cid, "code": backup })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a spent backup code must not work again");
}

// =================================================================================================
// ENROL-ON-NEXT-SIGN-IN — and the last-Owner guarantee
// =================================================================================================

/// The one that must never fail: an Owner required to hold 2FA but with no factor enrolled can still
/// sign in far enough to enrol. Enrol-on-next-sign-in is a wall, never a lockout — so the last Owner
/// can never brick the instance.
#[tokio::test]
async fn a_required_but_unenrolled_owner_can_still_reach_enrolment() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    // Instance supports TOTP; the account is required to hold a factor but has none.
    state.settings.write().await.auth.two_factor.totp_enabled = true;
    state.users.write().await.get_mut(&uid).unwrap().two_factor_required = true;

    // Sign-in succeeds (no factor yet ⇒ no challenge) and reports the wall.
    let (status, body) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token, walled but real").to_owned();
    assert_eq!(body["required_action"], "enrol_two_factor", "{body}");

    // The wall blocks ordinary work...
    let (status, blocked) = send(
        state.clone(),
        with_session(get("/v1/users"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{blocked}");
    assert_eq!(blocked["required_action"], "enrol_two_factor");

    // ...but the enrolment path is open, so the Owner is never locked out.
    let (status, started) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "enrolment must be reachable behind the wall: {started}");
    let secret = started["secret"].as_str().unwrap().to_owned();
    let (status, _) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/two-factor/totp/confirm", uid.0), json!({ "code": current_code(&secret) })),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm behind the wall");

    // The wall is now lifted for this same session — the factor exists.
    let (status, view) = send(state.clone(), with_session(get("/v1/users"), &token)).await;
    assert_eq!(status, StatusCode::OK, "the wall must lift once enrolled: {view}");
}

// =================================================================================================
// FORCED PASSWORD CHANGE WALL
// =================================================================================================

#[tokio::test]
async fn a_forced_change_session_can_only_change_the_password() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    state.users.write().await.get_mut(&uid).unwrap().force_password_change = true;

    let (status, body) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(body["required_action"], "change_password");

    // Ordinary work is walled.
    let (status, _) = send(state.clone(), with_session(get("/v1/users"), &token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Changing the own password is allowed and lifts the wall.
    let (status, _) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/secret", uid.0),
                json!({ "password": NEW_PASSWORD, "current_password": TEST_PASSWORD }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the password change must be reachable");

    // Wall lifted.
    let (status, _) = send(state.clone(), with_session(get("/v1/users"), &token)).await;
    assert_eq!(status, StatusCode::OK, "the wall must lift after the change");

    // GET /v1/session no longer reports a required action.
    let (_, sess) = send(state.clone(), with_session(get("/v1/session"), &token)).await;
    assert!(sess.get("required_action").is_none(), "{sess}");
}
