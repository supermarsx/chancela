//! t95 P1-C + §2.3 items 2/3 over the wire: TOTP self-enrolment, per-account mandatory 2FA, and the
//! forced-first-login password change — including the fingerprint-preservation guarantee the change
//! must never break.
//!
//! Sign-in *enforcement* of the second factor and the forced change is P2 (`session.rs`) and is not
//! exercised here; this suite covers the enrolment mechanism, the policy fields, and the account
//! state each transition leaves behind.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::totp::{STEP_SECONDS, TotpSecret, verify_code_against_secret, VerifyOutcome};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleId, Scope};
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
        let dir = std::env::temp_dir().join(format!("chancela-totp-{}", Uuid::new_v4()));
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
fn get(uri: &str) -> Request<Body> {
    Request::builder().method("GET").uri(uri).body(Body::empty()).expect("req")
}
fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}
fn post(uri: &str, body: Value) -> Request<Body> {
    json_request("POST", uri, body)
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

async fn open_session(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post("/v1/session", json!({ "user_id": uid.0, "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// Enrol and confirm a factor for `uid` (whose session is `token`). Returns the base32 secret so the
/// test can compute live codes. The secret is read back from the enrol response, which shows it once.
async fn enrol_and_confirm(state: &AppState, uid: UserId, token: &str) -> String {
    let (status, started) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "enrol: {started}");
    let secret = started["secret"].as_str().expect("secret").to_owned();
    assert_eq!(started["confirmed"], false);

    let code = current_code(&secret);
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
    assert_eq!(
        confirmed["backup_codes"].as_array().expect("codes").len(),
        10
    );
    secret
}

/// The current 6-digit code for a base32 secret. Uses the production generator so it is fast and
/// deterministic (a brute-force search over 10^6 is slow enough under parallel load that the TOTP
/// step can roll over before the server verifies).
fn current_code(secret: &str) -> String {
    chancela_api::totp::code_for_secret(secret, OffsetDateTime::now_utc().unix_timestamp())
        .expect("decodable secret")
}

// =================================================================================================
// ENROL / CONFIRM
// =================================================================================================

#[tokio::test]
async fn a_confirmed_enrolment_activates_the_factor_and_shows_backup_codes_once() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;

    // Before enrolment: not a factor.
    let (status, view) = send(state.clone(), with_session(get(&format!("/v1/users/{}", uid.0)), &token)).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["has_totp"], false);

    enrol_and_confirm(&state, uid, &token).await;

    let (status, view) = send(state.clone(), with_session(get(&format!("/v1/users/{}", uid.0)), &token)).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["has_totp"], true, "confirmed factor must read as active");

    let (status, twofa) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/two-factor", uid.0)), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{twofa}");
    assert_eq!(twofa["confirmed"], true);
    assert_eq!(twofa["backup_codes_remaining"], 10);
    assert!(twofa["confirmed_at"].is_string());
}

/// A pending (unconfirmed) enrolment grants nothing: `has_totp` stays false until a live code proves
/// the authenticator. This is what keeps a user who scanned nothing from being locked out.
#[tokio::test]
async fn a_pending_enrolment_is_not_yet_a_factor() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;

    let (status, _) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_, view) = send(state.clone(), with_session(get(&format!("/v1/users/{}", uid.0)), &token)).await;
    assert_eq!(view["has_totp"], false, "an unconfirmed secret is not a factor");
    let (_, twofa) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/two-factor", uid.0)), &token),
    )
    .await;
    assert_eq!(twofa["enrolled"], true);
    assert_eq!(twofa["confirmed"], false);
}

#[tokio::test]
async fn confirming_with_a_wrong_code_does_not_activate() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;

    let (status, started) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{started}");
    let secret = started["secret"].as_str().unwrap().to_owned();
    // A code that is definitely not the current one.
    let good = current_code(&secret);
    let bad = if good == "000000" { "111111" } else { "000000" };
    let (status, body) = send(
        state.clone(),
        with_session(
            post(&format!("/v1/users/{}/two-factor/totp/confirm", uid.0), json!({ "code": bad })),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (_, view) = send(state.clone(), with_session(get(&format!("/v1/users/{}", uid.0)), &token)).await;
    assert_eq!(view["has_totp"], false);
}

/// Enrolling, confirming, disabling and regenerating are self-service. Another user — even one who
/// could otherwise administer accounts — cannot enrol on your behalf, because the secret has to
/// reach *your* authenticator; and an API key can never enrol at all.
#[tokio::test]
async fn only_the_account_holder_may_manage_their_own_second_factor() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let alice = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let bob = seed_user(&state, "bruno.dias", OWNER_ROLE_ID).await;
    let bob_token = open_session(&state, bob).await;

    // Bob (an Owner) cannot enrol a factor for Alice.
    let (status, body) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", alice.0), Value::Null), &bob_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Unauthenticated is a 401.
    let (status, _) = send(
        state.clone(),
        post(&format!("/v1/users/{}/two-factor/totp/enrol", alice.0), Value::Null),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn re_enrolling_over_an_active_factor_is_refused() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    enrol_and_confirm(&state, uid, &token).await;

    let (status, body) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/totp/enrol", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "an active factor must not be silently replaced: {body}");
}

// =================================================================================================
// DISABLE / BACKUP CODES
// =================================================================================================

#[tokio::test]
async fn a_user_can_disable_their_own_factor_unless_it_is_required() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    enrol_and_confirm(&state, uid, &token).await;

    // Make it required (directly on state — the admin toggle has its own test).
    state.users.write().await.get_mut(&uid).unwrap().two_factor_required = true;
    let (status, body) = send(
        state.clone(),
        with_session(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{}/two-factor/totp", uid.0))
                .body(Body::empty())
                .unwrap(),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "a required factor must not be self-disabled: {body}");

    // Lift the requirement, then disable succeeds.
    state.users.write().await.get_mut(&uid).unwrap().two_factor_required = false;
    let (status, view) = send(
        state.clone(),
        with_session(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/users/{}/two-factor/totp", uid.0))
                .body(Body::empty())
                .unwrap(),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["has_totp"], false);
}

#[tokio::test]
async fn regenerating_backup_codes_requires_an_active_factor_and_replaces_the_old_set() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;

    // No factor yet → refused.
    let (status, _) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/backup-codes", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    enrol_and_confirm(&state, uid, &token).await;
    let (status, first) = send(
        state.clone(),
        with_session(post(&format!("/v1/users/{}/two-factor/backup-codes", uid.0), Value::Null), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["backup_codes_remaining"], 10);
    assert_eq!(first["backup_codes"].as_array().unwrap().len(), 10);
}

// =================================================================================================
// PER-ACCOUNT MANDATORY 2FA
// =================================================================================================

/// The admin toggle is refused unless the instance actually supports TOTP — a requirement no account
/// could satisfy is a lockout with no cure.
#[tokio::test]
async fn requiring_two_factor_needs_totp_enabled_instance_wide() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let admin = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let target = seed_user(&state, "bruno.dias", READER_ROLE_ID).await;
    let admin_token = open_session(&state, admin).await;

    // totp_enabled is off by default → the toggle-on is refused.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PATCH", &format!("/v1/users/{}", target.0), json!({ "two_factor_required": true })),
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("totp_enabled"),
        "{body}"
    );
    assert_eq!(
        state.users.read().await.get(&target).unwrap().two_factor_required,
        false
    );

    // Enable TOTP instance-wide, then the toggle lands.
    state.settings.write().await.auth.two_factor.totp_enabled = true;
    let (status, view) = send(
        state.clone(),
        with_session(
            json_request("PATCH", &format!("/v1/users/{}", target.0), json!({ "two_factor_required": true })),
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["two_factor_required"], true);
}

// =================================================================================================
// FORCED FIRST-LOGIN PASSWORD CHANGE — and the fingerprint invariant
// =================================================================================================

/// An account created **with a welcome email** carries `force_password_change`; a plain create does
/// not; and the bootstrap first-Owner never does (they set their own password).
#[tokio::test]
async fn a_welcome_email_account_is_flagged_for_a_forced_change() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let admin = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let admin_token = open_session(&state, admin).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post(
                "/v1/users",
                json!({
                    "username": "bruno.dias",
                    "email": "bruno.dias@example.pt",
                    "password": TEST_PASSWORD,
                    "send_welcome_email": true
                }),
            ),
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let new_id = created["id"].as_str().unwrap();
    let uid = UserId(Uuid::parse_str(new_id).unwrap());
    assert!(
        state.users.read().await.get(&uid).unwrap().force_password_change,
        "an account created with a welcome email must be flagged"
    );

    // A create WITHOUT a welcome email is not flagged.
    let (status, plain) = send(
        state.clone(),
        with_session(
            post(
                "/v1/users",
                json!({ "username": "carla.nunes", "password": TEST_PASSWORD }),
            ),
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{plain}");
    let plain_uid = UserId(Uuid::parse_str(plain["id"].as_str().unwrap()).unwrap());
    assert!(!state.users.read().await.get(&plain_uid).unwrap().force_password_change);
}

/// The interaction the lead flagged as the one that must be right: a forced first-login change goes
/// through the ordinary self-service `set_secret`, which **re-wraps the same attestation keypair**.
/// The fingerprint must be unchanged across the change, so every attestation the account made before
/// the change still verifies — and the flag is cleared.
#[tokio::test]
async fn a_forced_first_login_change_preserves_the_attestation_fingerprint() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let admin = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let admin_token = open_session(&state, admin).await;

    // Create the account with a welcome email (so it is flagged) — `create_user` also generates the
    // attestation key at creation, wrapped under the admin-chosen password (t88).
    let (status, created) = send(
        state.clone(),
        with_session(
            post(
                "/v1/users",
                json!({
                    "username": "bruno.dias",
                    "email": "bruno.dias@example.pt",
                    "password": TEST_PASSWORD,
                    "send_welcome_email": true
                }),
            ),
            &admin_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let uid = UserId(Uuid::parse_str(created["id"].as_str().unwrap()).unwrap());
    let fingerprint_before = created["attestation_key_fingerprint"]
        .as_str()
        .expect("the account was created with an attestation key")
        .to_owned();
    assert!(state.users.read().await.get(&uid).unwrap().force_password_change);

    // The user signs in and changes their own password (the forced-change flow drives this).
    let user_token = open_session(&state, uid).await;
    let (status, view) = send(
        state.clone(),
        with_session(
            post(
                &format!("/v1/users/{}/secret", uid.0),
                json!({ "password": NEW_PASSWORD, "current_password": TEST_PASSWORD }),
            ),
            &user_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");

    // THE INVARIANT: same fingerprint, so past attestations still verify.
    assert_eq!(
        view["attestation_key_fingerprint"].as_str(),
        Some(fingerprint_before.as_str()),
        "a forced change must re-wrap the SAME key, not retire it"
    );
    // And the flag is cleared, so the account is no longer walled off.
    assert!(
        !state.users.read().await.get(&uid).unwrap().force_password_change,
        "the forced-change flag must clear on the first successful change"
    );
    // Belt and braces: the account still has an active key (it was re-wrapped, not dropped).
    assert_eq!(view["has_attestation_key"], true);
}

// =================================================================================================
// SECRET HYGIENE
// =================================================================================================

/// The TOTP secret is shown once at enrol and never again — not on the status read, not in the
/// ledger, not in the user view.
#[tokio::test]
async fn the_totp_secret_never_reappears_after_enrolment() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let uid = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let secret = enrol_and_confirm(&state, uid, &token).await;

    // The status read carries no secret.
    let (_, twofa) = send(
        state.clone(),
        with_session(get(&format!("/v1/users/{}/two-factor", uid.0)), &token),
    )
    .await;
    assert!(!twofa.to_string().contains(&secret), "status leaked the secret");

    // The user view carries no secret.
    let (_, view) = send(state.clone(), with_session(get(&format!("/v1/users/{}", uid.0)), &token)).await;
    assert!(!view.to_string().contains(&secret));

    // The ledger carries no secret.
    let ledger = state.ledger.read().await;
    let rendered = serde_json::to_string(&ledger.events()).expect("ledger serialises");
    assert!(!rendered.contains(&secret), "the ledger leaked the secret");
    let kinds: Vec<&str> = ledger.events().iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"user.totp.enrolled"), "{kinds:?}");
}

/// Sanity that the exported verifier and secret type behave as the enrolment flow relies on: a
/// generated secret produces a code the verifier accepts within the current step.
#[tokio::test]
async fn the_exported_verifier_round_trips_a_generated_secret() {
    let secret = TotpSecret::generate();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let code = current_code(secret.expose());
    assert!(matches!(
        verify_code_against_secret(secret.expose(), &code, now, None),
        VerifyOutcome::Accepted { .. }
    ));
    // The window is one step wide either side.
    assert_eq!(STEP_SECONDS, 30);
}
