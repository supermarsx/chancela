//! The saved CMD mobile number (`GET|PUT /v1/me/cmd-phone`) over the wire, plus its appearance in
//! the subject-access export.
//!
//! Four properties, and the reason each is here rather than covered by the module's own unit tests:
//!
//! 1. **Opt-in and self-scoped.** The row is written only by an explicit `PUT` from the owner's own
//!    session, and no other user's session can read it. The unit tests prove the handler; these
//!    prove the *routing and session plumbing* around it — that the key an attestor extractor pulls
//!    out of the live session registry is the signed-in user's own.
//! 2. **Step-up is really enforced on the wire.** `require_step_up` inside the handler is only a
//!    guarantee if the route actually reaches it with the acting session attached.
//! 3. **Password custody survives a password change.** The number is sealed to the attestation
//!    scalar; a password change re-wraps that same scalar, so the number must still open afterwards.
//!    This is the whole reason for chaining to the scalar and cannot be observed below the HTTP
//!    layer, because it is the credential endpoint that performs the re-wrap.
//! 4. **It reaches the subject-access export**, in plaintext for the subject's own unlocked session
//!    and as an explicit "saved but sealed" statement otherwise — never as a silent absence.
//!
//! Every number here is synthetic (`+351 900 000 000`), and every assertion about at-rest storage
//! checks the sidecar bytes rather than trusting the API's own answer.

use crate::common;

use std::path::{Path, PathBuf};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, AttestationKeyBlob, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

/// A clearly-synthetic number in the shape the CMD lane accepts. No real number, ever.
const FAKE_PHONE: &str = "+351 900 000 000";
/// The written forms `FAKE_PHONE` could leak as. Each is long enough that finding one in the
/// sidecar is proof of plaintext at rest rather than a coincidence in random base64/hex.
const PLAINTEXT_FORMS: [&str; 5] = [
    FAKE_PHONE,
    "+351900000000",
    "351900000000",
    "900000000",
    "900 000 000",
];
const OTHER_FAKE_PHONE: &str = "+351 900 000 001";

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-cmd-phone-{}", Uuid::new_v4()));
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

fn json_req(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("req")
}

/// Seed a user who holds a password AND an attestation key — the shape whose sign-in yields the
/// unlocked scalar this feature seals to.
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
            attestation_key: Some(AttestationKeyBlob::generate(TEST_PASSWORD).expect("key")),
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

async fn sign_in(state: &AppState, uid: UserId) -> String {
    sign_in_with(state, uid, TEST_PASSWORD).await
}

async fn sign_in_with(state: &AppState, uid: UserId, password: &str) -> String {
    let req = json_req(
        "POST",
        "/v1/session",
        json!({ "user_id": uid.0, "password": password }),
    );
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "sign-in: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// `PUT /v1/me/cmd-phone` with a password step-up proof. `phone: None` clears.
async fn put_phone(
    state: &AppState,
    token: &str,
    phone: Option<&str>,
    password: &str,
) -> (StatusCode, Value) {
    send(
        state.clone(),
        with_session(
            json_req(
                "PUT",
                "/v1/me/cmd-phone",
                json!({ "phone": phone, "reauth": { "password": password } }),
            ),
            token,
        ),
    )
    .await
}

async fn get_phone(state: &AppState, token: &str) -> (StatusCode, Value) {
    send(state.clone(), with_session(get("/v1/me/cmd-phone"), token)).await
}

/// The sidecar's raw bytes, or an empty string when it was never written.
fn sidecar(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("cmd-saved-phones.json")).unwrap_or_default()
}

/// A Reader — no administrative verb — saves, re-reads and clears their own number, and the file on
/// disk never contains it. The role matters: a regression that quietly re-gates this on a permission
/// verb must fail here rather than pass because the fixture happened to hold one.
#[tokio::test]
async fn a_user_with_no_admin_permission_saves_reads_and_clears_their_own_number() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    // Nothing saved to begin with — opt-in means the default is empty.
    let (status, body) = get_phone(&state, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["saved"], json!(false));
    assert_eq!(body["phone"], Value::Null);

    let (status, body) = put_phone(&state, &token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "save: {body}");
    assert_eq!(body["saved"], json!(true));
    assert_eq!(body["readable"], json!(true));
    assert_eq!(body["phone"], json!(FAKE_PHONE));

    // Byte-identical on the way back out.
    let (status, body) = get_phone(&state, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["phone"], json!(FAKE_PHONE));

    // At rest it is ciphertext. Assert against the file, not the API's own claim.
    let on_disk = sidecar(&temp.0);
    assert!(!on_disk.is_empty(), "the sidecar must have been written");
    // Every plausible WRITTEN form of the number, not a three-character fragment of it. A bare
    // "900" collides with `key_fingerprint`, which is hex: three digits land in 64 hex characters
    // by chance roughly 1.5% of the time (and an RFC 3339 `saved_at` can carry them in its
    // fractional seconds), so that spelling failed on luck rather than on a leak — it went red on
    // Linux CI while passing 20/20 here. These forms are long enough that a base64/hex collision
    // is not a possibility, so a red here means the plaintext really did reach the file.
    for form in PLAINTEXT_FORMS {
        assert!(
            !on_disk.contains(form),
            "the number must never be at rest in cleartext (found {form})"
        );
    }
    assert!(on_disk.contains("ciphertext"));

    // Clearing discards the row and every wrap with it.
    let (status, body) = put_phone(&state, &token, None, TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "clear: {body}");
    assert_eq!(body["saved"], json!(false));
    let (_, body) = get_phone(&state, &token).await;
    assert_eq!(body["saved"], json!(false));
    assert!(
        !sidecar(&temp.0).contains("ciphertext"),
        "clearing must leave no sealed row behind"
    );
}

/// Step-up is reached and enforced on the wire, in **both** directions. A session token alone —
/// exactly what an attacker holding a stolen session has — must not be able to point the CMD
/// confirmation SMS at a different handset, nor to wipe the owner's saved number.
#[tokio::test]
async fn a_session_alone_can_neither_set_nor_clear_the_number() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    // No proof at all.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req("PUT", "/v1/me/cmd-phone", json!({ "phone": FAKE_PHONE })),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!sidecar(&temp.0).contains("ciphertext"));

    // A wrong password is refused identically — and still writes nothing.
    let (status, body) = put_phone(&state, &token, Some(FAKE_PHONE), "not-the-password").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!sidecar(&temp.0).contains("ciphertext"));

    // With a real proof it stores; the clear then has to prove itself again.
    let (status, _) = put_phone(&state, &token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req("PUT", "/v1/me/cmd-phone", json!({ "phone": Value::Null })),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "clear needs step-up too: {body}"
    );
    let (_, body) = get_phone(&state, &token).await;
    assert_eq!(
        body["phone"],
        json!(FAKE_PHONE),
        "a refused clear must leave the number intact"
    );
}

/// One user's number is invisible and untouchable to another. There is no administrative read path
/// and no list endpoint, so the only thing to prove is that a *different* signed-in session sees
/// its own (empty) row and cannot overwrite the neighbour's.
#[tokio::test]
async fn another_signed_in_user_can_neither_see_nor_overwrite_the_number() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let amelia = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let bruno = seed_user(&state, "bruno.costa", READER_ROLE_ID).await;
    let amelia_token = sign_in(&state, amelia).await;
    let bruno_token = sign_in(&state, bruno).await;

    let (status, _) = put_phone(&state, &amelia_token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);

    // Bruno's read is of Bruno's row: empty. Not a masked hint, not a timestamp, nothing.
    let (status, body) = get_phone(&state, &bruno_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["saved"], json!(false));
    assert_eq!(body["saved_at"], Value::Null);
    assert_eq!(body["phone"], Value::Null);

    // Bruno saving his own number does not disturb Amélia's.
    let (status, _) = put_phone(&state, &bruno_token, Some(OTHER_FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = get_phone(&state, &amelia_token).await;
    assert_eq!(body["phone"], json!(FAKE_PHONE));
    let (_, body) = get_phone(&state, &bruno_token).await;
    assert_eq!(body["phone"], json!(OTHER_FAKE_PHONE));
}

/// **The password wrap, end to end.** A password change re-wraps the *same* attestation scalar, so
/// the number — sealed to that scalar — must still open under the new password. This is the
/// property that makes chaining to the scalar worth doing: had the number been sealed under the
/// password directly, it would have needed its own re-wrap here, and a forgotten one would have
/// destroyed it silently.
#[tokio::test]
async fn the_number_survives_a_password_change_and_opens_under_the_new_one() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;
    let (status, _) = put_phone(&state, &token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);

    // A self-service password change: proves the current password, re-wraps the same scalar.
    const NEW_PASSWORD: &str = "Outra-Forte9!Z";
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                &format!("/v1/users/{}/secret", reader.0),
                json!({ "password": NEW_PASSWORD, "current_password": TEST_PASSWORD }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "password change: {body}");

    // Sign in afresh with the new password and the number is still there, byte-identical.
    let token = sign_in_with(&state, reader, NEW_PASSWORD).await;
    let (status, body) = get_phone(&state, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["readable"], json!(true));
    assert_eq!(body["phone"], json!(FAKE_PHONE));
}

/// A session unlocks the attestation scalar once, at sign-in, and holds it for the life of its
/// token — so a rotation does not reach it. Sealing under that superseded scalar would store a
/// record no key can ever open, which is exactly the state the reset path calls `clear_for_user_id`
/// to avoid; the module header's "an account with no attestation key cannot save a number" would be
/// a claim about the account that the session could walk straight past. The save is therefore
/// checked against the account's current anchor.
#[tokio::test]
async fn a_pre_rotation_session_cannot_save_under_the_superseded_key() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let stale_token = sign_in(&state, reader).await;

    // A real self-service rotation: `/attestation-key` REPLACES the scalar (unlike a password
    // change, which re-wraps the same one) and clears the saved number with it.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                &format!("/v1/users/{}/attestation-key", reader.0),
                json!({ "current_password": TEST_PASSWORD }),
            ),
            &stale_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attestation key rotates: {body}");

    // The still-open pre-rotation session holds the old scalar. Its save is refused, with the code
    // the client already resolves for "this session has no usable attestation key".
    let (status, body) = put_phone(&state, &stale_token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a pre-rotation session must not seal to the superseded key: {body}"
    );
    assert_eq!(body["code"], json!("cmd_phone_no_unlocked_key"), "{body}");
    assert!(
        !sidecar(&temp.0).contains("ciphertext"),
        "no doomed row may be written"
    );

    // A session opened after the rotation holds the current scalar and saves normally.
    let fresh_token = sign_in(&state, reader).await;
    let (status, body) = put_phone(&state, &fresh_token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the current key still saves: {body}"
    );
    assert_eq!(body["readable"], json!(true));
    assert_eq!(body["phone"], json!(FAKE_PHONE));

    // And the stale session can still CLEAR: the remedy for a doomed row must not require the key
    // that was taken away.
    let (status, body) = put_phone(&state, &stale_token, None, TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "a stale session can clear: {body}");
    assert_eq!(body["saved"], json!(false));
}

/// The subject-access export carries the number for the subject's own unlocked session, and states
/// its existence honestly for anyone else. The failure this guards against is the export quietly
/// omitting the field, which would make a saved number personal data the subject cannot obtain.
#[tokio::test]
async fn the_saved_number_reaches_the_subject_access_export() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let officer = seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;
    let officer_token = sign_in(&state, officer).await;

    // Before anything is saved the section is present and says so — the key set does not depend on
    // whether the subject uses the feature.
    let (status, body) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{}/data-export", reader.0)),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let section = &body["subject"]["cmd_signing_phone"];
    assert!(
        section.is_object(),
        "the section must always be present: {body}"
    );
    assert_eq!(section["saved"], json!(false));
    assert_eq!(section["phone"], Value::Null);
    assert_eq!(section["note"], Value::Null);

    let (status, _) = put_phone(&state, &token, Some(FAKE_PHONE), TEST_PASSWORD).await;
    assert_eq!(status, StatusCode::OK);

    // The subject's own session exports the number itself.
    let (status, body) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{}/data-export", reader.0)),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let section = &body["subject"]["cmd_signing_phone"];
    assert_eq!(section["saved"], json!(true));
    assert_eq!(section["phone"], json!(FAKE_PHONE));
    assert!(section["saved_at"].is_string());
    assert_eq!(section["note"], Value::Null);
    // And the number is not smuggled into the withheld-material list — it is the subject's data,
    // not secret material the export declines to carry.
    let exclusions = body["exclusions"].to_string();
    assert!(
        !exclusions.contains("cmd"),
        "unexpected exclusion: {exclusions}"
    );

    // A privacy officer exporting on the subject's behalf gets the honest statement instead: the
    // number exists and is sealed to credentials the officer does not hold. Never a bare null that
    // would read as "no number is stored".
    let (status, body) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{}/data-export", reader.0)),
            &officer_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let section = &body["subject"]["cmd_signing_phone"];
    assert_eq!(section["saved"], json!(true), "the fact is never dropped");
    assert_eq!(section["phone"], Value::Null);
    assert!(
        section["note"].as_str().is_some_and(|n| !n.is_empty()),
        "a withheld number must say why: {section}"
    );
}

/// A malformed number is refused with its stable code, and nothing is written. Refusing rather than
/// "repairing" is the point: a silently reformatted number is a different number, and the one it
/// would be replayed into is a qualified signature.
#[tokio::test]
async fn a_malformed_number_is_refused_with_its_code_and_stores_nothing() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    for bad in ["", "12345", "+351 900 000 000 ext 4"] {
        let (status, body) = put_phone(&state, &token, Some(bad), TEST_PASSWORD).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}: {body}");
        assert_eq!(body["code"], json!("cmd_phone_invalid"), "{bad:?}: {body}");
    }
    assert!(!sidecar(&temp.0).contains("ciphertext"));
}
