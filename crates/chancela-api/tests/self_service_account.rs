//! The self-service account surface (`/v1/me/profile`, `/v1/me/suspend`) over the wire.
//!
//! The defect these prove fixed: an ordinary user — one holding no `user.manage` and no `user.read`
//! — could not edit their own display name, e-mail or interface language, because the only endpoint
//! that wrote those fields was the administrative `PATCH /v1/users/{id}`. Every test here seeds a
//! **Reader**, deliberately, so a regression that quietly re-gates the self surface on an
//! administrative verb fails rather than passing because the fixture happened to be an Owner.
//!
//! The second property is the one that must not be got wrong: self-suspension is **one-way and
//! step-up gated**. A session token alone must not lock an account, all of the account's sessions
//! must die with it (including the caller's own), and the two states the instance cannot recover
//! from — sole active user, sole active Owner — must be refused *before* anything is written.

use crate::common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-account-{}", Uuid::new_v4()));
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

async fn sign_in(state: &AppState, uid: UserId) -> String {
    let req = json_req(
        "POST",
        "/v1/session",
        json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
    );
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "sign-in: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn is_active(state: &AppState, uid: UserId) -> bool {
    state.users.read().await.get(&uid).expect("user").active
}

// =================================================================================================
// PATCH /v1/me/profile
// =================================================================================================

/// The whole point of the surface: a user with no administrative verb edits their own profile, and
/// the administrative endpoint refuses that same user. Both halves are asserted in one test because
/// it is their *contrast* that is the requirement — a self endpoint that works is uninteresting if
/// the admin one would have worked too.
#[tokio::test]
async fn a_user_with_no_admin_permission_edits_their_own_profile_but_not_through_the_admin_route() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    // A second active user so no last-active-user guard is in play anywhere in this test.
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    // The administrative route refuses them — this is the state before the fix, still true.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "PATCH",
                &format!("/v1/users/{}", reader.0),
                json!({ "display_name": "Amélia Marques" }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the admin route must stay user.manage-gated: {body}"
    );

    // The self route serves them.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "PATCH",
                "/v1/me/profile",
                json!({
                    "display_name": "Amélia Marques",
                    "email": "amelia.marques@example.test",
                    "language": "pt-PT",
                }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "Amélia Marques");
    assert_eq!(body["email"], "amelia.marques@example.test");
    assert_eq!(body["language"], "pt-PT");

    // And it is the caller's OWN record that moved, readable back off the session.
    let (status, session) = send(state.clone(), with_session(get("/v1/session"), &token)).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user"]["display_name"], "Amélia Marques");
}

/// The narrow body IS the gate. `active` and `two_factor_required` are not fields of
/// `PatchMyProfile`, so they are not deserialized at all and sending them changes nothing — in
/// EITHER direction. The request below asks for both, alongside a field that really is writable, so
/// a `200` with the profile field moved and the two administrative fields unmoved is the assertion:
/// the request was served, and the administrative fields were simply not part of it.
///
/// `two_factor_required` is exercised false→true rather than true→false only because a
/// `two_factor_required` account with no enrolled factor is behind the second-factor wall and can
/// reach nothing but the enrolment routes. The field is absent from the body type, so one direction
/// proves the other.
#[tokio::test]
async fn the_self_profile_route_cannot_write_the_administrative_fields() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "PATCH",
                "/v1/me/profile",
                json!({
                    "display_name": "Amélia Marques",
                    "active": false,
                    "two_factor_required": true,
                    "role_assignments": [],
                }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "Amélia Marques");
    assert_eq!(
        body["active"], true,
        "`active` must not be writable from the self route: {body}"
    );
    assert_eq!(
        body["two_factor_required"], false,
        "the second-factor requirement is an administrator's field, not the holder's: {body}"
    );
    assert!(
        body["role_assignments"]
            .as_array()
            .expect("role assignments")
            .len()
            == 1,
        "authority is granted, never self-claimed or self-dropped: {body}"
    );
}

// =================================================================================================
// POST /v1/me/suspend
// =================================================================================================

/// Step-up, end to end: the session alone is refused; the account's own password is accepted; every
/// session of the account — including the one that made the request — is rejected afterwards; and
/// the suspension can only be lifted by a holder of `user.manage`.
#[tokio::test]
async fn self_suspension_demands_step_up_kills_every_session_and_is_lifted_only_by_an_admin() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let owner = seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;

    // Two live sessions for the same account: the one that will make the request, and the one an
    // attacker is imagined to be holding.
    let mine = sign_in(&state, reader).await;
    let other = sign_in(&state, reader).await;

    // A session token on its own is not enough — this is the whole gate.
    let (status, body) = send(
        state.clone(),
        with_session(json_req("POST", "/v1/me/suspend", json!({})), &mine),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a session token alone must never suspend an account: {body}"
    );
    assert!(
        is_active(&state, reader).await,
        "a refused step-up must leave the account untouched"
    );

    // A wrong password is the same uniform refusal.
    let (status, _) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": "not-the-password" } }),
            ),
            &mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(is_active(&state, reader).await);

    // Proved, and it goes through.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user"]["active"], false);
    assert_eq!(
        body["sessions_revoked"], 2,
        "both of the account's sessions must end, not just the other one: {body}"
    );
    assert!(!is_active(&state, reader).await);

    // Both tokens are rejected on their NEXT request — the attacker's session and the caller's.
    for (name, token) in [("the other session", &other), ("the caller's own", &mine)] {
        let (status, _) = send(
            state.clone(),
            with_session(get("/v1/users/page?limit=1"), token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{name} must be rejected after a self-suspension"
        );
    }

    // A suspended account cannot sign back in, so it cannot lift its own suspension by any route.
    let (status, _) = send(
        state.clone(),
        json_req(
            "POST",
            "/v1/session",
            json!({ "user_id": reader.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a suspended account must not be able to sign in"
    );

    // Only `user.manage` reactivates it.
    let admin = sign_in(&state, owner).await;
    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "PATCH",
                &format!("/v1/users/{}", reader.0),
                json!({ "active": true }),
            ),
            &admin,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], true);
    assert!(is_active(&state, reader).await);
}

/// The unrecoverable case the lead named: a sole Owner suspending themselves would leave nobody
/// able to lift it. Refused with a code, before anything is written — and the refusal is a
/// `409 Conflict` about state, not a `403` about authority, because the caller *did* prove
/// themselves.
#[tokio::test]
async fn the_sole_active_owner_cannot_suspend_themselves() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let owner = seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    // A second ACTIVE user, so the last-active-user guard is not what fires here.
    seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, owner).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "self_suspend_last_active_owner");
    assert!(
        is_active(&state, owner).await,
        "a refused suspension must not have written anything"
    );
    // The session it refused is still alive — nothing was torn down.
    let (status, _) = send(state.clone(), with_session(get("/v1/session"), &token)).await;
    assert_eq!(status, StatusCode::OK);
}

/// A second Owner makes the same suspension legitimate, which is what proves the guard above is
/// counting holders rather than simply refusing every Owner.
#[tokio::test]
async fn an_owner_may_suspend_themselves_once_another_active_owner_exists() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let owner = seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    seed_user(&state, "second.owner", OWNER_ROLE_ID).await;
    let token = sign_in(&state, owner).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!is_active(&state, owner).await);
}

/// The sole active user of an instance: suspending would leave nobody who can sign in at all, and
/// the bootstrap create only fires at *zero* users, so the instance would be bricked.
#[tokio::test]
async fn the_sole_active_user_cannot_suspend_themselves() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let only = seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    let token = sign_in(&state, only).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "self_suspend_last_active_user");
    assert!(is_active(&state, only).await);
}

/// The suspension appends its own ledger kind rather than hiding inside `user.updated`: an auditor
/// asking "when did this account lock itself" must be able to answer it by kind.
#[tokio::test]
async fn a_self_suspension_appends_its_own_ledger_kind() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let kinds: Vec<String> = state
        .ledger
        .read()
        .await
        .events()
        .iter()
        .map(|e| e.kind.clone())
        .collect();
    assert!(
        kinds.iter().any(|k| k == "user.self_suspended"),
        "expected a user.self_suspended event, saw {kinds:?}"
    );
}

/// A suspended account reaches nothing at all — not the self surface, not a second suspension.
///
/// This is the reachable truth about the already-suspended state, and it is stronger than the
/// `account_already_suspended` conflict the handler also carries: the `CurrentActor` extractor
/// admits only ACTIVE users, so a suspended account is refused at the door with a `401` before any
/// handler runs. The conflict arm stays as a defence in depth — it is what the handler owes if that
/// extractor rule ever loosens — but this is what an operator actually experiences, so this is what
/// is asserted rather than a branch that is currently unreachable.
#[tokio::test]
async fn a_suspended_account_can_reach_nothing_including_a_second_suspension() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_user(&state, "owner.holder", OWNER_ROLE_ID).await;
    let reader = seed_user(&state, "amelia.marques", READER_ROLE_ID).await;
    let token = sign_in(&state, reader).await;

    let suspend_with = |token: &str| {
        with_session(
            json_req(
                "POST",
                "/v1/me/suspend",
                json!({ "reauth": { "password": TEST_PASSWORD } }),
            ),
            token,
        )
    };
    let (status, body) = send(state.clone(), suspend_with(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The same token, now belonging to a suspended account: refused at the extractor.
    let (status, body) = send(state.clone(), suspend_with(&token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a suspended account must not be able to act at all: {body}"
    );
    let (status, _) = send(
        state.clone(),
        with_session(
            json_req("PATCH", "/v1/me/profile", json!({ "display_name": "X" })),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And no fresh session can be minted for it either, so there is no second route back in.
    let (status, _) = send(
        state.clone(),
        json_req(
            "POST",
            "/v1/session",
            json!({ "user_id": reader.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}
