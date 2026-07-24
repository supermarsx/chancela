//! t95 P1-A over the wire: self-signup, invitations, and the two remaining call sites of the
//! self-signup default-role ceiling.
//!
//! Every test here hits the endpoint **directly**, with whatever rule the UI would have enforced
//! deliberately violated (§2.5). A form that hides a field is a convenience; the refusal that
//! matters is the one the handler makes.

use crate::common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{
    CORPORATE_SECRETARY_ROLE_ID, GUEST_ROLE_ID, OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment,
    RoleId, Scope,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

/// A password that satisfies the strength policy and is not the seeded operator's.
const APPLICANT_PASSWORD: &str = "Inscricao-Forte9!Z";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-api-signup-{}", Uuid::new_v4()));
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
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
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
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn seed_owner_session(state: &AppState) -> String {
    let uid = seed_user(state, "amelia.marques", OWNER_ROLE_ID).await;
    open_session(state, uid).await
}

/// Configure the signup policy **directly on the state**.
///
/// Deliberately not through `PUT /v1/settings` for the enforcement tests: the point of §2.5 is that
/// the *handler* refuses, so the test must be able to put the handler in front of any policy the
/// document could ever hold — including one an operator reached by editing `settings.json`. The
/// ceiling tests below do go through `PUT`, because there the wire path is the thing under test.
async fn configure_signup(state: &AppState, mutate: impl FnOnce(&mut chancela_api::AuthSettings)) {
    let mut settings = state.settings.write().await;
    mutate(&mut settings.auth);
}

fn signup_body(email: &str) -> Value {
    json!({ "email": email, "password": APPLICANT_PASSWORD })
}

// =================================================================================================
// §2.7 — THE BOOTSTRAP INVARIANT
// =================================================================================================

/// The one that matters most: on an instance with **zero users**, signup is refused however
/// permissively it is configured, and no Owner is created.
///
/// `POST /v1/users` is unauthenticated exactly and only in this state, and forces the created user
/// to Owner\@Global. If signup could also run here, "the first account on a fresh instance" would
/// have two doors and one of them hands a stranger the protected super-role. The two are mutually
/// exclusive by construction — `create_user`'s unauthenticated path requires zero users, signup
/// requires at least one — and this test pins both halves of that sentence.
#[tokio::test]
async fn signup_is_refused_on_an_instance_with_no_users_however_it_is_configured() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        auth.signup.require_email_verification = false;
        auth.signup.default_role = GUEST_ROLE_ID;
    })
    .await;
    assert!(state.users.read().await.is_empty());

    for route in ["/v1/auth/signup", "/v1/auth/invite/accept"] {
        let body = json!({
            "email": "estranho@example.pt",
            "password": APPLICANT_PASSWORD,
            "token": "does-not-matter"
        });
        let (status, response) = send(state.clone(), post(route, body)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {response}");
    }

    // Nothing was created — and in particular no Owner.
    let users = state.users.read().await;
    assert!(
        users.is_empty(),
        "signup created an account on an empty instance"
    );

    // And the bootstrap door itself is untouched: the first user still arrives through
    // `POST /v1/users`, still as Owner@Global.
    drop(users);
    let (status, created) = send(
        state.clone(),
        post(
            "/v1/users",
            json!({ "username": "amelia.marques", "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["role_assignments"][0]["role_id"],
        OWNER_ROLE_ID.0.to_string()
    );
}

// =================================================================================================
// §2.5 — SERVER-SIDE ENFORCEMENT OF EVERY GATE
// =================================================================================================

#[tokio::test]
async fn signup_while_disabled_is_refused() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    // `Disabled` is the default; state it anyway so the test still means something if it changes.
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Disabled;
        auth.signup.require_email_verification = false;
    })
    .await;

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("estranho@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(state.users.read().await.len(), 1);
}

#[tokio::test]
async fn a_domain_outside_the_allow_list_is_refused_and_a_subdomain_is_not_a_match() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::DomainAllowlist;
        auth.signup.allowed_domains = vec!["example.pt".to_owned()];
        auth.signup.require_email_verification = false;
    })
    .await;

    for refused in [
        "outsider@outro.example",
        // The subdomain-takeover shape the settings validator refuses to let an operator *write*;
        // this is the matching half at the door.
        "outsider@abandonado.example.pt",
        "outsider@example.pt.evil.example",
    ] {
        let (status, body) =
            send(state.clone(), post("/v1/auth/signup", signup_body(refused))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}: {body}");
    }
    assert_eq!(state.users.read().await.len(), 1, "nothing was created");

    let (status, body) = send(
        state.clone(),
        // Case and padding must not decide the outcome: the stored list is normalized and the
        // address is normalized, so the comparison is a byte match on both sides.
        post(
            "/v1/auth/signup",
            signup_body("  Amelia.Marques@Example.PT "),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(state.users.read().await.len(), 2);
}

#[tokio::test]
async fn an_invite_only_instance_refuses_self_signup() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::InviteOnly;
        auth.signup.require_email_verification = false;
    })
    .await;

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("estranho@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(state.users.read().await.len(), 1);
}

/// The default is `true`, and proving control of an address needs a channel this phase does not
/// have. Refusing is the only honest option — creating accounts whose address was never checked
/// while a setting says it was would be a lie told by the settings page.
#[tokio::test]
async fn signup_refuses_while_email_verification_is_required_because_it_cannot_be_performed() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        assert!(
            auth.signup.require_email_verification,
            "the safe direction must stay the default"
        );
    })
    .await;

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("estranho@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(state.users.read().await.len(), 1);
}

// =================================================================================================
// ENUMERATION
// =================================================================================================

/// Signup must not become an account-existence oracle. A second attempt on an address that already
/// has an account returns the **identical** status and the **identical** body, and creates nothing.
#[tokio::test]
async fn signing_up_with_a_taken_address_is_indistinguishable_from_a_fresh_one() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        auth.signup.require_email_verification = false;
    })
    .await;

    let (fresh_status, fresh_body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("amelia.marques@example.pt")),
    )
    .await;
    assert_eq!(fresh_status, StatusCode::ACCEPTED, "{fresh_body}");
    assert_eq!(state.users.read().await.len(), 2);

    let (taken_status, taken_body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("amelia.marques@example.pt")),
    )
    .await;
    assert_eq!(taken_status, fresh_status, "the status distinguishes them");
    assert_eq!(taken_body, fresh_body, "the body distinguishes them");
    assert_eq!(
        state.users.read().await.len(),
        2,
        "the second attempt created a second account for one address"
    );

    // A differently-cased spelling of the same address is the same address.
    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("AMELIA.MARQUES@EXAMPLE.PT")),
    )
    .await;
    assert_eq!(status, fresh_status);
    assert_eq!(body, fresh_body);
    assert_eq!(state.users.read().await.len(), 2);
}

/// The username is derived, never submitted, so signup cannot be used to ask "is this name taken?"
/// either — and the collision it silently resolves is invisible in the response.
#[tokio::test]
async fn a_self_signed_up_account_gets_exactly_one_role_at_global_and_a_derived_username() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    // The seeded operator already owns the username the applicant's address would derive.
    seed_user(&state, "amelia.marques", OWNER_ROLE_ID).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        auth.signup.require_email_verification = false;
        auth.signup.default_role = GUEST_ROLE_ID;
    })
    .await;

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("amelia.marques@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    // The reply says nothing about the account it may or may not have made.
    assert_eq!(body, json!({ "status": "accepted" }));

    let users = state.users.read().await;
    let created = users
        .values()
        .find(|u| u.email.as_deref() == Some("amelia.marques@example.pt"))
        .expect("the account exists");
    assert_eq!(created.username, "amelia.marques2", "collision resolved");
    assert_eq!(
        created.role_assignments,
        vec![RoleAssignment::new(GUEST_ROLE_ID, Scope::Global)],
        "self-signup grants exactly one role, at Global only"
    );
    assert!(created.active);
    assert!(created.password_hash.is_some());
    // The audit key is generated at creation exactly as `create_user` does, so a self-signed-up
    // account can attest from its first sign-in rather than being quietly second-class.
    assert!(created.attestation_key.is_some());
}

// =================================================================================================
// §2.6 — THE DEFAULT-ROLE CEILING, GRANT-TIME SITE
// =================================================================================================

/// The catalog can become non-conforming without any request touching it — a `roles.json` restored
/// from a backup taken before the ceiling existed, say. Grant time re-checks, so the worst outcome
/// is a refused signup rather than a privileged stranger.
#[tokio::test]
async fn signup_refuses_when_the_configured_default_role_is_no_longer_eligible() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        auth.signup.require_email_verification = false;
        auth.signup.default_role = GUEST_ROLE_ID;
    })
    .await;

    // Bypass every handler: widen the role in the catalog the way a restored file would.
    {
        let mut roles = state.roles.write().await;
        let mut guest = roles.get(GUEST_ROLE_ID).cloned().expect("Guest is seeded");
        guest
            .permission_set
            .insert(chancela_authz::Permission::SettingsManage);
        roles.insert(guest);
    }

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("estranho@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("Guest"),
        "{body}"
    );
    assert_eq!(state.users.read().await.len(), 1);
}

/// A default role that names nothing in the catalog is a refusal, not a shrug — and certainly not a
/// roleless account.
#[tokio::test]
async fn signup_refuses_when_the_configured_default_role_does_not_exist() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.mode = chancela_api::SignupMode::Public;
        auth.signup.require_email_verification = false;
        auth.signup.default_role = RoleId(Uuid::from_u128(0xdead_beef));
    })
    .await;

    let (status, body) = send(
        state.clone(),
        post("/v1/auth/signup", signup_body("estranho@example.pt")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(state.users.read().await.len(), 1);
}

// =================================================================================================
// §2.6 — THE DEFAULT-ROLE CEILING, ROLE-EDIT SITE (the bypass t96 reported)
// =================================================================================================

/// Order 1 — **configure, then edit.** Guest is the configured default (and the shipped default);
/// widening it to hold `settings.manage` must be refused *at the edit*, because nothing
/// re-validates the settings document when a role changes.
///
/// Without this call site the ceiling is advisory: the settings page refuses to name a privileged
/// role, and the roles page then makes the named role privileged.
#[tokio::test]
async fn the_configured_signup_default_role_cannot_be_edited_into_a_privileged_one() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let token = seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        auth.signup.default_role = GUEST_ROLE_ID;
    })
    .await;

    let guest = state
        .roles
        .read()
        .await
        .get(GUEST_ROLE_ID)
        .cloned()
        .expect("Guest is seeded");
    let mut widened: Vec<String> = guest
        .permission_set
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    widened.push("settings.manage".to_owned());

    let (status, body) = send(
        state.clone(),
        with_session(
            json_request(
                "PATCH",
                &format!("/v1/roles/{}", GUEST_ROLE_ID.0),
                json!({ "permissions": widened }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let message = body["error"].as_str().unwrap_or_default().to_owned();
    assert!(message.contains("auth.signup.default_role"), "{message}");
    assert!(message.contains("settings.manage"), "{message}");

    // And the catalog is unchanged — the refusal happened before the write.
    assert!(
        !state
            .roles
            .read()
            .await
            .get(GUEST_ROLE_ID)
            .expect("Guest")
            .permission_set
            .contains(&chancela_authz::Permission::SettingsManage),
        "the edit landed despite the refusal"
    );

    // A *narrowing* edit of the same role is untouched: the ceiling refuses privilege, not editing.
    let narrowed: Vec<String> = Vec::new();
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request(
                "PATCH",
                &format!("/v1/roles/{}", GUEST_ROLE_ID.0),
                json!({ "permissions": narrowed }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Order 2 — **edit, then configure.** Point the default at an eligible role, widen a *different*
/// role freely (legal — it is not the default), then try to name the widened role as the default.
/// Settings-validate is the site that must catch this one. Both orders are closed; neither site
/// alone closes both.
#[tokio::test]
async fn a_role_widened_first_cannot_then_be_named_the_signup_default() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let token = seed_owner_session(&state).await;
    configure_signup(&state, |auth| {
        // Anything eligible that is not Guest, so the edit below is not the configured default.
        auth.signup.default_role = READER_ROLE_ID;
    })
    .await;

    let guest = state
        .roles
        .read()
        .await
        .get(GUEST_ROLE_ID)
        .cloned()
        .expect("Guest is seeded");
    let mut widened: Vec<String> = guest
        .permission_set
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    widened.push("settings.manage".to_owned());
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request(
                "PATCH",
                &format!("/v1/roles/{}", GUEST_ROLE_ID.0),
                json!({ "permissions": widened }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "widening a non-default role is legal: {body}"
    );

    // Now name it. The settings-validate site is what stands here.
    let (status, document) = send(state.clone(), with_session(get("/v1/settings"), &token)).await;
    assert_eq!(status, StatusCode::OK, "{document}");
    let mut document = document;
    document["auth"] = json!({ "signup": { "default_role": GUEST_ROLE_ID.0 } });
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("Guest"),
        "{body}"
    );
    assert_eq!(
        state.settings.read().await.auth.signup.default_role,
        READER_ROLE_ID,
        "the refused document must not have landed"
    );
}

// =================================================================================================
// INVITATIONS
// =================================================================================================

/// Set up an invite-capable instance: invite-only mode, a configured link origin, and a session for
/// a holder of `user.invite` that is deliberately **not** an Owner.
async fn invite_ready(state: &AppState) -> String {
    seed_user(state, "amelia.marques", OWNER_ROLE_ID).await;
    let secretary = seed_user(state, "carlos.pinto", CORPORATE_SECRETARY_ROLE_ID).await;
    {
        let mut settings = state.settings.write().await;
        settings.auth.signup.mode = chancela_api::SignupMode::InviteOnly;
        settings.auth.signup.default_role = GUEST_ROLE_ID;
        settings.platform.public_base_url = Some("https://livros.example.pt".to_owned());
    }
    open_session(state, secretary).await
}

async fn issue_invite(state: &AppState, token: &str, body: Value) -> (StatusCode, Value) {
    send(
        state.clone(),
        with_session(post("/v1/auth/invites", body), token),
    )
    .await
}

fn token_from(accept_url: &str) -> String {
    accept_url
        .split("token=")
        .nth(1)
        .expect("the accept url carries a token")
        .to_owned()
}

#[tokio::test]
async fn an_invitation_grants_the_default_role_and_can_be_accepted_exactly_once() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let session = invite_ready(&state).await;

    let (status, issued) = issue_invite(
        &state,
        &session,
        json!({ "email": "  Convidada@Example.PT " }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    assert_eq!(issued["email"], "convidada@example.pt");
    assert_eq!(issued["role_id"], GUEST_ROLE_ID.0.to_string());
    assert_eq!(issued["scope"], json!({ "kind": "global" }));
    let accept_url = issued["accept_url"]
        .as_str()
        .expect("accept url")
        .to_owned();
    // The origin is the configured one, never anything derived from the request.
    assert!(
        accept_url.starts_with("https://livros.example.pt/invite?token="),
        "{accept_url}"
    );
    let invite_token = token_from(&accept_url);

    let (status, created) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": invite_token, "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["email"], "convidada@example.pt");
    assert_eq!(created["username"], "convidada");
    assert_eq!(
        created["role_assignments"],
        json!([{ "role_id": GUEST_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }])
    );

    // Single use: the record is removed before the effect runs, so a replay finds nothing and gets
    // the same refusal an unknown token gets.
    let (status, replayed) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": token_from(&accept_url), "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{replayed}");
    let (status, unknown) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": "totally-made-up-token-value", "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{unknown}");
    assert_eq!(
        replayed, unknown,
        "a spent token must be indistinguishable from one that never existed"
    );
}

/// A token that is no longer live — expired, or superseded by a newer invitation for the same
/// address — is the same uniform refusal. Liveness is exercised through the store's own clock-free
/// pruning, because the handler reads the wall clock; the boundary semantics themselves are pinned
/// by `auth_token`'s unit tests.
#[tokio::test]
async fn an_expired_or_superseded_invitation_is_refused_uniformly() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let session = invite_ready(&state).await;

    // --- superseded --------------------------------------------------------------------------
    let (_, first) =
        issue_invite(&state, &session, json!({ "email": "convidada@example.pt" })).await;
    let first_token = token_from(first["accept_url"].as_str().expect("url"));
    let (_, second) =
        issue_invite(&state, &session, json!({ "email": "convidada@example.pt" })).await;
    let second_token = token_from(second["accept_url"].as_str().expect("url"));

    let (status, body) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": first_token, "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(state.users.read().await.len(), 2, "nothing was created");

    // --- expired -----------------------------------------------------------------------------
    let far_future = OffsetDateTime::now_utc() + time::Duration::days(365);
    assert_eq!(
        state.auth_tokens.write().await.prune_expired(far_future),
        1,
        "the live invitation should have been pruned"
    );
    let (status, expired) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": second_token, "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{expired}");
    assert_eq!(expired, body, "expiry and supersession must read alike");
    assert_eq!(state.users.read().await.len(), 2);
}

/// An invitation addressed to one mailbox must never produce an account for another. The invitation
/// decides the address; the request may only confirm it.
#[tokio::test]
async fn a_cross_subject_invitation_is_refused_and_the_address_comes_from_the_invitation() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let session = invite_ready(&state).await;

    let (_, issued) =
        issue_invite(&state, &session, json!({ "email": "convidada@example.pt" })).await;
    let accept_url = issued["accept_url"].as_str().expect("url").to_owned();

    let (status, body) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({
                "token": token_from(&accept_url),
                "password": APPLICANT_PASSWORD,
                "email": "atacante@evil.example"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(state.users.read().await.len(), 2, "no account was created");
    // And the token was spent by the attempt, so probing is not free.
    let (status, retry) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": token_from(&accept_url), "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{retry}");
}

/// A token of a different purpose presented at this door is simply not found — cross-purpose replay
/// fails as an unknown token, and is spent by the attempt.
#[tokio::test]
async fn a_token_of_another_purpose_cannot_be_redeemed_as_an_invitation() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    invite_ready(&state).await;

    let raw = {
        let mut tokens = state.auth_tokens.write().await;
        let (secret, _) = tokens.issue_default_ttl(
            chancela_api::auth_token::AuthTokenPurpose::PasswordRecovery,
            chancela_api::auth_token::AuthTokenSubject::email("convidada@example.pt"),
            OffsetDateTime::now_utc(),
        );
        secret.expose().to_owned()
    };

    let (status, body) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": raw, "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(state.users.read().await.len(), 2);
}

/// An invitation is a bearer credential in a URL, and that URL's origin is configuration — never a
/// request header. With nothing configured there is no honest link to build, so the endpoint refuses
/// instead of guessing (t96 P0-3: a guessed origin lets an attacker aim a live credential at a
/// domain they own).
#[tokio::test]
async fn an_invitation_cannot_be_issued_without_a_configured_public_base_url() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let session = invite_ready(&state).await;
    state.settings.write().await.platform.public_base_url = None;

    let mut request = post(
        "/v1/auth/invites",
        json!({ "email": "convidada@example.pt" }),
    );
    // A poisoned Host header must change nothing: there is no request-derived accessor.
    request
        .headers_mut()
        .insert(header::HOST, "evil.example".parse().expect("host"));
    let (status, body) = send(state.clone(), with_session(request, &session)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("public_base_url"),
        "{body}"
    );
    assert!(state.auth_tokens.read().await.is_empty());
}

/// `user.invite` is the gate, and it is distinct from `user.manage` on purpose — a Corporate
/// Secretary invites without administering accounts. A Reader holds neither.
#[tokio::test]
async fn issuing_an_invitation_requires_the_user_invite_permission() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    invite_ready(&state).await;
    let reader = seed_user(&state, "leitor", READER_ROLE_ID).await;
    let reader_session = open_session(&state, reader).await;

    let (status, body) = issue_invite(
        &state,
        &reader_session,
        json!({ "email": "convidada@example.pt" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(state.auth_tokens.read().await.is_empty());

    // And unauthenticated is a 401, not a silent accept.
    let (status, body) = send(
        state.clone(),
        post(
            "/v1/auth/invites",
            json!({ "email": "convidada@example.pt" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// An inviter can never hand out authority it does not itself hold: a named role runs the same
/// `role.assign` gate and subset invariant `POST /v1/users/{id}/roles` runs.
#[tokio::test]
async fn an_invitation_cannot_carry_a_role_the_inviter_could_not_assign() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let secretary_session = invite_ready(&state).await;

    let (status, body) = issue_invite(
        &state,
        &secretary_session,
        json!({
            "email": "convidada@example.pt",
            "role": { "role_id": OWNER_ROLE_ID.0, "scope": { "kind": "global" } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(state.auth_tokens.read().await.is_empty());
}

/// An invitation may carry its scope, and it is the only way a new account lands inside a tenant —
/// self-signup is pinned to `Global` (§2.6).
#[tokio::test]
async fn an_invitation_may_carry_a_scope_that_self_signup_could_never_reach() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    invite_ready(&state).await;
    // The Owner can assign anything, so the scope rather than the authority is what is under test.
    let owner = state
        .users
        .read()
        .await
        .values()
        .find(|u| u.username == "amelia.marques")
        .map(|u| u.id)
        .expect("owner seeded");
    let owner_session = open_session(&state, owner).await;

    let tenant = Uuid::new_v4();
    let (status, issued) = issue_invite(
        &state,
        &owner_session,
        json!({
            "email": "convidada@example.pt",
            "role": { "role_id": READER_ROLE_ID.0, "scope": { "kind": "tenant", "id": tenant } }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    assert_eq!(
        issued["scope"],
        json!({ "kind": "tenant", "id": tenant.to_string() })
    );

    let (status, created) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({
                "token": token_from(issued["accept_url"].as_str().expect("url")),
                "password": APPLICANT_PASSWORD
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        created["role_assignments"],
        json!([{
            "role_id": READER_ROLE_ID.0.to_string(),
            "scope": { "kind": "tenant", "id": tenant.to_string() }
        }])
    );
}

/// Nothing this module writes to the ledger carries token material, and the `justification` — which
/// t88 records verbatim — is a fixed string.
#[tokio::test]
async fn no_ledger_event_from_this_module_carries_token_material() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let session = invite_ready(&state).await;

    let (_, issued) =
        issue_invite(&state, &session, json!({ "email": "convidada@example.pt" })).await;
    let accept_url = issued["accept_url"].as_str().expect("url").to_owned();
    let invite_token = token_from(&accept_url);
    let (status, created) = send(
        state.clone(),
        post(
            "/v1/auth/invite/accept",
            json!({ "token": invite_token.clone(), "password": APPLICANT_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let ledger = state.ledger.read().await;
    let rendered = serde_json::to_string(&ledger.events()).expect("ledger serialises");
    assert!(
        !rendered.contains(&invite_token),
        "a token reached the ledger"
    );
    assert!(
        !rendered.contains(&accept_url),
        "an invite url reached the ledger"
    );
    let kinds: Vec<&str> = ledger.events().iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"user.invite.created"), "{kinds:?}");
    assert!(kinds.contains(&"user.created"), "{kinds:?}");
}
