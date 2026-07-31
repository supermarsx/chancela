//! `GET /v1/privacy/users/{id}/data-export` over the wire — the self-service subject-access export
//! (RGPD art. 15 / 20).
//!
//! Two properties matter and are proven here:
//!
//! 1. **The gate is self OR `privacy.manage`, and the self arm is genuinely self-only.** A user with
//!    no privacy authority may export their OWN record, and the same user passing ANOTHER user's id
//!    is refused with the generic 403 — the self arm compares the acting principal id to the target,
//!    so it cannot be turned into a read of somebody else. `user.manage` alone is not a key either:
//!    the non-self arm requires `privacy.manage` specifically. A privacy officer may export anyone's.
//!
//! 2. **The payload is the subject's own personal data only — no instance structure, no secrets.**
//!    Role assignments and ledger event references (which the administrative `…/export` carries) are
//!    absent; credential material (password hash, recovery verifier, TOTP secret and backup-code
//!    verifiers) never appears, only metadata that a factor exists.

use crate::common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{
    OWNER_ROLE_ID, Permission, READER_ROLE_ID, Role, RoleAssignment, RoleCatalog, RoleId, Scope,
};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-pde-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn seeded_state() -> AppState {
    AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        ..AppState::default()
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

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn base_user(id: UserId, username: &str, role: RoleAssignment) -> User {
    User {
        id,
        username: username.to_owned(),
        display_name: format!("{username} Display"),
        email: None,
        created_at: now(),
        active: true,
        password_hash: Some(password_hash()),
        attestation_key: None,
        retired_attestation_keys: Vec::new(),
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![role],
        language: Default::default(),
        totp: None,
        two_factor_required: false,
        force_password_change: false,
        passkeys: Vec::new(),
    }
}

async fn insert(state: &AppState, user: User) {
    state.users.write().await.insert(user.id, user);
}

async fn open_session(state: &AppState, id: UserId) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/session")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "user_id": id.0, "password": TEST_PASSWORD }).to_string(),
        ))
        .expect("request builds");
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

fn export_req(target: UserId, token: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/v1/privacy/users/{target}/data-export"))
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

/// A role holding exactly `perms` at Global, plus a user assigned it and an open session.
async fn user_with_permissions(
    state: &AppState,
    id: u128,
    username: &str,
    perms: &[Permission],
) -> (UserId, String) {
    let role_id = RoleId(Uuid::from_u128(id ^ 0x7065726d));
    state.roles.write().await.insert(Role {
        id: role_id,
        name: format!("{username} Role"),
        permission_set: perms.iter().copied().collect(),
        protected: false,
    });
    let uid = UserId(Uuid::from_u128(id));
    insert(
        state,
        base_user(uid, username, RoleAssignment::new(role_id, Scope::Global)),
    )
    .await;
    let token = open_session(state, uid).await;
    (uid, token)
}

#[tokio::test]
async fn self_can_export_own_personal_data_with_no_admin_permission() {
    let _tmp = TempDir::new();
    let state = seeded_state();
    let reader = UserId(Uuid::from_u128(0x5e1f));
    insert(
        &state,
        base_user(
            reader,
            "reader",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let token = open_session(&state, reader).await;

    let (status, body) = send(state, export_req(reader, &token)).await;

    assert_eq!(status, StatusCode::OK, "self export succeeds: {body}");
    assert_eq!(body["scope"], serde_json::json!(format!("user:{reader}")));
    assert_eq!(body["format_version"], serde_json::json!(1));
    assert_eq!(body["subject"]["id"], serde_json::json!(reader.to_string()));
    assert_eq!(body["subject"]["username"], serde_json::json!("reader"));
    // Personal data present.
    assert!(body["subject"]["created_at"].as_str().is_some());
    assert_eq!(
        body["subject"]["credentials"]["password_set"],
        serde_json::json!(true)
    );
    // The export states its own scope and names withheld secret categories.
    assert!(body["notes"].as_array().is_some_and(|n| !n.is_empty()));
    assert!(
        body["exclusions"]
            .as_array()
            .expect("exclusions")
            .iter()
            .any(|e| e == "password_hash")
    );
    // Instance structure the ADMIN export carries must be absent here.
    assert!(body.get("user").is_none(), "no admin `user` wrapper");
    assert!(body.get("ledger_event_refs").is_none(), "no ledger refs");
    assert!(
        body["subject"].get("role_assignments").is_none(),
        "no role assignments on the subject"
    );
}

#[tokio::test]
async fn self_arm_refuses_another_users_id() {
    let _tmp = TempDir::new();
    let state = seeded_state();
    let reader = UserId(Uuid::from_u128(0x5e1f));
    let other = UserId(Uuid::from_u128(0x2222));
    insert(
        &state,
        base_user(
            reader,
            "reader",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    insert(
        &state,
        base_user(
            other,
            "other",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let token = open_session(&state, reader).await;

    // The reader authenticates as themselves but points at `other`'s id.
    let (status, body) = send(state, export_req(other, &token)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a user cannot export another subject's record through the self arm: {body}"
    );
}

#[tokio::test]
async fn user_manage_alone_cannot_export_another_subject() {
    // The non-self arm requires `privacy.manage` specifically, not a neighbouring admin verb.
    let _tmp = TempDir::new();
    let state = seeded_state();
    let target = UserId(Uuid::from_u128(0x2222));
    insert(
        &state,
        base_user(
            target,
            "target",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let (_caller, token) =
        user_with_permissions(&state, 0xa011, "user-manager", &[Permission::UserManage]).await;

    let (status, body) = send(state, export_req(target, &token)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "user.manage does not authorize a cross-subject personal-data export: {body}"
    );
}

#[tokio::test]
async fn privacy_manage_holder_may_export_any_subject() {
    let _tmp = TempDir::new();
    let state = seeded_state();
    let owner = UserId(Uuid::from_u128(1));
    let target = UserId(Uuid::from_u128(0x2222));
    insert(
        &state,
        base_user(
            owner,
            "owner",
            RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    insert(
        &state,
        base_user(
            target,
            "target",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let token = open_session(&state, owner).await;

    let (status, body) = send(state, export_req(target, &token)).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "privacy.manage exports anyone: {body}"
    );
    assert_eq!(body["subject"]["username"], serde_json::json!("target"));
}

#[tokio::test]
async fn export_excludes_secret_material_and_reports_credential_metadata() {
    let _tmp = TempDir::new();
    let state = seeded_state();
    let reader = UserId(Uuid::from_u128(0x5e1f));
    let user = base_user(
        reader,
        "reader",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    );
    // The real password verifier that lets sign-in work, captured so we can prove it never reaches
    // the wire.
    let real_password_hash = user.password_hash.clone().expect("seeded password");
    insert(&state, user).await;
    // Open the session BEFORE enabling the second factor: a confirmed TOTP turns sign-in into a
    // two-step challenge, and this test is about the export, not the sign-in. The recovery and
    // backup-code verifiers carry a marker so we can prove they are withheld.
    let token = open_session(&state, reader).await;
    {
        let mut users = state.users.write().await;
        let seeded = users.get_mut(&reader).expect("seeded reader");
        seeded.recovery_hash = Some("recovery-verifier-DO-NOT-LEAK".to_owned());
        seeded.totp = Some(chancela_api::TotpEnrolment {
            confirmed: true,
            confirmed_at: Some(now()),
            last_accepted_step: Some(42),
            backup_code_hashes: vec!["backup-code-verifier-DO-NOT-LEAK".to_owned()],
        });
    }

    let (status, body) = send(state.clone(), export_req(reader, &token)).await;

    assert_eq!(status, StatusCode::OK, "export succeeds: {body}");
    // Metadata is disclosed: that the credentials exist.
    assert_eq!(
        body["subject"]["credentials"]["password_set"],
        serde_json::json!(true)
    );
    assert_eq!(
        body["subject"]["credentials"]["recovery_phrase_set"],
        serde_json::json!(true)
    );
    assert_eq!(
        body["subject"]["credentials"]["two_factor"]["method"],
        serde_json::json!("totp")
    );
    assert_eq!(
        body["subject"]["credentials"]["two_factor"]["backup_codes_remaining"],
        serde_json::json!(1)
    );
    // But no verifier or secret string is anywhere in the serialized bytes.
    let raw = serde_json::to_string(&body).expect("json string");
    assert!(
        !raw.contains("DO-NOT-LEAK"),
        "secret material leaked: {raw}"
    );
    assert!(
        !raw.contains(&real_password_hash),
        "password verifier leaked: {raw}"
    );
    assert!(
        !raw.contains("last_accepted_step"),
        "replay-guard internal leaked"
    );
}

#[tokio::test]
async fn unknown_target_is_404_for_a_privileged_caller() {
    let _tmp = TempDir::new();
    let state = seeded_state();
    let owner = UserId(Uuid::from_u128(1));
    insert(
        &state,
        base_user(
            owner,
            "owner",
            RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let token = open_session(&state, owner).await;
    let missing = UserId(Uuid::from_u128(0x999));

    let (status, _body) = send(state, export_req(missing, &token)).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "honest 404 for a privileged caller"
    );
}

#[tokio::test]
async fn unknown_target_is_403_not_404_for_an_ordinary_user() {
    // A non-self, non-privileged caller must not learn whether an id exists: they are refused before
    // the target is looked up, so a missing id and a present id both 403.
    let _tmp = TempDir::new();
    let state = seeded_state();
    let reader = UserId(Uuid::from_u128(0x5e1f));
    insert(
        &state,
        base_user(
            reader,
            "reader",
            RoleAssignment::new(READER_ROLE_ID, Scope::Global),
        ),
    )
    .await;
    let token = open_session(&state, reader).await;
    let missing = UserId(Uuid::from_u128(0x999));

    let (status, _body) = send(state, export_req(missing, &token)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an ordinary user gets 403 (no enumeration), not 404, for an unknown id"
    );
}
