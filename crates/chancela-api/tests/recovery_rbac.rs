//! t27 — granular-verb enforcement for ledger recovery.
//!
//! Re-anchor and whole-store restore used to share the broad `ledger.recover` verb. t27 split them
//! onto the specific `ledger.reanchor` / `ledger.restore` verbs (grandfathered to every prior
//! `ledger.recover` holder, so no admin is stripped). These tests prove the split at the endpoint:
//! each op now requires its OWN verb, the old broad `ledger.recover` no longer reaches either, and
//! neither granular verb leaks into the other.
//!
//! The RBAC gate (`require_permission`) runs BEFORE step-up in every recovery handler, so a
//! wrong-verb caller is `403`'d at the gate. Each request below supplies a VALID step-up proof (the
//! acting user's password), so the only thing that can still produce a `403` is the RBAC gate — which
//! makes both the deny (`403`) and the pass (`422` in-memory "needs durable store") assertions
//! unambiguous.

use crate::common;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

fn seeded_state() -> AppState {
    AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        ..AppState::default()
    }
}

async fn send_status(state: AppState, req: Request<Body>) -> StatusCode {
    router(state)
        .oneshot(req)
        .await
        .expect("router responds")
        .status()
}

async fn open_session(state: &AppState, uid: UserId) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/session")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
        ))
        .expect("request builds");
    let response = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK, "session opens");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value: Value = serde_json::from_slice(&bytes).expect("body is JSON");
    value["token"].as_str().expect("token").to_owned()
}

/// Insert a user whose single role holds exactly `perms` at Global, seeded with the shared test
/// password so a step-up proof of `TEST_PASSWORD` succeeds. Returns an open session token.
async fn user_with_permissions(
    state: &AppState,
    id: u128,
    username: &str,
    perms: &[Permission],
) -> String {
    let role_id = RoleId(Uuid::from_u128(id ^ 0x726f6c65));
    state.roles.write().await.insert(Role {
        id: role_id,
        name: format!("{username} Role"),
        permission_set: perms.iter().copied().collect(),
        protected: false,
    });
    let uid = UserId(Uuid::from_u128(id));
    let user = User {
        id: uid,
        username: username.to_owned(),
        display_name: format!("{username} Display"),
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
        role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
        language: Default::default(),
    };
    state.users.write().await.insert(uid, user);
    open_session(state, uid).await
}

fn reanchor_req(token: &str) -> Request<Body> {
    with_session(
        "/v1/ledger/recovery/reanchor",
        json!({ "reason": "t27 rbac test", "reauth": { "password": TEST_PASSWORD } }),
        token,
    )
}

fn restore_req(token: &str) -> Request<Body> {
    with_session(
        "/v1/ledger/recovery/restore",
        json!({ "archive": "does-not-exist.tar", "reauth": { "password": TEST_PASSWORD } }),
        token,
    )
}

fn restore_preflight_req(token: &str) -> Request<Body> {
    // Preflight has no step-up by design, so its body carries no reauth.
    with_session(
        "/v1/ledger/recovery/restore/preflight",
        json!({ "archive": "does-not-exist.tar" }),
        token,
    )
}

fn with_session(uri: &str, body: Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

#[tokio::test]
async fn reanchor_requires_ledger_reanchor_not_the_broad_recover_or_sibling() {
    let state = seeded_state();

    // The OLD broad verb no longer reaches re-anchor — the split stripped it.
    let recover_only =
        user_with_permissions(&state, 0x2731, "recover-only", &[Permission::LedgerRecover]).await;
    // The sibling `ledger.restore` must not leak into re-anchor.
    let restore_only =
        user_with_permissions(&state, 0x2732, "restore-only", &[Permission::LedgerRestore]).await;
    // Exactly `ledger.reanchor` authorizes it.
    let reanchor_only = user_with_permissions(
        &state,
        0x2733,
        "reanchor-only",
        &[Permission::LedgerReanchor],
    )
    .await;

    assert_eq!(
        send_status(state.clone(), reanchor_req(&recover_only)).await,
        StatusCode::FORBIDDEN,
        "ledger.recover alone must be denied re-anchor"
    );
    assert_eq!(
        send_status(state.clone(), reanchor_req(&restore_only)).await,
        StatusCode::FORBIDDEN,
        "ledger.restore alone must be denied re-anchor"
    );
    // RBAC + step-up both pass; the in-memory store then refuses with 422 (needs durable persistence).
    assert_eq!(
        send_status(state.clone(), reanchor_req(&reanchor_only)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "ledger.reanchor clears the gate (422 only because the test store is in-memory)"
    );
}

#[tokio::test]
async fn restore_requires_ledger_restore_not_the_broad_recover_or_sibling() {
    let state = seeded_state();

    let recover_only =
        user_with_permissions(&state, 0x2741, "recover-only", &[Permission::LedgerRecover]).await;
    let reanchor_only = user_with_permissions(
        &state,
        0x2742,
        "reanchor-only",
        &[Permission::LedgerReanchor],
    )
    .await;
    let restore_only =
        user_with_permissions(&state, 0x2743, "restore-only", &[Permission::LedgerRestore]).await;

    for (label, token) in [
        ("ledger.recover alone", &recover_only),
        ("ledger.reanchor alone", &reanchor_only),
    ] {
        assert_eq!(
            send_status(state.clone(), restore_req(token)).await,
            StatusCode::FORBIDDEN,
            "{label} must be denied restore"
        );
        assert_eq!(
            send_status(state.clone(), restore_preflight_req(token)).await,
            StatusCode::FORBIDDEN,
            "{label} must be denied restore preflight"
        );
    }

    // Exactly `ledger.restore` clears both the execution restore and its read-only preflight.
    assert_eq!(
        send_status(state.clone(), restore_req(&restore_only)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "ledger.restore clears the restore gate (422 only because the test store is in-memory)"
    );
    assert_eq!(
        send_status(state.clone(), restore_preflight_req(&restore_only)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "ledger.restore clears the preflight gate (422 only because the test store is in-memory)"
    );
}
