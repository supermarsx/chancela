//! wp19-fix — RBAC mutations must leave the ledger `verify()`-healthy.
//!
//! Regression coverage for a latent, correctness-critical ledger bug: `POST /v1/users/{id}/roles`
//! (`role.assigned`) and `POST /v1/delegations` (`delegation.granted`) — plus the role-catalog and
//! revoke/unassign siblings — used to append their audit events on a chain keyed by a **bare UUID**
//! (the user id / delegation id). The ledger classifies a bare-UUID scope as a `company:{uuid}`
//! book-action chain whose genesis event kind is required to be `entity.created` (WFL-11). A
//! `role.assigned` / `delegation.granted` event opening such a chain therefore failed classification,
//! so the global `Ledger::verify()` broke after *any* RBAC mutation (the instance would go into a
//! degraded / "broken ledger" state after merely assigning a role).
//!
//! These tests drive the **real** `chancela_api::router` over in-process requests and then assert the
//! ledger is verify()-healthy — both through `GET /v1/ledger/verify` + `GET /v1/ledger/integrity`
//! and directly against the in-memory `Ledger`. They also pin the fix's shape: the events land on the
//! shared `application` audit chain (keyword scopes `user:{uuid}` / `role:{uuid}` /
//! `delegation:{uuid}`), and NO spurious `company:` chain is minted by an RBAC change.

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_authz::LEITOR_ROLE_ID;
use chancela_ledger::ChainId;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const TEST_PASSWORD: &str = "Teste-Forte7!X";

/// A temp data dir that seeds the role catalog (so the bootstrap Owner resolves real authority) and
/// is cleaned up on drop. Mirrors the `seed_dataset` integration harness.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-rbac-ledger-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fresh_state(tmp: &TempDir) -> AppState {
    AppState::with_data_dir(tmp.0.clone())
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
    };
    (status, value)
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

/// Bootstrap the first (auth-exempt Owner) user and open a session; returns `(id, token)`.
async fn bootstrap_owner(state: &AppState) -> (String, String) {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amélia Marques",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap owner: {user}");
    let id = user["id"].as_str().expect("owner id").to_owned();
    let token = open_session(state, &id).await;
    (id, token)
}

async fn create_user(state: &AppState, owner: &str, username: &str, display: &str) -> String {
    let (status, user) = send(
        state,
        json_req(
            "POST",
            "/v1/users",
            owner,
            json!({ "username": username, "display_name": display, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create user {username}: {user}"
    );
    user["id"].as_str().expect("user id").to_owned()
}

async fn open_session(state: &AppState, user_id: &str) -> String {
    let (status, s) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": user_id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {s}");
    s["token"].as_str().expect("token").to_owned()
}

/// Assert the whole ledger verifies, via BOTH HTTP surfaces and the in-memory `Ledger`.
async fn assert_ledger_healthy(state: &AppState, owner: &str, ctx: &str) {
    let (status, verify) = send(state, get_req("/v1/ledger/verify", owner)).await;
    assert_eq!(status, StatusCode::OK, "[{ctx}] verify status: {verify}");
    assert_eq!(
        verify["valid"], true,
        "[{ctx}] GET /v1/ledger/verify must be valid after RBAC mutation: {verify}"
    );

    let (status, integrity) = send(state, get_req("/v1/ledger/integrity", owner)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "[{ctx}] integrity status: {integrity}"
    );
    assert_eq!(
        integrity["healthy"], true,
        "[{ctx}] chain must be healthy after RBAC mutation: {integrity}"
    );
    assert_eq!(
        integrity["degraded"], false,
        "[{ctx}] chain must not be degraded after RBAC mutation: {integrity}"
    );

    // Ground truth: the authoritative in-memory ledger re-verifies cleanly.
    let ledger = state.ledger.read().await;
    assert!(
        ledger.verify().is_ok(),
        "[{ctx}] in-memory Ledger::verify() must hold: {:?}",
        ledger.verify()
    );
}

/// The headline regression: create a user, assign a role, grant a delegation — all through the real
/// API — and the ledger stays verify()-healthy at every step. Before the fix, the `role.assigned`
/// (and `delegation.granted`) events opened a bogus `company:{uuid}` chain and `verify()` failed.
#[tokio::test]
async fn rbac_mutations_via_api_keep_the_ledger_verify_healthy() {
    let tmp = TempDir::new();
    let state = fresh_state(&tmp);
    let (_owner_id, owner) = bootstrap_owner(&state).await;

    // Baseline: a fresh instance with only user/session events verifies.
    assert_ledger_healthy(&state, &owner, "baseline").await;

    let member_id = create_user(&state, &owner, "bento.salgueiro", "Bento Salgueiro").await;
    assert_ledger_healthy(&state, &owner, "after user.created").await;

    // --- role.assigned via POST /v1/users/{id}/roles -----------------------------------------
    let (status, assignments) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/users/{member_id}/roles"),
            &owner,
            json!({ "role_id": LEITOR_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "assign role: {assignments}");
    assert_ledger_healthy(&state, &owner, "after role.assigned").await;

    // --- delegation.granted via POST /v1/delegations -----------------------------------------
    let (status, delegation) = send(
        &state,
        json_req(
            "POST",
            "/v1/delegations",
            &owner,
            json!({
                "to": member_id,
                "permission": "act.advance",
                "scope": { "kind": "global" },
                "legal_basis": "Ata do conselho R-19 (evidência sintética de teste)",
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "grant delegation: {delegation}"
    );
    let delegation_id = delegation["id"].as_str().expect("delegation id").to_owned();
    assert_ledger_healthy(&state, &owner, "after delegation.granted").await;

    // --- delegation.revoked via DELETE /v1/delegations/{id} ----------------------------------
    let (status, _) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/delegations/{delegation_id}"),
            &owner,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke delegation");
    assert_ledger_healthy(&state, &owner, "after delegation.revoked").await;

    // --- role.unassigned via DELETE /v1/users/{id}/roles -------------------------------------
    let (status, _) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/users/{member_id}/roles"),
            &owner,
            json!({ "role_id": LEITOR_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unassign role");
    assert_ledger_healthy(&state, &owner, "after role.unassigned").await;

    // The RBAC events land on the shared `application` audit chain and mint NO `company:` chain.
    // (No entity/book was ever created, so the only legitimate non-global chain is `application`.)
    let ledger = state.ledger.read().await;
    for status in ledger.chains() {
        assert!(
            matches!(status.chain, ChainId::Application),
            "RBAC mutations must not mint a book-action chain; found {}",
            status.chain
        );
        assert!(
            status.verified,
            "the application chain verifies: {status:?}"
        );
    }
    assert!(
        ledger.verify_chain(&ChainId::Application).is_ok(),
        "the application audit chain re-verifies in isolation"
    );

    // Pin the audit scopes: role.* → user:/role:, delegation.* → delegation:, never a bare UUID.
    for event in ledger.events() {
        match event.kind.as_str() {
            "role.assigned" | "role.unassigned" => assert_eq!(
                event.scope,
                format!("user:{member_id}"),
                "role assignment event is user-scoped (application chain)"
            ),
            "delegation.granted" | "delegation.revoked" => assert_eq!(
                event.scope,
                format!("delegation:{delegation_id}"),
                "delegation event is delegation-scoped (application chain)"
            ),
            _ => {}
        }
    }
}

/// The role-catalog mutations (`role.created` / `role.updated` / `role.deleted`) are the other
/// bare-UUID-scoped RBAC events; they too must leave the ledger verify()-healthy.
#[tokio::test]
async fn role_catalog_mutations_via_api_keep_the_ledger_verify_healthy() {
    let tmp = TempDir::new();
    let state = fresh_state(&tmp);
    let (_owner_id, owner) = bootstrap_owner(&state).await;

    // Create a custom role (subset of the Owner's authority) → role.created.
    let (status, role) = send(
        &state,
        json_req(
            "POST",
            "/v1/roles",
            &owner,
            json!({ "name": "Auditor Sénior", "permissions": ["ledger.read"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create role: {role}");
    let role_id = role["id"].as_str().expect("role id").to_owned();
    assert_ledger_healthy(&state, &owner, "after role.created").await;

    // Update it → role.updated.
    let (status, _) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/roles/{role_id}"),
            &owner,
            json!({ "name": "Auditor Principal" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch role");
    assert_ledger_healthy(&state, &owner, "after role.updated").await;

    // Delete it → role.deleted.
    let (status, _) = send(
        &state,
        json_req("DELETE", &format!("/v1/roles/{role_id}"), &owner, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete role");
    assert_ledger_healthy(&state, &owner, "after role.deleted").await;

    // No book-action chain was minted by pure role-catalog churn.
    let ledger = state.ledger.read().await;
    for status in ledger.chains() {
        assert!(
            matches!(status.chain, ChainId::Application),
            "role-catalog mutations must not mint a book-action chain; found {}",
            status.chain
        );
    }
}
