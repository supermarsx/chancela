//! `GET /v1/trust/anchor-suggestions` at the router boundary (t118).
//!
//! The unit tests in `chancela-api/src/trust_anchor_suggestions.rs` pin the proposal logic — which
//! candidates carry LOTL provenance, which carry none, what an unauthenticated LOTL yields. These
//! pin the two properties that only the whole stack can demonstrate:
//!
//! - the endpoint is gated on `signing.configure`, the same verb that writes the anchors, so a
//!   caller who could not save an anchor cannot be handed one either; and
//! - it **writes nothing**. An "assistant" that quietly persisted its own suggestion would be the
//!   worst possible version of this feature, so the settings document is captured byte-for-byte
//!   before the call and compared after it.

use crate::common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::trust_anchor_suggestion_codes as codes;
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const SUGGEST: &str = "/v1/trust/anchor-suggestions";

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("chancela-api-anchor-suggest-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
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

async fn seed_session(state: &AppState, username: &str, role_id: RoleId) -> String {
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
            role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
            language: Default::default(),
        },
    );
    let (status, body) = send(
        state.clone(),
        json_request(
            "POST",
            "/v1/session",
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

/// A role holding the settings verbs but deliberately NOT `signing.configure` — the same shape
/// `signing_configure_gate.rs` uses to pin the write side of this boundary.
async fn seed_settings_only_role(state: &AppState) -> RoleId {
    let id = RoleId(Uuid::new_v4());
    let permission_set: BTreeSet<Permission> = [
        Permission::SettingsRead,
        Permission::SettingsManage,
        // Explicitly present: reading the trust CATALOG is a different verb, and holding it must
        // not be mistaken for permission to be handed a trust anchor.
        Permission::CaeRead,
    ]
    .into_iter()
    .collect();
    let mut roles = state.roles.write().await;
    *roles = RoleCatalog::seeded_defaults();
    roles.insert(Role {
        id,
        name: "Settings Only".to_owned(),
        permission_set,
        protected: false,
    });
    id
}

#[tokio::test]
async fn anchor_suggestions_require_the_same_verb_that_writes_the_anchors() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let settings_only_id = seed_settings_only_role(&state).await;
    let settings_only = seed_session(&state, "amelia.settings", settings_only_id).await;

    let (status, body) = send(state.clone(), with_session(get(SUGGEST), &settings_only)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a caller who could not SAVE an anchor must not be handed one: {body}"
    );
}

#[tokio::test]
async fn an_unauthenticated_caller_is_refused() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (status, _) = send(state.clone(), get(SUGGEST)).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "an anonymous caller must not reach the proposal flow, got {status}"
    );
}

#[tokio::test]
async fn a_proposal_run_mutates_no_settings_and_fails_closed_without_a_lotl_anchor() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
    }
    let owner = seed_session(&state, "amelia.owner", OWNER_ROLE_ID).await;

    // The settings document as bytes, not as a `Value`: a comparison of parsed JSON would forgive a
    // reordering or a re-serialisation, and "the assistant rewrote the document but the fields came
    // out equal" is exactly the outcome this test must not forgive.
    let before = serde_json::to_vec(&*state.settings.read().await).expect("settings serialise");

    let (status, body) = send(state.clone(), with_session(get(SUGGEST), &owner)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let after = serde_json::to_vec(&*state.settings.read().await).expect("settings serialise");
    assert_eq!(
        before, after,
        "the suggestion endpoint proposes; it must never write an anchor itself"
    );

    // A fresh install configures no anchor, so the root of trust cannot authenticate and NOTHING is
    // proposed. This is the bootstrap case, and it is the honest one: the first anchor is the
    // Official Journal value, which no assistant can supply. It also means this test needs no
    // network — the flow refuses before it would fetch.
    assert_eq!(body["lotl_authenticated"], json!(false));
    assert_eq!(
        body["lotl_code"],
        json!(codes::LOTL_ANCHOR_NOT_CONFIGURED),
        "expected the fail-closed bootstrap code: {body}"
    );
    let sources = body["sources"].as_array().expect("sources array");
    assert!(
        !sources.is_empty(),
        "the configured sources must still be listed, so the operator sees they were considered"
    );
    for source in sources {
        assert_eq!(
            source["proposals"],
            json!([]),
            "an unauthenticated LOTL proposes nothing at all: {source}"
        );
    }
}

#[tokio::test]
async fn every_code_on_the_wire_belongs_to_the_closed_vocabulary() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
    }
    let owner = seed_session(&state, "amelia.owner", OWNER_ROLE_ID).await;

    let (status, body) = send(state.clone(), with_session(get(SUGGEST), &owner)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A code outside the closed list has no translation in any locale, and the settings screen would
    // render the raw identifier. The web-side completeness test guards the other direction (every
    // listed code is mapped); this guards that the wire never carries an unlisted one.
    let mut seen = vec![body["lotl_code"].as_str().expect("lotl_code").to_owned()];
    for source in body["sources"].as_array().expect("sources array") {
        seen.push(source["code"].as_str().expect("source code").to_owned());
    }
    for code in seen {
        assert!(
            codes::ALL_TRUST_ANCHOR_SUGGESTION_CODES.contains(&code.as_str()),
            "{code} is on the wire but not in ALL_TRUST_ANCHOR_SUGGESTION_CODES"
        );
    }
}
