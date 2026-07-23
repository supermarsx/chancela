//! The t50 `signing.configure` slice-guard on `PUT /v1/settings`.
//!
//! Relocating the signature-policy surface behind a dedicated verb only becomes a real *server* gate
//! if changing the signing slice of the settings document requires `signing.configure`, not merely
//! the document-wide `settings.manage`. These tests pin exactly that boundary:
//!
//! - a role holding `settings.manage` but NOT `signing.configure` (a future custom role — the
//!   grandfather migration grants the verb to every EXISTING `settings.manage` holder, so this shape
//!   only arises when an operator deliberately builds it) may still save an unrelated document, but
//!   is refused (403) the moment the signing slice changes;
//! - a holder of both (Owner) may change the signing slice.

use crate::common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{
    OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-api-signing-gate-{}", Uuid::new_v4()));
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

/// Seed a user assigned `role_id` and open a session, returning the session token.
async fn seed_session(state: &AppState, username: &str, role_id: RoleId) -> String {
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

#[tokio::test]
async fn put_settings_gates_the_signing_slice_on_signing_configure() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());

    // A custom role holding settings.manage + settings.read but deliberately NOT signing.configure
    // (a future operator-authored role: grandfathering would have granted the verb to every existing
    // settings.manage holder, so only a deliberate build produces this shape).
    let settings_only_id = RoleId(Uuid::new_v4());
    let permission_set: BTreeSet<Permission> =
        [Permission::SettingsRead, Permission::SettingsManage]
            .into_iter()
            .collect();
    {
        let mut roles = state.roles.write().await;
        *roles = RoleCatalog::seeded_defaults();
        roles.insert(Role {
            id: settings_only_id,
            name: "Settings Only".to_owned(),
            permission_set,
            protected: false,
        });
    }

    let settings_only = seed_session(&state, "amelia.settings", settings_only_id).await;
    let owner = seed_session(&state, "amelia.owner", OWNER_ROLE_ID).await;

    // The current document, read back as the settings.manage holder.
    let (status, doc) = send(
        state.clone(),
        with_session(get("/v1/settings"), &settings_only),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{doc}");

    // Re-PUT the document UNCHANGED: the signing slice did not change, so settings.manage alone is
    // enough — the server-owned `providers` metadata must not spuriously trip the gate.
    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PUT", "/v1/settings", doc.clone()),
            &settings_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unchanged signing slice must not require signing.configure: {body}"
    );

    // Now flip a signing-policy field. The same settings.manage-only caller is refused.
    let mut changed = doc.clone();
    let prior = changed["signing"]["require_qualified_for_seal"]
        .as_bool()
        .unwrap_or(false);
    changed["signing"]["require_qualified_for_seal"] = json!(!prior);

    let (status, body) = send(
        state.clone(),
        with_session(
            json_request("PUT", "/v1/settings", changed.clone()),
            &settings_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "changing the signing slice without signing.configure must be refused: {body}"
    );

    // A holder of signing.configure (Owner, via Permission::ALL) may make the same change.
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", changed), &owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner may change signing policy: {body}");
    assert_eq!(body["signing"]["require_qualified_for_seal"], json!(!prior));
}
