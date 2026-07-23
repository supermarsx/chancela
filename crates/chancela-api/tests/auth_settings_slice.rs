//! t95 P0-1 / P0-3 over the wire: the `auth` slice and `platform.public_base_url` on
//! `PUT /v1/settings`.
//!
//! The unit tests in `settings.rs` cover the validation rules in isolation. What can only be
//! asserted here is the part that involves the **handler**: `PUT` is a whole-document replace, so
//! the interesting failure is not a bad value — it is a client that says nothing at all about a
//! section and thereby erases it.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, PLATFORM_ADMIN_ROLE_ID, RoleAssignment, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-api-authslice-{}", Uuid::new_v4()));
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

async fn seed_owner_session(state: &AppState, username: &str) -> String {
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
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
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

async fn read_settings(state: &AppState, token: &str) -> Value {
    let (status, document) = send(state.clone(), with_session(get("/v1/settings"), token)).await;
    assert_eq!(status, StatusCode::OK, "settings readable: {document}");
    document
}

/// A document with the relay and the link origin configured, so the auth toggles under test are
/// the only thing in question.
fn ready_for_links(document: &mut Value) {
    document["email"] = json!({
        "enabled": true,
        "host": "smtp.example.pt",
        "port": 587,
        "encryption": "starttls",
        "username": null,
        "from_address": "sistema@example.pt",
        "from_name": null,
        "helo_name": null,
        "allow_insecure": false
    });
    document["platform"]["public_base_url"] = json!("https://livros.example.pt");
}

/// Recursively assert `actual` and `expected` have the same object key-sets, the same rule
/// `chancela-server`'s `assert_shape` applies to `contracts/*.json`.
fn assert_same_keys(path: &str, actual: &Value, expected: &Value) {
    if let (Value::Object(a), Value::Object(e)) = (actual, expected) {
        let ak: std::collections::BTreeSet<&String> = a.keys().collect();
        let ek: std::collections::BTreeSet<&String> = e.keys().collect();
        assert_eq!(
            ak, ek,
            "{path}: key-set mismatch\n  live:     {ak:?}\n  contract: {ek:?}"
        );
        for (k, ev) in e {
            assert_same_keys(&format!("{path}.{k}"), &a[k], ev);
        }
    }
}

/// The committed `contracts/settings.json` must still describe the live `GET /v1/settings` after
/// t95 adds a slice to the document.
///
/// `chancela-server`'s `e2e_contracts` journey is the canonical guard, but it asserts the `user`
/// contract first and so cannot currently reach `settings` — an unrelated in-flight change added
/// `attestation_key_fingerprint` to the user response without updating `contracts/user.json`. This
/// test covers the settings half directly so the P0 change is verified rather than assumed.
#[tokio::test]
async fn the_settings_contract_fixture_still_describes_the_live_document() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let token = seed_owner_session(&state, "amelia.marques").await;
    let live = read_settings(&state, &token).await;

    let fixture: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("contracts")
                .join("settings.json"),
        )
        .expect("contracts/settings.json is readable"),
    )
    .expect("contracts/settings.json is JSON");

    assert_same_keys("settings", &live, &fixture);
    // Specifically: the new `platform.public_base_url` is described, and the default `auth` slice
    // is absent from both sides.
    assert!(fixture["platform"].get("public_base_url").is_some());
    assert!(live["platform"].get("public_base_url").is_some());
    assert!(fixture.get("auth").is_none());
    assert!(live.get("auth").is_none());
}

#[tokio::test]
async fn the_auth_slice_is_additive_ceilinged_and_survives_a_client_that_has_never_heard_of_it() {
    let temp = TempDir::new();
    let state = AppState::with_data_dir(&temp.0);
    let token = seed_owner_session(&state, "amelia.marques").await;

    // --- Additive on the wire ------------------------------------------------------------
    // A fresh instance's document carries no `auth` key at all, so a pre-t95 client and the
    // committed `contracts/settings.json` see exactly what they saw before.
    let fresh = read_settings(&state, &token).await;
    assert!(
        fresh.get("auth").is_none(),
        "a default auth slice must not appear on the wire: {fresh}"
    );
    assert_eq!(fresh["platform"]["public_base_url"], Value::Null);

    // --- The ceiling is enforced by the handler, not only by the form --------------------
    let mut document = fresh.clone();
    ready_for_links(&mut document);
    document["auth"] = json!({ "signup": { "default_role": OWNER_ROLE_ID.0 } });
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("Owner"),
        "{body}"
    );

    // The catalog-dependent half of the same ceiling: a role that exists but is privileged.
    let mut document = fresh.clone();
    ready_for_links(&mut document);
    document["auth"] = json!({ "signup": { "default_role": PLATFORM_ADMIN_ROLE_ID.0 } });
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Platform Administrator"),
        "{body}"
    );

    // --- A link-issuing feature cannot be enabled with no configured origin --------------
    let mut document = fresh.clone();
    ready_for_links(&mut document);
    document["platform"]["public_base_url"] = Value::Null;
    document["auth"] = json!({ "password_recovery": { "email_link_enabled": true } });
    let (status, body) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let message = body["error"].as_str().unwrap_or_default().to_owned();
    assert!(message.contains("platform.public_base_url"), "{message}");
    assert!(message.contains("Host header"), "{message}");

    // --- Configure it for real ------------------------------------------------------------
    let mut document = fresh.clone();
    ready_for_links(&mut document);
    document["auth"] = json!({
        "signup": {
            "mode": "domain_allowlist",
            "allowed_domains": ["  Example.PT ", "example.pt"],
            "require_email_verification": false
        },
        "password_recovery": { "email_link_enabled": true }
    });
    let (status, saved) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["auth"]["signup"]["mode"], "domain_allowlist");
    // Stored normalized, so a signup check is a byte comparison rather than a per-request parse.
    assert_eq!(
        saved["auth"]["signup"]["allowed_domains"],
        json!(["example.pt"])
    );
    assert_eq!(
        saved["platform"]["public_base_url"],
        "https://livros.example.pt"
    );

    // --- THE CARRY-FORWARD ----------------------------------------------------------------
    // A client built before this slice existed — an old browser tab, a script, the desktop app one
    // version behind — sends the whole document with no `auth` key and no `public_base_url`. Under
    // a plain `#[serde(default)]` replace that silently switches password recovery off and blanks
    // the link origin. Saving an unrelated tab must not be a security downgrade.
    let mut stale = saved.clone();
    stale.as_object_mut().expect("object").remove("auth");
    stale["platform"]
        .as_object_mut()
        .expect("object")
        .remove("public_base_url");
    stale["appearance"]["theme"] = json!("dark");
    let (status, after) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", stale), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["appearance"]["theme"], "dark", "the real edit landed");
    assert_eq!(
        after["auth"]["signup"]["mode"], "domain_allowlist",
        "an old client blanked the auth slice: {after}"
    );
    assert_eq!(
        after["auth"]["password_recovery"]["email_link_enabled"],
        true
    );
    assert_eq!(
        after["platform"]["public_base_url"], "https://livros.example.pt",
        "an old client blanked the link origin: {after}"
    );

    // Carry-forward restores intent; it does not make the fields unwritable. A client that sends
    // the keys explicitly still replaces them — including with `null`.
    let mut explicit = after.clone();
    explicit["auth"] = json!({});
    explicit["platform"]["public_base_url"] = Value::Null;
    let (status, cleared) = send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", explicit), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert!(
        cleared.get("auth").is_none(),
        "an explicit empty slice returns to defaults, and defaults are skipped: {cleared}"
    );
    assert_eq!(cleared["platform"]["public_base_url"], Value::Null);
}
