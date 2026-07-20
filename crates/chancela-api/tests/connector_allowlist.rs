//! Admin-configurable connector egress allowlist (t21).
//!
//! The setting is a containment boundary, so these tests assert the properties that make it one:
//! the environment variable is a **ceiling** the runtime setting can only narrow, dangerous entries
//! are refused, every change is ledgered with a before/after, and the boundary the worker enforces
//! from is republished on disk rather than living only in the API's memory.
//!
//! Everything runs in one test function on purpose: the ceiling is process-global environment
//! state, and a second test mutating it concurrently would make both meaningless.

mod common;

use std::path::PathBuf;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
use chancela_connectors::{ALLOWED_HOSTS_ENV, NetworkPolicy, RuntimeAllowlist};
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
        let dir = std::env::temp_dir().join(format!("chancela-api-allowlist-{}", Uuid::new_v4()));
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
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
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

/// `PUT /v1/settings` carrying only the connector section, on top of the current document.
async fn put_allowed_hosts(state: &AppState, token: &str, hosts: &[&str]) -> (StatusCode, Value) {
    let (status, mut document) =
        send(state.clone(), with_session(get("/v1/settings"), token)).await;
    assert_eq!(status, StatusCode::OK, "settings readable: {document}");
    document["connectors"] = json!({ "allowed_hosts": hosts });
    send(
        state.clone(),
        with_session(json_request("PUT", "/v1/settings", document), token),
    )
    .await
}

async fn ledger_kinds(state: &AppState) -> Vec<String> {
    state
        .ledger
        .read()
        .await
        .events()
        .iter()
        .map(|event| event.kind.clone())
        .collect()
}

/// Actor and justification of the most recent allowlist event.
///
/// The ledger commits to a payload by digest and does not retain its bytes, so `justification` is
/// the field that has to carry the before/after for the change to be reconstructable from the
/// chain alone. Asserting on it is asserting on what an investigator would actually have.
async fn latest_allowlist_event(state: &AppState) -> (String, String) {
    let ledger = state.ledger.read().await;
    let event = ledger
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "connector.allowlist.updated")
        .expect("a connector.allowlist.updated event was appended");
    (
        event.actor.clone(),
        event.justification.clone().unwrap_or_default(),
    )
}

#[tokio::test]
async fn connector_allowlist_is_admin_configurable_bounded_audited_and_republished() {
    let temp = TempDir::new();
    // Start with no deployment ceiling: the case this feature exists to serve.
    unsafe { std::env::remove_var(ALLOWED_HOSTS_ENV) };

    let state = AppState::with_data_dir(&temp.dir);
    let token = seed_owner_session(&state, "amelia.marques").await;
    let sidecar = RuntimeAllowlist::path_in(&temp.dir);

    // --- Saving an allowlist -----------------------------------------------------------
    let (status, body) =
        put_allowed_hosts(&state, &token, &["Backup.Example.com", "10.42.0.0/16"]).await;
    assert_eq!(status, StatusCode::OK, "allowlist saves: {body}");
    assert_eq!(
        body["connectors"]["allowed_hosts"],
        json!(["backup.example.com", "10.42.0.0/16"]),
        "entries are stored normalized"
    );

    // The worker is a separate process: the boundary must exist on disk, not only in memory.
    let published: RuntimeAllowlist =
        serde_json::from_slice(&std::fs::read(&sidecar).expect("sidecar published"))
            .expect("sidecar is a runtime allowlist document");
    assert_eq!(
        published.entries,
        vec!["backup.example.com".to_owned(), "10.42.0.0/16".to_owned()]
    );
    assert_eq!(published.updated_by, "amelia.marques");

    // --- The change is reconstructable after the fact ------------------------------------
    let kinds = ledger_kinds(&state).await;
    assert!(kinds.contains(&"settings.updated".to_owned()));
    assert!(
        kinds.contains(&"connector.allowlist.updated".to_owned()),
        "the egress boundary change needs its own event, not just a whole-document diff"
    );
    let (actor, summary) = latest_allowlist_event(&state).await;
    assert_eq!(actor, "amelia.marques", "who changed it");
    assert!(
        summary.contains("+[backup.example.com 10.42.0.0/16]"),
        "the event must say what was added: {summary}"
    );
    assert!(
        summary.contains("deployment ceiling unset"),
        "and whether a ceiling was in force: {summary}"
    );

    // --- With no ceiling, the saved list is the boundary connectors actually enforce -----
    //
    // Publishing a document is only half the claim. What makes the setting a containment boundary is
    // that the policy resolved from it *refuses* a host nobody allowed — asserted through the same
    // `NetworkPolicy` a connector or the worker validates against, with IP literals so the check is
    // deterministic and never touches a resolver.
    let policy = NetworkPolicy::resolve(None, Some(&published))
        .expect("with no ceiling the runtime list is authoritative");
    policy
        .validate_host("10.42.0.7", 443, "backup")
        .await
        .expect("an address inside the saved CIDR is permitted");
    let refused = policy
        .validate_host("198.51.100.9", 443, "backup")
        .await
        .expect_err("a host nobody allowlisted must be blocked");
    assert!(
        refused.to_string().contains(ALLOWED_HOSTS_ENV),
        "the block must name the boundary that caused it: {refused}"
    );
    // Neighbouring-but-outside is the case an off-by-one prefix would let through.
    assert!(
        policy
            .validate_host("10.43.0.7", 443, "backup")
            .await
            .is_err(),
        "10.43.0.7 is outside 10.42.0.0/16 and must be blocked"
    );

    // --- Dangerous entries are refused ---------------------------------------------------
    for dangerous in [
        "169.254.169.254", // cloud instance metadata
        "169.254.0.0/16",  // the range that carries it
        "*",               // everything
        "*.example.com",   // bounded-looking, still a wildcard
        "127.0.0.1",       // back at Chancela itself
        "localhost",
        "0.0.0.0/0",
        "10.0.0.0/8", // too broad to be a boundary
        "https://backup.example.com",
        "backup.example.com:443",
        "backup.example.com/path",
    ] {
        let (status, body) = put_allowed_hosts(&state, &token, &[dangerous]).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{dangerous} must be refused, got {body}"
        );
    }
    // A refused save changes nothing that is enforced.
    let unchanged: RuntimeAllowlist =
        serde_json::from_slice(&std::fs::read(&sidecar).expect("sidecar still there")).unwrap();
    assert_eq!(unchanged.entries.len(), 2);

    // --- The environment variable is a ceiling, not a default ----------------------------
    unsafe { std::env::set_var(ALLOWED_HOSTS_ENV, "backup.example.com,10.42.0.0/16") };

    let (status, body) = send(state.clone(), with_session(get("/v1/settings"), &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["connectors"]["environment_ceiling"],
        json!(["backup.example.com", "10.42.0.0/16"]),
        "the UI is told what the ceiling actually is"
    );

    // Narrowing within the ceiling is allowed …
    let (status, body) = put_allowed_hosts(&state, &token, &["backup.example.com"]).await;
    assert_eq!(status, StatusCode::OK, "narrowing is allowed: {body}");

    // … widening past it is not, however privileged the session.
    let (status, body) = put_allowed_hosts(&state, &token, &["attacker.example.net"]).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a host outside the ceiling must be refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains(ALLOWED_HOSTS_ENV),
        "the refusal must name the ceiling that caused it: {body}"
    );
    // A broader CIDR than the ceiling grants is a widening too.
    let (status, _) = put_allowed_hosts(&state, &token, &["10.0.0.0/16"]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // A hostname in the ceiling does NOT cover an IP literal, even one the name might resolve to
    // today. Treating it as covering would let an administrator convert "this name, whatever it
    // resolves to" into "this address, unconditionally" — a widening the ceiling never granted, and
    // the ceiling here allows no IP entry at all beyond 10.42.0.0/16.
    for literal in ["203.0.113.10", "203.0.113.0/24"] {
        let (status, body) = put_allowed_hosts(&state, &token, &[literal]).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "the ceiling's hostname must not be read as covering {literal}: {body}"
        );
    }
    // …and the converse: the ceiling's own CIDR does not cover an unrelated hostname.
    let (status, _) = put_allowed_hosts(&state, &token, &["ten-forty-two.example.com"]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // --- Clearing the list restores the ceiling as the sole boundary ---------------------
    let (status, body) = put_allowed_hosts(&state, &token, &[]).await;
    assert_eq!(status, StatusCode::OK, "clearing is allowed: {body}");
    assert!(
        !sidecar.exists(),
        "a stale sidecar would keep enforcing a boundary nobody can see"
    );

    unsafe { std::env::remove_var(ALLOWED_HOSTS_ENV) };
}
