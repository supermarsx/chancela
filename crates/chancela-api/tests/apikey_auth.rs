use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, router};
use chancela_apikey::{ApiKey, ApiKeyGrant, KeySpec, NewApiKey, RateLimit};
use chancela_authz::{
    EntityId as AuthzEntityId, GUEST_ROLE_ID, NoBooks, OWNER_ROLE_ID, Permission, RoleAssignment,
    RoleCatalog, RoleId, Scope, UserId as AuthzUserId, effective_permissions,
};
use chancela_core::{Entity, EntityKind, Nipc};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

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

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn bearer(mut req: Request<Body>, key: &str) -> Request<Body> {
    req.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {key}").parse().expect("valid header value"),
    );
    req
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        "x-chancela-session",
        token.parse().expect("valid header value"),
    );
    req
}

async fn seed_owner(state: &AppState) -> UserId {
    let uid = UserId(Uuid::new_v4());
    let user = User {
        id: uid,
        username: "owner".to_owned(),
        display_name: "Owner".to_owned(),
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        active: true,
        password_hash: None,
        attestation_key: None,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
    };
    state.users.write().await.insert(uid, user);
    uid
}

async fn open_session(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post_json("/api/v1/session", json!({ "user_id": uid.0 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn bootstrap_owner_session(state: &AppState) -> (UserId, String) {
    let (status, body) = send(
        state.clone(),
        post_json(
            "/api/v1/users",
            json!({ "username": "owner", "display_name": "Owner" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner bootstraps: {body}");
    let id = UserId(Uuid::parse_str(body["id"].as_str().expect("id")).expect("uuid id"));
    let token = open_session(state, id).await;
    (id, token)
}

async fn issue_key(state: &AppState, creator: UserId, permission: Permission) -> String {
    issue_key_with_rate_limit(state, creator, permission, None).await
}

async fn issue_key_with_rate_limit(
    state: &AppState,
    creator: UserId,
    permission: Permission,
    rate_limit: Option<RateLimit>,
) -> String {
    issue_key_with_grant(
        state,
        creator,
        ApiKeyGrant::perms([permission], Scope::Global),
        rate_limit,
    )
    .await
}

async fn issue_key_with_grant(
    state: &AppState,
    creator: UserId,
    grant: ApiKeyGrant,
    rate_limit: Option<RateLimit>,
) -> String {
    let roles = RoleCatalog::seeded_defaults();
    let creator_effective = effective_permissions(
        AuthzUserId(creator.0),
        &[RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        &roles,
        &[],
        OffsetDateTime::now_utc(),
    );
    let NewApiKey { plaintext, api_key } = ApiKey::issue(
        &creator_effective,
        &roles,
        &NoBooks,
        KeySpec {
            name: "test-key".to_owned(),
            principal_grant: grant,
            created_by: AuthzUserId(creator.0),
            created_at: OffsetDateTime::now_utc(),
            expires_at: None,
            rate_limit,
        },
    )
    .expect("grant is within Owner authority");

    state
        .api_keys
        .write()
        .await
        .insert(api_key.prefix.clone(), api_key);
    plaintext
}

async fn set_user_roles(state: &AppState, user_id: UserId, roles: Vec<RoleAssignment>) {
    let mut users = state.users.write().await;
    let user = users.get_mut(&user_id).expect("seeded user exists");
    user.role_assignments = roles;
}

async fn set_user_active(state: &AppState, user_id: UserId, active: bool) {
    let mut users = state.users.write().await;
    let user = users.get_mut(&user_id).expect("seeded user exists");
    user.active = active;
}

fn role(role_id: RoleId, scope: Scope) -> RoleAssignment {
    RoleAssignment::new(role_id, scope)
}

async fn create_managed_key(
    state: &AppState,
    token: &str,
    permission: Permission,
    rate_limit: Option<Value>,
) -> Value {
    let mut body = json!({
        "name": format!("managed-{permission}"),
        "grant": {
            "kind": "permissions",
            "permissions": [permission.as_str()],
            "scope": { "kind": "global" }
        }
    });
    if let Some(rate_limit) = rate_limit {
        body["rate_limit"] = rate_limit;
    }
    let (status, created) = send(
        state.clone(),
        with_session(post_json("/api/v1/api-keys", body), token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "key created: {created}");
    assert!(
        created["secret"]
            .as_str()
            .expect("secret")
            .starts_with("chk_")
    );
    assert!(
        created.get("key_hash").is_none(),
        "create response must not expose stored hash"
    );
    created
}

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-apikey-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn bearer_api_key_with_read_grant_can_use_api_v1_read_route() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::LedgerRead).await;

    let (status, body) = send(state, bearer(get("/api/v1/ledger/verify"), &key)).await;

    assert_eq!(status, StatusCode::OK, "valid key reads: {body}");
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn bearer_api_key_invalid_or_malformed_is_401() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::LedgerRead).await;

    let (status, _) = send(
        state.clone(),
        bearer(get("/api/v1/ledger/verify"), "not-a-chancela-key"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "malformed key rejected");

    let (status, _) = send(
        state,
        bearer(get("/api/v1/ledger/verify"), &format!("{key}x")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong key rejected");
}

#[tokio::test]
async fn bearer_api_key_with_insufficient_grant_is_403() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::EntityRead).await;

    let (status, _) = send(state, bearer(get("/api/v1/ledger/verify"), &key)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_key_auto_attenuates_after_creator_role_downgrade() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::LedgerRead).await;

    let (status, body) = send(state.clone(), bearer(get("/api/v1/ledger/verify"), &key)).await;
    assert_eq!(status, StatusCode::OK, "key works before downgrade: {body}");

    set_user_roles(&state, owner, vec![role(GUEST_ROLE_ID, Scope::Global)]).await;
    let (status, _) = send(state, bearer(get("/api/v1/ledger/verify"), &key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "key loses ledger.read when the creator is downgraded"
    );
}

#[tokio::test]
async fn api_key_auto_attenuates_after_creator_deactivation() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::LedgerRead).await;

    let (status, body) = send(state.clone(), bearer(get("/api/v1/ledger/verify"), &key)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key works before deactivation: {body}"
    );

    set_user_active(&state, owner, false).await;
    let (status, _) = send(state, bearer(get("/api/v1/ledger/verify"), &key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "valid key resolves to no authority when its creator is inactive"
    );
}

#[tokio::test]
async fn api_key_auto_attenuates_after_creator_loses_scope() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let accessible = Entity::new(
        "Scoped Entity, S.A.",
        Nipc::parse("503004642").expect("valid NIPC"),
        "Lisboa",
        EntityKind::SociedadeAnonima,
    );
    let other = Entity::new(
        "Other Entity, S.A.",
        Nipc::parse("500000000").expect("valid NIPC"),
        "Porto",
        EntityKind::SociedadeAnonima,
    );
    let accessible_id = accessible.id;
    let other_id = other.id;
    state
        .entities
        .write()
        .await
        .insert(accessible.id, accessible);
    state.entities.write().await.insert(other.id, other);

    let key = issue_key_with_grant(
        &state,
        owner,
        ApiKeyGrant::perms(
            [Permission::EntityRead],
            Scope::Entity(AuthzEntityId(accessible_id.0)),
        ),
        None,
    )
    .await;

    let (status, body) = send(
        state.clone(),
        bearer(get(&format!("/api/v1/entities/{accessible_id}")), &key),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key works before scope loss: {body}"
    );

    set_user_roles(
        &state,
        owner,
        vec![role(
            OWNER_ROLE_ID,
            Scope::Entity(AuthzEntityId(other_id.0)),
        )],
    )
    .await;
    let (status, _) = send(
        state,
        bearer(get(&format!("/api/v1/entities/{accessible_id}")), &key),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "key loses access when the creator no longer covers its original scope"
    );
}

#[tokio::test]
async fn session_and_bearer_credentials_cannot_be_mixed() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;
    let key = issue_key(&state, owner, Permission::LedgerRead).await;

    let (status, _) = send(
        state,
        with_session(bearer(get("/api/v1/ledger/verify"), &key), &token),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_auth_still_works_without_bearer_key() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;

    let (status, body) = send(state, with_session(get("/api/v1/ledger/verify"), &token)).await;

    assert_eq!(status, StatusCode::OK, "session auth unchanged: {body}");
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn api_key_is_not_an_interactive_session_for_session_or_self_service_routes() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/api/v1/users/{owner}/secret"),
                json!({ "password": "Inicial-Forte7!" }),
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner sets initial secret: {body}");

    let read_key = issue_key(&state, owner, Permission::LedgerRead).await;
    let (status, _) = send(
        state.clone(),
        bearer(get("/api/v1/session/permissions"), &read_key),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "session-only route rejects key"
    );

    let user_manage_key = issue_key(&state, owner, Permission::UserManage).await;
    let (status, _) = send(
        state,
        bearer(
            post_json(
                &format!("/api/v1/users/{owner}/secret"),
                json!({
                    "password": "Nova-Forte8!",
                    "current_password": "Inicial-Forte7!"
                }),
            ),
            &user_manage_key,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "self-service credential route rejects key"
    );
}

#[tokio::test]
async fn api_key_management_persists_across_state_reload_without_exposing_secret() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, token) = bootstrap_owner_session(&state).await;
    let created = create_managed_key(&state, &token, Permission::LedgerRead, None).await;
    let secret = created["secret"].as_str().expect("secret").to_owned();
    let id = created["id"].as_str().expect("id").to_owned();
    let prefix = created["prefix"].as_str().expect("prefix").to_owned();

    let (status, body) = send(state.clone(), bearer(get("/api/v1/ledger/verify"), &secret)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "new key works before reload: {body}"
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, list) = send(
        restarted.clone(),
        with_session(get("/api/v1/api-keys"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after reload: {list}");
    let keys = list.as_array().expect("list");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], id);
    assert_eq!(keys[0]["prefix"], prefix);
    assert!(keys[0].get("secret").is_none(), "list never returns secret");
    assert!(
        keys[0].get("key_hash").is_none(),
        "list never returns stored hash"
    );

    let (status, body) = send(restarted, bearer(get("/api/v1/ledger/verify"), &secret)).await;
    assert_eq!(status, StatusCode::OK, "key works after reload: {body}");
}

#[tokio::test]
async fn revoked_api_key_is_rejected() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;
    let created = create_managed_key(&state, &token, Permission::LedgerRead, None).await;
    let secret = created["secret"].as_str().expect("secret").to_owned();
    let id = created["id"].as_str().expect("id");

    let (status, revoked) = send(
        state.clone(),
        with_session(delete(&format!("/api/v1/api-keys/{id}")), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke succeeds: {revoked}");
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["active"], false);

    let (status, _) = send(state, bearer(get("/api/v1/ledger/verify"), &secret)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked key is invalid");
}

#[tokio::test]
async fn rotated_api_key_replaces_secret_keeps_metadata_and_audits() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;
    let created = create_managed_key(
        &state,
        &token,
        Permission::LedgerRead,
        Some(json!({ "rpm": 0, "burst": 2 })),
    )
    .await;
    let old_secret = created["secret"].as_str().expect("secret").to_owned();
    let id = created["id"].as_str().expect("id").to_owned();
    let old_prefix = created["prefix"].as_str().expect("prefix").to_owned();

    for attempt in 1..=2 {
        let (status, body) = send(
            state.clone(),
            bearer(get("/api/v1/ledger/verify"), &old_secret),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "old key burst token {attempt} allowed: {body}"
        );
    }
    let (status, _) = send(
        state.clone(),
        bearer(get("/api/v1/ledger/verify"), &old_secret),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "old key bucket is exhausted before rotation"
    );

    let (status, rotated) = send(
        state.clone(),
        with_session(
            post_json(&format!("/api/v1/api-keys/{id}/rotate"), json!({})),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate succeeds: {rotated}");
    let new_secret = rotated["secret"]
        .as_str()
        .expect("rotated secret")
        .to_owned();
    assert!(new_secret.starts_with("chk_"));
    assert_ne!(new_secret, old_secret, "rotation returns a fresh secret");
    assert_eq!(rotated["id"], created["id"], "rotation preserves key id");
    assert_eq!(rotated["name"], created["name"]);
    assert_eq!(rotated["created_by"], created["created_by"]);
    assert_eq!(rotated["created_at"], created["created_at"]);
    assert_eq!(rotated["grant"], created["grant"]);
    assert_eq!(rotated["rate_limit"], created["rate_limit"]);
    assert_eq!(rotated["revoked"], false);
    assert_eq!(rotated["active"], true);
    assert_ne!(rotated["prefix"], old_prefix, "display prefix rotates");
    assert!(
        rotated.get("key_hash").is_none(),
        "rotate response must not expose stored hash"
    );

    let (status, _) = send(
        state.clone(),
        bearer(get("/api/v1/ledger/verify"), &old_secret),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old secret is rejected after rotation"
    );

    let (status, _) = send(
        state.clone(),
        bearer(
            post_json(
                "/api/v1/entities",
                json!({
                    "name": "Denied, S.A.",
                    "nipc": "503004642",
                    "seat": "Lisboa",
                    "kind": "SociedadeAnonima"
                }),
            ),
            &new_secret,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "new secret retains the original ledger-only grant"
    );

    let (status, body) = send(
        state.clone(),
        bearer(get("/api/v1/ledger/verify"), &new_secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "new secret is accepted: {body}");

    let (status, _) = send(
        state.clone(),
        bearer(get("/api/v1/ledger/verify"), &new_secret),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "new secret retains the two-token rate-limit policy"
    );

    let (status, list) = send(state.clone(), with_session(get("/api/v1/api-keys"), &token)).await;
    assert_eq!(status, StatusCode::OK, "list after rotate: {list}");
    let keys = list.as_array().expect("list");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], id);
    assert_eq!(keys[0]["prefix"], rotated["prefix"]);
    assert!(keys[0].get("secret").is_none(), "list never returns secret");
    assert!(
        keys[0].get("key_hash").is_none(),
        "list never returns stored hash"
    );

    let (status, events) = send(state, with_session(get("/api/v1/ledger/events"), &token)).await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    assert!(
        events
            .as_array()
            .expect("events")
            .iter()
            .any(|e| e["kind"] == "api_key.rotated"),
        "rotation is audited"
    );
    let event_text = events.to_string();
    assert!(!event_text.contains(&old_secret));
    assert!(!event_text.contains(&new_secret));
    assert!(!event_text.contains("key_hash"));
}

#[tokio::test]
async fn bearer_api_key_rate_limit_returns_429() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let token = open_session(&state, owner).await;
    let created = create_managed_key(
        &state,
        &token,
        Permission::LedgerRead,
        Some(json!({ "rpm": 0, "burst": 1 })),
    )
    .await;
    let secret = created["secret"].as_str().expect("secret").to_owned();

    let (status, body) = send(state.clone(), bearer(get("/api/v1/ledger/verify"), &secret)).await;
    assert_eq!(status, StatusCode::OK, "first token allowed: {body}");

    let (status, body) = send(state, bearer(get("/api/v1/ledger/verify"), &secret)).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "second is limited: {body}"
    );
}

#[tokio::test]
async fn api_key_principal_cannot_manage_api_keys() {
    let state = seeded_state();
    let owner = seed_owner(&state).await;
    let key = issue_key(&state, owner, Permission::UserManage).await;

    let (status, _) = send(state, bearer(get("/api/v1/api-keys"), &key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "API keys are not interactive administrators"
    );
}
