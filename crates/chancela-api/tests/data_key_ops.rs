mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{
    AppState, DB_KEY_ENV, DB_KEY_FILE_ENV, DB_KEY_SOURCE_ENV, DatabaseEncryptionConfig,
    DatabaseEncryptionConfigError, DatabaseEncryptionKeySource, User, UserId, router,
};
use chancela_authz::{OWNER_ROLE_ID, READER_ROLE_ID, RoleAssignment, RoleCatalog, RoleId, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const PREFLIGHT_PATH: &str = "/v1/data/key-rotation/preflight";
const EXECUTE_PATH: &str = "/v1/data/key-rotation";
const STATUS_PATH: &str = "/v1/data/status";
const RECEIPTS_FILE: &str = "data-key-rotation-receipts.json";

static ENV_LOCK: Mutex<()> = Mutex::new(());

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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds")
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        "x-chancela-session",
        token.parse().expect("valid header value"),
    );
    req
}

async fn seed_user(state: &AppState, username: &str, role_id: RoleId) -> UserId {
    let uid = UserId(Uuid::new_v4());
    let user = User {
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
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
        language: Default::default(),
    };
    state.users.write().await.insert(uid, user);
    uid
}

async fn open_session(state: &AppState, uid: UserId) -> String {
    let (status, body) = send(
        state.clone(),
        post_json(
            "/v1/session",
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn owner_session(state: &AppState) -> String {
    let uid = seed_user(state, "owner", OWNER_ROLE_ID).await;
    open_session(state, uid).await
}

fn assert_secret_free(body: &Value, secrets: &[&str]) {
    let rendered = body.to_string();
    for secret in secrets {
        assert!(
            !rendered.contains(secret),
            "response leaked secret {secret:?}: {rendered}"
        );
    }
}

fn state_for_header_only_data_dir(dir: PathBuf) -> AppState {
    AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        persist_path: Some(Arc::new(dir.join("settings.json"))),
        ..AppState::default()
    }
}

fn state_for_header_only_data_dir_with_key_source(
    dir: PathBuf,
    source: DatabaseEncryptionKeySource,
) -> AppState {
    AppState {
        database_encryption_key_source: Some(source),
        ..state_for_header_only_data_dir(dir)
    }
}

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("chancela-data-key-ops-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn capture(keys: &[&'static str]) -> Self {
        Self(
            keys.iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect(),
        )
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[tokio::test]
async fn preflight_requires_settings_manage_permission() {
    let tmp = TempDir::new("permission-denied");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let uid = seed_user(&state, "reader", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let current_key = "current-key-denied";
    let new_key = "replacement-key-denied";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "new_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "permission denial: {body}");
    assert_secret_free(&body, &[current_key, new_key]);
}

#[tokio::test]
async fn execution_requires_settings_manage_permission_without_leaking_keys() {
    let tmp = TempDir::new("execute-permission-denied");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let uid = seed_user(&state, "reader", READER_ROLE_ID).await;
    let token = open_session(&state, uid).await;
    let new_key = "replacement-key-execute-denied";

    let (status, body) = send(
        state,
        with_session(
            post_json(EXECUTE_PATH, json!({ "new_key": new_key })),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "permission denial: {body}");
    assert_secret_free(&body, &[new_key]);
    assert!(
        !tmp.dir.join(RECEIPTS_FILE).exists(),
        "forbidden execution must not create a key-rotation receipt"
    );
}

#[tokio::test]
async fn execution_refuses_plaintext_store_without_leaking_key_or_migrating() {
    let tmp = TempDir::new("execute-plaintext");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let new_key = "replacement-key-for-execute-plaintext";

    // t22 put this execution behind step-up re-auth. The gate runs BEFORE the plaintext check, so
    // an operator who proves nothing never learns anything about the store — pin that ordering
    // rather than letting it silently swallow the refusal this test is really about.
    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(EXECUTE_PATH, json!({ "new_key": new_key })),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "step-up is required before the store is even inspected: {body}"
    );
    assert_secret_free(&body, &[new_key]);

    let (status, body) = send(
        state,
        with_session(
            post_json(
                EXECUTE_PATH,
                json!({ "new_key": new_key, "reauth": { "password": TEST_PASSWORD } }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "plaintext refused: {body}"
    );
    assert!(
        body["error"].as_str().expect("error string").contains(
            "plaintext stores must use the supported backup/export-restore migration plan"
        ),
        "plaintext refusal explains non-destructive migration boundary: {body}"
    );
    assert_secret_free(&body, &[new_key]);
    assert!(
        !tmp.dir.join(RECEIPTS_FILE).exists(),
        "plaintext refusal must not create a key-rotation receipt"
    );

    let db =
        std::fs::read(tmp.dir.join(chancela_store::DB_FILE)).expect("database remains readable");
    assert!(
        db.starts_with(b"SQLite format 3\0"),
        "execution must not rewrite a plaintext SQLite store"
    );
}

#[tokio::test]
async fn preflight_reports_empty_and_missing_replacement_key_without_leaking_keys() {
    let tmp = TempDir::new("empty-new-key");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-empty-new-key";

    for body in [
        json!({ "current_key": current_key, "new_key": " \n\t " }),
        json!({ "current_key": current_key }),
    ] {
        let (status, body) = send(
            state.clone(),
            with_session(post_json(PREFLIGHT_PATH, body), &token),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "empty replacement report: {body}");
        assert_eq!(body["ready"], false);
        assert_eq!(body["status"], "reject_empty_new_key");
        assert_eq!(body["evidence"]["requested_key_config"], "empty");
        assert_secret_free(&body, &[current_key]);
    }
}

#[tokio::test]
async fn preflight_reports_plaintext_store_not_rotatable_without_leaking_keys() {
    let tmp = TempDir::new("plaintext");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-plaintext";
    let new_key = "replacement-key-for-plaintext";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "new_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "plaintext report: {body}");
    assert_eq!(body["ready"], false);
    assert_eq!(body["status"], "plaintext_store_not_rotatable");
    assert_eq!(body["evidence"]["database_format"], "plaintext_sqlite");
    assert_eq!(body["evidence"]["current_key_config"], "configured");
    assert_eq!(body["evidence"]["requested_key_config"], "configured");
    assert_secret_free(&body, &[current_key, new_key]);
}

#[test]
fn hardware_derived_fallback_source_request_fails_closed_without_static_key() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let _restore = EnvRestore::capture(&[DB_KEY_SOURCE_ENV, DB_KEY_ENV, DB_KEY_FILE_ENV]);
    let operator_secret = "operator secret should not be used as hardware fallback";
    unsafe {
        std::env::set_var(DB_KEY_SOURCE_ENV, "hardware_derived_fallback");
        std::env::set_var(DB_KEY_ENV, operator_secret);
        std::env::remove_var(DB_KEY_FILE_ENV);
    }

    let err = DatabaseEncryptionConfig::from_env()
        .expect_err("hardware fallback must fail closed until a real provider exists");

    assert!(matches!(
        err,
        DatabaseEncryptionConfigError::HardwareDerivedFallbackUnavailable
    ));
    let message = err.to_string();
    assert!(message.contains(DB_KEY_SOURCE_ENV));
    assert!(message.contains("fails closed"));
    assert!(!message.contains(operator_secret));
}

#[tokio::test]
async fn data_status_exposes_plaintext_database_encryption_gap() {
    let tmp = TempDir::new("status-plaintext-gap");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;

    let (status, body) = send(state, with_session(get(STATUS_PATH), &token)).await;

    assert_eq!(status, StatusCode::OK, "data status: {body}");
    let encryption = &body["persistence"]["database_encryption"];
    assert_eq!(body["persistence"]["database_encryption_configured"], false);
    assert_eq!(encryption["configured"], false);
    assert_eq!(encryption["sqlcipher_backed"], false);
    assert_eq!(encryption["key_source"], "none");
    assert_eq!(
        encryption["hardware_derived_fallback"]["status"],
        "unavailable"
    );
    assert_eq!(
        encryption["hardware_derived_fallback"]["fail_closed_if_requested"],
        true
    );
    assert_eq!(encryption["database_format"], "plaintext_sqlite");
    assert_eq!(encryption["key_ops_plan"], "open_plaintext_store");
    assert_eq!(encryption["plaintext_migration_pending"], true);
    assert_eq!(encryption["plaintext_migration_blocked"], false);
    assert_eq!(encryption["key_ops"]["key_config"], "unconfigured");
    assert_eq!(body["key_rotation"]["latest_receipt"], Value::Null);
    assert_eq!(body["key_rotation"]["history"], json!([]));
    assert_eq!(body["key_rotation"]["history_count"], 0);
    assert_eq!(body["key_rotation"]["history_limit"], 10);
}

#[tokio::test]
async fn data_status_reports_operator_key_source_and_blocked_plaintext_migration() {
    let tmp = TempDir::new("status-blocked-migration");
    chancela_store::Store::open(&tmp.dir).expect("create plaintext store");
    let state = state_for_header_only_data_dir_with_key_source(
        tmp.dir.clone(),
        DatabaseEncryptionKeySource::Env,
    );
    let token = owner_session(&state).await;

    let (status, body) = send(state, with_session(get(STATUS_PATH), &token)).await;

    assert_eq!(status, StatusCode::OK, "data status: {body}");
    let encryption = &body["persistence"]["database_encryption"];
    assert_eq!(encryption["configured"], false);
    assert_eq!(encryption["sqlcipher_backed"], false);
    assert_eq!(encryption["key_source"], "operator_env");
    assert_eq!(encryption["database_format"], "plaintext_sqlite");
    assert_eq!(
        encryption["key_ops_plan"],
        "refuse_plaintext_to_encrypted_migration"
    );
    assert_eq!(encryption["plaintext_migration_pending"], true);
    assert_eq!(encryption["plaintext_migration_blocked"], true);
    assert_eq!(encryption["key_ops"]["key_config"], "configured");
    assert_eq!(
        encryption["key_ops"]["migration_plan"]["status"],
        "refuse_direct_plaintext_to_encrypted_migration"
    );
    assert_secret_free(&body, &["<configured>"]);
}

#[cfg(feature = "sqlcipher")]
#[tokio::test]
async fn successful_guarded_rekey_persists_secret_free_receipt_and_status_history() {
    let tmp = TempDir::new("execute-success-receipt");
    let initial_key = "initial-key-not-persisted";
    let replacement_key = "replacement-key-not-persisted";
    let state = AppState::try_with_data_dir(
        tmp.dir.clone(),
        DatabaseEncryptionConfig::with_key(initial_key).expect("initial key config"),
    )
    .expect("encrypted state opens");
    let token = owner_session(&state).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(EXECUTE_PATH, json!({ "new_key": replacement_key })),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "rekey execution: {body}");
    assert_eq!(body["status"], "rekey_applied");
    assert_eq!(body["rekey_executed"], true);
    assert_secret_free(&body, &[initial_key, replacement_key]);

    let receipt_path = tmp.dir.join(RECEIPTS_FILE);
    assert!(receipt_path.is_file(), "success receipt is persisted");
    let receipt_file: Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("receipt file reads"))
            .expect("receipt file is JSON");
    assert_eq!(receipt_file["schema_version"], 1);
    let receipts = receipt_file["receipts"]
        .as_array()
        .expect("receipt history array");
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt["schema_version"], 1);
    assert!(
        receipt["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert!(receipt["rotated_at"].as_str().is_some());
    assert_eq!(receipt["actor_user_id"].is_string(), true);
    assert_eq!(receipt["mode"], "guarded_sqlcipher_rekey");
    assert_eq!(receipt["status"], "rekey_applied");
    assert_eq!(receipt["backend_family"], "sqlite");
    assert_eq!(receipt["rekey_executed"], true);
    assert_eq!(receipt["ledger_integrity_verified"], true);
    assert_eq!(receipt["evidence"]["operation"], "sqlcipher_rekey");
    assert_eq!(receipt["evidence"]["requested_key_config"], "configured");
    assert_eq!(receipt["evidence"]["sqlcipher_available"], true);
    assert_eq!(receipt["no_claims"]["current_key_persisted"], false);
    assert_eq!(receipt["no_claims"]["replacement_key_persisted"], false);
    assert_eq!(receipt["no_claims"]["key_fingerprint_persisted"], false);
    assert_eq!(receipt["no_claims"]["database_path_persisted"], false);
    assert_eq!(receipt["no_claims"]["sqlcipher_at_rest_certified"], false);
    assert_eq!(receipt["no_claims"]["plaintext_migration_performed"], false);
    assert_eq!(
        receipt["no_claims"]["legal_disposal_or_erasure_certified"],
        false
    );
    assert_secret_free(
        &receipt_file,
        &[initial_key, replacement_key, "chancela.db"],
    );

    let (status, status_body) = send(state, with_session(get(STATUS_PATH), &token)).await;
    assert_eq!(status, StatusCode::OK, "data status: {status_body}");
    assert_eq!(
        status_body["key_rotation"]["latest_receipt"]["receipt_id"],
        receipt["receipt_id"]
    );
    assert_eq!(status_body["key_rotation"]["history_count"], 1);
    assert_eq!(status_body["key_rotation"]["history_limit"], 10);
    assert_eq!(
        status_body["key_rotation"]["history"][0]["status"],
        "rekey_applied"
    );
    assert_secret_free(&status_body, &[initial_key, replacement_key, "chancela.db"]);
}

#[cfg(not(feature = "sqlcipher"))]
#[tokio::test]
async fn preflight_reports_sqlcipher_build_required_without_leaking_keys() {
    let tmp = TempDir::new("no-sqlcipher");
    std::fs::write(
        tmp.dir.join(chancela_store::DB_FILE),
        b"not a plaintext sqlite header",
    )
    .expect("fake non-plaintext database header");
    let state = state_for_header_only_data_dir(tmp.dir.clone());
    let token = owner_session(&state).await;
    let current_key = "current-key-for-no-sqlcipher";
    let new_key = "replacement-key-for-no-sqlcipher";

    let (status, body) = send(
        state,
        with_session(
            post_json(
                PREFLIGHT_PATH,
                json!({ "current_key": current_key, "replacement_key": new_key }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "no-sqlcipher report: {body}");
    assert_eq!(body["ready"], false);
    assert_eq!(body["status"], "sqlcipher_build_required");
    assert_eq!(
        body["evidence"]["database_format"],
        "non_plaintext_or_encrypted"
    );
    assert_eq!(body["evidence"]["current_key_config"], "configured");
    assert_eq!(body["evidence"]["requested_key_config"], "configured");
    assert_eq!(body["evidence"]["sqlcipher_available"], false);
    assert_secret_free(&body, &[current_key, new_key]);
}
