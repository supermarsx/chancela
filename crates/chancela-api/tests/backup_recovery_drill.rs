mod common;

use std::path::{Path, PathBuf};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const DRILL_PATH: &str = "/v1/backup/recovery-drills";

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "chancela-api-backup-recovery-drill-{name}-{}",
            Uuid::new_v4()
        ));
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

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
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
    req.headers_mut()
        .insert("x-chancela-session", token.parse().expect("session header"));
    req
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
        post_json(
            "/v1/session",
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

fn assert_secret_free(value: &Value, forbidden: &[&str]) {
    let rendered = value.to_string();
    for needle in forbidden {
        assert!(
            !rendered.contains(needle),
            "response leaked forbidden value {needle:?}: {rendered}"
        );
    }
}

fn assert_raw_secret_free(path: &Path, forbidden: &[&str]) {
    let raw = std::fs::read_to_string(path).expect("sidecar readable");
    for needle in forbidden {
        assert!(
            !raw.contains(needle),
            "sidecar leaked forbidden value {needle:?}: {raw}"
        );
    }
}

#[tokio::test]
async fn backup_recovery_drill_creates_receipt_from_preflight_and_persists_whitelist_only() {
    let tmp = TempDir::new("create");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.owner").await;
    let sidecar_name = "backup-secret-member-name.json";
    let sidecar_path = tmp.dir.join(sidecar_name);
    std::fs::write(&sidecar_path, br#"{"operator":"local-only"}"#).expect("sidecar");
    let passphrase = "receipt-passphrase-not-persisted";
    let manifest = state
        .store
        .as_ref()
        .expect("durable store")
        .backup_encrypted(&tmp.dir, std::slice::from_ref(&sidecar_path), passphrase)
        .expect("encrypted backup");
    let archive = manifest.path.clone();
    let db_path = tmp.dir.join(chancela_store::DB_FILE);
    let db_before = std::fs::read(&db_path).expect("db before");
    let sidecar_before = std::fs::read(&sidecar_path).expect("sidecar before");

    let (status, receipt) = send(
        state.clone(),
        with_session(
            post_json(
                DRILL_PATH,
                json!({
                    "archive": archive,
                    "passphrase": passphrase,
                    "operator_notes": "Quarterly recovery drill. Preflight only.",
                    "custody_location": "Evidence safe A / shelf 3",
                    "restore_executed": false,
                    "live_db_swapped": false
                }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "receipt response: {receipt}");
    assert_eq!(receipt["preflight_ok"], true);
    assert_eq!(receipt["preflight_ready"], true);
    assert_eq!(receipt["encrypted"], true);
    assert_eq!(receipt["ledger_verified"], true);
    assert_eq!(receipt["manifest"]["schema"], "chancela-backup-manifest/v1");
    assert_eq!(
        receipt["manifest"]["store_schema_version"],
        chancela_store::schema::SCHEMA_VERSION
    );
    assert!(receipt["manifest"]["member_count"].as_u64().unwrap() >= 2);
    assert!(
        receipt["manifest"]["sidecar_member_count"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(receipt["manifest"]["db_member_present"], true);
    assert!(receipt["manifest"].get("path").is_none());
    assert!(receipt["manifest"].get("app_version").is_none());
    assert!(receipt["manifest"].get("files").is_none());
    for flag in [
        "restore_executed",
        "live_db_swapped",
        "sidecars_staged",
        "ledger_restored_appended",
        "data_deleted",
        "offsite_custody_proven",
        "legal_archive_certified",
    ] {
        assert_eq!(receipt[flag], false, "{flag} must stay false");
    }
    assert_secret_free(
        &receipt,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
        ],
    );

    let receipt_path = tmp.dir.join("backup-recovery-drills.json");
    assert!(receipt_path.is_file(), "receipt sidecar persisted");
    assert_raw_secret_free(
        &receipt_path,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
        ],
    );
    assert_eq!(
        std::fs::read(&db_path).expect("db after"),
        db_before,
        "drill receipt must not swap or rewrite the live database"
    );
    assert_eq!(
        std::fs::read(&sidecar_path).expect("sidecar after"),
        sidecar_before,
        "drill receipt must not stage or replace sidecars"
    );
    let loaded = state
        .store
        .as_ref()
        .unwrap()
        .load()
        .expect("load live store");
    assert!(
        !loaded
            .ledger
            .events()
            .iter()
            .any(|event| event.kind == "ledger.restored"),
        "drill receipt must not append ledger.restored"
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = seed_owner_session(&restarted, "drill.owner.restarted").await;
    let (status, list) = send(restarted, with_session(get(DRILL_PATH), &restarted_token)).await;
    assert_eq!(status, StatusCode::OK, "list response: {list}");
    assert_eq!(list["durable"], true);
    assert_eq!(list["receipts"].as_array().unwrap().len(), 1);
    assert_secret_free(
        &list,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
        ],
    );
}

#[tokio::test]
async fn backup_recovery_drill_rejects_overclaim_flags_without_restore() {
    let tmp = TempDir::new("overclaim");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.overclaim").await;
    let manifest = state
        .store
        .as_ref()
        .expect("durable store")
        .backup(&tmp.dir, &[])
        .expect("backup");
    let db_path = tmp.dir.join(chancela_store::DB_FILE);
    let db_before = std::fs::read(&db_path).expect("db before");

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                DRILL_PATH,
                json!({
                    "archive": manifest.path,
                    "restore_executed": true,
                    "live_db_swapped": true,
                    "sidecars_staged": true,
                    "ledger_restored_appended": true,
                    "data_deleted": true,
                    "offsite_custody_proven": true,
                    "legal_archive_certified": true
                }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "overclaim: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("restore_executed"),
        "422 names the overclaimed flag: {body}"
    );
    assert!(
        !tmp.dir.join("backup-recovery-drills.json").exists(),
        "rejected overclaim must not persist a receipt"
    );
    assert_eq!(
        std::fs::read(&db_path).expect("db after"),
        db_before,
        "overclaim rejection must not touch the live database"
    );
    let loaded = state
        .store
        .as_ref()
        .unwrap()
        .load()
        .expect("load live store");
    assert!(
        !loaded
            .ledger
            .events()
            .iter()
            .any(|event| event.kind == "ledger.restored"),
        "overclaim rejection must not append ledger.restored"
    );
}
