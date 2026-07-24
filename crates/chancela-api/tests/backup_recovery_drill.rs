use crate::common;

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

fn assert_no_overclaim_flags(receipt: &Value) {
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
}

fn assert_no_freshness_overclaim_flags(freshness: &Value) {
    for flag in [
        "restore_performed",
        "db_swap_performed",
        "offsite_custody_verified",
        "rpo_rto_certified",
        "production_backup_policy_certified",
    ] {
        assert_eq!(freshness[flag], false, "{flag} must stay false");
    }
}

fn assert_bounded_messages(value: &Value, field: &str) {
    let messages = value[field].as_array().expect("message array");
    assert!(messages.len() <= 8, "{field} is bounded: {messages:?}");
    for message in messages {
        let message = message.as_str().expect("message text");
        assert!(
            message.len() <= 512,
            "{field} message exceeds receipt bound: {message}"
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
    assert_eq!(receipt["isolated_restore_verified"], true);
    let isolated = &receipt["isolated_restore_verification"];
    assert_eq!(isolated["status"], "verified");
    assert_eq!(isolated["db_snapshot_materialized"], true);
    assert_eq!(isolated["db_snapshot_opened"], true);
    assert_eq!(isolated["state_loaded"], true);
    assert_eq!(isolated["ledger_verified"], true);
    assert_eq!(isolated["cleanup_verified"], true);
    assert!(isolated["sidecar_root_count"].as_u64().unwrap() >= 1);
    assert!(
        isolated["sidecar_materialized_file_count"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(isolated["sidecar_materialized_bytes"].as_u64().unwrap() > 0);
    assert!(isolated["temp_dir_name"].is_null());
    assert!(isolated["errors"].as_array().unwrap().is_empty());
    assert!(
        isolated["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding
                .as_str()
                .unwrap()
                .contains("isolated database snapshot")),
        "receipt includes isolated snapshot findings: {isolated}"
    );
    assert!(
        isolated["next_step"]
            .as_str()
            .unwrap()
            .contains("preflight-only"),
        "receipt does not certify a recovery execution: {isolated}"
    );
    assert_bounded_messages(isolated, "findings");
    assert_bounded_messages(isolated, "errors");
    assert_no_overclaim_flags(&receipt);
    assert_secret_free(
        &receipt,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
            "ledger.restored",
        ],
    );

    let receipt_path = tmp.dir.join("backup-recovery-drills.json");
    assert!(receipt_path.is_file(), "receipt sidecar persisted");
    let persisted: Value = serde_json::from_str(
        &std::fs::read_to_string(&receipt_path).expect("receipt sidecar readable"),
    )
    .expect("receipt sidecar JSON");
    let persisted_receipt = &persisted.as_array().unwrap()[0];
    assert_eq!(persisted_receipt["isolated_restore_verified"], true);
    assert_eq!(
        persisted_receipt["isolated_restore_verification"]["status"],
        "verified"
    );
    assert_no_overclaim_flags(persisted_receipt);
    assert_raw_secret_free(
        &receipt_path,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
            "ledger.restored",
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
    assert_eq!(list["freshness"]["status"], "fresh");
    assert_eq!(
        list["freshness"]["policy"]["max_drill_age_days"],
        chancela_api::DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS
    );
    assert_eq!(
        list["freshness"]["policy"]["target_rpo_minutes"],
        chancela_api::DEFAULT_BACKUP_RECOVERY_TARGET_RPO_MINUTES
    );
    assert_eq!(
        list["freshness"]["policy"]["target_rto_minutes"],
        chancela_api::DEFAULT_BACKUP_RECOVERY_TARGET_RTO_MINUTES
    );
    assert_eq!(list["freshness"]["latest_receipt_id"], receipt["id"]);
    assert_eq!(
        list["freshness"]["latest_receipt_at"],
        receipt["created_at"]
    );
    assert_eq!(list["freshness"]["latest_receipt_preflight_ready"], true);
    assert_eq!(
        list["freshness"]["latest_receipt_isolated_restore_verified"],
        true
    );
    assert!(list["freshness"]["latest_receipt_age_days"].is_number());
    assert_no_freshness_overclaim_flags(&list["freshness"]);
    let listed_receipt = &list["receipts"].as_array().unwrap()[0];
    assert_eq!(listed_receipt["isolated_restore_verified"], true);
    assert_eq!(
        listed_receipt["isolated_restore_verification"]["status"],
        "verified"
    );
    assert_secret_free(
        &list,
        &[
            passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
            "ledger.restored",
        ],
    );
}

#[tokio::test]
async fn backup_recovery_drill_list_reports_no_receipt_freshness_with_default_policy() {
    let tmp = TempDir::new("no-receipt");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.no.receipt").await;

    let (status, list) = send(state, with_session(get(DRILL_PATH), &token)).await;

    assert_eq!(status, StatusCode::OK, "empty list response: {list}");
    assert_eq!(list["receipts"].as_array().unwrap().len(), 0);
    assert_eq!(list["freshness"]["status"], "no_receipt");
    assert!(list["freshness"]["latest_receipt_id"].is_null());
    assert!(list["freshness"]["latest_receipt_at"].is_null());
    assert!(list["freshness"]["latest_receipt_age_days"].is_null());
    assert_eq!(
        list["freshness"]["policy"]["max_drill_age_days"],
        chancela_api::DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS
    );
    assert_no_freshness_overclaim_flags(&list["freshness"]);
}

#[tokio::test]
async fn backup_recovery_drill_list_reports_stale_verified_receipt_against_policy() {
    let tmp = TempDir::new("stale");
    std::fs::write(
        tmp.dir.join("backup-recovery-drills.json"),
        json!([{
            "id": "stale-receipt",
            "created_at": "2000-01-01T00:00:00Z",
            "archive": "backups/stale.zip",
            "preflight_ok": true,
            "preflight_ready": true,
            "encrypted": false,
            "ledger_verified": true,
            "manifest": null,
            "isolated_restore_verified": true,
            "isolated_restore_verification": {
                "status": "verified",
                "db_snapshot_materialized": true,
                "db_snapshot_opened": true,
                "state_loaded": true,
                "ledger_verified": true,
                "cleanup_verified": true,
                "findings": [],
                "errors": [],
                "next_step": "record as preflight-only isolated snapshot evidence; authorize any recovery execution separately"
            },
            "restore_executed": false,
            "live_db_swapped": false,
            "sidecars_staged": false,
            "ledger_restored_appended": false,
            "data_deleted": false,
            "offsite_custody_proven": false,
            "legal_archive_certified": false
        }])
        .to_string(),
    )
    .expect("stale receipt sidecar");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.stale").await;

    let (status, list) = send(state, with_session(get(DRILL_PATH), &token)).await;

    assert_eq!(status, StatusCode::OK, "stale list response: {list}");
    assert_eq!(list["freshness"]["status"], "stale");
    assert_eq!(list["freshness"]["latest_receipt_id"], "stale-receipt");
    assert_eq!(list["freshness"]["latest_receipt_preflight_ready"], true);
    assert_eq!(
        list["freshness"]["latest_receipt_isolated_restore_verified"],
        true
    );
    assert!(
        list["freshness"]["latest_receipt_age_days"]
            .as_u64()
            .unwrap()
            > chancela_api::DEFAULT_BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS as u64
    );
    assert_no_freshness_overclaim_flags(&list["freshness"]);
}

#[tokio::test]
async fn backup_recovery_drill_loads_old_receipts_as_isolated_restore_not_recorded() {
    let tmp = TempDir::new("legacy");
    std::fs::write(
        tmp.dir.join("backup-recovery-drills.json"),
        json!([{
            "id": "legacy-receipt",
            "created_at": "2026-07-12T00:00:00Z",
            "archive": "backups/legacy.zip",
            "preflight_ok": true,
            "preflight_ready": true,
            "encrypted": false,
            "ledger_verified": true,
            "manifest": null,
            "restore_executed": true,
            "live_db_swapped": true,
            "sidecars_staged": true,
            "ledger_restored_appended": true,
            "data_deleted": true,
            "offsite_custody_proven": true,
            "legal_archive_certified": true
        }])
        .to_string(),
    )
    .expect("legacy receipt sidecar");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.legacy").await;

    let (status, list) = send(state, with_session(get(DRILL_PATH), &token)).await;

    assert_eq!(status, StatusCode::OK, "legacy list response: {list}");
    assert_eq!(list["receipts"].as_array().unwrap().len(), 1);
    let receipt = &list["receipts"].as_array().unwrap()[0];
    assert_eq!(receipt["isolated_restore_verified"], false);
    assert_eq!(
        receipt["isolated_restore_verification"]["status"],
        "not_recorded"
    );
    assert_eq!(
        receipt["isolated_restore_verification"]["next_step"],
        "run a new recovery drill to record isolated snapshot verification"
    );
    assert_no_overclaim_flags(receipt);
}

#[tokio::test]
async fn backup_recovery_drill_wrong_passphrase_records_failed_isolated_evidence_only() {
    let tmp = TempDir::new("wrong-passphrase");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let token = seed_owner_session(&state, "drill.wrong.passphrase").await;
    let sidecar_name = "failed-secret-member-name.json";
    let sidecar_path = tmp.dir.join(sidecar_name);
    std::fs::write(&sidecar_path, br#"{"operator":"local-only-failed"}"#).expect("sidecar");
    let passphrase = "correct-passphrase-not-persisted";
    let wrong_passphrase = "wrong-passphrase-not-persisted";
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
                    "passphrase": wrong_passphrase
                }),
            ),
            &token,
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "failed receipt response: {receipt}"
    );
    assert_eq!(receipt["preflight_ok"], false);
    assert_eq!(receipt["preflight_ready"], false);
    assert_eq!(receipt["encrypted"], true);
    assert_eq!(receipt["ledger_verified"], false);
    assert!(receipt["manifest"].is_null());
    assert_eq!(receipt["isolated_restore_verified"], false);
    let isolated = &receipt["isolated_restore_verification"];
    assert_eq!(isolated["status"], "failed");
    assert_eq!(isolated["db_snapshot_materialized"], false);
    assert_eq!(isolated["db_snapshot_opened"], false);
    assert_eq!(isolated["state_loaded"], false);
    assert_eq!(isolated["ledger_verified"], false);
    assert_eq!(isolated["cleanup_verified"], false);
    assert_eq!(isolated["sidecar_root_count"], 0);
    assert_eq!(isolated["sidecar_materialized_file_count"], 0);
    assert_eq!(isolated["sidecar_materialized_bytes"], 0);
    assert_eq!(isolated["errors"].as_array().unwrap().len(), 1);
    assert!(
        isolated["errors"][0]
            .as_str()
            .unwrap()
            .contains("isolated snapshot verification"),
        "failed receipt stores bounded generic evidence: {isolated}"
    );
    assert_bounded_messages(isolated, "findings");
    assert_bounded_messages(isolated, "errors");
    assert_no_overclaim_flags(&receipt);
    assert_secret_free(
        &receipt,
        &[
            passphrase,
            wrong_passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
            "ledger.restored",
        ],
    );

    let receipt_path = tmp.dir.join("backup-recovery-drills.json");
    assert!(receipt_path.is_file(), "failed receipt sidecar persisted");
    let persisted: Value = serde_json::from_str(
        &std::fs::read_to_string(&receipt_path).expect("receipt sidecar readable"),
    )
    .expect("receipt sidecar JSON");
    let persisted_receipt = &persisted.as_array().unwrap()[0];
    assert_eq!(persisted_receipt["isolated_restore_verified"], false);
    assert_eq!(
        persisted_receipt["isolated_restore_verification"]["status"],
        "failed"
    );
    assert_no_overclaim_flags(persisted_receipt);
    assert_raw_secret_free(
        &receipt_path,
        &[
            passphrase,
            wrong_passphrase,
            sidecar_name,
            "sha256",
            manifest.app_version.as_str(),
            "ledger_head",
            "ledger.restored",
        ],
    );
    assert_eq!(
        std::fs::read(&db_path).expect("db after"),
        db_before,
        "failed drill receipt must not swap or rewrite the live database"
    );
    assert_eq!(
        std::fs::read(&sidecar_path).expect("sidecar after"),
        sidecar_before,
        "failed drill receipt must not stage or replace sidecars"
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
        "failed drill receipt must not append ledger.restored"
    );

    let (status, list) = send(state, with_session(get(DRILL_PATH), &token)).await;
    assert_eq!(status, StatusCode::OK, "failed list response: {list}");
    assert_eq!(list["freshness"]["status"], "failed");
    assert_eq!(list["freshness"]["latest_receipt_id"], receipt["id"]);
    assert_eq!(list["freshness"]["latest_receipt_preflight_ready"], false);
    assert_eq!(
        list["freshness"]["latest_receipt_isolated_restore_verified"],
        false
    );
    assert_no_freshness_overclaim_flags(&list["freshness"]);
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
