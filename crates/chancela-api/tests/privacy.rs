use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{
    LEITOR_ROLE_ID, OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

const PROCESSORS_FILE: &str = "privacy-processors.json";
const DPIAS_FILE: &str = "privacy-dpias.json";
const BREACH_PLAYBOOKS_FILE: &str = "privacy-breach-playbooks.json";
const TRANSFER_CONTROLS_FILE: &str = "privacy-transfer-controls.json";
const DSR_REQUESTS_FILE: &str = "privacy-dsr-requests.json";
const RETENTION_POLICIES_FILE: &str = "retention-policies.json";
const RETENTION_EXECUTIONS_FILE: &str = "privacy-retention-executions.json";

struct TempDir {
    dir: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("chancela-privacy-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

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

fn body_json(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    body_json("POST", uri, body)
}

fn patch_json(uri: &str, body: Value) -> Request<Body> {
    body_json("PATCH", uri, body)
}

fn with_session(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut().insert(
        "x-chancela-session",
        token.parse().expect("valid session header"),
    );
    req
}

async fn bootstrap_owner(state: &AppState) -> (UserId, String) {
    let (status, body) = send(
        state.clone(),
        post_json(
            "/v1/users",
            json!({
                "username": "owner",
                "display_name": "Owner",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner bootstraps: {body}");
    let uid = UserId(Uuid::parse_str(body["id"].as_str().expect("owner id")).expect("uuid"));
    let token = open_session(state, uid).await;
    (uid, token)
}

async fn open_session(state: &AppState, uid: UserId) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/session")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "user_id": uid.0 }).to_string()))
        .expect("request builds");
    let (status, body) = send(state.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "session opens: {body}");
    body["token"].as_str().expect("token").to_owned()
}

async fn insert_user(state: &AppState, id: UserId, username: &str, role: RoleAssignment) {
    let user = User {
        id,
        username: username.to_owned(),
        display_name: format!("{username} Display"),
        email: None,
        created_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        active: true,
        password_hash: None,
        attestation_key: None,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![role],
    };
    state.users.write().await.insert(id, user);
}

async fn add_settings_manager(state: &AppState) -> (UserId, String) {
    let role_id = RoleId(Uuid::from_u128(0x707269766163795f_73657474696e6773));
    state.roles.write().await.insert(Role {
        id: role_id,
        name: "Privacy Settings Manager".to_owned(),
        permission_set: [Permission::SettingsManage].into_iter().collect(),
        protected: false,
    });

    let user = UserId(Uuid::from_u128(4));
    insert_user(
        state,
        user,
        "settings-manager",
        RoleAssignment::new(role_id, Scope::Global),
    )
    .await;
    let token = open_session(state, user).await;
    (user, token)
}

async fn fixture_state() -> (AppState, UserId, String, UserId, String) {
    let state = seeded_state();
    let owner = UserId(Uuid::from_u128(1));
    let target = UserId(Uuid::from_u128(2));
    let reader = UserId(Uuid::from_u128(3));
    insert_user(
        &state,
        owner,
        "owner",
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        target,
        "bruno",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        reader,
        "reader",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;

    let owner_token = open_session(&state, owner).await;
    let reader_token = open_session(&state, reader).await;
    (state, target, owner_token, reader, reader_token)
}

fn processor_payload(risk_level: &str, status: &str) -> Value {
    json!({
        "name": "  Acme Hosting Ltd  ",
        "purpose": "  Customer portal hosting  ",
        "legal_basis": "  GDPR Art. 6(1)(b) contract  ",
        "data_categories": [" contact details ", "", "account metadata", "contact details"],
        "subprocessors": ["  EU Backup SARL ", "", "EU Backup SARL"],
        "risk_level": risk_level,
        "status": status,
    })
}

fn dpia_payload(risk_level: &str, status: &str) -> Value {
    json!({
        "title": "  Payroll analytics DPIA  ",
        "purpose": "  Workforce reporting  ",
        "legal_basis": "  GDPR Art. 6(1)(f) legitimate interests  ",
        "data_categories": ["employee identifiers", "payroll data"],
        "subprocessors": ["Analytics Processor SA"],
        "risk_level": risk_level,
        "status": status,
    })
}

fn retention_policy_payload(disposal_action: &str, status: &str) -> Value {
    json!({
        "name": "  Signed PDF archive  ",
        "scope": "  document  ",
        "category": "  signed_pdf  ",
        "schedule_id": " documents-signed-10y ",
        "retention_period": " P10Y ",
        "legal_basis": "  Commercial recordkeeping obligation  ",
        "disposal_action": disposal_action,
        "status": status,
        "active": true,
        "notes": "  Register only; disposal execution is out of scope.  "
    })
}

fn breach_playbook_payload(risk_level: &str, status: &str) -> Value {
    json!({
        "title": "  Suspected account compromise  ",
        "scope": "  account-access  ",
        "detection_channels": [" SIEM alert ", "", "support report", "SIEM alert"],
        "containment_steps": ["Disable affected sessions", "Rotate API keys"],
        "notification_roles": ["DPO", "Security lead"],
        "authority_notification_window": "72 hours after awareness when required",
        "subject_notification_guidance": "Notify affected subjects when high-risk impact is confirmed.",
        "risk_level": risk_level,
        "status": status,
        "review_notes": "Register only; incident execution remains manual."
    })
}

fn transfer_control_payload(risk_level: &str, status: &str) -> Value {
    json!({
        "name": "  EU to UK support access  ",
        "purpose": "  Support ticket investigation  ",
        "legal_basis": "  Contract support obligation  ",
        "data_categories": ["account metadata", "support messages"],
        "recipient": "  UK Support Ltd  ",
        "destination_country": "  United Kingdom  ",
        "transfer_mechanism": "  UK adequacy regulation  ",
        "safeguards": ["least-privilege access", "ticket-scoped audit"],
        "risk_level": risk_level,
        "status": status,
        "review_notes": "Review annually."
    })
}

#[tokio::test]
async fn privacy_export_requires_user_manage() {
    let (state, target, _owner_token, _reader, reader_token) = fixture_state().await;

    let (status, body) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &reader_token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");
}

#[tokio::test]
async fn privacy_export_returns_target_shape_and_ledger_refs() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;
    {
        let mut ledger = state.ledger.write().await;
        ledger.append("bruno", "user", "user.updated", Some("safe ref"), b"target");
        ledger.append("owner", "user", "user.updated", Some("other"), b"other");
    }

    let (status, body) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &owner_token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "export succeeds: {body}");
    assert_eq!(body["format_version"], json!(1));
    assert_eq!(body["scope"], json!(format!("user:{target}")));
    assert!(body["exported_at"].as_str().is_some());
    assert_eq!(body["user"]["id"], json!(target.to_string()));
    assert_eq!(body["user"]["username"], json!("bruno"));
    assert_eq!(body["user"]["active"], json!(true));
    assert_eq!(body["user"]["has_secret"], json!(false));
    assert_eq!(body["user"]["has_recovery_phrase"], json!(false));
    assert_eq!(body["user"]["has_attestation_key"], json!(false));
    assert_eq!(
        body["user"]["role_assignments"][0]["role_name"],
        json!("Leitor")
    );
    assert!(
        body["user"]["role_assignments"][0]["permissions"]
            .as_array()
            .expect("permissions")
            .iter()
            .any(|p| p == "act.read")
    );
    assert_eq!(
        body["ledger_event_refs"]
            .as_array()
            .expect("ledger refs")
            .len(),
        1
    );
    assert_eq!(body["ledger_event_refs"][0]["actor"], json!("bruno"));
    assert!(body["ledger_event_refs"][0].get("payload").is_none());
}

#[tokio::test]
async fn privacy_export_excludes_secret_material() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;
    {
        let mut users = state.users.write().await;
        let user = users.get_mut(&target).expect("target");
        user.password_hash = Some("secret-phc-value".to_owned());
        user.recovery_hash = Some("recovery-phc-value".to_owned());
    }

    let (status, body) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &owner_token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "export succeeds: {body}");
    assert_eq!(body["user"]["has_secret"], json!(true));
    assert_eq!(body["user"]["has_recovery_phrase"], json!(true));
    let raw = serde_json::to_string(&body).expect("json string");
    assert!(!raw.contains("secret-phc-value"));
    assert!(!raw.contains("recovery-phc-value"));
    assert!(!raw.contains("chk_"));
}

#[tokio::test]
async fn privacy_export_unknown_user_matches_admin_404_pattern() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let missing = Uuid::from_u128(0x999);

    let (status, body) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{missing}/export")),
            &owner_token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], json!("resource not found"));
}

#[tokio::test]
async fn dsr_request_lifecycle_requires_user_manage() {
    let (state, target, _owner_token, _reader, reader_token) = fixture_state().await;

    let (status, body) = send(
        state,
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "export" }),
            ),
            &reader_token,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");
}

#[tokio::test]
async fn dsr_request_create_list_complete_appends_audit_events() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "export" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id").to_owned();
    assert_eq!(created["subject_user_id"], json!(target.to_string()));
    assert_eq!(created["request_type"], json!("export"));
    assert_eq!(created["status"], json!("pending"));
    assert_eq!(created["created_by"], json!("owner"));
    assert!(created["created_at"].as_str().is_some());
    assert!(created.get("completed_at").is_none());

    let (status, list) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let list = list.as_array().expect("list body");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(request_id));

    let (status, completed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");
    assert_eq!(completed["status"], json!("completed"));
    assert_eq!(completed["completed_by"], json!("owner"));
    assert!(completed["completed_at"].as_str().is_some());
    assert_eq!(completed["outcome"], json!("fulfilled"));
    assert_eq!(completed["executed_by"], json!("owner"));
    assert_eq!(completed["executed_at"], completed["completed_at"]);
    assert_eq!(completed["affected_records"], json!([]));

    let (status, events) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/ledger/events?scope=user:{target}&limit=1000")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    let created_event = events
        .iter()
        .find(|e| e["kind"] == "privacy.dsr.request.created")
        .expect("created audit event");
    let completed_event = events
        .iter()
        .find(|e| e["kind"] == "privacy.dsr.request.completed")
        .expect("completed audit event");
    assert_eq!(created_event["scope"], json!(format!("user:{target}")));
    assert_eq!(completed_event["scope"], json!(format!("user:{target}")));
    assert_eq!(created_event["actor"], json!("owner"));
    assert_eq!(completed_event["actor"], json!("owner"));
    assert!(created_event.get("payload").is_none());
    assert!(completed_event.get("payload").is_none());
}

#[tokio::test]
async fn dsr_request_invalid_types_and_transitions_fail_closed() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "access" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("request_type")
    );

    let (status, list) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().expect("list").is_empty());

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "rectification" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id");

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dsr-requests/{request_id}"),
                json!({ "status": "pending" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("transition")
    );

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dsr-requests/{request_id}"),
                json!({ "status": "closed" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().expect("error").contains("status"));

    let (status, completed) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dsr-requests/{request_id}"),
                json!({ "status": "completed" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("cannot be completed again")
    );

    let (status, events) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/ledger/events?scope=user:{target}&limit=1000")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = events.as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.dsr.request.created")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.dsr.request.completed")
            .count(),
        1
    );
}

#[tokio::test]
async fn dsr_request_completion_records_execution_evidence_and_empty_affected_records() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{owner}/dsr-requests"),
                json!({ "request_type": "restriction" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id").to_owned();

    let (status, completed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{owner}/dsr-requests/{request_id}/complete"),
                json!({
                    "outcome": "no-action-required",
                    "execution_notes": "  No application records required mutation.  ",
                    "affected_records": [],
                    "retention_review": "  Statutory ledger retention remains in force.  ",
                    "legal_basis_review": "  GDPR Art. 6(1)(c) recordkeeping basis reviewed.  "
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");
    assert_eq!(completed["status"], json!("completed"));
    assert_eq!(completed["outcome"], json!("no_action_required"));
    assert_eq!(completed["completed_by"], json!("owner"));
    assert_eq!(completed["executed_by"], json!("owner"));
    assert_eq!(completed["executed_at"], completed["completed_at"]);
    assert_eq!(
        completed["execution_notes"],
        json!("No application records required mutation.")
    );
    assert_eq!(completed["affected_records"], json!([]));
    assert_eq!(
        completed["retention_review"],
        json!("Statutory ledger retention remains in force.")
    );
    assert_eq!(
        completed["legal_basis_review"],
        json!("GDPR Art. 6(1)(c) recordkeeping basis reviewed.")
    );

    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(DSR_REQUESTS_FILE)).expect("DSR sidecar"),
    )
    .expect("valid DSR sidecar");
    assert_eq!(persisted.as_array().expect("persisted DSRs").len(), 1);
    assert_eq!(persisted[0]["id"], json!(request_id));
    assert_eq!(persisted[0]["outcome"], json!("no_action_required"));
    assert_eq!(persisted[0]["affected_records"], json!([]));
    assert_eq!(
        persisted[0]["execution_notes"],
        json!("No application records required mutation.")
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, list) = send(
        restarted,
        with_session(
            get(&format!("/v1/privacy/users/{owner}/dsr-requests")),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after restart: {list}");
    let list = list.as_array().expect("DSR list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(request_id));
    assert_eq!(list[0]["outcome"], json!("no_action_required"));
    assert_eq!(list[0]["affected_records"], json!([]));
}

#[tokio::test]
async fn dsr_request_rejects_invalid_execution_evidence_without_audit_or_transition() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "erasure" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id").to_owned();

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({
                    "outcome": "fulfilled",
                    "execution_notes": "x".repeat(4097),
                    "affected_records": [{
                        "collection": "users",
                        "action": "reviewed",
                        "count": 1
                    }]
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("execution_notes")
    );

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dsr-requests/{request_id}"),
                json!({
                    "status": "completed",
                    "execution_notes": "password_hash=secret-phc-value"
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("sensitive credential")
    );

    let (status, list) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let list = list.as_array().expect("DSR list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["status"], json!("pending"));
    assert!(list[0].get("outcome").is_none());

    let (status, events) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/ledger/events?scope=user:{target}&limit=1000")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.dsr.request.created")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.dsr.request.completed")
            .count(),
        0
    );
}

#[tokio::test]
async fn dsr_requests_persist_across_restart_with_reasons_and_audit_refs() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;
    let reason = format!("  {}  ", "restriction context ".repeat(96));

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{owner}/dsr-requests"),
                json!({
                    "request_type": "restriction",
                    "reason": reason,
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id").to_owned();
    let trimmed_reason = "restriction context ".repeat(96).trim().to_owned();
    assert_eq!(created["reason"], json!(trimmed_reason));
    assert_eq!(created["status"], json!("pending"));
    assert!(tmp.dir.join(DSR_REQUESTS_FILE).is_file());

    let completion_reason = format!(
        "  {}  ",
        "completed after operator evidence review. ".repeat(96)
    );
    let (status, completed) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dsr-requests/{request_id}"),
                json!({
                    "status": " COMPLETED ",
                    "reason": completion_reason,
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");
    let trimmed_completion_reason = "completed after operator evidence review. "
        .repeat(96)
        .trim()
        .to_owned();
    assert_eq!(completed["status"], json!("completed"));
    assert_eq!(
        completed["completion_reason"],
        json!(trimmed_completion_reason)
    );
    assert_eq!(completed["outcome"], json!("fulfilled"));
    assert_eq!(completed["executed_by"], json!("owner"));
    assert_eq!(completed["executed_at"], completed["completed_at"]);
    assert_eq!(completed["affected_records"], json!([]));
    assert!(completed["completed_at"].as_str().is_some());

    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(DSR_REQUESTS_FILE)).expect("DSR sidecar"),
    )
    .expect("valid DSR sidecar");
    assert_eq!(persisted.as_array().expect("persisted DSRs").len(), 1);
    assert_eq!(persisted[0]["id"], json!(request_id));
    assert_eq!(persisted[0]["status"], json!("completed"));
    assert_eq!(persisted[0]["reason"], json!(trimmed_reason));
    assert_eq!(
        persisted[0]["completion_reason"],
        json!(trimmed_completion_reason)
    );
    assert_eq!(persisted[0]["outcome"], json!("fulfilled"));
    assert_eq!(persisted[0]["executed_by"], json!("owner"));
    assert_eq!(persisted[0]["affected_records"], json!([]));

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, list) = send(
        restarted.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{owner}/dsr-requests")),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after restart: {list}");
    let list = list.as_array().expect("DSR list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(request_id));
    assert_eq!(list[0]["request_type"], json!("restriction"));
    assert_eq!(list[0]["status"], json!("completed"));
    assert_eq!(list[0]["reason"], json!(trimmed_reason));
    assert_eq!(
        list[0]["completion_reason"],
        json!(trimmed_completion_reason)
    );
    assert_eq!(list[0]["created_by"], json!("owner"));
    assert_eq!(list[0]["completed_by"], json!("owner"));
    assert_eq!(list[0]["outcome"], json!("fulfilled"));
    assert_eq!(list[0]["executed_by"], json!("owner"));
    assert_eq!(list[0]["executed_at"], list[0]["completed_at"]);
    assert_eq!(list[0]["affected_records"], json!([]));
    assert!(list[0]["created_at"].as_str().is_some());
    assert!(list[0]["completed_at"].as_str().is_some());

    let (status, events) = send(
        restarted,
        with_session(
            get(&format!("/v1/ledger/events?scope=user:{owner}&limit=1000")),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger after restart: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.dsr.request.created" && e["scope"] == json!(format!("user:{owner}"))
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.dsr.request.completed" && e["scope"] == json!(format!("user:{owner}"))
    }));
}

#[tokio::test]
async fn dsr_request_load_tolerates_malformed_sidecar_and_preserves_authz() {
    let tmp = TempDir::new();
    std::fs::write(tmp.dir.join(DSR_REQUESTS_FILE), b"{not json").expect("write malformed DSRs");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let owner = UserId(Uuid::from_u128(0x100));
    let target = UserId(Uuid::from_u128(0x200));
    let reader = UserId(Uuid::from_u128(0x300));
    insert_user(
        &state,
        owner,
        "owner",
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        target,
        "target",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        reader,
        "reader",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;
    let owner_token = open_session(&state, owner).await;
    let reader_token = open_session(&state, reader).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &reader_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");

    let (status, list) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "malformed sidecar ignored: {list}");
    assert!(list.as_array().expect("DSR list").is_empty());

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "export" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create rewrites sidecar: {created}"
    );
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(DSR_REQUESTS_FILE)).expect("DSR sidecar"),
    )
    .expect("valid DSR sidecar after create");
    assert_eq!(persisted.as_array().expect("persisted DSRs").len(), 1);
    assert_eq!(persisted[0]["subject_user_id"], json!(target.to_string()));
}

#[tokio::test]
async fn dsr_request_load_skips_malformed_legacy_entries_and_defaults_execution_fields() {
    let tmp = TempDir::new();
    let target = UserId(Uuid::from_u128(0x350));
    let valid_id = Uuid::from_u128(0x351);
    let malformed_id = Uuid::from_u128(0x352);
    std::fs::write(
        tmp.dir.join(DSR_REQUESTS_FILE),
        json!([
            {
                "id": valid_id,
                "subject_user_id": target.to_string(),
                "request_type": "erasure",
                "status": "completed",
                "created_at": "2026-07-09T08:00:00Z",
                "created_by": "legacy-admin",
                "completed_at": "2026-07-09T09:00:00Z",
                "completed_by": "legacy-admin"
            },
            {
                "id": malformed_id,
                "subject_user_id": target.to_string(),
                "request_type": "restriction",
                "status": "completed",
                "outcome": "destructively_erased",
                "created_at": "2026-07-09T10:00:00Z",
                "created_by": "legacy-admin",
                "completed_at": "2026-07-09T11:00:00Z",
                "completed_by": "legacy-admin"
            }
        ])
        .to_string(),
    )
    .expect("write mixed legacy DSR sidecar");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let owner = UserId(Uuid::from_u128(0x353));
    insert_user(
        &state,
        owner,
        "owner",
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        target,
        "target",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;
    let owner_token = open_session(&state, owner).await;

    let (status, list) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mixed legacy DSR list: {list}");
    let list = list.as_array().expect("DSR list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(valid_id.to_string()));
    assert_eq!(list[0]["status"], json!("completed"));
    assert_eq!(list[0]["affected_records"], json!([]));
    assert!(list[0].get("outcome").is_none());
    assert!(list[0].get("executed_at").is_none());
    assert!(list[0].get("executed_by").is_none());
}

#[tokio::test]
async fn dsr_request_legacy_sidecar_orders_by_created_at_and_preserves_long_reasons() {
    let tmp = TempDir::new();
    let target = UserId(Uuid::from_u128(0x400));
    let older_id = Uuid::from_u128(0x401);
    let newer_id = Uuid::from_u128(0x402);
    let long_reason = "legacy evidence bundle reviewed; ".repeat(160);
    std::fs::write(
        tmp.dir.join(DSR_REQUESTS_FILE),
        json!([
            {
                "id": newer_id,
                "subject_user_id": target.to_string(),
                "request_type": "export",
                "status": "pending",
                "created_at": "2026-07-09T12:00:00Z",
                "created_by": "legacy-admin"
            },
            {
                "id": older_id,
                "subject_user_id": target.to_string(),
                "request_type": "erasure",
                "status": "completed",
                "reason": long_reason,
                "created_at": "2026-07-09T08:00:00Z",
                "created_by": "legacy-admin",
                "completed_at": "2026-07-09T09:00:00Z",
                "completed_by": "legacy-admin",
                "completion_reason": long_reason
            }
        ])
        .to_string(),
    )
    .expect("write legacy DSR sidecar");
    let state = AppState::with_data_dir(tmp.dir.clone());
    let owner = UserId(Uuid::from_u128(0x403));
    insert_user(
        &state,
        owner,
        "owner",
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        target,
        "target",
        RoleAssignment::new(LEITOR_ROLE_ID, Scope::Global),
    )
    .await;
    let owner_token = open_session(&state, owner).await;

    let (status, list) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "legacy DSR list: {list}");
    let list = list.as_array().expect("DSR list");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["id"], json!(older_id.to_string()));
    assert_eq!(list[0]["status"], json!("completed"));
    assert_eq!(list[0]["reason"], json!(long_reason));
    assert_eq!(list[0]["completion_reason"], json!(long_reason));
    assert_eq!(list[1]["id"], json!(newer_id.to_string()));
    assert_eq!(list[1]["status"], json!("pending"));
    assert!(list[1].get("reason").is_none());
    assert!(list[1].get("completed_at").is_none());
}

#[tokio::test]
async fn privacy_export_includes_dsr_refs_without_payloads_or_secret_material() {
    let (state, target, owner_token, _reader, _reader_token) = fixture_state().await;
    {
        let mut users = state.users.write().await;
        let user = users.get_mut(&target).expect("target");
        user.password_hash = Some("secret-phc-value".to_owned());
        user.recovery_hash = Some("recovery-phc-value".to_owned());
    }

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{target}/dsr-requests"),
                json!({ "request_type": "erasure" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let request_id = created["id"].as_str().expect("request id");

    let (status, completed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({
                    "outcome": "partially_fulfilled",
                    "execution_notes": "Exported safe profile fields; credential verifiers remained excluded.",
                    "affected_records": [{
                        "collection": "users",
                        "action": "reviewed",
                        "count": 1
                    }],
                    "retention_review": "Ledger retention preserved.",
                    "legal_basis_review": "Accountability basis reviewed."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");

    let (status, list) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/dsr-requests")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let raw_list = serde_json::to_string(&list).expect("json string");
    assert!(!raw_list.contains("secret-phc-value"));
    assert!(!raw_list.contains("recovery-phc-value"));

    let (status, body) = send(
        state,
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "export succeeds: {body}");
    let dsr_ref = body["ledger_event_refs"]
        .as_array()
        .expect("ledger refs")
        .iter()
        .find(|e| e["kind"] == "privacy.dsr.request.created")
        .expect("DSR audit ref");
    assert_eq!(dsr_ref["scope"], json!(format!("user:{target}")));
    assert!(dsr_ref.get("payload").is_none());
    let completed_ref = body["ledger_event_refs"]
        .as_array()
        .expect("ledger refs")
        .iter()
        .find(|e| e["kind"] == "privacy.dsr.request.completed")
        .expect("DSR completed audit ref");
    assert_eq!(completed_ref["scope"], json!(format!("user:{target}")));
    assert!(completed_ref.get("payload").is_none());

    let raw = serde_json::to_string(&body).expect("json string");
    assert!(!raw.contains("secret-phc-value"));
    assert!(!raw.contains("recovery-phc-value"));
}

#[tokio::test]
async fn processor_records_allow_settings_manage_sanitize_and_audit_updates() {
    let (state, _target, owner_token, _reader, reader_token) = fixture_state().await;
    let (_settings_user, settings_token) = add_settings_manager(&state).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/processors",
                processor_payload("medium", "active"),
            ),
            &reader_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/processors",
                processor_payload("medium", "active"),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let processor_id = created["id"].as_str().expect("processor id").to_owned();
    assert_eq!(created["name"], json!("Acme Hosting Ltd"));
    assert_eq!(created["purpose"], json!("Customer portal hosting"));
    assert_eq!(created["legal_basis"], json!("GDPR Art. 6(1)(b) contract"));
    assert_eq!(
        created["data_categories"],
        json!(["contact details", "account metadata"])
    );
    assert_eq!(created["subprocessors"], json!(["EU Backup SARL"]));
    assert_eq!(created["risk_level"], json!("medium"));
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["created_by"], json!("settings-manager"));
    assert_eq!(created["updated_by"], json!("settings-manager"));
    assert!(created["created_at"].as_str().is_some());
    assert!(created["updated_at"].as_str().is_some());

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/processors"), &settings_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let list = list.as_array().expect("processor list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(processor_id));
    assert_eq!(list[0]["data_categories"], created["data_categories"]);
    assert_eq!(list[0]["subprocessors"], created["subprocessors"]);

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/processors/{processor_id}"),
                json!({
                    "purpose": "  Updated hosting purpose  ",
                    "risk_level": "high",
                    "status": "under_review",
                    "subprocessors": ["EU Backup SARL", "Risk Review GmbH"],
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch succeeds: {updated}");
    assert_eq!(updated["purpose"], json!("Updated hosting purpose"));
    assert_eq!(updated["risk_level"], json!("high"));
    assert_eq!(updated["status"], json!("under_review"));
    assert_eq!(
        updated["subprocessors"],
        json!(["EU Backup SARL", "Risk Review GmbH"])
    );
    assert_eq!(updated["updated_by"], json!("settings-manager"));

    let (status, events) = send(
        state.clone(),
        with_session(
            get("/v1/ledger/events?scope=privacy:processor:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    let created_event = events
        .iter()
        .find(|e| e["kind"] == "privacy.processor.created")
        .expect("created audit event");
    let updated_event = events
        .iter()
        .find(|e| e["kind"] == "privacy.processor.updated")
        .expect("updated audit event");
    assert_eq!(
        created_event["scope"],
        json!(format!("privacy:processor:{processor_id}"))
    );
    assert_eq!(
        updated_event["scope"],
        json!(format!("privacy:processor:{processor_id}"))
    );
    assert_eq!(created_event["actor"], json!("settings-manager"));
    assert_eq!(updated_event["actor"], json!("settings-manager"));
    assert!(created_event.get("payload").is_none());
    assert!(updated_event.get("payload").is_none());
}

#[tokio::test]
async fn dpia_records_allow_user_manage_list_update_and_audit() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/dpias", dpia_payload("high", "draft")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let dpia_id = created["id"].as_str().expect("dpia id").to_owned();
    assert_eq!(created["title"], json!("Payroll analytics DPIA"));
    assert_eq!(created["purpose"], json!("Workforce reporting"));
    assert_eq!(created["risk_level"], json!("high"));
    assert_eq!(created["status"], json!("draft"));
    assert_eq!(created["created_by"], json!("owner"));

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/dpias"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let list = list.as_array().expect("dpia list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(dpia_id));

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dpias/{dpia_id}"),
                json!({
                    "status": "active",
                    "risk_level": "medium",
                    "data_categories": ["employee identifiers", "aggregated payroll metrics"],
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch succeeds: {updated}");
    assert_eq!(updated["status"], json!("active"));
    assert_eq!(updated["risk_level"], json!("medium"));
    assert_eq!(
        updated["data_categories"],
        json!(["employee identifiers", "aggregated payroll metrics"])
    );
    assert_eq!(updated["updated_by"], json!("owner"));

    let (status, events) = send(
        state.clone(),
        with_session(
            get("/v1/ledger/events?scope=privacy:dpia:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.dpia.created"
            && e["scope"] == json!(format!("privacy:dpia:{dpia_id}"))
            && e["actor"] == json!("owner")
            && e.get("payload").is_none()
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.dpia.updated"
            && e["scope"] == json!(format!("privacy:dpia:{dpia_id}"))
            && e["actor"] == json!("owner")
            && e.get("payload").is_none()
    }));
}

#[tokio::test]
async fn breach_playbooks_allow_settings_manage_persist_and_audit() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, _owner_token) = bootstrap_owner(&state).await;
    let (_settings_user, settings_token) = add_settings_manager(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/breach-playbooks",
                breach_playbook_payload("high", "active"),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let playbook_id = created["id"].as_str().expect("playbook id").to_owned();
    assert_eq!(created["title"], json!("Suspected account compromise"));
    assert_eq!(created["scope"], json!("account-access"));
    assert_eq!(
        created["detection_channels"],
        json!(["SIEM alert", "support report"])
    );
    assert_eq!(
        created["containment_steps"],
        json!(["Disable affected sessions", "Rotate API keys"])
    );
    assert_eq!(created["risk_level"], json!("high"));
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["created_by"], json!("settings-manager"));

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/breach-playbooks/{playbook_id}"),
                json!({
                    "status": "under_review",
                    "risk_level": "critical",
                    "containment_steps": ["Disable affected sessions", "Preserve audit evidence"],
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch succeeds: {updated}");
    assert_eq!(updated["status"], json!("under_review"));
    assert_eq!(updated["risk_level"], json!("critical"));
    assert_eq!(
        updated["containment_steps"],
        json!(["Disable affected sessions", "Preserve audit evidence"])
    );

    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(BREACH_PLAYBOOKS_FILE)).expect("breach playbooks sidecar"),
    )
    .expect("valid breach playbooks sidecar");
    assert_eq!(persisted.as_array().expect("persisted playbooks").len(), 1);
    assert_eq!(persisted[0]["id"], json!(playbook_id));

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, list) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/breach-playbooks"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after restart: {list}");
    assert_eq!(list.as_array().expect("playbook list").len(), 1);
    assert_eq!(list[0]["id"], json!(playbook_id));

    let (status, events) = send(
        restarted,
        with_session(
            get("/v1/ledger/events?scope=privacy:breach-playbook:&limit=1000"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.breach.playbook.created"
            && e["scope"] == json!(format!("privacy:breach-playbook:{playbook_id}"))
            && e["actor"] == json!("settings-manager")
            && e.get("payload").is_none()
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.breach.playbook.updated"
            && e["scope"] == json!(format!("privacy:breach-playbook:{playbook_id}"))
            && e["actor"] == json!("settings-manager")
            && e.get("payload").is_none()
    }));
}

#[tokio::test]
async fn transfer_controls_allow_user_manage_validate_persist_and_audit() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/transfer-controls",
                transfer_control_payload("medium", "draft"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let control_id = created["id"].as_str().expect("control id").to_owned();
    assert_eq!(created["name"], json!("EU to UK support access"));
    assert_eq!(created["recipient"], json!("UK Support Ltd"));
    assert_eq!(created["destination_country"], json!("United Kingdom"));
    assert_eq!(
        created["transfer_mechanism"],
        json!("UK adequacy regulation")
    );
    assert_eq!(
        created["safeguards"],
        json!(["least-privilege access", "ticket-scoped audit"])
    );

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/transfer-controls/{control_id}"),
                json!({ "review_notes": "password_hash=secret" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("sensitive credential")
    );

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/transfer-controls/{control_id}"),
                json!({
                    "status": "active",
                    "risk_level": "high",
                    "safeguards": ["least-privilege access", "quarterly review"],
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch succeeds: {updated}");
    assert_eq!(updated["status"], json!("active"));
    assert_eq!(updated["risk_level"], json!("high"));
    assert_eq!(
        updated["safeguards"],
        json!(["least-privilege access", "quarterly review"])
    );

    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(TRANSFER_CONTROLS_FILE)).expect("transfer controls sidecar"),
    )
    .expect("valid transfer controls sidecar");
    assert_eq!(persisted.as_array().expect("persisted controls").len(), 1);
    assert_eq!(persisted[0]["id"], json!(control_id));

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, list) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/transfer-controls"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after restart: {list}");
    assert_eq!(list.as_array().expect("transfer list").len(), 1);
    assert_eq!(list[0]["id"], json!(control_id));

    let (status, events) = send(
        restarted,
        with_session(
            get("/v1/ledger/events?scope=privacy:transfer-control:&limit=1000"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.transfer.control.created"
            && e["scope"] == json!(format!("privacy:transfer-control:{control_id}"))
            && e["actor"] == json!("owner")
            && e.get("payload").is_none()
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.transfer.control.updated"
            && e["scope"] == json!(format!("privacy:transfer-control:{control_id}"))
            && e["actor"] == json!("owner")
            && e.get("payload").is_none()
    }));
}

#[tokio::test]
async fn retention_policies_allow_settings_manage_update_and_guarded_execution_request() {
    let (state, _target, owner_token, _reader, reader_token) = fixture_state().await;
    let (_settings_user, settings_token) = add_settings_manager(&state).await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("delete", "active"),
            ),
            &reader_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("delete", "active"),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create succeeds: {created}");
    let policy_id = created["id"].as_str().expect("policy id").to_owned();
    assert_eq!(created["name"], json!("Signed PDF archive"));
    assert_eq!(created["scope"], json!("document"));
    assert_eq!(created["category"], json!("signed_pdf"));
    assert_eq!(created["schedule_id"], json!("documents-signed-10y"));
    assert_eq!(created["retention_period"], json!("P10Y"));
    assert_eq!(created["disposal_action"], json!("delete"));
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["active"], json!(true));
    assert_eq!(created["created_by"], json!("settings-manager"));
    assert_eq!(created["updated_by"], json!("settings-manager"));

    let (status, dry_run) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-123"
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run succeeds: {dry_run}");
    assert_eq!(dry_run["mode"], json!("dry_run"));
    assert_eq!(dry_run["execution_supported"], json!(false));
    assert_eq!(dry_run["destructive_execution_supported"], json!(false));
    assert_eq!(dry_run["matched_count"], json!(1));
    assert_eq!(dry_run["matches"][0]["policy_id"], json!(policy_id));
    assert_eq!(dry_run["matches"][0]["destructive_action"], json!(true));
    assert_eq!(dry_run["matches"][0]["would_execute"], json!(false));

    let (status, execution_request) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": " document ",
                    "category": " signed_pdf ",
                    "record_id": "doc-123",
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "operator_notes": "  Operator reviewed the retention candidate.  ",
                        "evidence": [
                            {
                                "label": " case ",
                                "value": "  archive package hash reviewed  "
                            }
                        ]
                    }
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "execution request is recorded: {execution_request}"
    );
    assert_eq!(execution_request["mode"], json!("execution_request"));
    assert_eq!(execution_request["matched_count"], json!(1));
    let execution_record = &execution_request["execution_record"];
    assert_eq!(execution_record["actor"], json!("settings-manager"));
    assert_eq!(execution_record["requested_policy"]["id"], json!(policy_id));
    assert_eq!(execution_record["requested_policy"]["found"], json!(true));
    assert_eq!(
        execution_record["requested_policy"]["destructive_action"],
        json!(true)
    );
    assert_eq!(
        execution_record["outcome"],
        json!("blocked_destructive_action")
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(
        execution_record["operator_notes"],
        json!("Operator reviewed the retention candidate.")
    );
    assert_eq!(
        execution_record["operator_evidence"][0]["label"],
        json!("case")
    );
    assert_eq!(
        execution_record["operator_evidence"][0]["value"],
        json!("archive package hash reviewed")
    );
    assert_eq!(
        execution_record["matched_records_summary"]["record_count"],
        json!(1)
    );
    assert_eq!(
        execution_record["matched_records_summary"]["policy_match_count"],
        json!(1)
    );

    let execution_id = execution_record["id"]
        .as_str()
        .expect("execution id")
        .to_owned();
    let (status, denied_history) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-executions"), &reader_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "reader cannot list execution evidence: {denied_history}"
    );

    let (status, history) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-executions"), &settings_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "execution history lists: {history}");
    let history = history.as_array().expect("execution history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["id"], json!(execution_id));
    assert_eq!(history[0]["requested_policy"]["id"], json!(policy_id));
    assert_eq!(history[0]["outcome"], json!("blocked_destructive_action"));

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/retention-policies/{policy_id}"),
                json!({
                    "status": "retired",
                    "active": false,
                    "disposal_action": "archive",
                    "notes": "No longer applied to new records."
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch succeeds: {updated}");
    assert_eq!(updated["status"], json!("retired"));
    assert_eq!(updated["active"], json!(false));
    assert_eq!(updated["disposal_action"], json!("archive"));

    let (status, dry_run) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({ "scope": "document", "category": "signed_pdf" }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run after retire: {dry_run}");
    assert_eq!(dry_run["matched_count"], json!(0));
    assert!(dry_run["matches"].as_array().expect("matches").is_empty());

    let (status, events) = send(
        state.clone(),
        with_session(
            get("/v1/ledger/events?scope=privacy:retention&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.retention.policy.created"
            && e["scope"] == json!(format!("privacy:retention-policy:{policy_id}"))
            && e["actor"] == json!("settings-manager")
            && e.get("payload").is_none()
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.retention.policy.updated"
            && e["scope"] == json!(format!("privacy:retention-policy:{policy_id}"))
            && e["actor"] == json!("settings-manager")
            && e.get("payload").is_none()
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.retention.execution.requested"
            && e["scope"]
                .as_str()
                .is_some_and(|scope| scope.starts_with("privacy:retention-execution:"))
            && e["actor"] == json!("settings-manager")
            && e.get("payload").is_none()
    }));
}

#[tokio::test]
async fn retention_execution_request_records_manual_review_for_non_destructive_policy() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("review", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "policy create: {created}");
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-review",
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "operator_notes": "Manual review evidence captured."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "manual review request: {body}");
    let execution_record = &body["execution_record"];
    assert_eq!(execution_record["actor"], json!("owner"));
    assert_eq!(execution_record["requested_policy"]["id"], json!(policy_id));
    assert_eq!(execution_record["requested_policy"]["found"], json!(true));
    assert_eq!(
        execution_record["requested_policy"]["destructive_action"],
        json!(false)
    );
    assert_eq!(execution_record["outcome"], json!("manual_review_required"));
    assert_eq!(execution_record["would_execute"], json!(false));
    assert!(
        execution_record["legal_hold_blockers"]
            .as_array()
            .expect("legal hold blockers")
            .is_empty()
    );
    assert_eq!(
        execution_record["matched_records_summary"]["destructive_policy_count"],
        json!(0)
    );

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-execution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    assert!(events.as_array().expect("events").iter().any(|e| {
        e["kind"] == "privacy.retention.execution.requested" && e["actor"] == json!("owner")
    }));
}

#[tokio::test]
async fn retention_execution_request_blocks_active_legal_hold() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, delete_policy) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("delete", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "delete policy create: {delete_policy}"
    );
    let delete_policy_id = delete_policy["id"]
        .as_str()
        .expect("delete policy id")
        .to_owned();

    let mut hold_payload = retention_policy_payload("legal_hold", "active");
    hold_payload["name"] = json!("Litigation hold");
    hold_payload["schedule_id"] = json!("litigation-hold");
    hold_payload["retention_period"] = json!("P99Y");
    hold_payload["notes"] = json!("Open matter hold; no disposal execution.");
    let (status, hold_policy) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies", hold_payload),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "legal hold policy create: {hold_policy}"
    );
    let hold_policy_id = hold_policy["id"]
        .as_str()
        .expect("legal hold policy id")
        .to_owned();

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-on-hold",
                    "execution_request": {
                        "requested_policy_id": delete_policy_id,
                        "operator_notes": "Legal hold checked before disposal."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "legal hold block: {body}");
    assert_eq!(body["matched_count"], json!(2));
    let execution_record = &body["execution_record"];
    assert_eq!(execution_record["outcome"], json!("blocked_legal_hold"));
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(
        execution_record["requested_policy"]["destructive_action"],
        json!(true)
    );
    assert_eq!(
        execution_record["matched_records_summary"]["policy_match_count"],
        json!(2)
    );
    assert_eq!(
        execution_record["matched_records_summary"]["destructive_policy_count"],
        json!(1)
    );
    assert_eq!(
        execution_record["legal_hold_blockers"][0]["policy_id"],
        json!(hold_policy_id)
    );

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-execution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    assert!(events.as_array().expect("events").iter().any(|e| {
        e["kind"] == "privacy.retention.execution.requested" && e["actor"] == json!("owner")
    }));
}

#[tokio::test]
async fn retention_execution_request_records_missing_and_stale_policy_blocks() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let missing_policy_id = Uuid::from_u128(0xfeed).to_string();
    let (status, missing) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-missing-policy",
                    "execution_request": {
                        "requested_policy_id": missing_policy_id,
                        "operator_notes": "No register policy found for this request."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "missing policy block: {missing}");
    assert_eq!(missing["matched_count"], json!(0));
    let execution_record = &missing["execution_record"];
    assert_eq!(execution_record["outcome"], json!("blocked_missing_policy"));
    assert_eq!(execution_record["requested_policy"]["found"], json!(false));
    assert_eq!(
        execution_record["requested_policy"]["id"],
        json!(missing_policy_id)
    );
    assert_eq!(execution_record["would_execute"], json!(false));

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("archive", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "policy create: {created}");
    let stale_policy_id = created["id"].as_str().expect("policy id").to_owned();
    let (status, patched) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/retention-policies/{stale_policy_id}"),
                json!({
                    "status": "suspended",
                    "active": false,
                    "notes": "Schedule superseded pending review."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy suspend: {patched}");

    let (status, stale) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-stale-policy",
                    "execution_request": {
                        "requested_policy_id": stale_policy_id,
                        "operator_notes": "Policy status checked before action."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stale policy block: {stale}");
    assert_eq!(stale["matched_count"], json!(0));
    let execution_record = &stale["execution_record"];
    assert_eq!(execution_record["outcome"], json!("blocked_stale_policy"));
    assert_eq!(execution_record["requested_policy"]["found"], json!(true));
    assert_eq!(execution_record["requested_policy"]["stale"], json!(true));
    assert_eq!(
        execution_record["requested_policy"]["status"],
        json!("suspended")
    );
    assert_eq!(execution_record["requested_policy"]["active"], json!(false));
    assert_eq!(execution_record["would_execute"], json!(false));

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-execution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    assert_eq!(
        events
            .as_array()
            .expect("events")
            .iter()
            .filter(|e| e["kind"] == "privacy.retention.execution.requested")
            .count(),
        2
    );
}

#[tokio::test]
async fn retention_execution_request_rejects_sensitive_operator_notes_and_evidence() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("review", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "policy create: {created}");
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let bodies = [
        json!({
            "scope": "document",
            "category": "signed_pdf",
            "record_id": "doc-sensitive-notes",
            "execution_request": {
                "requested_policy_id": policy_id,
                "operator_notes": "password_hash was pasted into the notes"
            }
        }),
        json!({
            "scope": "document",
            "category": "signed_pdf",
            "record_id": "doc-sensitive-evidence",
            "execution_request": {
                "requested_policy_id": policy_id,
                "evidence": [
                    {
                        "label": "review",
                        "value": "bearer_token copied from incident notes"
                    }
                ]
            }
        }),
    ];

    for body in bodies {
        let (status, err) = send(
            state.clone(),
            with_session(
                post_json("/v1/privacy/retention-policies/dry-run", body),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
        assert!(
            err["error"]
                .as_str()
                .expect("error")
                .contains("sensitive credential")
        );
    }

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-execution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger readable: {events}");
    assert!(events.as_array().expect("events").is_empty());
}

#[tokio::test]
async fn retention_policy_invalid_inputs_fail_closed() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let mut blank_id = retention_policy_payload("review", "draft");
    blank_id["id"] = json!(" ");
    let mut blank_name = retention_policy_payload("review", "draft");
    blank_name["name"] = json!(" ");
    let mut path_scope = retention_policy_payload("review", "draft");
    path_scope["scope"] = json!("../documents");
    let invalid_action = retention_policy_payload("shred", "draft");
    let mut legal_secret = retention_policy_payload("review", "draft");
    legal_secret["legal_basis"] = json!("password_hash evidence");
    let mut notes_secret = retention_policy_payload("review", "draft");
    notes_secret["notes"] = json!("bearer_token evidence");
    let invalid_status = retention_policy_payload("review", "closed");

    for body in [
        blank_id,
        blank_name,
        path_scope,
        invalid_action,
        legal_secret,
        notes_secret,
        invalid_status,
    ] {
        let (status, err) = send(
            state.clone(),
            with_session(
                post_json("/v1/privacy/retention-policies", body),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
    }

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-policies"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    assert!(list.as_array().expect("policy list").is_empty());

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-policy:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = events.as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.retention.policy.created")
            .count(),
        0
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.retention.policy.updated")
            .count(),
        0
    );
}

#[tokio::test]
async fn privacy_record_invalid_status_or_risk_fails_closed() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/processors",
                processor_payload("severe", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("risk_level")
    );

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/dpias", dpia_payload("high", "closed")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().expect("error").contains("status"));

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/processors"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().expect("processor list").is_empty());

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/dpias"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(list.as_array().expect("dpia list").is_empty());

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/processors", processor_payload("low", "draft")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "valid create succeeds: {created}"
    );
    let processor_id = created["id"].as_str().expect("processor id").to_owned();

    for body in [
        json!({ "risk_level": "severe" }),
        json!({ "status": "closed" }),
        json!({
            "purpose": "should not stick",
            "risk_level": "unknown",
        }),
    ] {
        let (status, err) = send(
            state.clone(),
            with_session(
                patch_json(&format!("/v1/privacy/processors/{processor_id}"), body),
                &owner_token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
    }

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/processors"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list = list.as_array().expect("processor list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["purpose"], json!("Customer portal hosting"));
    assert_eq!(list[0]["risk_level"], json!("low"));
    assert_eq!(list[0]["status"], json!("draft"));

    let (status, events) = send(
        state.clone(),
        with_session(
            get("/v1/ledger/events?scope=privacy:processor:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = events.as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.processor.created")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.processor.updated")
            .count(),
        0
    );
}

#[tokio::test]
async fn retention_policy_records_persist_across_restart() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("archive", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "policy create: {created}");
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, execution) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "document",
                    "category": "signed_pdf",
                    "record_id": "doc-persisted-execution",
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "operator_notes": "Recorded before restart."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "execution request records before restart: {execution}"
    );
    let execution_id = execution["execution_record"]["id"]
        .as_str()
        .expect("execution id")
        .to_owned();
    assert!(tmp.dir.join(RETENTION_EXECUTIONS_FILE).is_file());

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/retention-policies/{policy_id}"),
                json!({
                    "status": "suspended",
                    "active": false,
                    "retention_period": "P12Y"
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "policy patch: {updated}");
    assert!(tmp.dir.join(RETENTION_POLICIES_FILE).is_file());

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;

    let (status, policies) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/retention-policies"), &restarted_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "policy list after restart: {policies}"
    );
    let policies = policies.as_array().expect("policy list");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], json!(policy_id));
    assert_eq!(policies[0]["status"], json!("suspended"));
    assert_eq!(policies[0]["active"], json!(false));
    assert_eq!(policies[0]["retention_period"], json!("P12Y"));

    let (status, executions) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/retention-executions"), &restarted_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "execution list after restart: {executions}"
    );
    let executions = executions.as_array().expect("execution list");
    assert_eq!(executions.len(), 1);
    assert_eq!(executions[0]["id"], json!(execution_id));
    assert_eq!(executions[0]["requested_policy"]["id"], json!(policy_id));
    assert_eq!(executions[0]["outcome"], json!("manual_review_required"));
    assert_eq!(
        executions[0]["operator_notes"],
        json!("Recorded before restart.")
    );
    assert_eq!(executions[0]["would_execute"], json!(false));

    let (status, dry_run) = send(
        restarted,
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({ "scope": "document", "category": "signed_pdf" }),
            ),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run after restart: {dry_run}");
    assert_eq!(dry_run["matched_count"], json!(0));
}

#[tokio::test]
async fn privacy_processor_and_dpia_records_persist_across_restart() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, processor) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/processors",
                processor_payload("medium", "active"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "processor create: {processor}");
    let processor_id = processor["id"].as_str().expect("processor id").to_owned();

    let (status, dpia) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/dpias", dpia_payload("high", "draft")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "dpia create: {dpia}");
    let dpia_id = dpia["id"].as_str().expect("dpia id").to_owned();

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/processors/{processor_id}"),
                json!({
                    "status": "under_review",
                    "risk_level": "high",
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "processor patch: {updated}");
    assert!(tmp.dir.join(PROCESSORS_FILE).is_file());
    assert!(tmp.dir.join(DPIAS_FILE).is_file());

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;

    let (status, processors) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/processors"), &restarted_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "processor list after restart: {processors}"
    );
    let processors = processors.as_array().expect("processor list");
    assert_eq!(processors.len(), 1);
    assert_eq!(processors[0]["id"], json!(processor_id));
    assert_eq!(processors[0]["status"], json!("under_review"));
    assert_eq!(processors[0]["risk_level"], json!("high"));

    let (status, dpias) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/dpias"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dpia list after restart: {dpias}");
    let dpias = dpias.as_array().expect("dpia list");
    assert_eq!(dpias.len(), 1);
    assert_eq!(dpias[0]["id"], json!(dpia_id));
    assert_eq!(dpias[0]["title"], json!("Payroll analytics DPIA"));

    let (status, events) = send(
        restarted,
        with_session(
            get("/v1/ledger/events?scope=privacy:processor:&limit=1000"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger after restart: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.processor.created"
            && e["scope"] == json!(format!("privacy:processor:{processor_id}"))
    }));
    assert!(events.iter().any(|e| {
        e["kind"] == "privacy.processor.updated"
            && e["scope"] == json!(format!("privacy:processor:{processor_id}"))
    }));
}

#[tokio::test]
async fn durable_invalid_privacy_patch_does_not_persist_or_audit() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/processors", processor_payload("low", "draft")),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "processor create: {created}");
    let processor_id = created["id"].as_str().expect("processor id").to_owned();
    let before = std::fs::read(tmp.dir.join(PROCESSORS_FILE)).expect("processor json");

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/processors/{processor_id}"),
                json!({
                    "purpose": "should not persist",
                    "risk_level": "severe",
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let after = std::fs::read(tmp.dir.join(PROCESSORS_FILE)).expect("processor json");
    assert_eq!(
        after, before,
        "invalid patch did not rewrite the durable record"
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, processors) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/processors"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let processors = processors.as_array().expect("processor list");
    assert_eq!(processors.len(), 1);
    assert_eq!(processors[0]["purpose"], json!("Customer portal hosting"));
    assert_eq!(processors[0]["risk_level"], json!("low"));

    let (status, events) = send(
        restarted,
        with_session(
            get("/v1/ledger/events?scope=privacy:processor:&limit=1000"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = events.as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.processor.created")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["kind"] == "privacy.processor.updated")
            .count(),
        0
    );
}

#[tokio::test]
async fn privacy_register_load_tolerates_malformed_and_old_files() {
    let tmp = TempDir::new();
    std::fs::write(tmp.dir.join(PROCESSORS_FILE), b"{not json").expect("write malformed");
    let old_dpia_id = Uuid::from_u128(0x44504941);
    std::fs::write(
        tmp.dir.join(DPIAS_FILE),
        json!([
            {
                "id": old_dpia_id,
                "title": "Legacy DPIA",
                "purpose": "Legacy purpose",
                "legal_basis": "GDPR Art. 6(1)(f)",
                "data_categories": ["legacy data"],
                "risk_level": "medium",
                "status": "active",
                "created_at": "2026-01-01T00:00:00Z",
                "created_by": "legacy",
                "updated_at": "2026-01-01T00:00:00Z",
                "updated_by": "legacy"
            }
        ])
        .to_string(),
    )
    .expect("write old dpia");

    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;

    let (status, processors) = send(
        state.clone(),
        with_session(get("/v1/privacy/processors"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "processor list: {processors}");
    assert!(processors.as_array().expect("processors").is_empty());

    let (status, dpias) = send(state, with_session(get("/v1/privacy/dpias"), &owner_token)).await;
    assert_eq!(status, StatusCode::OK, "dpia list: {dpias}");
    let dpias = dpias.as_array().expect("dpias");
    assert_eq!(dpias.len(), 1);
    assert_eq!(dpias[0]["id"], json!(old_dpia_id.to_string()));
    assert_eq!(dpias[0]["subprocessors"], json!([]));
}
