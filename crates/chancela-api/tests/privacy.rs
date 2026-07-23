use crate::common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, User, UserId, provision_subject_dek, router};
use chancela_authz::{
    OWNER_ROLE_ID, Permission, READER_ROLE_ID, Role, RoleAssignment, RoleCatalog, RoleId, Scope,
};
use chancela_core::book::ClosingReason;
use chancela_core::{
    Book, BookKind, EntityId, NumberingScheme, TermoDeAbertura, TermoDeEncerramento,
};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use tokio::sync::{Barrier, RwLock};
use tower::ServiceExt;
use uuid::Uuid;

use common::{TEST_PASSWORD, password_hash};

const PROCESSORS_FILE: &str = "privacy-processors.json";
const DPIAS_FILE: &str = "privacy-dpias.json";
const BREACH_PLAYBOOKS_FILE: &str = "privacy-breach-playbooks.json";
const TRANSFER_CONTROLS_FILE: &str = "privacy-transfer-controls.json";
const DSR_REQUESTS_FILE: &str = "privacy-dsr-requests.json";
const RETENTION_POLICIES_FILE: &str = "retention-policies.json";
const RETENTION_EXECUTIONS_FILE: &str = "privacy-retention-executions.json";
const RETENTION_CANDIDATE_RESOLUTIONS_FILE: &str = "privacy-retention-candidate-resolutions.json";

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

async fn send_status(state: AppState, req: Request<Body>) -> StatusCode {
    router(state)
        .oneshot(req)
        .await
        .expect("router responds")
        .status()
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
                "password": TEST_PASSWORD,
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
        .body(Body::from(
            json!({ "user_id": uid.0, "password": TEST_PASSWORD }).to_string(),
        ))
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
        password_hash: Some(password_hash()),
        attestation_key: None,
        retired_attestation_keys: Vec::new(),
        totp: None,
        two_factor_required: false,
        force_password_change: false,
        secret_source: Default::default(),
        recovery_hash: None,
        role_assignments: vec![role],
        language: Default::default(),
    };
    state.users.write().await.insert(id, user);
}

async fn add_settings_manager(state: &AppState) -> (UserId, String) {
    let role_id = RoleId(Uuid::from_u128(0x707269766163795f_73657474696e6773));
    state.roles.write().await.insert(Role {
        id: role_id,
        name: "Privacy Settings Manager".to_owned(),
        // t27 re-gated privacy records + retention off the broad `settings.manage` onto the granular
        // `privacy.manage` / `retention.manage`. The grandfather migration grants both to every prior
        // `settings.manage` holder, so a settings manager keeps the access these tests assert. This
        // role mirrors that post-migration reality (settings.manage + its grandfathered children); the
        // precise "the narrow verb is what actually gates now" is proven by the dedicated tests below.
        permission_set: [
            Permission::SettingsManage,
            Permission::PrivacyManage,
            Permission::RetentionManage,
        ]
        .into_iter()
        .collect(),
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

/// Creates a user whose sole role holds exactly `perms` at Global, opens a session, and returns
/// `(id, token)`. Used by the t27 granular-verb tests to prove each op is gated on its *specific*
/// verb — a holder of a neighbouring or parent verb (but not the exact one) must be denied.
async fn add_user_with_permissions(
    state: &AppState,
    id: u128,
    username: &str,
    perms: &[Permission],
) -> (UserId, String) {
    let role_id = RoleId(Uuid::from_u128(id ^ 0x726f6c65));
    state.roles.write().await.insert(Role {
        id: role_id,
        name: format!("{username} Role"),
        permission_set: perms.iter().copied().collect(),
        protected: false,
    });
    let user = UserId(Uuid::from_u128(id));
    insert_user(
        state,
        user,
        username,
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
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        reader,
        "reader",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
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
        "evidence_receipt": {
            "evidence_type": "drill",
            "occurred_at": "2026-07-09T09:30:00Z",
            "notes": "Local DPIA tabletop review only.",
            "authority_filing_completed": false,
            "legal_review_accepted": false,
            "legal_certification_completed": false,
            "external_delivery_completed": false,
            "dpia_completed": false,
            "compliance_certification_completed": false
        }
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

fn archive_retention_policy_payload(disposal_action: &str, retention_period: &str) -> Value {
    json!({
        "name": "  Closed book archive  ",
        "scope": "  book_archive  ",
        "category": "  documents  ",
        "schedule_id": " archive-documents-v1 ",
        "retention_period": retention_period,
        "legal_basis": "  Closed book archive retention obligation  ",
        "disposal_action": disposal_action,
        "status": "active",
        "active": true,
        "notes": "  Scanner only; no disposal execution.  "
    })
}

fn retention_review_closure_payload(decision: &str, note: &str) -> Value {
    json!({
        "review_closure_decision": decision,
        "review_closure_note": note,
        "review_closure_evidence": [
            {
                "label": "  checklist  ",
                "value": "  operator evidence acknowledged  "
            }
        ],
        "destructive_disposal_completed": false,
        "full_erasure_completed": false,
        "legal_hold_mutated": false,
        "retention_policy_mutated": false
    })
}

async fn create_retention_execution_for_closure(
    state: &AppState,
    token: &str,
    policy_payload: Value,
    scope: &str,
    category: &str,
    record_id: &str,
    execution_mode: &str,
) -> (String, Value) {
    let (status, created) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies", policy_payload),
            token,
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
                    "scope": scope,
                    "category": category,
                    "record_id": record_id,
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "execution_mode": execution_mode,
                        "operator_notes": "Record bounded review evidence."
                    }
                }),
            ),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "execution request: {execution}");
    (policy_id, execution["execution_record"].clone())
}

fn date(year: i32, month: Month, day: u8) -> Date {
    Date::from_calendar_date(year, month, day).expect("valid date")
}

async fn insert_closed_book(state: &AppState, closing_date: Date) -> String {
    let entity_id = EntityId(Uuid::new_v4());
    let mut book = Book::new(entity_id, BookKind::AssembleiaGeral);
    book.open(TermoDeAbertura {
        entity_name: "Retained Entity SA".to_owned(),
        entity_nipc: "503004642".to_owned(),
        entity_seat: "Lisboa".to_owned(),
        purpose: "Livro de atas".to_owned(),
        numbering_scheme: NumberingScheme::Sequential,
        opening_date: date(1999, Month::January, 1),
        required_signatories: vec!["Management".to_owned()],
        required_signatory_records: Vec::new(),
        ..Default::default()
    })
    .expect("book opens");
    book.close(TermoDeEncerramento {
        ata_count: 0,
        reason: ClosingReason::BookFull,
        closing_date,
        required_signatories: vec!["Management".to_owned()],
        required_signatory_records: Vec::new(),
        ..Default::default()
    })
    .expect("book closes");
    let book_id = book.id.to_string();
    state.books.write().await.insert(book.id, book);
    book_id
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
        "review_notes": "Register only; incident execution remains manual.",
        "evidence_receipt": {
            "evidence_type": "drill",
            "occurred_at": "2026-07-09T10:30:00Z",
            "notes": "Tabletop drill reviewed escalation paths.",
            "authority_notified": false,
            "subjects_notified": false
        }
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
        "review_notes": "Review annually.",
        "evidence_receipt": {
            "reviewed_at": "2026-07-09T11:00:00Z",
            "notes": "Quarterly control review captured by operator.",
            "transfer_approved": false,
            "data_transfer_executed": false
        }
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
    // t68: a user's secret is their password; the fixture seeds bruno with a password_hash, so
    // has_secret now reflects that (was false before passwords became the secret).
    assert_eq!(body["user"]["has_secret"], json!(true));
    assert_eq!(body["user"]["has_recovery_phrase"], json!(false));
    assert_eq!(body["user"]["has_attestation_key"], json!(false));
    // t87: seeded role names are stored in English and localized by the *client* from the role id.
    // This export is server-rendered and the request carries no locale, so it reports the stored
    // name verbatim — "Reader", not "Leitor". That is deliberate: a DSR export is a record of what
    // is stored, and inventing a translation here would make the export disagree with the database
    // it is supposed to disclose. `role_id` below is the stable handle a reader can resolve.
    assert_eq!(
        body["user"]["role_assignments"][0]["role_name"],
        json!("Reader")
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
async fn dsr_erasure_completion_records_preflight_without_full_erasure_claim() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{owner}/dsr-requests"),
                json!({ "request_type": "erasure" }),
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
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({
                    "execution_notes": "Preflight recorded; no erasure mutation executed.",
                    "erasure_plan": [{
                        "collection": "users",
                        "record_id": owner.to_string(),
                        "action": "anonymize",
                        "status": "planned",
                        "reason": "Review mutable profile fields in a separate approved workflow."
                    }]
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "complete succeeds: {completed}");
    assert_eq!(completed["status"], json!("completed"));
    assert_eq!(completed["outcome"], json!("partially_fulfilled"));

    let preflight = &completed["erasure_preflight"];
    assert_eq!(preflight["dsr_request_id"], json!(request_id));
    assert_eq!(preflight["subject_user_id"], json!(owner.to_string()));
    assert_eq!(preflight["status"], json!("blocked_immutable_ledger"));
    assert_eq!(preflight["assessed_by"], json!("owner"));
    assert!(
        preflight["ledger_event_count_before_completion"]
            .as_u64()
            .expect("ledger event count")
            >= 1
    );
    assert_eq!(preflight["destructive_mutation_completed"], json!(false));
    assert_eq!(preflight["full_erasure_completed"], json!(false));
    assert_eq!(
        preflight["idempotency_guard"]["duplicate_completion_behavior"],
        json!("conflict_existing_completed_request")
    );

    let blockers = preflight["immutable_ledger_blockers"]
        .as_array()
        .expect("immutable blockers");
    assert!(blockers.iter().any(|blocker| {
        blocker["code"] == json!("immutable_ledger_events")
            && blocker["detail"]
                .as_str()
                .expect("blocker detail")
                .contains("append-only")
    }));
    assert!(blockers.iter().any(|blocker| {
        blocker["code"] == json!("dsr_audit_chain_retention")
            && blocker["target"] == json!(format!("privacy:dsr-request:{request_id}"))
    }));

    let plan = preflight["mutable_sidecar_plan"]
        .as_array()
        .expect("sidecar plan");
    let user_plan = plan
        .iter()
        .find(|item| item["collection"] == json!("users"))
        .expect("user sidecar plan");
    assert_eq!(user_plan["record_id"], json!(owner.to_string()));
    assert_eq!(user_plan["action"], json!("anonymize"));
    assert_eq!(user_plan["status"], json!("planned"));
    assert_eq!(user_plan["mutation_completed"], json!(false));
    assert!(plan.iter().any(|item| {
        item["collection"] == json!(DSR_REQUESTS_FILE)
            && item["action"] == json!("retain")
            && item["status"] == json!("not_applicable")
            && item["mutation_completed"] == json!(false)
    }));
    assert!(
        !serde_json::to_string(&completed)
            .expect("json string")
            .contains("\"full_erasure_completed\":true")
    );

    let persisted: Value = serde_json::from_slice(
        &std::fs::read(tmp.dir.join(DSR_REQUESTS_FILE)).expect("DSR sidecar"),
    )
    .expect("valid DSR sidecar");
    assert_eq!(
        persisted[0]["erasure_preflight"]["status"],
        json!("blocked_immutable_ledger")
    );
    assert_eq!(
        persisted[0]["erasure_preflight"]["full_erasure_completed"],
        json!(false)
    );

    let (status, repeat) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({ "outcome": "partially_fulfilled" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "repeat completion is blocked: {repeat}"
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
    assert_eq!(
        list[0]["erasure_preflight"]["full_erasure_completed"],
        json!(false)
    );
}

#[tokio::test]
async fn dsr_erasure_rejects_full_erasure_and_completed_plan_claims() {
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
                    "erasure_plan": [{
                        "collection": "users",
                        "record_id": target.to_string(),
                        "action": "redact",
                        "status": "planned"
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
            .contains("cannot be marked fulfilled")
    );

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/dsr-requests/{request_id}/complete"),
                json!({
                    "outcome": "partially_fulfilled",
                    "erasure_plan": [{
                        "collection": "users",
                        "record_id": target.to_string(),
                        "action": "redact",
                        "status": "completed"
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
            .contains("preflight only")
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
    assert!(list[0].get("erasure_preflight").is_none());

    let (status, events) = send(
        state,
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
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    insert_user(
        &state,
        reader,
        "reader",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
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
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
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
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
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
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;

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
    assert_eq!(
        created["evidence_receipts"][0]["evidence_type"],
        json!("drill")
    );
    assert_eq!(
        created["evidence_receipts"][0]["notes"],
        json!("Local DPIA tabletop review only.")
    );
    assert_eq!(
        created["evidence_receipts"][0]["authority_filing_completed"],
        json!(false)
    );
    assert_eq!(
        created["evidence_receipts"][0]["legal_review_accepted"],
        json!(false)
    );
    assert_eq!(
        created["evidence_receipts"][0]["external_delivery_completed"],
        json!(false)
    );
    assert_eq!(
        created["evidence_receipts"][0]["dpia_completed"],
        json!(false)
    );
    assert_eq!(created["advisory_review"]["status"], json!("current"));
    assert_eq!(
        created["advisory_review"]["last_drill_at"],
        json!("2026-07-09T09:30:00Z")
    );
    assert_eq!(
        created["advisory_review"]["next_review_due_at"],
        json!("2027-07-09")
    );
    assert_eq!(
        created["advisory_review"]["authority_filing_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["legal_acceptance_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["legal_certification_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["external_delivery_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["completion_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["compliance_certification_claimed"],
        json!(false)
    );

    let (status, list) = send(
        state.clone(),
        with_session(get("/v1/privacy/dpias"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list succeeds: {list}");
    let list = list.as_array().expect("dpia list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(dpia_id));

    let before_invalid =
        std::fs::read(tmp.dir.join(DPIAS_FILE)).expect("dpia sidecar before invalid");
    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dpias/{dpia_id}"),
                json!({
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "notes": "Authority filing and legal certification completed.",
                        "authority_filing_completed": true,
                        "legal_review_accepted": true,
                        "legal_certification_completed": true,
                        "external_delivery_completed": true,
                        "dpia_completed": true,
                        "compliance_certification_completed": true
                    }
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
            .contains("review evidence only")
    );
    let after_invalid =
        std::fs::read(tmp.dir.join(DPIAS_FILE)).expect("dpia sidecar after invalid");
    assert_eq!(after_invalid, before_invalid);

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dpias/{dpia_id}"),
                json!({
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "notes": "password_hash=secret",
                        "authority_filing_completed": false,
                        "legal_review_accepted": false,
                        "legal_certification_completed": false,
                        "external_delivery_completed": false,
                        "dpia_completed": false,
                        "compliance_certification_completed": false
                    }
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
    let after_sensitive_receipt =
        std::fs::read(tmp.dir.join(DPIAS_FILE)).expect("dpia sidecar after sensitive receipt");
    assert_eq!(after_sensitive_receipt, before_invalid);

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/dpias/{dpia_id}"),
                json!({
                    "status": "active",
                    "risk_level": "medium",
                    "data_categories": ["employee identifiers", "aggregated payroll metrics"],
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "occurred_at": "2026-07-09T13:00:00Z",
                        "notes": "Operator reviewed DPIA evidence locally.",
                        "authority_filing_completed": false,
                        "legal_review_accepted": false,
                        "legal_certification_completed": false,
                        "external_delivery_completed": false,
                        "dpia_completed": false,
                        "compliance_certification_completed": false
                    }
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
    assert_eq!(
        updated["evidence_receipts"]
            .as_array()
            .expect("evidence receipts")
            .len(),
        2
    );
    assert_eq!(
        updated["evidence_receipts"][1]["compliance_certification_completed"],
        json!(false)
    );
    assert_eq!(updated["advisory_review"]["status"], json!("current"));
    assert_eq!(updated["advisory_review"]["receipt_count"], json!(2));
    assert_eq!(updated["advisory_review"]["review_receipt_count"], json!(1));
    assert_eq!(updated["advisory_review"]["drill_receipt_count"], json!(1));

    let persisted: Value =
        serde_json::from_slice(&std::fs::read(tmp.dir.join(DPIAS_FILE)).expect("dpia sidecar"))
            .expect("valid dpia sidecar");
    assert_eq!(persisted.as_array().expect("persisted dpias").len(), 1);
    assert_eq!(persisted[0]["id"], json!(dpia_id));

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, restarted_list) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/dpias"), &restarted_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "list after restart: {restarted_list}"
    );
    assert_eq!(restarted_list.as_array().expect("dpia list").len(), 1);
    assert_eq!(restarted_list[0]["id"], json!(dpia_id));
    assert_eq!(
        restarted_list[0]["evidence_receipts"]
            .as_array()
            .expect("persisted receipts")
            .len(),
        2
    );
    assert_eq!(
        restarted_list[0]["advisory_review"]["compliance_certification_claimed"],
        json!(false)
    );

    let (status, events) = send(
        restarted,
        with_session(
            get("/v1/ledger/events?scope=privacy:dpia:&limit=1000"),
            &restarted_token,
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
async fn dpia_template_is_static_guidance_only_with_no_echo_or_claims() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;

    let processor_payload = json!({
        "name": "SENTINEL_LIVE_PROCESSOR_NAME",
        "purpose": "SENTINEL_LIVE_PROCESSOR_PURPOSE",
        "legal_basis": "SENTINEL_LIVE_PROCESSOR_LEGAL_BASIS",
        "data_categories": ["SENTINEL_LIVE_PROCESSOR_CATEGORY"],
        "subprocessors": ["SENTINEL_LIVE_SUBPROCESSOR_NAME"],
        "risk_level": "medium",
        "status": "active"
    });
    let (status, processor) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/processors", processor_payload),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "processor seed: {processor}");

    let dpia_payload = json!({
        "title": "SENTINEL_LIVE_DPIA_TITLE",
        "purpose": "SENTINEL_LIVE_DPIA_PURPOSE",
        "legal_basis": "SENTINEL_LIVE_DPIA_LEGAL_BASIS",
        "data_categories": ["SENTINEL_LIVE_DPIA_CATEGORY"],
        "subprocessors": ["SENTINEL_LIVE_DPIA_SUBPROCESSOR"],
        "risk_level": "high",
        "status": "under_review",
        "evidence_receipt": {
            "evidence_type": "review",
            "notes": "SENTINEL_LIVE_DPIA_NOTE",
            "authority_filing_completed": false,
            "legal_review_accepted": false,
            "legal_certification_completed": false,
            "external_delivery_completed": false,
            "dpia_completed": false,
            "compliance_certification_completed": false
        }
    });
    let (status, dpia) = send(
        state.clone(),
        with_session(post_json("/v1/privacy/dpias", dpia_payload), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "dpia seed: {dpia}");

    let (status, before_events) = send(
        state.clone(),
        with_session(get("/v1/ledger/events?limit=1000"), &owner_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ledger before template: {before_events}"
    );
    let before_event_count = before_events.as_array().expect("ledger events").len();

    let (status, template) = send(
        state.clone(),
        with_session(get("/v1/privacy/dpia-template"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "template fetch: {template}");
    assert_eq!(
        template["schema"],
        json!("chancela-privacy-dpia-template/v1")
    );
    assert_eq!(template["template_id"], json!("privacy-dpia-guidance/v1"));
    assert_eq!(template["scope"], json!("local_offline_guidance_only"));
    assert_eq!(template["local_offline_guidance_only"], json!(true));
    let section_ids: Vec<&str> = template["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|section| section["id"].as_str().expect("section id"))
        .collect();
    assert_eq!(
        section_ids,
        vec![
            "processing_description",
            "necessity_proportionality",
            "risk_prompts",
            "safeguards",
            "consultation_escalation",
            "evidence_boundaries",
        ]
    );
    assert!(
        template["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .all(|section| {
                section["prompts"]
                    .as_array()
                    .is_some_and(|prompts| !prompts.is_empty())
                    && section["checklist"]
                        .as_array()
                        .is_some_and(|checklist| !checklist.is_empty())
            }),
        "every section has prompts and checklist fields"
    );

    let no_claims = template["no_claims"].as_object().expect("no_claims object");
    for flag in [
        "authority_filing_completed",
        "authority_approval_obtained",
        "cnpd_filing_completed",
        "edpb_filing_completed",
        "cnpd_or_edpb_approval_obtained",
        "legal_review_accepted",
        "legal_validation_completed",
        "external_validation_completed",
        "external_legal_validation_completed",
        "external_delivery_completed",
        "dpia_completed",
        "dpia_completion_certified",
        "compliance_certification_completed",
        "transfer_approval_claimed",
        "transfer_execution_claimed",
        "authority_notification_claimed",
        "subject_notification_claimed",
        "automated_risk_scoring_performed",
        "risk_score_authority_claimed",
        "automated_legal_decision_made",
        "register_mutation_performed",
        "external_call_performed",
        "raw_register_contents_included",
        "processor_names_included",
        "data_subjects_included",
        "recipients_included",
        "personal_data_included",
        "secrets_included",
    ] {
        assert_eq!(no_claims.get(flag), Some(&json!(false)), "{flag} false");
    }

    let template_text = template.to_string();
    for forbidden in [
        "SENTINEL_LIVE_PROCESSOR_NAME",
        "SENTINEL_LIVE_PROCESSOR_PURPOSE",
        "SENTINEL_LIVE_PROCESSOR_LEGAL_BASIS",
        "SENTINEL_LIVE_PROCESSOR_CATEGORY",
        "SENTINEL_LIVE_SUBPROCESSOR_NAME",
        "SENTINEL_LIVE_DPIA_TITLE",
        "SENTINEL_LIVE_DPIA_PURPOSE",
        "SENTINEL_LIVE_DPIA_LEGAL_BASIS",
        "SENTINEL_LIVE_DPIA_CATEGORY",
        "SENTINEL_LIVE_DPIA_SUBPROCESSOR",
        "SENTINEL_LIVE_DPIA_NOTE",
        "password_hash",
        "recovery_phrase",
        "api_key_secret",
        "bearer_token",
    ] {
        assert!(
            !template_text.contains(forbidden),
            "template must not echo {forbidden}"
        );
    }

    let (status, after_events) = send(
        state.clone(),
        with_session(get("/v1/ledger/events?limit=1000"), &owner_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ledger after template: {after_events}"
    );
    assert_eq!(
        after_events.as_array().expect("ledger events").len(),
        before_event_count,
        "GET template does not append audit/mutation events"
    );

    let (status, dpias_after) = send(
        state.clone(),
        with_session(get("/v1/privacy/dpias"), &owner_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "dpias after template: {dpias_after}"
    );
    assert_eq!(dpias_after.as_array().expect("dpias after").len(), 1);

    let (status, processors_after) = send(
        state.clone(),
        with_session(get("/v1/privacy/processors"), &owner_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "processors after template: {processors_after}"
    );
    assert_eq!(
        processors_after.as_array().expect("processors after").len(),
        1
    );

    let status = send_status(
        state,
        with_session(
            post_json("/v1/privacy/dpia-template", json!({"claim": "mutate"})),
            &owner_token,
        ),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "DPIA template exposes no successful mutation route"
    );
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
    assert_eq!(
        created["evidence_receipts"][0]["evidence_type"],
        json!("drill")
    );
    assert_eq!(
        created["evidence_receipts"][0]["notes"],
        json!("Tabletop drill reviewed escalation paths.")
    );
    assert_eq!(
        created["evidence_receipts"][0]["authority_notified"],
        json!(false)
    );
    assert_eq!(
        created["evidence_receipts"][0]["subjects_notified"],
        json!(false)
    );
    assert_eq!(created["advisory_review"]["status"], json!("current"));
    assert_eq!(
        created["advisory_review"]["last_drill_at"],
        json!("2026-07-09T10:30:00Z")
    );
    assert_eq!(
        created["advisory_review"]["next_review_due_at"],
        json!("2027-07-09")
    );
    assert_eq!(
        created["advisory_review"]["local_advisory_only"],
        json!(true)
    );
    assert_eq!(
        created["advisory_review"]["authority_notification_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["legal_completion_claimed"],
        json!(false)
    );

    let before_invalid =
        std::fs::read(tmp.dir.join(BREACH_PLAYBOOKS_FILE)).expect("breach sidecar before invalid");
    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/breach-playbooks/{playbook_id}"),
                json!({
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "notes": "Notification completed.",
                        "authority_notified": true
                    }
                }),
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("review evidence only")
    );
    let after_invalid =
        std::fs::read(tmp.dir.join(BREACH_PLAYBOOKS_FILE)).expect("breach sidecar after invalid");
    assert_eq!(after_invalid, before_invalid);

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/breach-playbooks/{playbook_id}"),
                json!({
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "notes": "password_hash=secret",
                        "authority_notified": false,
                        "subjects_notified": false
                    }
                }),
            ),
            &settings_token,
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
    let after_sensitive_receipt = std::fs::read(tmp.dir.join(BREACH_PLAYBOOKS_FILE))
        .expect("breach sidecar after sensitive receipt");
    assert_eq!(after_sensitive_receipt, before_invalid);

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/breach-playbooks/{playbook_id}"),
                json!({
                    "status": "under_review",
                    "risk_level": "critical",
                    "containment_steps": ["Disable affected sessions", "Preserve audit evidence"],
                    "evidence_receipt": {
                        "evidence_type": "review",
                        "notes": "Operator reviewed playbook after drill.",
                        "authority_notified": false,
                        "subjects_notified": false
                    }
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
    assert_eq!(
        updated["evidence_receipts"]
            .as_array()
            .expect("evidence receipts")
            .len(),
        2
    );
    assert_eq!(
        updated["evidence_receipts"][1]["authority_notified"],
        json!(false)
    );
    assert_eq!(updated["advisory_review"]["status"], json!("under_review"));
    assert_eq!(updated["advisory_review"]["receipt_count"], json!(2));

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
    assert_eq!(
        list[0]["evidence_receipts"]
            .as_array()
            .expect("persisted receipts")
            .len(),
        2
    );
    assert_eq!(list[0]["advisory_review"]["status"], json!("under_review"));
    assert_eq!(
        list[0]["advisory_review"]["subject_notification_claimed"],
        json!(false)
    );

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
    assert_eq!(
        created["evidence_receipts"][0]["transfer_approved"],
        json!(false)
    );
    assert_eq!(
        created["evidence_receipts"][0]["data_transfer_executed"],
        json!(false)
    );
    assert_eq!(created["advisory_review"]["status"], json!("current"));
    assert_eq!(
        created["advisory_review"]["last_reviewed_at"],
        json!("2026-07-09T11:00:00Z")
    );
    assert_eq!(
        created["advisory_review"]["next_review_due_at"],
        json!("2027-07-09")
    );
    assert_eq!(
        created["advisory_review"]["transfer_approval_claimed"],
        json!(false)
    );
    assert_eq!(
        created["advisory_review"]["transfer_execution_claimed"],
        json!(false)
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

    let before_false_completion = std::fs::read(tmp.dir.join(TRANSFER_CONTROLS_FILE))
        .expect("transfer sidecar before invalid");
    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/transfer-controls/{control_id}"),
                json!({
                    "evidence_receipt": {
                        "notes": "Approved and executed.",
                        "transfer_approved": true,
                        "data_transfer_executed": true
                    }
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
            .contains("review evidence only")
    );
    let after_false_completion = std::fs::read(tmp.dir.join(TRANSFER_CONTROLS_FILE))
        .expect("transfer sidecar after invalid");
    assert_eq!(after_false_completion, before_false_completion);

    let (status, body) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/transfer-controls/{control_id}"),
                json!({
                    "evidence_receipt": {
                        "notes": "password_hash=secret",
                        "transfer_approved": false,
                        "data_transfer_executed": false
                    }
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
    let after_sensitive_receipt = std::fs::read(tmp.dir.join(TRANSFER_CONTROLS_FILE))
        .expect("transfer sidecar after sensitive receipt");
    assert_eq!(after_sensitive_receipt, before_false_completion);

    let (status, updated) = send(
        state.clone(),
        with_session(
            patch_json(
                &format!("/v1/privacy/transfer-controls/{control_id}"),
                json!({
                    "status": "active",
                    "risk_level": "high",
                    "safeguards": ["least-privilege access", "quarterly review"],
                    "evidence_receipt": {
                        "reviewed_at": "2026-07-09T12:00:00Z",
                        "notes": "Follow-up control review; no approval or transfer execution.",
                        "transfer_approved": false,
                        "data_transfer_executed": false
                    }
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
    assert_eq!(
        updated["evidence_receipts"]
            .as_array()
            .expect("evidence receipts")
            .len(),
        2
    );
    assert_eq!(
        updated["evidence_receipts"][1]["data_transfer_executed"],
        json!(false)
    );
    assert_eq!(updated["advisory_review"]["status"], json!("current"));
    assert_eq!(updated["advisory_review"]["receipt_count"], json!(2));

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
    assert_eq!(
        list[0]["evidence_receipts"]
            .as_array()
            .expect("persisted receipts")
            .len(),
        2
    );
    assert_eq!(list[0]["advisory_review"]["status"], json!("current"));
    assert_eq!(
        list[0]["advisory_review"]["transfer_execution_claimed"],
        json!(false)
    );

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
async fn retention_due_candidates_closed_book_with_active_archive_policy_becomes_due() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P10Y"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {created}"
    );
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, body) = send(
        state,
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["scope"], json!("book_archive"));
    assert_eq!(body["category"], json!("documents"));
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["record_id"], json!(book_id));
    assert_eq!(candidate["book_id"], json!(book_id));
    assert_eq!(candidate["policy_id"], json!(policy_id));
    assert_eq!(candidate["policy_name"], json!("Closed book archive"));
    assert_eq!(candidate["closing_date"], json!("2000-01-15"));
    assert_eq!(candidate["due_date"], json!("2010-01-15"));
    assert_eq!(candidate["overdue"], json!(true));
    assert_eq!(candidate["outcome"], json!("manual_review_required"));
    assert_eq!(candidate["status"], json!("awaiting_review"));
    assert_eq!(
        candidate["candidate_evidence_state"],
        json!("review_queued")
    );
    assert_eq!(
        candidate["evidence_next_step"], candidate["next_step"],
        "review-only due candidates should expose the same non-destructive next step"
    );
    assert_eq!(candidate["would_execute"], json!(false));
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));
    assert!(
        candidate["legal_hold_blockers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        candidate["required_approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|approval| approval["code"] == "retention_manual_review")
    );
}

#[tokio::test]
async fn retention_due_candidates_active_legal_hold_blocks_candidate() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, archive_policy) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P10Y"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {archive_policy}"
    );
    let (status, hold_policy) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("legal_hold", "P99Y"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "legal hold policy create: {hold_policy}"
    );
    let hold_policy_id = hold_policy["id"].as_str().expect("hold id").to_owned();

    let (status, body) = send(
        state,
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["record_id"], json!(book_id));
    assert_eq!(candidate["outcome"], json!("blocked_legal_hold"));
    assert_eq!(candidate["status"], json!("blocked"));
    assert_eq!(candidate["candidate_evidence_state"], json!("blocked"));
    assert_eq!(
        candidate["evidence_next_step"], candidate["next_step"],
        "blocked due candidates should not project prior bounded evidence as current progress"
    );
    assert_eq!(
        candidate["legal_hold_blockers"][0]["source"],
        json!("retention_policy")
    );
    assert_eq!(
        candidate["legal_hold_blockers"][0]["policy_id"],
        json!(hold_policy_id)
    );
    assert!(
        candidate["required_approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|approval| approval["code"] == "legal_hold_owner_release")
    );
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));
}

#[tokio::test]
async fn retention_due_candidates_destructive_policy_returns_approval_metadata_and_false_flags() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("delete", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "destructive policy create: {created}"
    );

    let (status, body) = send(
        state,
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["disposal_action"], json!("delete"));
    assert_eq!(candidate["destructive_action"], json!(true));
    assert_eq!(candidate["outcome"], json!("blocked_destructive_action"));
    assert_eq!(candidate["status"], json!("blocked"));
    assert_eq!(candidate["candidate_evidence_state"], json!("blocked"));
    assert_eq!(candidate["evidence_next_step"], candidate["next_step"]);
    assert_eq!(candidate["would_execute"], json!(false));
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));
    assert!(
        candidate["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == "destructive_action_disabled")
    );
    assert!(
        candidate["required_approvals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|approval| approval["code"] == "destructive_disposal_governance")
    );
}

#[tokio::test]
async fn retention_due_candidates_unsupported_retention_period_fails_closed() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    insert_closed_book(&state, date(2026, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "10 years"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "unsupported period policy create: {created}"
    );

    let (status, body) = send(
        state,
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["due_date"], Value::Null);
    assert_eq!(candidate["overdue"], json!(false));
    assert_eq!(candidate["outcome"], json!("unsupported_retention_period"));
    assert_eq!(candidate["status"], json!("blocked"));
    assert_eq!(candidate["candidate_evidence_state"], json!("blocked"));
    assert_eq!(candidate["evidence_next_step"], candidate["next_step"]);
    assert!(
        candidate["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "unsupported_retention_period")
    );
    assert!(
        candidate["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == "unsupported_retention_period")
    );
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));
}

#[tokio::test]
async fn retention_due_candidates_get_is_non_mutating() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {created}"
    );
    let execution_count_before = state.retention_execution_records.read().await.len();
    let ledger_count_before = state.ledger.read().await.events().len();
    let books_before = state.books.read().await.clone();

    let (status, body) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));

    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before,
        "GET must not write retention execution records"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before,
        "GET must not append audit events"
    );
    assert_eq!(
        *state.books.read().await,
        books_before,
        "GET must not mutate books"
    );
}

#[tokio::test]
async fn retention_candidate_resolution_records_evidence_only_and_projects_latest() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "policy create: {created}");

    let (status, due_before) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "due candidates before: {due_before}"
    );
    let candidate = &due_before["candidates"][0];
    let candidate_id = candidate["candidate_id"]
        .as_str()
        .expect("candidate id")
        .to_owned();
    let candidate_fingerprint = candidate["candidate_fingerprint"]
        .as_str()
        .expect("candidate fingerprint")
        .to_owned();

    let (status, recorded) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-due-candidates/{candidate_id}/resolution"),
                json!({
                    "candidate_fingerprint": candidate_fingerprint,
                    "disposition": "evidence_acknowledged",
                    "note": "Evidence reviewed locally for follow-up queue.",
                    "evidence": [
                        {
                            "label": "candidate_review",
                            "value": "candidate evidence checked only"
                        }
                    ],
                    "destructive_disposal_completed": false,
                    "disposal_completed": false,
                    "full_erasure_completed": false,
                    "erasure_completed": false,
                    "legal_hold_mutated": false,
                    "legal_hold_resolved": false,
                    "retention_policy_mutated": false,
                    "retention_policy_changed": false,
                    "legal_completion_claimed": false,
                    "legal_disposal_completed": false
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "resolution record: {recorded}");
    let resolution_id = recorded["id"].as_str().expect("resolution id").to_owned();
    assert_eq!(recorded["candidate_id"], json!(candidate_id));
    assert_eq!(recorded["candidate"]["record_id"], json!(book_id));
    assert_eq!(recorded["disposition"], json!("evidence_acknowledged"));
    assert_eq!(recorded["evidence_only"], json!(true));
    assert_eq!(recorded["destructive_disposal_completed"], json!(false));
    assert_eq!(recorded["disposal_completed"], json!(false));
    assert_eq!(recorded["full_erasure_completed"], json!(false));
    assert_eq!(recorded["erasure_completed"], json!(false));
    assert_eq!(recorded["legal_hold_mutated"], json!(false));
    assert_eq!(recorded["legal_hold_resolved"], json!(false));
    assert_eq!(recorded["retention_policy_mutated"], json!(false));
    assert_eq!(recorded["retention_policy_changed"], json!(false));
    assert_eq!(recorded["legal_completion_claimed"], json!(false));
    assert_eq!(recorded["legal_disposal_completed"], json!(false));
    assert!(tmp.dir.join(RETENTION_CANDIDATE_RESOLUTIONS_FILE).is_file());

    let (status, due_after) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates after: {due_after}");
    assert_eq!(due_after["candidate_count"], json!(1));
    assert_eq!(due_after["candidate_resolution_record_count"], json!(1));
    assert_eq!(due_after["candidates_with_resolution_count"], json!(1));
    let candidate_after = &due_after["candidates"][0];
    assert_eq!(candidate_after["candidate_id"], json!(candidate_id));
    assert_eq!(
        candidate_after["candidate_resolution_record_count"],
        json!(1)
    );
    assert_eq!(
        candidate_after["latest_resolution"]["id"],
        json!(resolution_id)
    );
    assert_eq!(
        candidate_after["latest_resolution"]["disposition"],
        json!("evidence_acknowledged")
    );
    assert_eq!(
        candidate_after["latest_resolution"]["destructive_disposal_completed"],
        json!(false)
    );

    let (status, records) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-candidate-resolutions"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolution list: {records}");
    let records = records.as_array().expect("resolution list");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], json!(resolution_id));

    let (status, events) = send(
        state.clone(),
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-candidate-resolution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    let events = events.as_array().expect("events");
    assert!(events.iter().any(|event| {
        event["kind"] == "privacy.retention.candidate.resolution.recorded"
            && event["scope"]
                == json!(format!(
                    "privacy:retention-candidate-resolution:{resolution_id}"
                ))
            && event["actor"] == json!("owner")
            && event.get("payload").is_none()
    }));

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, restarted_records) = send(
        restarted,
        with_session(
            get("/v1/privacy/retention-candidate-resolutions"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "resolution list after restart: {restarted_records}"
    );
    assert_eq!(restarted_records.as_array().expect("records").len(), 1);
    assert_eq!(restarted_records[0]["id"], json!(resolution_id));
}

#[tokio::test]
async fn retention_candidate_resolution_rejects_stale_flags_and_overclaim_terms() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("delete", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "destructive policy: {created}");

    let (status, due) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates: {due}");
    let candidate = &due["candidates"][0];
    let candidate_id = candidate["candidate_id"].as_str().expect("candidate id");
    let candidate_fingerprint = candidate["candidate_fingerprint"]
        .as_str()
        .expect("candidate fingerprint");

    let uri = format!("/v1/privacy/retention-due-candidates/{candidate_id}/resolution");
    let base = json!({
        "candidate_fingerprint": candidate_fingerprint,
        "disposition": "blocked_follow_up",
        "note": "Blocked follow-up evidence recorded for governance queue."
    });

    let (status, bad_fingerprint) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "candidate_fingerprint": "0".repeat(64),
                    "disposition": "blocked_follow_up",
                    "note": "Blocked follow-up evidence recorded for governance queue."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        bad_fingerprint["error"]
            .as_str()
            .expect("error")
            .contains("stale")
    );

    let (status, acknowledged_blocked) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "candidate_fingerprint": candidate_fingerprint,
                    "disposition": "evidence_acknowledged",
                    "note": "Evidence reviewed locally for follow-up queue."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        acknowledged_blocked["error"]
            .as_str()
            .expect("error")
            .contains("can only record follow-up evidence")
    );

    let mut true_flag = base.clone();
    true_flag["destructive_disposal_completed"] = json!(true);
    let (status, true_flag_body) = send(
        state.clone(),
        with_session(post_json(&uri, true_flag), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        true_flag_body["error"]
            .as_str()
            .expect("error")
            .contains("cannot be true")
    );

    let (status, overclaim) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "candidate_fingerprint": candidate_fingerprint,
                    "disposition": "blocked_follow_up",
                    "note": "Deleted records completed."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        overclaim["error"]
            .as_str()
            .expect("error")
            .contains("cannot claim")
    );

    for (claim, body) in [
        (
            "records anonymized",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Records anonymized."
            }),
        ),
        (
            "document redacted",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Blocked follow-up evidence recorded for governance queue.",
                "evidence": [
                    {
                        "label": "candidate_review",
                        "value": "Document redacted."
                    }
                ]
            }),
        ),
        (
            "legal hold mutation recorded",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Legal hold mutation recorded."
            }),
        ),
        (
            "retention policy mutation recorded",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Blocked follow-up evidence recorded for governance queue.",
                "evidence": [
                    {
                        "label": "candidate_review",
                        "value": "Retention policy mutation recorded."
                    }
                ]
            }),
        ),
        (
            "GDPR erasure completed",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "GDPR erasure completed."
            }),
        ),
        (
            "legal disposal performed",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Legal disposal performed."
            }),
        ),
        (
            "legal completion recorded",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Legal completion recorded."
            }),
        ),
        (
            "legal approval recorded",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Legal approval recorded."
            }),
        ),
        (
            "legal resolution recorded",
            json!({
                "candidate_fingerprint": candidate_fingerprint,
                "disposition": "blocked_follow_up",
                "note": "Legal resolution recorded."
            }),
        ),
    ] {
        let (status, rejected) = send(
            state.clone(),
            with_session(post_json(&uri, body), &owner_token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{claim}: {rejected}"
        );
        assert!(
            rejected["error"]
                .as_str()
                .expect("error")
                .contains("cannot claim"),
            "{claim}: {rejected}"
        );
    }

    let (status, unknown) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-due-candidates/missing-candidate/resolution",
                base,
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown candidate: {unknown}"
    );
    assert!(
        state
            .retention_candidate_resolutions
            .read()
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn retention_candidate_resolution_blocks_legal_hold_acknowledgement_but_allows_follow_up() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, archive_policy) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy: {archive_policy}"
    );
    let (status, hold_policy) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("legal_hold", "P99Y"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "legal hold policy: {hold_policy}"
    );

    let (status, due) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates: {due}");
    let candidate = &due["candidates"][0];
    assert_eq!(candidate["status"], json!("blocked"));
    assert!(
        !candidate["legal_hold_blockers"]
            .as_array()
            .expect("legal hold blockers")
            .is_empty()
    );
    let candidate_id = candidate["candidate_id"].as_str().expect("candidate id");
    let candidate_fingerprint = candidate["candidate_fingerprint"]
        .as_str()
        .expect("candidate fingerprint");
    let uri = format!("/v1/privacy/retention-due-candidates/{candidate_id}/resolution");

    let (status, acknowledged) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "candidate_fingerprint": candidate_fingerprint,
                    "disposition": "evidence_acknowledged",
                    "note": "Evidence reviewed locally for follow-up queue."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        acknowledged["error"]
            .as_str()
            .expect("error")
            .contains("can only record follow-up evidence")
    );

    let (status, recorded) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "candidate_fingerprint": candidate_fingerprint,
                    "disposition": "blocked_follow_up",
                    "note": "Blocked follow-up evidence recorded for governance queue.",
                    "legal_hold_resolved": false
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "blocked follow-up: {recorded}");
    assert_eq!(recorded["disposition"], json!("blocked_follow_up"));
    assert_eq!(recorded["legal_hold_resolved"], json!(false));
    assert_eq!(state.retention_candidate_resolutions.read().await.len(), 1);
}

#[tokio::test]
async fn retention_due_candidates_surface_existing_review_without_mutation() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {created}"
    );
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, review) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "book_archive",
                    "category": "documents",
                    "record_id": book_id,
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "execution_mode": "review_only",
                        "operator_notes": "Queue closed-book review evidence."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "review-only request: {review}");
    let execution_record = &review["execution_record"];
    assert_eq!(
        execution_record["execution_status"],
        json!("awaiting_review")
    );
    assert_eq!(execution_record["outcome"], json!("manual_review_required"));
    assert_eq!(execution_record["evidence_state"], json!("review_queued"));
    assert_eq!(
        execution_record["evidence_next_step"],
        execution_record["workflow"]["next_step"]
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert!(
        execution_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .is_empty()
    );
    assert_eq!(
        execution_record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        execution_record["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    let execution_count_before = state.retention_execution_records.read().await.len();
    let ledger_count_before = state.ledger.read().await.events().len();
    let books_before = state.books.read().await.clone();

    let (status, body) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["record_id"], json!(book_id));
    assert_eq!(candidate["policy_id"], json!(policy_id));
    assert_eq!(candidate["status"], execution_record["execution_status"]);
    assert_eq!(candidate["outcome"], execution_record["outcome"]);
    assert_eq!(
        candidate["candidate_evidence_state"],
        json!("review_queued")
    );
    assert_eq!(
        candidate["evidence_next_step"],
        execution_record["evidence_next_step"]
    );
    assert_eq!(candidate["would_execute"], json!(false));
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));

    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before,
        "GET must not write another retention execution record"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before,
        "GET must not append audit events"
    );
    assert_eq!(
        *state.books.read().await,
        books_before,
        "GET must not mutate books"
    );
}

#[tokio::test]
async fn retention_due_candidates_suppress_prior_bounded_archive_without_mutation() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {created}"
    );
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, execution) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "book_archive",
                    "category": "documents",
                    "record_id": book_id,
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "execution_mode": "execute_supported",
                        "operator_notes": "Record bounded archive evidence for the closed book."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bounded execution: {execution}");
    let execution_record = &execution["execution_record"];
    let execution_id = execution_record["id"]
        .as_str()
        .expect("execution id")
        .to_owned();
    assert_eq!(
        execution_record["outcome"],
        json!("bounded_archive_recorded")
    );
    assert_eq!(execution_record["execution_status"], json!("executed"));
    assert_eq!(
        execution_record["evidence_state"],
        json!("bounded_archive_recorded")
    );
    assert_eq!(
        execution_record["evidence_next_step"],
        json!("Bounded archive evidence recorded; no destructive operation was performed.")
    );
    assert_eq!(
        execution_record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        execution_record["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    {
        let mut records = state.retention_execution_records.write().await;
        let record = records
            .get_mut(&execution_id)
            .expect("persisted execution record");
        record.execution_result.next_step =
            "Legal disposal completed: source document deletion, anonymization, dispatch, and full erasure completed."
                .to_owned();
    }

    let execution_count_before = state.retention_execution_records.read().await.len();
    let ledger_count_before = state.ledger.read().await.events().len();
    let books_before = state.books.read().await.clone();

    let (status, body) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(0));
    assert_eq!(body["candidates"], json!([]));
    assert_eq!(body["suppressed_candidate_count"], json!(1));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(1));
    assert_eq!(
        body["suppression_summary"]["suppressed_by_bounded_evidence_count"],
        json!(1)
    );
    let suppression_note = body["suppression_summary"]["note"]
        .as_str()
        .expect("suppression summary note");
    for unsafe_term in [
        "deletion",
        "anonymization",
        "legal disposal",
        "dispatch",
        "full erasure",
        "completed",
    ] {
        assert!(
            !suppression_note.to_lowercase().contains(unsafe_term),
            "suppression summary must not surface unsafe term {unsafe_term:?}: {suppression_note}"
        );
    }

    assert_ne!(
        suppression_note,
        "Legal disposal completed: source document deletion, anonymization, dispatch, and full erasure completed."
    );

    let (status, history) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=executed"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "execution history lists: {history}");
    let history = history.as_array().expect("execution history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["id"], json!(execution_id));
    assert_eq!(history[0]["execution_status"], json!("executed"));
    assert_eq!(history[0]["outcome"], json!("bounded_archive_recorded"));
    assert_eq!(
        history[0]["execution_result"]["bounded_executor"],
        json!(true)
    );
    assert_eq!(
        history[0]["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .len(),
        1
    );
    assert_eq!(
        history[0]["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        history[0]["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before,
        "GET must not write another retention execution record"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before,
        "GET must not append audit events"
    );
    assert_eq!(
        *state.books.read().await,
        books_before,
        "GET must not mutate books"
    );
}

#[tokio::test]
async fn retention_due_candidates_ignore_unsafe_prior_bounded_execution_flags() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("archive", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "archive policy create: {created}"
    );
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, execution) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "book_archive",
                    "category": "documents",
                    "record_id": book_id,
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "execution_mode": "execute_supported",
                        "operator_notes": "Record bounded archive evidence for the closed book."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bounded execution: {execution}");
    let execution_id = execution["execution_record"]["id"]
        .as_str()
        .expect("execution id")
        .to_owned();

    {
        let mut records = state.retention_execution_records.write().await;
        let record = records
            .get_mut(&execution_id)
            .expect("persisted execution record");
        record.execution_result.bounded_executor = false;
        record.execution_result.targets_acted.clear();
        record.execution_result.destructive_disposal_completed = true;
        record.execution_result.full_erasure_completed = true;
    }

    let (status, body) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(1));
    assert_eq!(body["suppressed_candidate_count"], json!(0));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(0));
    let candidate = &body["candidates"][0];
    assert_eq!(candidate["record_id"], json!(book_id));
    assert_eq!(candidate["policy_id"], json!(policy_id));
    assert_eq!(
        candidate["candidate_evidence_state"],
        json!("review_queued")
    );
    assert_eq!(candidate["evidence_next_step"], candidate["next_step"]);
    assert_eq!(candidate["would_execute"], json!(false));
    assert_eq!(candidate["destructive_disposal_completed"], json!(false));
    assert_eq!(candidate["full_erasure_completed"], json!(false));
    assert!(
        !candidate
            .as_object()
            .expect("candidate object")
            .contains_key("prior_execution"),
        "unsafe persisted execution flags must not be projected"
    );
}

#[tokio::test]
async fn retention_due_candidates_suppress_prior_bounded_no_action_without_mutation() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                archive_retention_policy_payload("no_action", "P1D"),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "no-action policy create: {created}"
    );
    let policy_id = created["id"].as_str().expect("policy id").to_owned();

    let (status, execution) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "book_archive",
                    "category": "documents",
                    "record_id": book_id,
                    "execution_request": {
                        "requested_policy_id": policy_id,
                        "execution_mode": "execute_supported",
                        "operator_notes": "Record bounded no-action evidence for the closed book."
                    }
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bounded no action: {execution}");
    let execution_record = &execution["execution_record"];
    let execution_id = execution_record["id"]
        .as_str()
        .expect("execution id")
        .to_owned();
    assert_eq!(
        execution_record["outcome"],
        json!("bounded_no_action_recorded")
    );
    assert_eq!(execution_record["execution_status"], json!("executed"));
    assert_eq!(
        execution_record["evidence_state"],
        json!("bounded_no_action_recorded")
    );
    assert_eq!(
        execution_record["evidence_next_step"],
        json!("Bounded no-action evidence recorded; no destructive operation was performed.")
    );
    assert_eq!(
        execution_record["execution_result"]["bounded_executor"],
        json!(true)
    );
    assert_eq!(
        execution_record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        execution_record["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    let execution_count_before = state.retention_execution_records.read().await.len();
    let ledger_count_before = state.ledger.read().await.events().len();
    let books_before = state.books.read().await.clone();

    let (status, body) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates list: {body}");
    assert_eq!(body["candidate_count"], json!(0));
    assert_eq!(body["candidates"], json!([]));
    assert_eq!(body["suppressed_candidate_count"], json!(1));
    assert_eq!(body["suppressed_by_bounded_evidence_count"], json!(1));
    assert_eq!(
        body["suppression_summary"]["suppressed_by_bounded_evidence_count"],
        json!(1)
    );
    assert_eq!(
        body["suppression_summary"]["note"],
        json!(
            "Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review."
        )
    );

    let (status, history) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=executed"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "execution history lists: {history}");
    let history = history.as_array().expect("execution history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["id"], json!(execution_id));
    assert_eq!(history[0]["execution_status"], json!("executed"));
    assert_eq!(history[0]["outcome"], json!("bounded_no_action_recorded"));
    assert_eq!(
        history[0]["execution_result"]["bounded_executor"],
        json!(true)
    );
    assert_eq!(
        history[0]["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .len(),
        1
    );
    assert_eq!(
        history[0]["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        history[0]["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before,
        "GET must not write another retention execution record"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before,
        "GET must not append audit events"
    );
    assert_eq!(
        *state.books.read().await,
        books_before,
        "GET must not mutate books"
    );
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
    assert_eq!(dry_run["execution_supported"], json!(true));
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
                        "execution_mode": "execute_supported",
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
    assert_eq!(
        execution_record["execution_intent"],
        json!("execute_supported")
    );
    assert_eq!(execution_record["execution_status"], json!("blocked"));
    assert_eq!(
        execution_record["operator_review_decision"],
        json!("blocked")
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(execution_record["workflow"]["status"], json!("blocked"));
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["code"],
        json!("destructive_action_disabled")
    );
    assert!(
        execution_record["execution_result"]["reason_codes"]
            .as_array()
            .expect("reason codes")
            .iter()
            .any(|code| code == &json!("destructive_disposal_approval_required"))
    );
    assert!(
        execution_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .is_empty()
    );
    assert_eq!(
        execution_record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        execution_record["execution_result"]["full_erasure_completed"],
        json!(false)
    );
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["policy_id"],
        json!(policy_id)
    );
    assert_eq!(
        execution_record["workflow"]["required_approvals"][0]["code"],
        json!("retention_manual_review")
    );
    assert_eq!(
        execution_record["workflow"]["required_approvals"][1]["code"],
        json!("destructive_disposal_governance")
    );
    assert!(
        execution_record["workflow"]["next_step"]
            .as_str()
            .expect("next step")
            .contains("will not execute")
    );
    assert_eq!(
        execution_record["operator_notes"],
        json!("Operator reviewed the retention candidate.")
    );
    assert_eq!(
        execution_record["audit_evidence"][0]["label"],
        json!("case")
    );
    assert_eq!(
        execution_record["audit_evidence"][0]["value"],
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
    assert_eq!(history[0]["workflow"]["status"], json!("blocked"));

    let (status, blocked_history) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=blocked"),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "blocked execution history filters: {blocked_history}"
    );
    let blocked_history = blocked_history.as_array().expect("blocked history");
    assert_eq!(blocked_history.len(), 1);
    assert_eq!(blocked_history[0]["id"], json!(execution_id));

    let (status, awaiting_history) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=awaiting"),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "awaiting execution history filters: {awaiting_history}"
    );
    assert!(
        awaiting_history
            .as_array()
            .expect("awaiting history")
            .is_empty()
    );

    let (status, invalid_history) = send(
        state.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=destroy"),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid execution history filter is rejected: {invalid_history}"
    );

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
    assert_eq!(execution_record["execution_intent"], json!("review_only"));
    assert_eq!(
        execution_record["execution_status"],
        json!("awaiting_review")
    );
    assert_eq!(
        execution_record["operator_review_decision"],
        json!("review_required")
    );
    assert_eq!(execution_record["outcome"], json!("manual_review_required"));
    assert_eq!(execution_record["evidence_state"], json!("review_queued"));
    assert_eq!(
        execution_record["evidence_next_step"],
        execution_record["workflow"]["next_step"]
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(
        execution_record["workflow"]["status"],
        json!("awaiting_manual_review")
    );
    assert!(
        execution_record["workflow"]["blockers"]
            .as_array()
            .expect("workflow blockers")
            .is_empty()
    );
    assert_eq!(
        execution_record["workflow"]["required_approvals"][0]["code"],
        json!("retention_manual_review")
    );
    assert!(
        execution_record["legal_hold_blockers"]
            .as_array()
            .expect("legal hold blockers")
            .is_empty()
    );
    assert!(
        execution_record["audit_evidence"]
            .as_array()
            .expect("audit evidence")
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
async fn retention_review_only_duplicate_returns_existing_queue_without_new_history_or_ledger() {
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

    let first_request = json!({
        "scope": "document",
        "category": "signed_pdf",
        "record_id": "doc-review-duplicate",
        "execution_request": {
            "requested_policy_id": policy_id,
            "execution_mode": "review_only",
            "operator_notes": "Initial manual review evidence captured."
        }
    });

    let (status, first) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies/dry-run", first_request),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first review request: {first}");
    let first_record = &first["execution_record"];
    let first_execution_id = first_record["id"]
        .as_str()
        .expect("first execution id")
        .to_owned();
    let first_requested_at = first_record["requested_at"]
        .as_str()
        .expect("first requested_at")
        .to_owned();
    assert_eq!(first_record["execution_intent"], json!("review_only"));
    assert_eq!(first_record["execution_status"], json!("awaiting_review"));
    assert_eq!(first_record["outcome"], json!("manual_review_required"));
    assert_eq!(first_record["would_execute"], json!(false));
    assert!(
        first_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("first acted targets")
            .is_empty()
    );

    let execution_count_before_duplicate = state.retention_execution_records.read().await.len();
    let ledger_count_before_duplicate = state.ledger.read().await.events().len();

    let duplicate_request = json!({
        "scope": "document",
        "category": "signed_pdf",
        "record_id": "doc-review-duplicate",
        "execution_request": {
            "requested_policy_id": policy_id,
            "execution_mode": "review_only",
            "operator_notes": "Second request must not replace the queued review."
        }
    });
    let (status, duplicate) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies/dry-run", duplicate_request),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duplicate review request: {duplicate}"
    );
    let duplicate_record = &duplicate["execution_record"];
    assert_eq!(duplicate_record["id"], json!(first_execution_id));
    assert_eq!(duplicate_record["requested_at"], json!(first_requested_at));
    assert_eq!(
        duplicate_record["operator_notes"],
        json!("Initial manual review evidence captured.")
    );
    assert_eq!(duplicate_record["execution_intent"], json!("review_only"));
    assert_eq!(
        duplicate_record["execution_status"],
        json!("awaiting_review")
    );
    assert_eq!(duplicate_record["outcome"], json!("manual_review_required"));
    assert_ne!(duplicate_record["outcome"], json!("already_executed"));
    assert_eq!(duplicate_record["would_execute"], json!(false));
    assert!(
        duplicate_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("duplicate acted targets")
            .is_empty()
    );
    assert_eq!(
        duplicate_record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        duplicate_record["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before_duplicate,
        "duplicate review request must not write another execution record"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before_duplicate,
        "duplicate review request must not append another ledger event"
    );

    let (status, history) = send(
        state,
        with_session(get("/v1/privacy/retention-executions"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history: {history}");
    let matching = history
        .as_array()
        .expect("history")
        .iter()
        .filter(|record| {
            record["candidate"]["record_id"] == json!("doc-review-duplicate")
                && record["requested_policy"]["id"].as_str() == Some(policy_id.as_str())
        })
        .count();
    assert_eq!(matching, 1);
}

#[tokio::test]
async fn retention_execution_review_closure_records_review_only_and_idempotent_duplicate() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;
    let (_settings_user, settings_token) = add_settings_manager(&state).await;

    let (_policy_id, execution_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        retention_policy_payload("review", "active"),
        "document",
        "signed_pdf",
        "doc-review-close",
        "review_only",
    )
    .await;
    let execution_id = execution_record["id"]
        .as_str()
        .expect("execution id")
        .to_owned();
    assert_eq!(
        execution_record["execution_status"],
        json!("awaiting_review")
    );
    assert_eq!(execution_record["outcome"], json!("manual_review_required"));
    assert_eq!(execution_record["decision_state"], json!("open"));

    let ledger_count_before = state.ledger.read().await.events().len();
    let close_payload = retention_review_closure_payload(
        "review_evidence_acknowledged",
        "  Manual queue evidence acknowledged.  ",
    );
    let (status, closed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{execution_id}/review-closure"),
                close_payload,
            ),
            &settings_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "review closure: {closed}");
    assert_eq!(closed["id"], json!(execution_id));
    assert_eq!(closed["execution_status"], json!("awaiting_review"));
    assert_eq!(closed["outcome"], json!("manual_review_required"));
    assert_eq!(closed["decision_state"], json!("review_closed"));
    assert_eq!(
        closed["review_closure_decision"],
        json!("review_evidence_acknowledged")
    );
    assert_eq!(
        closed["review_closure_note"],
        json!("Manual queue evidence acknowledged.")
    );
    assert_eq!(
        closed["review_closure_evidence"][0]["label"],
        json!("checklist")
    );
    assert_eq!(
        closed["review_closure_evidence"][0]["value"],
        json!("operator evidence acknowledged")
    );
    assert_eq!(closed["review_closed_by"], json!("settings-manager"));
    let first_closed_at = closed["review_closed_at"]
        .as_str()
        .expect("closed timestamp")
        .to_owned();
    assert_eq!(closed["destructive_disposal_completed"], json!(false));
    assert_eq!(closed["full_erasure_completed"], json!(false));
    assert_eq!(closed["legal_hold_mutated"], json!(false));
    assert_eq!(closed["retention_policy_mutated"], json!(false));
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before + 1,
        "first closure records exactly one ledger event"
    );

    let ledger_count_before_repeat = state.ledger.read().await.events().len();
    let idempotent_payload = json!({
        "operator_decision": "review_evidence_acknowledged",
        "closure_note": "Manual queue evidence acknowledged.",
        "closure_evidence": [
            {
                "label": "checklist",
                "value": "operator evidence acknowledged"
            }
        ]
    });
    let (status, repeat) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{execution_id}/review-closure"),
                idempotent_payload,
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "idempotent closure: {repeat}");
    assert_eq!(repeat["id"], json!(execution_id));
    assert_eq!(repeat["review_closed_by"], json!("settings-manager"));
    assert_eq!(repeat["review_closed_at"], json!(first_closed_at));
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before_repeat,
        "idempotent duplicate must not append another ledger event"
    );

    let (status, conflict) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{execution_id}/review-closure"),
                retention_review_closure_payload(
                    "review_evidence_acknowledged",
                    "Different closure evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "different closure: {conflict}"
    );

    let (status, history) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-executions"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history: {history}");
    let closed_history = history
        .as_array()
        .expect("history")
        .iter()
        .find(|record| record["id"] == json!(execution_id))
        .expect("closed record remains queryable");
    assert_eq!(closed_history["decision_state"], json!("review_closed"));
    assert_eq!(
        closed_history["review_closure_decision"],
        json!("review_evidence_acknowledged")
    );

    let (status, events) = send(
        state,
        with_session(
            get("/v1/ledger/events?scope=privacy:retention-execution:&limit=1000"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    assert_eq!(
        events
            .as_array()
            .expect("events")
            .iter()
            .filter(|event| {
                event["kind"] == json!("privacy.retention.execution.review.closed")
                    && event["scope"]
                        == json!(format!("privacy:retention-execution:{execution_id}"))
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn retention_execution_review_closure_accepts_bounded_and_blocked_categories() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

    let (_archive_policy, archive_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        retention_policy_payload("archive", "active"),
        "document",
        "signed_pdf",
        "doc-archive-close",
        "execute_supported",
    )
    .await;
    let archive_id = archive_record["id"].as_str().expect("archive id");
    assert_eq!(archive_record["outcome"], json!("bounded_archive_recorded"));
    let (status, archive_closed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{archive_id}/review-closure"),
                retention_review_closure_payload(
                    "bounded_evidence_acknowledged",
                    "Bounded archive evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "archive closure: {archive_closed}");
    assert_eq!(archive_closed["execution_status"], json!("executed"));
    assert_eq!(
        archive_closed["review_closure_decision"],
        json!("bounded_evidence_acknowledged")
    );
    assert_eq!(
        archive_closed["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(archive_closed["full_erasure_completed"], json!(false));

    let (_no_action_policy, no_action_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        retention_policy_payload("no_action", "active"),
        "document",
        "signed_pdf",
        "doc-no-action-close",
        "execute_supported",
    )
    .await;
    let no_action_id = no_action_record["id"].as_str().expect("no-action id");
    assert_eq!(
        no_action_record["outcome"],
        json!("bounded_no_action_recorded")
    );
    let (status, no_action_closed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{no_action_id}/review-closure"),
                retention_review_closure_payload(
                    "bounded_evidence_acknowledged",
                    "Bounded no-action evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "no-action closure: {no_action_closed}"
    );
    assert_eq!(
        no_action_closed["review_closure_decision"],
        json!("bounded_evidence_acknowledged")
    );

    let (_blocked_policy, blocked_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        retention_policy_payload("delete", "active"),
        "document",
        "signed_pdf",
        "doc-blocked-close",
        "execute_supported",
    )
    .await;
    let blocked_id = blocked_record["id"].as_str().expect("blocked id");
    assert_eq!(
        blocked_record["outcome"],
        json!("blocked_destructive_action")
    );
    let (status, mismatch) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{blocked_id}/review-closure"),
                retention_review_closure_payload(
                    "review_evidence_acknowledged",
                    "Blocked evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "wrong closure decision: {mismatch}"
    );

    let (status, blocked_closed) = send(
        state,
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{blocked_id}/review-closure"),
                retention_review_closure_payload(
                    "blocked_evidence_acknowledged",
                    "Blocked evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "blocked closure: {blocked_closed}");
    assert_eq!(blocked_closed["execution_status"], json!("blocked"));
    assert_eq!(
        blocked_closed["review_closure_decision"],
        json!("blocked_evidence_acknowledged")
    );
    assert_eq!(blocked_closed["legal_hold_mutated"], json!(false));
    assert_eq!(blocked_closed["retention_policy_mutated"], json!(false));
}

#[tokio::test]
async fn retention_execution_review_closure_rejects_claims_flags_unknowns_and_authz() {
    let (state, _target, owner_token, _reader, reader_token) = fixture_state().await;

    let (_policy_id, execution_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        retention_policy_payload("review", "active"),
        "document",
        "signed_pdf",
        "doc-review-close-validation",
        "review_only",
    )
    .await;
    let execution_id = execution_record["id"].as_str().expect("execution id");
    let uri = format!("/v1/privacy/retention-executions/{execution_id}/review-closure");

    let (status, denied) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                retention_review_closure_payload(
                    "review_evidence_acknowledged",
                    "Manual evidence acknowledged.",
                ),
            ),
            &reader_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {denied}");

    let (status, missing_decision) = send(
        state.clone(),
        with_session(
            post_json(&uri, json!({ "review_closure_note": "Evidence only." })),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing decision: {missing_decision}"
    );

    let (status, missing_evidence) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({ "operator_decision": "review_evidence_acknowledged" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing note/evidence: {missing_evidence}"
    );

    let (status, true_flag) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "operator_decision": "review_evidence_acknowledged",
                    "review_closure_note": "Evidence only.",
                    "destructive_disposal_completed": true
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "true flag rejected: {true_flag}"
    );

    let (status, claim_terms) = send(
        state.clone(),
        with_session(
            post_json(
                &uri,
                json!({
                    "operator_decision": "review_evidence_acknowledged",
                    "review_closure_note": "Legal approval resolved deletion and erasure."
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "claim terms rejected: {claim_terms}"
    );

    let (status, unknown_field) = send(
        state,
        with_session(
            post_json(
                &uri,
                json!({
                    "operator_decision": "review_evidence_acknowledged",
                    "review_closure_note": "Evidence only.",
                    "legal_approval": false
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown field rejected: {unknown_field}"
    );
    assert!(
        unknown_field["error"]
            .as_str()
            .expect("error")
            .contains("unknown field")
    );
}

#[tokio::test]
async fn retention_execution_review_closure_persists_and_due_candidates_stay_non_mutating() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (owner, owner_token) = bootstrap_owner(&state).await;
    let book_id = insert_closed_book(&state, date(2000, Month::January, 15)).await;

    let (_policy_id, execution_record) = create_retention_execution_for_closure(
        &state,
        &owner_token,
        archive_retention_policy_payload("archive", "P1D"),
        "book_archive",
        "documents",
        &book_id,
        "review_only",
    )
    .await;
    let execution_id = execution_record["id"]
        .as_str()
        .expect("execution id")
        .to_owned();

    let (status, closed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/retention-executions/{execution_id}/review-closure"),
                retention_review_closure_payload(
                    "review_evidence_acknowledged",
                    "Due candidate evidence acknowledged.",
                ),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "closure persists: {closed}");
    assert_eq!(closed["decision_state"], json!("review_closed"));
    assert!(tmp.dir.join(RETENTION_EXECUTIONS_FILE).is_file());

    let execution_count_before_due = state.retention_execution_records.read().await.len();
    let ledger_count_before_due = state.ledger.read().await.events().len();
    let books_before_due = state.books.read().await.clone();
    let (status, due) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-due-candidates"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "due candidates: {due}");
    assert_eq!(due["candidate_count"], json!(1));
    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before_due,
        "due-candidate GET must not write execution records"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before_due,
        "due-candidate GET must not append ledger events"
    );
    assert_eq!(
        *state.books.read().await,
        books_before_due,
        "due-candidate GET must not mutate books"
    );

    let restarted = AppState::with_data_dir(tmp.dir.clone());
    let restarted_token = open_session(&restarted, owner).await;
    let (status, history) = send(
        restarted.clone(),
        with_session(get("/v1/privacy/retention-executions"), &restarted_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history after restart: {history}");
    let history = history.as_array().expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["id"], json!(execution_id));
    assert_eq!(history[0]["decision_state"], json!("review_closed"));
    assert_eq!(
        history[0]["review_closure_decision"],
        json!("review_evidence_acknowledged")
    );
    assert_eq!(
        history[0]["review_closure_note"],
        json!("Due candidate evidence acknowledged.")
    );

    let (status, duplicate_review) = send(
        restarted.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies/dry-run",
                json!({
                    "scope": "book_archive",
                    "category": "documents",
                    "record_id": book_id,
                    "execution_request": {
                        "requested_policy_id": history[0]["requested_policy"]["id"],
                        "execution_mode": "review_only",
                        "operator_notes": "Create a fresh queue after review closure."
                    }
                }),
            ),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "new queue after closure: {duplicate_review}"
    );
    let duplicate_record = &duplicate_review["execution_record"];
    assert_ne!(duplicate_record["id"], json!(execution_id));
    assert_eq!(duplicate_record["decision_state"], json!("open"));
    assert_eq!(
        restarted.retention_execution_records.read().await.len(),
        2,
        "closed review is not reused as the active queued review"
    );
}

#[tokio::test]
async fn retention_review_only_concurrent_duplicates_create_one_queue_and_ledger_event() {
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

    let execution_count_before = state.retention_execution_records.read().await.len();
    let ledger_count_before = state.ledger.read().await.events().len();
    let attempts = 8;
    let barrier = Arc::new(Barrier::new(attempts));
    let mut tasks = Vec::new();
    for idx in 0..attempts {
        let state = state.clone();
        let owner_token = owner_token.clone();
        let policy_id = policy_id.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let request = json!({
                "scope": "document",
                "category": "signed_pdf",
                "record_id": "doc-review-concurrent-duplicate",
                "execution_request": {
                    "requested_policy_id": policy_id,
                    "execution_mode": "review_only",
                    "operator_notes": format!("Concurrent review request {idx}.")
                }
            });
            send(
                state,
                with_session(
                    post_json("/v1/privacy/retention-policies/dry-run", request),
                    &owner_token,
                ),
            )
            .await
        }));
    }

    let mut execution_ids = Vec::new();
    for task in tasks {
        let (status, body) = task.await.expect("concurrent review request joins");
        assert_eq!(status, StatusCode::OK, "concurrent review request: {body}");
        let execution_record = &body["execution_record"];
        let execution_id = execution_record["id"]
            .as_str()
            .expect("concurrent execution id")
            .to_owned();
        execution_ids.push(execution_id);
        assert_eq!(execution_record["execution_intent"], json!("review_only"));
        assert_eq!(
            execution_record["execution_status"],
            json!("awaiting_review")
        );
        assert_eq!(execution_record["outcome"], json!("manual_review_required"));
        assert_eq!(execution_record["would_execute"], json!(false));
        assert!(
            execution_record["execution_result"]["targets_acted"]
                .as_array()
                .expect("concurrent acted targets")
                .is_empty()
        );
        assert_eq!(
            execution_record["execution_result"]["destructive_disposal_completed"],
            json!(false)
        );
        assert_eq!(
            execution_record["execution_result"]["full_erasure_completed"],
            json!(false)
        );
    }

    let first_execution_id = execution_ids
        .first()
        .expect("at least one concurrent response");
    assert!(
        execution_ids.iter().all(|id| id == first_execution_id),
        "concurrent duplicates returned different execution ids: {execution_ids:?}"
    );
    assert_eq!(
        state.retention_execution_records.read().await.len(),
        execution_count_before + 1,
        "concurrent duplicate review requests must create one execution record"
    );
    assert_eq!(
        state.ledger.read().await.events().len(),
        ledger_count_before + 1,
        "concurrent duplicate review requests must append one ledger event"
    );

    let execution_records = state.retention_execution_records.read().await;
    let matching = execution_records
        .values()
        .filter(|record| {
            record.candidate.record_id.as_deref() == Some("doc-review-concurrent-duplicate")
                && record.requested_policy.id.as_deref() == Some(policy_id.as_str())
        })
        .count();
    assert_eq!(matching, 1);
}

#[tokio::test]
async fn retention_execution_records_bounded_archive_and_idempotent_repeat() {
    let (state, _target, owner_token, _reader, _reader_token) = fixture_state().await;

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

    let request = json!({
        "scope": "document",
        "category": "signed_pdf",
        "record_id": "doc-bounded-archive",
        "execution_request": {
            "requested_policy_id": policy_id,
            "execution_mode": "execute_supported",
            "operator_notes": "Bounded archive marker only.",
            "approval": {
                "approval_reference": "privacy-board-42",
                "policy_id": policy_id,
                "disposal_action": "archive",
                "approved_by": "privacy-board",
                "approved_at": "2026-07-10T12:00:00Z"
            }
        }
    });

    let (status, executed) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies/dry-run", request.clone()),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bounded execution: {executed}");
    assert_eq!(executed["execution_supported"], json!(true));
    assert_eq!(executed["destructive_execution_supported"], json!(false));
    assert_eq!(executed["matches"][0]["would_execute"], json!(true));
    let record = &executed["execution_record"];
    assert_eq!(record["outcome"], json!("bounded_archive_recorded"));
    assert_eq!(record["execution_intent"], json!("execute_supported"));
    assert_eq!(record["execution_status"], json!("executed"));
    assert_eq!(record["evidence_state"], json!("bounded_archive_recorded"));
    assert_eq!(
        record["evidence_next_step"],
        json!("Bounded archive evidence recorded; no destructive operation was performed.")
    );
    assert_eq!(
        record["operator_review_decision"],
        json!("execution_recorded")
    );
    assert_eq!(record["would_execute"], json!(true));
    assert_eq!(
        record["approval"]["approval_reference"],
        json!("privacy-board-42")
    );
    assert_eq!(record["execution_result"]["executed_by"], json!("owner"));
    assert!(record["execution_result"]["executed_at"].as_str().is_some());
    assert_eq!(
        record["execution_result"]["targets_considered"]
            .as_array()
            .expect("considered")
            .len(),
        1
    );
    assert_eq!(
        record["execution_result"]["targets_acted"][0]["target_id"],
        json!("doc-bounded-archive")
    );
    assert_eq!(
        record["execution_result"]["targets_acted"][0]["reason_code"],
        json!("bounded_archive_recorded")
    );
    assert!(
        record["execution_result"]["targets_skipped"]
            .as_array()
            .expect("skipped")
            .is_empty()
    );
    assert_eq!(
        record["execution_result"]["destructive_disposal_completed"],
        json!(false)
    );
    assert_eq!(
        record["execution_result"]["full_erasure_completed"],
        json!(false)
    );

    let (status, repeat) = send(
        state.clone(),
        with_session(
            post_json("/v1/privacy/retention-policies/dry-run", request),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "repeat execution: {repeat}");
    let repeat_record = &repeat["execution_record"];
    assert_eq!(repeat_record["outcome"], json!("already_executed"));
    assert_eq!(repeat_record["execution_status"], json!("executed"));
    assert_eq!(
        repeat_record["evidence_state"],
        json!("prior_bounded_evidence_available")
    );
    assert_eq!(
        repeat_record["evidence_next_step"],
        json!(
            "Prior bounded evidence is already available for this target/policy; no duplicate action was recorded."
        )
    );
    assert_eq!(repeat_record["would_execute"], json!(false));
    assert!(
        repeat_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("repeat acted")
            .is_empty()
    );
    assert_eq!(
        repeat_record["execution_result"]["targets_skipped"][0]["reason_code"],
        json!("already_executed")
    );
    assert!(
        repeat_record["execution_result"]["reason_codes"]
            .as_array()
            .expect("repeat reason codes")
            .iter()
            .any(|code| code == &json!("prior_bounded_execution_found"))
    );

    let (status, history) = send(
        state.clone(),
        with_session(get("/v1/privacy/retention-executions"), &owner_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history: {history}");
    let history = history.as_array().expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(
        history
            .iter()
            .filter(|record| record["execution_result"]["targets_acted"]
                .as_array()
                .expect("acted")
                .len()
                == 1)
            .count(),
        1
    );

    let (status, executed_history) = send(
        state,
        with_session(
            get("/v1/privacy/retention-executions?status=executed"),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "executed history filters: {executed_history}"
    );
    let executed_history = executed_history.as_array().expect("executed history");
    assert_eq!(executed_history.len(), 2);
    assert!(
        executed_history
            .iter()
            .all(|record| record["execution_status"] == json!("executed"))
    );
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
                        "execution_mode": "execute_supported",
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
    assert_eq!(execution_record["evidence_state"], json!("blocked"));
    assert_eq!(
        execution_record["evidence_next_step"],
        execution_record["workflow"]["next_step"]
    );
    assert_eq!(
        execution_record["execution_intent"],
        json!("execute_supported")
    );
    assert_eq!(execution_record["execution_status"], json!("blocked"));
    assert_eq!(
        execution_record["operator_review_decision"],
        json!("blocked")
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(execution_record["workflow"]["status"], json!("blocked"));
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["code"],
        json!("legal_hold_release")
    );
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["policy_id"],
        json!(hold_policy_id)
    );
    assert!(
        execution_record["workflow"]["required_approvals"]
            .as_array()
            .expect("required approvals")
            .iter()
            .any(|approval| approval["code"] == json!("legal_hold_owner_release"))
    );
    assert!(
        execution_record["workflow"]["required_approvals"]
            .as_array()
            .expect("required approvals")
            .iter()
            .any(|approval| approval["code"] == json!("destructive_disposal_governance"))
    );
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
    assert!(
        execution_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .is_empty()
    );
    assert_eq!(
        execution_record["execution_result"]["targets_skipped"][0]["reason_code"],
        json!("legal_hold_release")
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
                        "execution_mode": "execute_supported",
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
    assert_eq!(execution_record["evidence_state"], json!("blocked"));
    assert_eq!(
        execution_record["evidence_next_step"],
        execution_record["workflow"]["next_step"]
    );
    assert_eq!(execution_record["requested_policy"]["found"], json!(false));
    assert_eq!(
        execution_record["requested_policy"]["id"],
        json!(missing_policy_id)
    );
    assert_eq!(
        execution_record["execution_intent"],
        json!("execute_supported")
    );
    assert_eq!(execution_record["execution_status"], json!("blocked"));
    assert_eq!(
        execution_record["operator_review_decision"],
        json!("blocked")
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(execution_record["workflow"]["status"], json!("blocked"));
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["code"],
        json!("requested_policy_required")
    );
    assert_eq!(
        execution_record["workflow"]["required_approvals"][0]["code"],
        json!("policy_register_review")
    );
    assert!(
        execution_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .is_empty()
    );
    assert_eq!(
        execution_record["execution_result"]["targets_skipped"][0]["reason_code"],
        json!("requested_policy_required")
    );

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
                        "execution_mode": "execute_supported",
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
    assert_eq!(execution_record["evidence_state"], json!("blocked"));
    assert_eq!(
        execution_record["evidence_next_step"],
        execution_record["workflow"]["next_step"]
    );
    assert_eq!(execution_record["requested_policy"]["found"], json!(true));
    assert_eq!(execution_record["requested_policy"]["stale"], json!(true));
    assert_eq!(
        execution_record["requested_policy"]["status"],
        json!("suspended")
    );
    assert_eq!(execution_record["requested_policy"]["active"], json!(false));
    assert_eq!(
        execution_record["execution_intent"],
        json!("execute_supported")
    );
    assert_eq!(execution_record["execution_status"], json!("blocked"));
    assert_eq!(
        execution_record["operator_review_decision"],
        json!("blocked")
    );
    assert_eq!(execution_record["would_execute"], json!(false));
    assert_eq!(
        execution_record["workflow"]["blockers"][0]["code"],
        json!("requested_policy_active")
    );
    assert_eq!(
        execution_record["workflow"]["required_approvals"][0]["required_from"],
        json!("privacy_or_settings_manager")
    );
    assert!(
        execution_record["execution_result"]["targets_acted"]
            .as_array()
            .expect("acted targets")
            .is_empty()
    );
    assert_eq!(
        execution_record["execution_result"]["targets_skipped"][0]["reason_code"],
        json!("requested_policy_active")
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
    assert_eq!(
        execution["execution_record"]["execution_intent"],
        json!("review_only")
    );
    assert_eq!(
        execution["execution_record"]["execution_status"],
        json!("awaiting_review")
    );
    assert_eq!(
        execution["execution_record"]["operator_review_decision"],
        json!("review_required")
    );
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
    assert_eq!(executions[0]["execution_intent"], json!("review_only"));
    assert_eq!(executions[0]["execution_status"], json!("awaiting_review"));
    assert_eq!(
        executions[0]["operator_review_decision"],
        json!("review_required")
    );
    assert_eq!(
        executions[0]["workflow"]["status"],
        json!("awaiting_manual_review")
    );
    assert_eq!(
        executions[0]["operator_notes"],
        json!("Recorded before restart.")
    );
    assert!(
        executions[0]["audit_evidence"]
            .as_array()
            .expect("audit evidence")
            .is_empty()
    );
    assert_eq!(executions[0]["would_execute"], json!(false));

    let (status, awaiting_executions) = send(
        restarted.clone(),
        with_session(
            get("/v1/privacy/retention-executions?status=awaiting_review"),
            &restarted_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "awaiting review execution filter after restart: {awaiting_executions}"
    );
    let awaiting_executions = awaiting_executions
        .as_array()
        .expect("awaiting execution list");
    assert_eq!(awaiting_executions.len(), 1);
    assert_eq!(awaiting_executions[0]["id"], json!(execution_id));

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

// =================================================================================================
// wp26-gdpr — destructive right-to-erasure workflow (preflight -> approve -> execute -> attest).
// The MERGE-GATE test proves ledger integrity is preserved across a real destructive erasure.
// Subject Amelia Marques of Encosto Estrategico Lda (fictional). Never real names.
// =================================================================================================

/// Insert an interactive admin user (Owner @ Global) with a password session, returning its token.
async fn insert_admin_session(state: &AppState, id: UserId, username: &str) -> String {
    insert_user(
        state,
        id,
        username,
        RoleAssignment::new(OWNER_ROLE_ID, Scope::Global),
    )
    .await;
    open_session(state, id).await
}

async fn create_erasure_dsr(state: &AppState, subject: UserId, actor_token: &str) -> String {
    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests"),
                json!({ "request_type": "erasure" }),
            ),
            actor_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "erasure DSR created: {created}"
    );
    created["id"].as_str().expect("request id").to_owned()
}

#[tokio::test]
async fn erasure_preflight_enumerates_targets_and_carveouts() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xA3E1));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;

    let (status, report) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/preflight"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preflight: {report}");
    assert_eq!(report["status"], json!("ready_for_approval"));
    assert_eq!(report["subject_user_id"], json!(subject.to_string()));
    let targets = report["erasable_targets"].as_array().expect("targets");
    assert!(
        targets.iter().any(
            |t| t["collection"] == json!("users") && t["technique"] == json!("physical_delete")
        ),
        "users row is an erasable target: {report}"
    );
    let carveouts = report["retained_carveouts"].as_array().expect("carveouts");
    assert!(
        carveouts
            .iter()
            .any(|c| c["collection"] == json!("ledger_events")),
        "ledger events retained as a carve-out: {report}"
    );
    assert!(
        report["preflight_digest"]
            .as_str()
            .is_some_and(|d| d.len() == 64),
        "preflight digest is a 64-hex sha256: {report}"
    );
}

#[tokio::test]
async fn erasure_approve_enforces_dual_control_and_confirmation() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let auditor_token =
        insert_admin_session(&state, UserId(Uuid::from_u128(0xA0D1)), "auditor").await;
    let subject = UserId(Uuid::from_u128(0xA3E2));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;

    let (_s, report) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/preflight"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    let digest = report["preflight_digest"]
        .as_str()
        .expect("digest")
        .to_owned();

    let approve_uri =
        format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/approve");
    // The requester (owner) cannot self-approve -- dual control.
    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &approve_uri,
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": subject.to_string(),
                    "acknowledge_carveouts": true
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "self-approval blocked by dual control: {body}"
    );

    // Wrong subject confirmation is rejected.
    let (status, _b) = send(
        state.clone(),
        with_session(
            post_json(
                &approve_uri,
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": "not-the-subject",
                    "acknowledge_carveouts": true
                }),
            ),
            &auditor_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "confirmation mismatch"
    );

    // Missing carve-out acknowledgement is rejected.
    let (status, _b) = send(
        state.clone(),
        with_session(
            post_json(
                &approve_uri,
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": subject.to_string(),
                    "acknowledge_carveouts": false
                }),
            ),
            &auditor_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "carve-outs must be acked"
    );

    // A distinct approver with the correct confirmation + ack succeeds.
    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &approve_uri,
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": subject.to_string(),
                    "acknowledge_carveouts": true
                }),
            ),
            &auditor_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "distinct approver approves: {body}");
    assert_eq!(
        body["erasure_authorization"]["approved_by"],
        json!("auditor")
    );
    assert_eq!(
        body["erasure_authorization"]["requested_by"],
        json!("owner")
    );
}

#[tokio::test]
async fn erasure_execute_rejects_unapproved_request() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xA3E3));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;
    let execute_uri =
        format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/execute");

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &execute_uri,
                json!({
                    "preflight_digest": "deadbeef",
                    "reauth": { "password": TEST_PASSWORD },
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "execute needs approval first: {body}"
    );
}

#[tokio::test]
async fn erasure_execute_rejects_last_owner_removal() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let subject = UserId(Uuid::from_u128(0xA3EA));
    let subject_token = insert_admin_session(&state, subject, "subject.owner").await;
    let requester = UserId(Uuid::from_u128(0xA0EA));
    let requester_token = insert_admin_session(&state, requester, "requester.owner").await;
    let request_id = create_erasure_dsr(&state, subject, &requester_token).await;

    let (_status, report) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/preflight"),
                json!({}),
            ),
            &requester_token,
        ),
    )
    .await;
    let digest = report["preflight_digest"]
        .as_str()
        .expect("digest")
        .to_owned();

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/approve"),
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": subject.to_string(),
                    "acknowledge_carveouts": true
                }),
            ),
            &subject_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approval succeeds: {body}");

    {
        let mut users = state.users.write().await;
        let requester = users.get_mut(&requester).expect("requester exists");
        requester.role_assignments = vec![RoleAssignment::new(READER_ROLE_ID, Scope::Global)];
    }

    let (status, body) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/execute"),
                json!({
                    "preflight_digest": digest,
                    "reauth": { "password": TEST_PASSWORD },
                }),
            ),
            &subject_token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "erasure must preserve at least one active Owner: {body}"
    );
    assert!(
        state.users.read().await.contains_key(&subject),
        "blocked last Owner remains in the users store"
    );
}

/// THE MERGE-GATE (plan P5): a real destructive erasure must preserve ledger integrity.
#[tokio::test]
async fn merge_gate_erasure_preserves_ledger_integrity_and_destroys_dek() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let auditor_token =
        insert_admin_session(&state, UserId(Uuid::from_u128(0xA0D9)), "auditor").await;
    let subject = UserId(Uuid::from_u128(0xA3E9));
    let subject_id = subject.to_string();
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;

    // Provision a per-subject DEK and encrypt a PII field under it (the crypto-erase target).
    let dek = provision_subject_dek(&state, &subject_id).expect("provision subject DEK");
    let crypto = state
        .provider_credentials
        .subject_dek_crypto()
        .expect("subject DEK crypto");
    let envelope = crypto
        .encrypt_field(
            &dek,
            &subject_id,
            "email",
            b"amelia@encosto-estrategico.test",
        )
        .expect("encrypt PII under DEK");
    // Sanity: the DEK currently decrypts the PII.
    assert_eq!(
        crypto
            .decrypt_field(&dek, &subject_id, "email", &envelope)
            .expect("decrypt while DEK lives")
            .as_slice(),
        b"amelia@encosto-estrategico.test"
    );

    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;

    // Preflight -> approve (distinct principal).
    let (_s, report) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/preflight"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    let digest = report["preflight_digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert!(
        report["subject_dek_present"].as_bool().unwrap_or(false),
        "the provisioned DEK is enumerated: {report}"
    );
    let (status, _b) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/approve"),
                json!({
                    "preflight_digest": digest,
                    "subject_confirmation": subject_id,
                    "acknowledge_carveouts": true
                }),
            ),
            &auditor_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approval succeeds");

    // BEFORE: ledger verifies at n.
    let n = {
        let ledger = state.ledger.read().await;
        ledger.verify().expect("ledger verifies before erasure")
    };

    // EXECUTE the destructive erasure.
    let (status, executed) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/execute"),
                json!({
                    "preflight_digest": digest,
                    "reauth": { "password": TEST_PASSWORD },
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "erasure executes: {executed}");
    assert_eq!(executed["status"], json!("completed"));
    assert_eq!(executed["outcome"], json!("partially_fulfilled"));
    assert_eq!(executed["erasure_execution"]["dek_destroyed"], json!(true));

    // (a) AFTER: ledger verifies at n+1 -- exactly one appended `subject.erased` event, nothing mutated.
    {
        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.verify(),
            Ok(n + 1),
            "erasure appended exactly one event and preserved integrity"
        );
        // (d) the subject.erased attestation is present.
        assert!(
            ledger.events().iter().any(|e| e.kind == "subject.erased"),
            "subject.erased attestation appended"
        );
    }

    // (b) subject store reads return none.
    assert!(
        !state.users.read().await.contains_key(&subject),
        "subject users row physically removed"
    );

    // (c) the subject DEK is destroyed -> decrypt is now impossible (PII irrecoverable, incl. backups).
    let store = state.store.as_ref().expect("durable store");
    let key_row = store
        .get_subject_key(&subject_id)
        .expect("subject key read")
        .expect("row still exists as an erasure tombstone");
    assert!(key_row.erased_at.is_some(), "DEK marked erased");
    assert!(
        key_row.wrapped_dek.is_empty(),
        "wrapped DEK bytes destroyed"
    );
    assert!(
        crypto
            .unwrap_dek(&subject_id, &key_row.wrapped_dek)
            .is_err(),
        "destroyed DEK can no longer be unwrapped -- the PII ciphertext is cryptographically dead"
    );
}

// =================================================================================================
// wp26-gdpr — append-only ANNOTATION remedy (the STANDARD data-subject path for statutorily-retained
// sealed acts/books/signed documents). Signatures/sealed content stay valid because annotation only
// ever appends a new ledger event; it never mutates or re-chains any prior (signed) event.
// =================================================================================================

/// Snapshot every ledger event's frozen (hash, payload_digest) — the bytes a signature is over.
async fn ledger_frozen_snapshot(state: &AppState) -> Vec<([u8; 32], [u8; 32])> {
    let ledger = state.ledger.read().await;
    ledger
        .events()
        .iter()
        .map(|e| (e.hash, e.payload_digest))
        .collect()
}

#[tokio::test]
async fn rectification_annotation_is_append_only_and_preserves_signed_events() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xB101));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;

    // BEFORE: capture the full frozen ledger + the count.
    let before = ledger_frozen_snapshot(&state).await;
    let n = {
        let ledger = state.ledger.read().await;
        ledger.verify().expect("verifies before annotation")
    };

    // Record an append-only rectification note against a (representative) sealed-act scope.
    let (status, view) = send(
        state.clone(),
        with_session(
            post_json(
                &format!(
                    "/v1/privacy/users/{subject}/dsr-requests/{request_id}/rectification"
                ),
                // Default subject scope (Application chain). Annotating a specific sealed-act scope is
                // a mid-chain append proven byte-preserving in the chancela-ledger unit test
                // `annotation_preserves_prior_sealed_events_byte_for_byte` (a real act.sealed event).
                json!({
                    "note": "Display name misspelled in the sealed minute; corrected here by annotation.",
                    "field": "display_name"
                }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rectification recorded: {view}");
    assert_eq!(view["annotation"], json!("rectification"));
    assert_eq!(view["event_kind"], json!("subject.rectification_noted"));
    assert!(
        view["event_id"].as_str().is_some(),
        "annotation event id present"
    );

    // AFTER: the ledger grew by exactly one and every prior (signed/sealed) event is byte-identical.
    let after = ledger_frozen_snapshot(&state).await;
    {
        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.verify(),
            Ok(n + 1),
            "append-only: verify advances by one"
        );
        let annotation = ledger
            .events()
            .iter()
            .find(|e| e.kind == "subject.rectification_noted")
            .expect("rectification annotation appended");
        let justification = annotation
            .justification
            .as_deref()
            .expect("annotation has non-sensitive justification");
        assert!(
            justification.starts_with("rectification annotation recorded; payload_digest="),
            "justification identifies annotation and digest only"
        );
        assert!(
            !justification.contains("Display name misspelled"),
            "justification must not leak sensitive annotation note"
        );
        assert!(
            !justification.contains("display_name"),
            "justification must not leak sensitive annotation field"
        );
    }
    assert_eq!(after.len(), before.len() + 1, "exactly one new event");
    for (i, prior) in before.iter().enumerate() {
        assert_eq!(
            &after[i], prior,
            "prior signed/sealed event {i} is byte-identical after annotation"
        );
    }
}

#[tokio::test]
async fn restriction_annotation_records_append_only_marker() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xB102));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;
    let n = {
        let ledger = state.ledger.read().await;
        ledger.verify().expect("verifies before")
    };

    let (status, view) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/restriction"),
                json!({ "note": "Subject objects to further processing pending review." }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "restriction recorded: {view}");
    assert_eq!(view["annotation"], json!("restriction"));
    assert_eq!(view["event_kind"], json!("subject.processing_restricted"));
    // Default scope is the subject's user chain.
    assert_eq!(view["scope"], json!(format!("user:{subject}")));
    let ledger = state.ledger.read().await;
    assert_eq!(ledger.verify(), Ok(n + 1), "append-only marker");
}

#[tokio::test]
async fn rectification_requires_a_note() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xB103));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;
    let (status, _b) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/rectification"),
                json!({ "field": "display_name" }),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "note is required");
}

#[tokio::test]
async fn preflight_marks_sealed_records_as_annotation_remedy() {
    let tmp = TempDir::new();
    let state = AppState::with_data_dir(tmp.dir.clone());
    let (_owner, owner_token) = bootstrap_owner(&state).await;
    let subject = UserId(Uuid::from_u128(0xB104));
    insert_user(
        &state,
        subject,
        "amelia.marques",
        RoleAssignment::new(READER_ROLE_ID, Scope::Global),
    )
    .await;
    let request_id = create_erasure_dsr(&state, subject, &owner_token).await;
    let (status, report) = send(
        state.clone(),
        with_session(
            post_json(
                &format!("/v1/privacy/users/{subject}/dsr-requests/{request_id}/erasure/preflight"),
                json!({}),
            ),
            &owner_token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preflight: {report}");
    let carveouts = report["retained_carveouts"].as_array().expect("carveouts");
    let sealed = carveouts
        .iter()
        .find(|c| c["collection"] == json!("acts_books_signed_documents"))
        .expect("sealed-records carve-out present");
    assert_eq!(
        sealed["legal_basis"],
        json!("art_17_3_b_statutory_retention"),
        "honest Art. 17(3)(b) legal-retention basis"
    );
    assert_eq!(
        sealed["remedy"],
        json!("annotation"),
        "the remedy for sealed records is annotation, not erasure"
    );
}

// ---------------------------------------------------------------------------------------------------
// t27 — granular-verb enforcement. Privacy records, DSR/subject-rights and retention were re-gated off
// the broad `user.manage` | `settings.manage` pair onto the specific `privacy.manage` /
// `retention.manage` verbs. These tests prove each op requires its *own* verb and denies a holder of
// only a neighbouring or parent verb — the security property of the split, not just reachability.
// ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn privacy_records_gate_on_privacy_manage_and_reject_bare_parents() {
    let (state, _target, _owner_token, _reader, _reader_token) = fixture_state().await;

    // A holder of the OLD parent `settings.manage` alone — WITHOUT the grandfathered child — is now
    // denied. This is the whole point of the split: the broad verb no longer reaches privacy records.
    let (_u, settings_only) = add_user_with_permissions(
        &state,
        0x2701,
        "settings-only",
        &[Permission::SettingsManage],
    )
    .await;
    // Likewise the other old parent, `user.manage`, no longer reaches privacy records.
    let (_u, user_only) =
        add_user_with_permissions(&state, 0x2702, "user-only", &[Permission::UserManage]).await;
    // The neighbouring granular verb `retention.manage` must NOT leak into privacy records.
    let (_u, retention_only) = add_user_with_permissions(
        &state,
        0x2703,
        "retention-only",
        &[Permission::RetentionManage],
    )
    .await;
    // Exactly `privacy.manage` clears the gate.
    let (_u, privacy_only) =
        add_user_with_permissions(&state, 0x2704, "privacy-only", &[Permission::PrivacyManage])
            .await;

    for (label, token) in [
        ("settings.manage alone", &settings_only),
        ("user.manage alone", &user_only),
        ("retention.manage alone", &retention_only),
    ] {
        let status = send_status(
            state.clone(),
            with_session(
                post_json(
                    "/v1/privacy/processors",
                    processor_payload("medium", "active"),
                ),
                token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label} must be denied privacy records"
        );
    }

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/processors",
                processor_payload("medium", "active"),
            ),
            &privacy_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "privacy.manage manages records: {created}"
    );
}

#[tokio::test]
async fn retention_gates_on_retention_manage_distinct_from_privacy_manage() {
    let (state, _target, _owner_token, _reader, _reader_token) = fixture_state().await;

    // The sibling `privacy.manage` verb must NOT reach retention — the split made them independent.
    let (_u, privacy_only) =
        add_user_with_permissions(&state, 0x2711, "privacy-only", &[Permission::PrivacyManage])
            .await;
    // Neither old parent reaches retention on its own anymore.
    let (_u, settings_only) = add_user_with_permissions(
        &state,
        0x2712,
        "settings-only",
        &[Permission::SettingsManage],
    )
    .await;
    // Exactly `retention.manage` clears the gate.
    let (_u, retention_only) = add_user_with_permissions(
        &state,
        0x2713,
        "retention-only",
        &[Permission::RetentionManage],
    )
    .await;

    for (label, token) in [
        ("privacy.manage alone", &privacy_only),
        ("settings.manage alone", &settings_only),
    ] {
        let status = send_status(
            state.clone(),
            with_session(
                post_json(
                    "/v1/privacy/retention-policies",
                    retention_policy_payload("delete", "active"),
                ),
                token,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label} must be denied retention"
        );
    }

    let (status, created) = send(
        state.clone(),
        with_session(
            post_json(
                "/v1/privacy/retention-policies",
                retention_policy_payload("delete", "active"),
            ),
            &retention_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "retention.manage manages retention: {created}"
    );
}

#[tokio::test]
async fn dsr_subject_rights_gate_on_privacy_manage_not_user_manage() {
    let (state, target, _owner_token, _reader, _reader_token) = fixture_state().await;

    // DSR / subject-rights used to ride `user.manage`; t27 moved them onto `privacy.manage`. A bare
    // `user.manage` holder is now denied the subject export.
    let (_u, user_only) =
        add_user_with_permissions(&state, 0x2721, "user-only", &[Permission::UserManage]).await;
    let status = send_status(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &user_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "user.manage alone denied the DSR export"
    );

    // `privacy.manage` is the verb that now authorizes it.
    let (_u, privacy_only) =
        add_user_with_permissions(&state, 0x2722, "privacy-only", &[Permission::PrivacyManage])
            .await;
    let (status, body) = send(
        state.clone(),
        with_session(
            get(&format!("/v1/privacy/users/{target}/export")),
            &privacy_only,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "privacy.manage authorizes the DSR export: {body}"
    );
}
