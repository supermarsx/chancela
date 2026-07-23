use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_core::{ActId, ActState};
use serde_json::{Value, json};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-external-invites-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn send_raw(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, headers, bytes.to_vec())
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn public_json_req(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn empty_req(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds")
}

async fn bootstrap(state: &AppState) -> String {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "amelia.marques",
                    "display_name": "Amelia Marques",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create first user: {user}");
    let uid = user["id"].as_str().expect("user id").to_owned();

    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": uid, "password": TEST_PASSWORD }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

async fn draft_act(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Encosto Estrategico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    let book_id = book["id"].as_str().unwrap().to_owned();

    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": "Ata da AG anual", "channel": "Physical" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "act: {act}");
    act["id"].as_str().unwrap().to_owned()
}

async fn prepare_signing_act(state: &AppState, token: &str, act_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Aprovadas as contas do exercicio."
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch act: {body}");

    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        let (status, body) = send(
            state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/advance"),
                token,
                json!({ "to": to }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
    }
}

async fn signing_act(state: &AppState, token: &str) -> String {
    let act_id = draft_act(state, token).await;
    prepare_signing_act(state, token, &act_id).await;
    act_id
}

fn invite_body(expires_at: String) -> Value {
    json!({
        "recipient_name": "Bruno Dias",
        "recipient_email": "bruno@example.test",
        "provider_hint": "manual-envelope",
        "expires_at": expires_at,
        "purpose": "Assinar a ata como administrador externo"
    })
}

fn future_expiry() -> String {
    (OffsetDateTime::now_utc() + Duration::days(2))
        .format(&Rfc3339)
        .unwrap()
}

async fn ledger_len(state: &AppState) -> usize {
    state.ledger.read().await.events().len()
}

async fn create_invite(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, created) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            token,
            invite_body(future_expiry()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create invite: {created}");
    created
}

fn linked_invite_body(envelope_id: &str, slot_id: &str) -> Value {
    let mut body = invite_body(future_expiry());
    let object = body.as_object_mut().expect("invite body object");
    object.insert("external_envelope_id".to_owned(), json!(envelope_id));
    object.insert("external_slot_id".to_owned(), json!(slot_id));
    body
}

async fn create_two_slot_envelope(
    state: &AppState,
    token: &str,
    act_id: &str,
    order_policy: &str,
) -> Value {
    let (status, envelope) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            token,
            json!({
                "order_policy": order_policy,
                "slots": [
                    { "signer_label": "Chair", "required": true },
                    { "signer_label": "Secretary", "required": true }
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create envelope: {envelope}");
    envelope
}

async fn read_envelope(state: &AppState, token: &str, envelope_id: &str) -> Value {
    let (status, envelope) = send(
        state,
        empty_req(
            "GET",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read envelope: {envelope}");
    envelope
}

fn assert_no_legal_or_qualified_field_names(value: &Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let key = key.to_ascii_lowercase();
                assert!(
                    !key.contains("legal")
                        && !key.contains("qualified")
                        && !key.contains("qualification"),
                    "public lookup exposes legal/qualified field name `{key}`"
                );
                assert_no_legal_or_qualified_field_names(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_legal_or_qualified_field_names(item);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn create_returns_token_once_and_list_redacts_secret() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;

    let created = create_invite(&state, &token, &act_id).await;
    let invite_id = created["invite"]["id"].as_str().expect("invite id");
    let secret = created["token"].as_str().expect("invite token");
    assert_eq!(created["invite"]["workflow"], "tracking_only");
    assert!(
        created["invite"].get("external_envelope").is_none(),
        "unlinked create response stays standalone tracking_only"
    );
    assert!(secret.starts_with("cxi_"));
    assert!(
        secret.len() >= 68,
        "32 random bytes are rendered as a long hex token"
    );

    let invite_uuid = Uuid::parse_str(invite_id).expect("invite uuid");
    let record = state
        .external_signer_invites
        .read()
        .await
        .get(&invite_uuid)
        .cloned()
        .expect("invite stored");
    assert_eq!(record.token_sha256.len(), 64);
    assert_ne!(record.token_sha256, secret);
    assert_ne!(record.token_hint, secret);
    assert_eq!(created["invite"]["token_hint"], record.token_hint);

    let (status, list) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list invites: {list}");
    let rows = list.as_array().expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "pending");
    assert_eq!(rows[0]["workflow"], "tracking_only");
    assert!(rows[0].get("token").is_none(), "secret token is absent");
    assert!(
        rows[0].get("token_sha256").is_none(),
        "token hash is not exposed"
    );
    assert!(
        !list.to_string().contains(secret),
        "full invite token must not leak through list"
    );
}

#[tokio::test]
async fn linked_invite_for_second_sequential_slot_conflicts_without_token() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_two_slot_envelope(&state, &token, &act_id, "sequential").await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let second_slot = envelope["slots"][1]["id"].as_str().expect("second slot");

    let before_invites = state.external_signer_invites.read().await.len();
    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
            linked_invite_body(envelope_id, second_slot),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "later sequential slot is blocked: {body}"
    );
    assert!(
        body.get("token").is_none(),
        "conflict must not return a token"
    );
    assert!(
        !body.to_string().contains("cxi_"),
        "conflict body must not contain an invite token"
    );
    assert_eq!(
        state.external_signer_invites.read().await.len(),
        before_invites,
        "blocked linked invite is not stored"
    );

    let read = read_envelope(&state, &token, envelope_id).await;
    assert_eq!(read["slots"][1]["status"], "pending");
}

#[tokio::test]
async fn linked_invite_for_first_sequential_slot_succeeds_and_initiates_slot() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_two_slot_envelope(&state, &token, &act_id, "sequential").await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let first_slot = envelope["slots"][0]["id"].as_str().expect("first slot");

    let (status, created) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
            linked_invite_body(envelope_id, first_slot),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "linked invite: {created}");
    assert!(
        created["token"]
            .as_str()
            .is_some_and(|token| token.starts_with("cxi_"))
    );
    assert_eq!(created["invite"]["workflow"], "external_envelope");
    assert_eq!(created["invite"]["external_envelope"]["id"], envelope_id);
    assert_eq!(
        created["invite"]["external_envelope"]["slot_id"],
        first_slot
    );
    assert_eq!(
        created["invite"]["external_envelope"]["order_policy"],
        "sequential"
    );
    assert_eq!(
        created["invite"]["external_envelope"]["slot_status"],
        "initiated"
    );

    let read = read_envelope(&state, &token, envelope_id).await;
    assert_eq!(read["slots"][0]["status"], "initiated");
    assert_eq!(read["slots"][1]["status"], "pending");
}

#[tokio::test]
async fn linked_invite_envelope_persist_failure_rolls_back_slot_and_invite() {
    let dir = TempDir::new();
    let mut state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_two_slot_envelope(&state, &token, &act_id, "parallel").await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let first_slot = envelope["slots"][0]["id"].as_str().expect("first slot");

    state.external_signing_envelopes_path = Some(Arc::new(dir.0.clone()));
    let before_invites = state.external_signer_invites.read().await.len();
    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
            linked_invite_body(envelope_id, first_slot),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "forced envelope persistence failure: {body}"
    );
    assert!(
        body.get("token").is_none(),
        "failed linked create must not return a token"
    );
    assert!(
        !body.to_string().contains("cxi_"),
        "failed linked create must not leak an invite token"
    );
    assert_eq!(
        state.external_signer_invites.read().await.len(),
        before_invites,
        "failed linked invite is removed"
    );

    let read = read_envelope(&state, &token, envelope_id).await;
    assert_eq!(read["slots"][0]["status"], "pending");
    assert_eq!(read["slots"][1]["status"], "pending");
}

#[tokio::test]
async fn linked_invite_for_parallel_second_slot_succeeds() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_two_slot_envelope(&state, &token, &act_id, "parallel").await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let second_slot = envelope["slots"][1]["id"].as_str().expect("second slot");

    let (status, created) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
            linked_invite_body(envelope_id, second_slot),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "parallel later slot can be invited: {created}"
    );
    assert_eq!(created["invite"]["workflow"], "external_envelope");
    assert_eq!(
        created["invite"]["external_envelope"]["slot_status"],
        "initiated"
    );

    let read = read_envelope(&state, &token, envelope_id).await;
    assert_eq!(read["slots"][0]["status"], "pending");
    assert_eq!(read["slots"][1]["status"], "initiated");
}

#[tokio::test]
async fn act_outside_signing_refuses_external_invite_creation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = draft_act(&state, &token).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
            invite_body(future_expiry()),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "act outside Signing refused: {body}"
    );
    assert!(
        state.external_signer_invites.read().await.is_empty(),
        "no invite record is created for an act outside Signing"
    );
}

#[tokio::test]
async fn revoke_updates_status_and_appends_audit_event() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let created = create_invite(&state, &token, &act_id).await;
    let invite_id = created["invite"]["id"].as_str().expect("invite id");

    let (status, revoked) = send(
        &state,
        empty_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites/{invite_id}/revoke"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke invite: {revoked}");
    assert_eq!(revoked["status"], "revoked");
    assert!(revoked["revoked_at"].is_string());

    let (status, list) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list after revoke: {list}");
    assert_eq!(list[0]["status"], "revoked");

    let (status, events) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/ledger/events?scope=act:{act_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    let kinds: Vec<_> = events
        .as_array()
        .expect("events")
        .iter()
        .map(|event| event["kind"].as_str().unwrap_or_default())
        .collect();
    assert!(
        kinds.contains(&"signature.external_invite.revoked"),
        "revoke event is audited: {kinds:?}"
    );
}

#[tokio::test]
async fn expired_status_is_visible_in_list() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let created = create_invite(&state, &token, &act_id).await;
    let invite_id = Uuid::parse_str(created["invite"]["id"].as_str().expect("invite id")).unwrap();
    {
        let mut invites = state.external_signer_invites.write().await;
        let invite = invites.get_mut(&invite_id).expect("invite stored");
        invite.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
    }

    let (status, list) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list expired invite: {list}");
    assert_eq!(list[0]["status"], "expired");
}

#[tokio::test]
async fn public_lookup_reveals_safe_metadata_only_for_live_token() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let session = bootstrap(&state).await;
    let act_id = signing_act(&state, &session).await;
    let created = create_invite(&state, &session, &act_id).await;
    let token = created["token"].as_str().expect("invite token");

    let (status, envelope) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "lookup live token: {envelope}");
    assert_eq!(envelope["workflow"], "tracking_only");
    assert_eq!(envelope["status"], "pending");
    assert_eq!(envelope["recipient_name"], "Bruno Dias");
    assert_eq!(
        envelope["purpose"],
        "Assinar a ata como administrador externo"
    );
    assert_eq!(envelope["act"]["id"], act_id);
    assert_eq!(envelope["act"]["title"], "Ata da AG anual");
    assert_eq!(envelope["act"]["entity_name"], "Encosto Estrategico, S.A.");
    assert_eq!(envelope["act"]["state"], "Signing");
    assert_eq!(envelope["act"]["ata_number"], Value::Null);
    assert!(envelope["document"]["id"].is_string());
    assert_eq!(envelope["document"]["template_id"], "csc-ata-ag/v1");
    assert_eq!(
        envelope["document"]["profile"],
        "application/pdf; profile=PDF/A-2u"
    );
    assert_eq!(
        envelope["document"]["pdf_digest"]
            .as_str()
            .expect("document digest")
            .len(),
        64
    );
    assert_eq!(
        envelope["document"]["artifact"]["kind"],
        "working_copy_markdown"
    );
    assert_eq!(envelope["document"]["artifact"]["method"], "POST");
    assert_eq!(
        envelope["document"]["artifact"]["path"],
        "/v1/signature/external-invites/document/working-copy"
    );
    assert_eq!(
        envelope["document"]["artifact"]["content_type"],
        "text/markdown; charset=utf-8"
    );
    assert!(
        envelope["document"].get("pdf_bytes").is_none(),
        "raw PDF bytes are not public"
    );
    assert!(
        envelope["document"].get("download").is_none(),
        "canonical PDF download URL is not public"
    );
    assert!(
        envelope["notice"]
            .as_str()
            .expect("notice")
            .contains("nao assina")
    );
    assert!(envelope.get("token").is_none(), "token is never echoed");
    assert!(
        envelope.get("token_hint").is_none(),
        "redacted token is not public"
    );
    assert!(
        envelope.get("token_sha256").is_none(),
        "token hash is not public"
    );
    assert!(
        envelope.get("recipient_email").is_none(),
        "recipient email is not part of the public token view"
    );
    assert!(
        !envelope.to_string().contains(token),
        "lookup response must not contain the full token"
    );

    let before_download = ledger_len(&state).await;
    let (status, headers, body) = send_raw(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/document/working-copy",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "download working copy");
    assert!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/markdown")),
        "working copy is markdown: {headers:?}"
    );
    assert!(
        headers
            .get("content-disposition")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("external-working-copy.md")),
        "working copy is an attachment: {headers:?}"
    );
    let markdown = String::from_utf8(body).expect("markdown is utf-8");
    assert!(markdown.contains("EXTERNAL SIGNER WORKING COPY - NON-EVIDENTIARY"));
    assert!(markdown.contains("not a qualified electronic signature"));
    assert!(markdown.contains("Canonical PDF: not exposed"));
    assert!(markdown.contains("Ata da AG anual"));
    assert!(
        !markdown.starts_with("%PDF-"),
        "raw canonical PDF is not returned"
    );
    assert!(
        !markdown.contains(token),
        "working copy must not contain the invite token"
    );
    assert!(
        !markdown.contains("bruno@example.test"),
        "recipient email stays out of the public artifact"
    );
    assert_eq!(
        ledger_len(&state).await,
        before_download,
        "working-copy download is read-only"
    );

    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": "cxi_wrong" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "bad token is generic 404");

    let invite_id = Uuid::parse_str(created["invite"]["id"].as_str().expect("invite id")).unwrap();
    {
        let mut invites = state.external_signer_invites.write().await;
        invites.get_mut(&invite_id).unwrap().expires_at =
            OffsetDateTime::now_utc() - Duration::seconds(1);
    }
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "expired token is unavailable"
    );
}

#[tokio::test]
async fn public_lookup_for_linked_invite_redacts_secrets_and_legal_claim_fields() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let session = bootstrap(&state).await;
    let act_id = signing_act(&state, &session).await;
    let envelope = create_two_slot_envelope(&state, &session, &act_id, "parallel").await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let slot_id = envelope["slots"][1]["id"].as_str().expect("slot id");

    let (status, created) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &session,
            linked_invite_body(envelope_id, slot_id),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "linked invite: {created}");
    let token = created["token"].as_str().expect("invite token");

    let (status, envelope) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "lookup linked token: {envelope}");
    assert_eq!(envelope["workflow"], "external_envelope");
    assert_eq!(envelope["status"], "pending");
    assert_eq!(envelope["external_envelope"]["id"], envelope_id);
    assert_eq!(envelope["external_envelope"]["slot_id"], slot_id);
    assert_eq!(envelope["external_envelope"]["order_policy"], "parallel");
    assert_eq!(envelope["external_envelope"]["slot_status"], "initiated");
    assert_eq!(envelope["act"]["id"], act_id);

    assert!(envelope.get("token").is_none(), "token is never echoed");
    assert!(
        envelope.get("token_hint").is_none(),
        "redacted token is not public"
    );
    assert!(
        envelope.get("token_sha256").is_none(),
        "token hash is not public"
    );
    assert!(
        envelope.get("recipient_email").is_none(),
        "recipient email is not part of the public token view"
    );
    assert!(
        !envelope.to_string().contains(token),
        "lookup response must not contain the full token"
    );
    assert_no_legal_or_qualified_field_names(&envelope);
}

#[tokio::test]
async fn public_lookup_and_working_copy_fail_closed_without_ledger_mutation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let session = bootstrap(&state).await;
    let act_id = signing_act(&state, &session).await;
    let created = create_invite(&state, &session, &act_id).await;
    let token = created["token"].as_str().expect("invite token");
    let invite_id = Uuid::parse_str(created["invite"]["id"].as_str().expect("invite id")).unwrap();

    let before_wrong = ledger_len(&state).await;
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": "cxi_wrong" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "wrong lookup is generic 404");
    let (status, _, _) = send_raw(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/document/working-copy",
            json!({ "token": "cxi_wrong" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "wrong working-copy token is generic 404"
    );
    assert_eq!(
        ledger_len(&state).await,
        before_wrong,
        "wrong-token public failures do not mutate the ledger"
    );

    {
        let mut invites = state.external_signer_invites.write().await;
        invites.get_mut(&invite_id).unwrap().expires_at =
            OffsetDateTime::now_utc() - Duration::seconds(1);
    }
    let before_expired = ledger_len(&state).await;
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "expired lookup is generic 404"
    );
    let (status, _, _) = send_raw(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/document/working-copy",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "expired working-copy token is generic 404"
    );
    assert_eq!(
        ledger_len(&state).await,
        before_expired,
        "expired public failures do not mutate the ledger"
    );

    let closed_act_id = signing_act(&state, &session).await;
    let closed_created = create_invite(&state, &session, &closed_act_id).await;
    let closed_token = closed_created["token"].as_str().expect("invite token");
    {
        let mut acts = state.acts.write().await;
        let act_uuid = Uuid::parse_str(&closed_act_id).expect("act uuid");
        let act = acts.get_mut(&ActId(act_uuid)).expect("act exists");
        act.state = ActState::Sealed;
    }
    let before_closed = ledger_len(&state).await;
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": closed_token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "sealed act lookup fails closed"
    );
    let (status, _, _) = send_raw(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/document/working-copy",
            json!({ "token": closed_token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "sealed act working-copy download fails closed"
    );
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/respond",
            json!({ "token": closed_token, "decision": "accept" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "sealed act response fails closed"
    );
    assert_eq!(
        ledger_len(&state).await,
        before_closed,
        "sealed public failures do not mutate the ledger"
    );
}

#[tokio::test]
async fn public_accept_updates_tracking_and_audit_without_signature_completion() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let session = bootstrap(&state).await;
    let act_id = signing_act(&state, &session).await;
    let created = create_invite(&state, &session, &act_id).await;
    let token = created["token"].as_str().expect("invite token");

    let (status, accepted) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/respond",
            json!({ "token": token, "decision": "accept" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "accept invite: {accepted}");
    assert_eq!(accepted["status"], "accepted");
    assert!(accepted["responded_at"].is_string());
    assert!(
        accepted["notice"]
            .as_str()
            .expect("notice")
            .contains("nao assina")
    );

    let (status, listed) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            &session,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list accepted invite: {listed}");
    assert_eq!(listed[0]["status"], "accepted");
    assert!(listed[0]["responded_at"].is_string());

    let (status, signature) = send(
        &state,
        empty_req("GET", &format!("/v1/acts/{act_id}/signature"), &session),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signature status: {signature}");
    assert_eq!(signature["status"], "unsigned");
    assert_eq!(signature["evidence"]["current_level"], "Unsigned");

    let (status, events) = send(
        &state,
        empty_req(
            "GET",
            &format!("/v1/ledger/events?scope=act:{act_id}"),
            &session,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    let kinds: Vec<_> = events
        .as_array()
        .expect("events")
        .iter()
        .map(|event| event["kind"].as_str().unwrap_or_default())
        .collect();
    assert!(
        kinds.contains(&"signature.external_invite.accepted"),
        "acceptance event is audited: {kinds:?}"
    );

    let (status, again) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/respond",
            json!({ "token": token, "decision": "accept" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same response is idempotent: {again}"
    );

    let (status, conflict) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/respond",
            json!({ "token": token, "decision": "decline" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "opposite response is refused: {conflict}"
    );
}

#[tokio::test]
async fn revoked_token_cannot_be_looked_up_or_answered() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let session = bootstrap(&state).await;
    let act_id = signing_act(&state, &session).await;
    let created = create_invite(&state, &session, &act_id).await;
    let invite_id = created["invite"]["id"].as_str().expect("invite id");
    let token = created["token"].as_str().expect("invite token");

    let (status, revoked) = send(
        &state,
        empty_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites/{invite_id}/revoke"),
            &session,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke invite: {revoked}");

    let before_failures = ledger_len(&state).await;
    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/lookup",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "revoked token lookup refused"
    );

    let (status, _) = send(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/respond",
            json!({ "token": token, "decision": "accept" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "revoked token response refused"
    );

    let (status, _, _) = send_raw(
        &state,
        public_json_req(
            "POST",
            "/v1/signature/external-invites/document/working-copy",
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "revoked token working-copy download refused"
    );
    assert_eq!(
        ledger_len(&state).await,
        before_failures,
        "revoked public failures do not mutate the ledger"
    );
}
