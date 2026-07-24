use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-external-signing-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
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

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn get_req(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
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

/// Creates an act and advances it into `Signing`, the state required before an
/// external-signing envelope can be created (see signature.rs guard).
async fn signing_act(state: &AppState, token: &str) -> String {
    let act_id = draft_act(state, token).await;
    prepare_signing_act(state, token, &act_id).await;
    act_id
}

async fn create_envelope(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, envelope) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            token,
            json!({
                "order_policy": "sequential",
                "slots": [
                    { "signer_label": "Chair", "contact_hint": "***1234", "required": true },
                    { "signer_label": "Observer", "required": false }
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create envelope: {envelope}");
    envelope
}

#[tokio::test]
async fn marker_only_completion_is_rejected_until_required_slot_is_signed() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_envelope(&state, &token, &act_id).await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let required_slot = envelope["slots"][0]["id"].as_str().expect("slot id");

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({ "complete": true }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "marker-only completion refused: {body}"
    );

    let (status, signed) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": required_slot,
                    "status": "signed",
                    "evidence": [{
                        "label": "provider event",
                        "reference": "provider:event:chair-signed",
                        "digest": "0707070707070707070707070707070707070707070707070707070707070707"
                    }]
                }],
                "complete": true
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "signed completion succeeds: {signed}"
    );
    assert_eq!(signed["completed"], true);
    assert_eq!(signed["completion"]["signed_required_slot_count"], 1);
    assert_eq!(
        signed["slots"][0]["evidence"][0]["reference"],
        "provider:event:chair-signed"
    );
    assert!(
        signed
            .to_string()
            .contains("External signing envelope workflow only")
    );
    assert!(
        signed.get("legal_effect").is_none(),
        "API must not surface legal claim fields"
    );
    assert!(signed.get("qualified").is_none());

    let (status, read) = send(
        &state,
        get_req(
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read envelope: {read}");
    assert_eq!(read["completed"], true);
}

#[tokio::test]
async fn signed_status_without_evidence_is_rejected() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_envelope(&state, &token, &act_id).await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let required_slot = envelope["slots"][0]["id"].as_str().expect("slot id");

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({ "slots": [{ "id": required_slot, "status": "signed" }] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "signed marker without evidence refused: {body}"
    );
}

#[tokio::test]
async fn signed_slot_evidence_without_complete_stays_workflow_open() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;
    let envelope = create_envelope(&state, &token, &act_id).await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let required_slot = envelope["slots"][0]["id"].as_str().expect("slot id");

    let (status, signed) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": required_slot,
                    "status": "signed",
                    "evidence": [{
                        "label": "operator technical evidence",
                        "reference": "operator:event:chair-signed",
                        "digest": "0707070707070707070707070707070707070707070707070707070707070707"
                    }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signed slot evidence: {signed}");
    assert_eq!(signed["completed"], false);
    assert_eq!(signed["slots"][0]["status"], "signed");
    assert_eq!(
        signed["slots"][0]["evidence"][0]["reference"],
        "operator:event:chair-signed"
    );
    assert_eq!(signed["completion"]["signed_required_slot_count"], 1);
    assert_eq!(
        signed["completion"]["blocking_required_slot_ids"],
        json!([])
    );

    let (status, read) = send(
        &state,
        get_req(
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read envelope: {read}");
    assert_eq!(read["completed"], false);
    assert_eq!(read["completion"]["completed"], false);
}

#[tokio::test]
async fn configured_identity_requirements_need_matching_evidence_before_signed() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;

    let (status, envelope) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            &token,
            json!({
                "order_policy": "parallel",
                "slots": [{
                    "signer_label": "Chair",
                    "contact_hint": "***1234",
                    "required": true,
                    "identity_requirements": [
                        "contact_control",
                        "provider_identity_assertion"
                    ]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create envelope: {envelope}");
    assert_eq!(
        envelope["slots"][0]["identity_requirements"],
        json!(["contact_control", "provider_identity_assertion"])
    );
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let slot_id = envelope["slots"][0]["id"].as_str().expect("slot id");

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": slot_id,
                    "status": "signed",
                    "evidence": [{
                        "label": "signature artifact",
                        "reference": "provider:event:chair-signed"
                    }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing identity evidence refused: {body}"
    );

    let (status, signed) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": slot_id,
                    "status": "signed",
                    "evidence": [
                        {
                            "label": "signature artifact",
                            "reference": "provider:event:chair-signed",
                            "digest": "0707070707070707070707070707070707070707070707070707070707070707"
                        },
                        {
                            "label": "contact-channel evidence",
                            "reference": "provider:event:contact-control",
                            "identity_requirement": "contact_control"
                        },
                        {
                            "label": "provider identity assertion",
                            "reference": "provider:event:identity-asserted",
                            "identity_requirement": "provider_identity_assertion"
                        }
                    ]
                }],
                "complete": true
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "identity-backed signed update succeeds: {signed}"
    );
    assert_eq!(signed["completed"], true);
    assert_eq!(signed["slots"][0]["status"], "signed");
    assert_eq!(
        signed["slots"][0]["evidence"][1]["identity_requirement"],
        "contact_control"
    );
    assert_eq!(
        signed["slots"][0]["evidence"][2]["identity_requirement"],
        "provider_identity_assertion"
    );
    assert!(signed.get("legal_effect").is_none());
    assert!(signed.get("qualified").is_none());
}

#[tokio::test]
async fn declined_expired_and_revoked_required_slots_block_completion() {
    for terminal in ["declined", "expired", "revoked"] {
        let dir = TempDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let token = bootstrap(&state).await;
        let act_id = signing_act(&state, &token).await;
        let envelope = create_envelope(&state, &token, &act_id).await;
        let envelope_id = envelope["id"].as_str().expect("envelope id");
        let required_slot = envelope["slots"][0]["id"].as_str().expect("slot id");

        let (status, updated) = send(
            &state,
            json_req(
                "PATCH",
                &format!("/v1/external-signing/envelopes/{envelope_id}"),
                &token,
                json!({
                    "slots": [{
                        "id": required_slot,
                        "status": terminal,
                        "evidence": [{ "label": "provider event", "reference": format!("provider:event:{terminal}") }]
                    }]
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{terminal} update: {updated}");
        assert_eq!(updated["slots"][0]["status"], terminal);

        let (status, body) = send(
            &state,
            json_req(
                "PATCH",
                &format!("/v1/external-signing/envelopes/{envelope_id}"),
                &token,
                json!({ "complete": true }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{terminal} required slot blocks completion: {body}"
        );

        let (status, read) = send(
            &state,
            get_req(
                &format!("/v1/external-signing/envelopes/{envelope_id}"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(read["completed"], false);
        assert_eq!(
            read["completion"]["blocking_required_slot_ids"][0],
            required_slot
        );
    }
}

#[tokio::test]
async fn sequential_flow_blocks_later_required_slots_until_earlier_resolves() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;

    let (status, envelope) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            &token,
            json!({
                "order_policy": "sequential",
                "slots": [
                    { "signer_label": "Chair", "required": true },
                    { "signer_label": "Secretary", "required": true }
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create envelope: {envelope}");
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let first = envelope["slots"][0]["id"].as_str().expect("first slot");
    let second = envelope["slots"][1]["id"].as_str().expect("second slot");

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({ "slots": [{ "id": second, "status": "initiated" }] }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "later slot blocked by sequential order: {body}"
    );

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": second,
                    "status": "signed",
                    "evidence": [{
                        "label": "provider event",
                        "reference": "provider:event:second-signed"
                    }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "later signature blocked by sequential order: {body}"
    );

    let (status, updated) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({
                "slots": [{
                    "id": first,
                    "status": "declined",
                    "evidence": [{ "label": "provider event", "reference": "provider:event:first-declined" }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first resolved: {updated}");

    let (status, updated) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
            json!({ "slots": [{ "id": second, "status": "initiated" }] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second now allowed: {updated}");
    assert_eq!(updated["slots"][1]["status"], "initiated");
}
