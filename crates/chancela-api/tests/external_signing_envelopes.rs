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

/// A parallel-order envelope whose two slots are **both required**, so each can be resolved
/// independently and both must be signed for the envelope to complete.
async fn parallel_two_required_envelope(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, envelope) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            token,
            json!({
                "order_policy": "parallel",
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

fn sign_slot_body(slot_id: &str, reference: &str) -> Value {
    json!({
        "slots": [{
            "id": slot_id,
            "status": "signed",
            "evidence": [{ "label": "provider event", "reference": reference }]
        }]
    })
}

/// Assert `slot_id` is signed in `envelope` **and** still carries its own evidence reference.
///
/// Status alone is not enough: the failure this guards against reverts the status *and* drops the
/// evidence, and evidence recorded through this path exists in no other store.
///
/// `signed` is spelled by the caller because the two serializations differ: the API DTO is
/// `#[serde(rename_all = "snake_case")]` and emits `"signed"`, while the persisted domain enum
/// emits its variant name `"Signed"`. Asserting the exact spelling of whichever document is in
/// hand keeps this from quietly passing on the wrong shape.
fn assert_signed_with_evidence(envelope: &Value, slot_id: &str, signed: &str, reference: &str) {
    let slot = envelope["slots"]
        .as_array()
        .expect("slots")
        .iter()
        .find(|slot| slot["id"] == slot_id)
        .unwrap_or_else(|| panic!("slot {slot_id} is missing: {envelope}"));
    assert_eq!(
        slot["status"], signed,
        "slot {slot_id} lost its update and reverted: {envelope}"
    );
    assert!(
        slot["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|item| item["reference"] == reference),
        "slot {slot_id} lost the evidence recorded against it: {envelope}"
    );
}

/// **Lost-update regression.** Two operators record evidence on two *different* slots of one
/// envelope at the same time. Before the fix, each request read the aggregate, mutated a detached
/// clone, and blind-inserted the whole aggregate back: the second insert overwrote the first, the
/// first slot silently reverted to `pending`, and its evidence — which exists nowhere but this
/// aggregate — was destroyed. Both requests still answered `200 OK`. That is the silent drop this
/// guards against; a refusal would have been fine.
///
/// **How the overlap is forced.** `require_permission` reaches `authz::scope_relations`, which
/// snapshots `group_template_libraries` on every authorization decision. In `patch_envelope` that
/// snapshot happens *after* the aggregate has been read and *before* it is written back, and
/// nothing else on this request path touches that map — its only other readers are the groups
/// handlers and the cluster feed, neither of which this test calls. Holding the write side parks
/// both requests inside the read-modify-write window; releasing it lets both proceed to their
/// writes having already read the same pre-state.
///
/// **Why it repeats.** Neither guard below is airtight on its own, and a concurrency test that
/// interleaves nothing passes green while the defect ships. The barrier proves both tasks reached
/// the same starting line with their code paths already warm; `is_finished` proves neither request
/// *completed* before the gate dropped. Neither proves a request had actually reached the gate
/// rather than still being on its way there, and a starved task that arrives late makes an attempt
/// prove nothing. Measured against the unfixed code a single attempt reproduces the loss about four
/// times in five, so the attempts repeat on independent envelopes and *every* attempt must preserve
/// both signatures.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_updates_to_different_slots_keep_both_signatures() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let act_id = signing_act(&state, &token).await;

    for attempt in 1..=5 {
        let envelope = parallel_two_required_envelope(&state, &token, &act_id).await;
        let envelope_id = envelope["id"].as_str().expect("envelope id").to_owned();
        let chair = envelope["slots"][0]["id"]
            .as_str()
            .expect("slot id")
            .to_owned();
        let secretary = envelope["slots"][1]["id"]
            .as_str()
            .expect("slot id")
            .to_owned();

        // Two rendezvous, and they must be separate. The warm-up GET goes through
        // `require_permission` too, so it needs the *read* side of the very map this test gates on.
        // Closing the gate before the writers have finished warming would block them inside the
        // warm-up, they would never reach the rendezvous, and the test would deadlock rather than
        // race. So: `warmed` proves both warm-ups are done and the read lock is free, *then* the
        // gate closes, and only then does `go` release both writers into the racing PATCH.
        let warmed = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let go = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let spawn_sign = |slot_id: String, reference: String| {
            let state = state.clone();
            let token = token.clone();
            let warmed = warmed.clone();
            let go = go.clone();
            let uri = format!("/v1/external-signing/envelopes/{envelope_id}");
            tokio::spawn(async move {
                // Warm the whole path first — router construction, session resolution, permission
                // resolution — so that after `go` the only work left before the gate is code this
                // task has already executed once.
                let (status, body) = send(&state, get_req(&uri, &token)).await;
                assert_eq!(status, StatusCode::OK, "warm-up read: {body}");
                warmed.wait().await;
                go.wait().await;
                send(
                    &state,
                    json_req("PATCH", &uri, &token, sign_slot_body(&slot_id, &reference)),
                )
                .await
            })
        };
        let chair_write = spawn_sign(chair.clone(), "provider:event:chair-signed".to_owned());
        let secretary_write = spawn_sign(
            secretary.clone(),
            "provider:event:secretary-signed".to_owned(),
        );

        warmed.wait().await;
        let gate = state.group_template_libraries.write().await;
        go.wait().await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !chair_write.is_finished(),
            "attempt {attempt}: the chair request completed before the gate was released, so the \
             two writes never overlapped and this attempt would prove nothing"
        );
        assert!(
            !secretary_write.is_finished(),
            "attempt {attempt}: the secretary request completed before the gate was released, so \
             the two writes never overlapped and this attempt would prove nothing"
        );
        drop(gate);

        let (chair_status, chair_body) = chair_write.await.expect("chair request completes");
        let (secretary_status, secretary_body) =
            secretary_write.await.expect("secretary request completes");
        assert_eq!(
            chair_status,
            StatusCode::OK,
            "attempt {attempt} chair signed: {chair_body}"
        );
        assert_eq!(
            secretary_status,
            StatusCode::OK,
            "attempt {attempt} secretary signed: {secretary_body}"
        );

        let (status, read) = send(
            &state,
            get_req(
                &format!("/v1/external-signing/envelopes/{envelope_id}"),
                &token,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt} read: {read}");
        assert_signed_with_evidence(&read, &chair, "signed", "provider:event:chair-signed");
        assert_signed_with_evidence(
            &read,
            &secretary,
            "signed",
            "provider:event:secretary-signed",
        );
        assert_eq!(
            read["completion"]["signed_required_slot_count"], 2,
            "attempt {attempt}: both required slots must be counted as signed: {read}"
        );
        assert!(
            read["completion"]["blocking_required_slot_ids"]
                .as_array()
                .expect("blocking ids")
                .is_empty(),
            "attempt {attempt}: a required slot regained blocking status after being signed: {read}"
        );

        // The durable record must carry both updates too. Persisting after the write guard dropped
        // left a second, quieter window: two writers could rename their files in the opposite order
        // and leave the older snapshot on disk with memory still correct — a loss that surfaces
        // only on restart.
        let persisted: Value = serde_json::from_slice(
            &std::fs::read(dir.0.join("external-signing-envelopes.json"))
                .expect("envelopes persisted"),
        )
        .expect("envelope document parses");
        let stored = persisted
            .as_array()
            .expect("envelope list")
            .iter()
            .find(|stored| stored["id"] == envelope_id.as_str())
            .unwrap_or_else(|| panic!("attempt {attempt}: the envelope is not on disk"))
            .clone();
        assert_signed_with_evidence(&stored, &chair, "Signed", "provider:event:chair-signed");
        assert_signed_with_evidence(
            &stored,
            &secretary,
            "Signed",
            "provider:event:secretary-signed",
        );
    }

    // Both writes of every attempt were recorded. Note what this can and cannot show: the ledger
    // retains only `payload_digest`, never the payload, so the completion counts these events carry
    // are not readable back and a lost update leaves no detectable trace in the event history.
    let updates = {
        let ledger = state.ledger.read().await;
        ledger
            .events()
            .iter()
            .filter(|event| event.kind == "signature.external_envelope.updated")
            .count()
    };
    assert_eq!(
        updates, 10,
        "both slot updates of all five attempts recorded"
    );
}
