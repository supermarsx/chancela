//! The `Signing` dead end: the gate that prevents it, and the reverse edge that rescues an act
//! already caught in it.
//!
//! Before this slice an act could be advanced into `Signing` while carrying a blocking compliance
//! error. `Signing` makes the act immutable, and the seal gate refuses on blocking errors, so such
//! an act could be neither corrected nor sealed — permanently stranded. Two halves fix it:
//! advancing now runs the same compliance evaluation the seal runs, and `POST /v1/acts/{id}/reopen`
//! walks the one reverse edge (`Signing → TextApproved`) for acts that are already stuck.

use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_core::{ActId, ActState};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-act-reopen-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
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
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body is JSON")
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
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create owner: {user}");
    let user_id = user["id"].as_str().expect("user id");

    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "user_id": user_id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

async fn open_book(state: &AppState, token: &str) -> String {
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
    assert_eq!(status, StatusCode::CREATED, "create entity: {entity}");
    let entity_id = entity["id"].as_str().expect("entity id");

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
    assert_eq!(status, StatusCode::CREATED, "open book: {book}");
    book["id"].as_str().expect("book id").to_owned()
}

async fn draft_act(state: &AppState, token: &str, book_id: &str, title: &str) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": title, "channel": "Physical" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "draft act: {act}");
    act["id"].as_str().expect("act id").to_owned()
}

/// Every CSC art. 63.º mandatory content **except** the mesa, so the only blocking finding is the
/// missing presidente.
async fn patch_contents_without_a_mesa(state: &AppState, token: &str, act_id: &str) {
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
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Aprovadas as contas do exercicio."
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch contents: {body}");
}

async fn patch_mesa(state: &AppState, token: &str, act_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({ "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch mesa: {body}");
}

async fn advance(state: &AppState, token: &str, act_id: &str, to: &str) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/advance"),
            token,
            json!({ "to": to }),
        ),
    )
    .await
}

async fn advance_ok(state: &AppState, token: &str, act_id: &str, to: &str) {
    let (status, body) = advance(state, token, act_id, to).await;
    assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
}

async fn advance_to_text_approved(state: &AppState, token: &str, act_id: &str) {
    for to in ["Review", "Convened", "Deliberated", "TextApproved"] {
        advance_ok(state, token, act_id, to).await;
    }
}

async fn reopen(state: &AppState, token: &str, act_id: &str, reason: &str) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/reopen"),
            token,
            json!({ "reason": reason }),
        ),
    )
    .await
}

async fn compliance(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, body) = send(
        state,
        get_req(&format!("/v1/acts/{act_id}/compliance"), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compliance: {body}");
    body
}

fn blocking_rule_ids(issues: &Value) -> Vec<String> {
    let mut ids: Vec<String> = issues
        .as_array()
        .expect("issues array")
        .iter()
        .filter(|issue| issue["severity"] == "Error")
        .map(|issue| issue["rule_id"].as_str().expect("rule id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// Strand an act exactly the way the pre-fix code did: legitimately in `Signing` with its canonical
/// snapshot generated, then with the mesa removed underneath it. Reached through the read model
/// because the API can no longer produce this state — which is Part A working.
async fn strand_act_in_signing(state: &AppState, token: &str, book_id: &str) -> String {
    let act_id = draft_act(state, token, book_id, "Ata presa em assinatura").await;
    patch_contents_without_a_mesa(state, token, &act_id).await;
    patch_mesa(state, token, &act_id).await;
    advance_to_text_approved(state, token, &act_id).await;
    advance_ok(state, token, &act_id, "Signing").await;

    let mut acts = state.acts.write().await;
    let act = acts
        .get_mut(&ActId(Uuid::parse_str(&act_id).expect("uuid")))
        .expect("act present");
    assert_eq!(act.state, ActState::Signing);
    act.mesa.presidente = None;
    act.mesa.secretarios.clear();
    drop(acts);
    act_id
}

async fn ledger_events(state: &AppState, kind: &str) -> Vec<Value> {
    state
        .ledger
        .read()
        .await
        .events()
        .iter()
        .filter(|event| event.kind == kind)
        .map(|event| {
            json!({
                "actor": event.actor,
                "scope": event.scope,
                "justification": event.justification,
            })
        })
        .collect()
}

#[tokio::test]
async fn advancing_to_signing_without_a_mesa_is_refused_in_the_seal_refusal_shape() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata sem mesa").await;
    patch_contents_without_a_mesa(&state, &token, &act_id).await;

    // Everything up to the content freeze is untouched: the gate fires only where the act would
    // become immutable.
    advance_to_text_approved(&state, &token, &act_id).await;

    let (status, body) = advance(&state, &token, &act_id, "Signing").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "refusal: {body}");
    assert!(
        body["error"]
            .as_str()
            .expect("error string")
            .contains("CSC-63/mesa-presidente"),
        "the refusal names what is missing: {body}"
    );
    // Same structured `issues` array the seal refusal returns, so the UI renders both identically.
    let issue = body["issues"]
        .as_array()
        .expect("issues array")
        .iter()
        .find(|issue| issue["rule_id"] == "CSC-63/mesa-presidente")
        .expect("blocking mesa issue");
    assert_eq!(issue["severity"], "Error");
    assert!(issue["message"].is_string(), "issue carries a message");
    assert!(
        issue["legal_basis"][0]["article"] == "63",
        "issue carries its legal basis: {issue}"
    );

    // One evaluation, not two: the advance refusal reports exactly the compliance report's
    // blocking findings. A divergence here is the bug growing back in a new place.
    let report = compliance(&state, &token, &act_id).await;
    assert_eq!(
        blocking_rule_ids(&body["issues"]),
        blocking_rule_ids(&report["issues"]),
        "advance gate and compliance report must agree"
    );

    // The act stayed correctable, and nothing was frozen on its behalf.
    let (status, act) = send(&state, get_req(&format!("/v1/acts/{act_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {act}");
    assert_eq!(act["state"], "TextApproved");
    let (status, _) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document"), &token),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a refused advance must not mint a signing snapshot"
    );

    // Supplying the mesa clears the block and the same advance now succeeds.
    patch_mesa(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;
}

#[tokio::test]
async fn warnings_do_not_block_the_advance() {
    // The gate is `Error`-severity only. An entity whose NIPC was stored via the validation
    // override raises `CSC-63/nipc-unvalidated` as a Warning; sealing it needs an acknowledgement,
    // but advancing must not be held hostage to one.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;

    let (status, entity) = send(
        &state,
        json_req(
            "POST",
            "/v1/entities",
            &token,
            json!({
                "name": "Foreign Holdings Ltd.",
                "nipc": "GB-00000000",
                "allow_invalid_nipc": true,
                "seat": "London",
                "kind": "SociedadeAnonima"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create entity: {entity}");
    let (status, book) = send(
        &state,
        json_req(
            "POST",
            "/v1/books",
            &token,
            json!({
                "entity_id": entity["id"],
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "open book: {book}");
    let book_id = book["id"].as_str().expect("book id").to_owned();

    let act_id = draft_act(&state, &token, &book_id, "Ata com advertencia").await;
    patch_contents_without_a_mesa(&state, &token, &act_id).await;
    patch_mesa(&state, &token, &act_id).await;
    let report = compliance(&state, &token, &act_id).await;
    assert!(
        report["warnings"].as_u64().expect("warnings") > 0,
        "{report}"
    );
    assert_eq!(report["errors"], 0, "{report}");

    advance_to_text_approved(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;
}

#[tokio::test]
async fn a_stuck_act_is_reopened_corrected_re_advanced_and_sealed() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = strand_act_in_signing(&state, &token, &book_id).await;

    // The dead end, reproduced: sealing refuses on the blocking error, and the act is immutable.
    let (status, refusal) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/seal"),
            &token,
            json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "seal: {refusal}");
    let (status, patched) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            &token,
            json!({ "mesa": { "presidente": "Ana Presidente", "secretarios": [] } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "patch in Signing: {patched}");

    // The rescue.
    let (status, reopened) = reopen(&state, &token, &act_id, "mesa em falta na ata").await;
    assert_eq!(status, StatusCode::OK, "reopen: {reopened}");
    assert_eq!(reopened["from"], "Signing");
    assert_eq!(reopened["to"], "TextApproved");
    assert_eq!(reopened["act"]["state"], "TextApproved");
    let retired = reopened["superseded_signing_snapshot"]["document_id"]
        .as_str()
        .expect("retired snapshot id")
        .to_owned();

    // The retired snapshot no longer resolves as this act's signing document, so nothing can sign
    // or seal against the bytes that were pulled back.
    let (status, _) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document"), &token),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the superseded snapshot must not resolve as the signing document"
    );

    // Correct, re-advance, seal.
    patch_mesa(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;

    let (status, act) = send(&state, get_req(&format!("/v1/acts/{act_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {act}");
    assert_eq!(act["state"], "Signing");

    let (status, sealed) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/seal"),
            &token,
            json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal after correction: {sealed}");
    assert_eq!(sealed["act"]["state"], "Sealed");
    // The seal bound the *fresh* snapshot, never the one the reopen retired.
    assert_ne!(
        sealed["document"]["id"]
            .as_str()
            .expect("sealed document id"),
        retired,
        "the seal must not bind the retired snapshot"
    );
    assert!(
        state.ledger.read().await.verify().is_ok(),
        "the chain verifies across reopen, re-advance and seal"
    );
}

#[tokio::test]
async fn a_reopen_is_ledgered_with_who_when_from_what_and_which_snapshot() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = strand_act_in_signing(&state, &token, &book_id).await;

    let (status, reopened) = reopen(&state, &token, &act_id, "mesa em falta na ata").await;
    assert_eq!(status, StatusCode::OK, "reopen: {reopened}");

    let events = ledger_events(&state, "act.reopened").await;
    assert_eq!(events.len(), 1, "exactly one reopen event: {events:?}");
    assert_eq!(events[0]["actor"], "amelia.marques");
    assert!(
        events[0]["scope"]
            .as_str()
            .expect("scope")
            .contains(&format!("act:{act_id}")),
        "event is scoped to the act: {events:?}"
    );
    assert!(
        events[0]["justification"]
            .as_str()
            .expect("justification")
            .contains("mesa em falta na ata"),
        "the reason is on the event: {events:?}"
    );
    assert!(
        reopened["event_seq"].as_u64().is_some(),
        "the response names the ledger event: {reopened}"
    );
    assert!(
        state.ledger.read().await.verify().is_ok(),
        "the chain still verifies after a state regression"
    );

    // A reason is mandatory: an unexplained regression on an evidentiary object is not accepted.
    let act_id2 = strand_act_in_signing(&state, &token, &book_id).await;
    let (status, refusal) = reopen(&state, &token, &act_id2, "   ").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "blank reason: {refusal}"
    );
}

#[tokio::test]
async fn a_collected_signature_refuses_the_reopen_and_is_never_discarded() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;

    let act_id = draft_act(&state, &token, &book_id, "Ata ja assinada").await;
    patch_contents_without_a_mesa(&state, &token, &act_id).await;
    patch_mesa(&state, &token, &act_id).await;
    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            &token,
            json!({
                "signatories": [
                    { "name": "Ana Presidente", "capacity": "Chair", "signed": true },
                    { "name": "Rui Secretario", "capacity": "Secretary", "signed": false }
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch signatories: {body}");
    advance_to_text_approved(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;

    let (status, refusal) = reopen(&state, &token, &act_id, "corrigir a mesa").await;
    assert_eq!(status, StatusCode::CONFLICT, "reopen: {refusal}");
    let error = refusal["error"].as_str().expect("error string");
    assert!(
        error.contains("collected signature") && error.contains("WFL-21"),
        "the refusal says why and names the remedy: {refusal}"
    );

    // Refused means untouched: still in Signing, signature intact, nothing superseded.
    let (status, act) = send(&state, get_req(&format!("/v1/acts/{act_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {act}");
    assert_eq!(act["state"], "Signing");
    assert_eq!(act["signatories"][0]["signed"], true);
    assert!(
        ledger_events(&state, "act.reopened").await.is_empty(),
        "a refused reopen appends nothing"
    );
}

#[tokio::test]
async fn a_legal_hold_refuses_the_reopen() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = strand_act_in_signing(&state, &token, &book_id).await;

    let (status, hold) = send(
        &state,
        json_req(
            "PUT",
            &format!("/v1/books/{book_id}/legal-hold"),
            &token,
            json!({ "reason": "litigio pendente" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set legal hold: {hold}");

    let (status, refusal) = reopen(&state, &token, &act_id, "corrigir a mesa").await;
    assert_eq!(status, StatusCode::CONFLICT, "reopen under hold: {refusal}");
    assert!(
        refusal["error"]
            .as_str()
            .expect("error string")
            .contains("legal hold"),
        "the refusal names the hold: {refusal}"
    );
    let (status, act) = send(&state, get_req(&format!("/v1/acts/{act_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {act}");
    assert_eq!(act["state"], "Signing");
    assert!(
        ledger_events(&state, "act.reopened").await.is_empty(),
        "a held book appends nothing"
    );

    // Released, the same reopen succeeds — the hold gates the action, it does not remove it.
    let (status, cleared) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/books/{book_id}/legal-hold"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clear legal hold: {cleared}");
    let (status, reopened) = reopen(&state, &token, &act_id, "corrigir a mesa").await;
    assert_eq!(status, StatusCode::OK, "reopen after release: {reopened}");
}
