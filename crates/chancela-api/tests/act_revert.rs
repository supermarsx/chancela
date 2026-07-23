//! The general "always allow going back" edge (t30): `POST /v1/acts/{id}/revert` walks an act
//! **backward** among the pre-signature drafting states (`Draft…TextApproved`).
//!
//! The binding constraints, as tests: a backward hop is ledgered as a **distinct `act.reverted`**
//! event and NEVER disguised as `act.advanced`; it requires a non-empty reason; a revert from
//! `Signing` is refused and points at the guarded `reopen` path; a `Sealed` act is never un-sealed;
//! a legal hold freezes the movement; and the endpoint is gated on the new `act.revert` permission.

use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use chancela_authz::READER_ROLE_ID;
use common::TEST_PASSWORD;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-act-revert-{}", Uuid::new_v4()));
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

async fn create_user(state: &AppState, token: &str, username: &str, display: &str) -> String {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header("content-type", "application/json")
            .header("x-chancela-session", token)
            .body(Body::from(
                json!({
                    "username": username,
                    "display_name": display,
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create user {username}: {user}"
    );
    user["id"].as_str().expect("user id").to_owned()
}

async fn open_session(state: &AppState, user_id: &str) -> String {
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

/// Bootstrap the first (Owner) user and open a session.
async fn bootstrap(state: &AppState) -> String {
    let user_id = create_user(state, "", "amelia.marques", "Amelia Marques").await;
    open_session(state, &user_id).await
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

/// The full CSC art. 63.º mandatory content plus the mesa, so the act carries no blocking finding
/// and can be advanced all the way into `Signing` and sealed.
async fn patch_valid_contents(state: &AppState, token: &str, act_id: &str) {
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
                "deliberations": "Aprovadas as contas do exercicio.",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch contents: {body}");
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

async fn revert(
    state: &AppState,
    token: &str,
    act_id: &str,
    to: &str,
    reason: &str,
) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/revert"),
            token,
            json!({ "to": to, "reason": reason }),
        ),
    )
    .await
}

async fn events_of_kind(state: &AppState, kind: &str) -> Vec<Value> {
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

async fn count_kind(state: &AppState, kind: &str) -> usize {
    state
        .ledger
        .read()
        .await
        .events()
        .iter()
        .filter(|event| event.kind == kind)
        .count()
}

async fn act_state(state: &AppState, token: &str, act_id: &str) -> String {
    let (status, act) = send(state, get_req(&format!("/v1/acts/{act_id}"), token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {act}");
    act["state"].as_str().expect("state").to_owned()
}

/// The headline guarantee: reverting across the pre-signature states regresses the marker and is
/// ledgered as a **`act.reverted`** event — never `act.advanced` — and the chain stays healthy.
#[tokio::test]
async fn revert_across_pre_signature_states_is_ledgered_as_reverted_not_advanced() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata a recuar").await;
    patch_valid_contents(&state, &token, &act_id).await;

    // Forward to TextApproved: four `act.advanced` events.
    advance_to_text_approved(&state, &token, &act_id).await;
    assert_eq!(count_kind(&state, "act.advanced").await, 4);

    // One jump all the way back to Draft (D1 = jump-to-any-earlier).
    let (status, reverted) = revert(&state, &token, &act_id, "Draft", "recomecar a redacao").await;
    assert_eq!(status, StatusCode::OK, "revert: {reverted}");
    assert_eq!(reverted["state"], "Draft");
    assert_eq!(act_state(&state, &token, &act_id).await, "Draft");

    // The backward hop is its OWN event kind, carrying who/why — and it did NOT masquerade as an
    // advance: the `act.advanced` count is unchanged.
    let reverted_events = events_of_kind(&state, "act.reverted").await;
    assert_eq!(
        reverted_events.len(),
        1,
        "one revert event: {reverted_events:?}"
    );
    let justification = reverted_events[0]["justification"]
        .as_str()
        .expect("justification");
    assert!(
        justification.contains("revert to Draft") && justification.contains("recomecar a redacao"),
        "the revert names its target and reason: {justification}"
    );
    assert_eq!(
        count_kind(&state, "act.advanced").await,
        4,
        "a revert must never append an act.advanced event"
    );
    assert!(
        state.ledger.read().await.verify().is_ok(),
        "the chain verifies across advance and revert"
    );

    // And the workflow can move forward again after going back.
    advance_ok(&state, &token, &act_id, "Review").await;
}

/// A reason is mandatory: an unexplained regression on an evidentiary object is not accepted, and a
/// refused revert appends nothing.
#[tokio::test]
async fn revert_requires_a_non_empty_reason() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata sem motivo").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Review").await;

    let (status, refusal) = revert(&state, &token, &act_id, "Draft", "   ").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "blank reason: {refusal}"
    );
    assert_eq!(act_state(&state, &token, &act_id).await, "Review");
    assert!(
        events_of_kind(&state, "act.reverted").await.is_empty(),
        "a refused revert appends nothing"
    );
}

/// A forward or same-state target is not a revert: `revert_to` rejects it as an invalid transition
/// (422), and the act does not move.
#[tokio::test]
async fn revert_to_a_forward_or_same_state_is_refused() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata em revisao").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Review").await;

    for (target, label) in [("Convened", "forward"), ("Review", "same-state")] {
        let (status, refusal) = revert(&state, &token, &act_id, target, "motivo").await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{label} target must be refused: {refusal}"
        );
    }
    assert_eq!(act_state(&state, &token, &act_id).await, "Review");
    assert!(events_of_kind(&state, "act.reverted").await.is_empty());
}

/// `Signing` is the freeze boundary: `revert` refuses it (409) and points at the guarded `reopen`
/// path, which is the only legal way back from `Signing` (it supersedes the snapshot and releases
/// the page reservation). The act stays in `Signing` and nothing is appended.
#[tokio::test]
async fn revert_from_signing_is_refused_and_points_at_reopen() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata em assinatura").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_to_text_approved(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;

    let (status, refusal) = revert(&state, &token, &act_id, "TextApproved", "corrigir").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "revert from Signing: {refusal}"
    );
    assert!(
        refusal["error"]
            .as_str()
            .expect("error string")
            .contains("reopen_for_correction"),
        "the refusal directs the caller to the guarded reopen path: {refusal}"
    );
    assert_eq!(act_state(&state, &token, &act_id).await, "Signing");
    assert!(
        events_of_kind(&state, "act.reverted").await.is_empty(),
        "a refused revert from Signing appends nothing"
    );
}

/// A `Sealed` act is never un-sealed: `revert` refuses it (422). "Back from sealed" is only ever a
/// new superseding retificacao act (WFL-21), which this endpoint deliberately does not perform.
#[tokio::test]
async fn revert_from_sealed_is_refused() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata selada").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_to_text_approved(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Signing").await;

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
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    assert_eq!(sealed["act"]["state"], "Sealed");

    let (status, refusal) = revert(&state, &token, &act_id, "TextApproved", "corrigir").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "revert from Sealed: {refusal}"
    );
    assert_eq!(act_state(&state, &token, &act_id).await, "Sealed");
    assert!(events_of_kind(&state, "act.reverted").await.is_empty());
}

/// A legal hold freezes the act's movement exactly as it freezes a reopen: the revert is refused
/// (409) while the hold stands, and succeeds once it is released — the hold gates the action, it
/// does not remove it.
#[tokio::test]
async fn a_legal_hold_refuses_the_revert() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata sob retencao").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Review").await;

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

    let (status, refusal) = revert(&state, &token, &act_id, "Draft", "corrigir").await;
    assert_eq!(status, StatusCode::CONFLICT, "revert under hold: {refusal}");
    assert!(
        refusal["error"]
            .as_str()
            .expect("error string")
            .contains("legal hold"),
        "the refusal names the hold: {refusal}"
    );
    assert_eq!(act_state(&state, &token, &act_id).await, "Review");
    assert!(events_of_kind(&state, "act.reverted").await.is_empty());

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
    let (status, reverted) = revert(&state, &token, &act_id, "Draft", "corrigir").await;
    assert_eq!(status, StatusCode::OK, "revert after release: {reverted}");
    assert_eq!(reverted["state"], "Draft");
}

/// The endpoint is gated on the new `act.revert` permission: a principal without it (here a user
/// with no role assignments at all) is forbidden, and the act is untouched.
#[tokio::test]
async fn revert_without_act_revert_permission_is_forbidden() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata protegida").await;
    patch_valid_contents(&state, &token, &act_id).await;
    advance_ok(&state, &token, &act_id, "Review").await;

    // A Reader holds only read verbs — never `act.revert` — so it cannot revert. (Creating a user
    // WITHOUT a role would fall back to the operational default, which does hold `act.revert`.)
    let (status, member) = send(
        &state,
        json_req(
            "POST",
            "/v1/users",
            &token,
            json!({
                "username": "bento.salgueiro",
                "display_name": "Bento Salgueiro",
                "password": TEST_PASSWORD,
                "role": { "role_id": READER_ROLE_ID.0.to_string(), "scope": { "kind": "global" } }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create reader: {member}");
    let member_id = member["id"].as_str().expect("user id").to_owned();
    let member = open_session(&state, &member_id).await;

    let (status, refusal) = revert(&state, &member, &act_id, "Draft", "sem autoridade").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-holder revert: {refusal}"
    );
    assert_eq!(act_state(&state, &token, &act_id).await, "Review");
    assert!(
        events_of_kind(&state, "act.reverted").await.is_empty(),
        "a forbidden revert appends nothing"
    );
}
