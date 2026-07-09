use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_core::{ActId, ActState};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-closed-book-acts-{}", Uuid::new_v4()));
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
                json!({ "username": "closed.book.owner", "display_name": "Closed Book Owner" })
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
            .body(Body::from(json!({ "user_id": user_id }).to_string()))
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
    assert_eq!(book["state"], "Open");
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

async fn patch_required_contents(state: &AppState, token: &str, act_id: &str) {
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
    assert_eq!(status, StatusCode::OK, "patch contents: {body}");
}

async fn patch_convening(state: &AppState, token: &str, act_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({
                "convening": {
                    "antecedence_days": 21,
                    "recipients": [{ "name": "Ana Presidente" }, { "name": "Rui Secretario" }]
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch convening: {body}");
}

async fn advance_to(state: &AppState, token: &str, act_id: &str, to: &str) {
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

async fn advance_to_signing(state: &AppState, token: &str, act_id: &str) {
    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        advance_to(state, token, act_id, to).await;
    }
}

async fn seal_act(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, body) = send(
        state,
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal act: {body}");
    body
}

async fn close_book(state: &AppState, token: &str, book_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/close"),
            token,
            json!({
                "reason": "BookFull",
                "closing_date": "2026-12-31",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "close book: {body}");
    assert_eq!(body["state"], "Closed");
}

async fn get_act(state: &AppState, token: &str, act_id: &str) -> Value {
    let (status, body) = send(state, get_req(&format!("/v1/acts/{act_id}"), token)).await;
    assert_eq!(status, StatusCode::OK, "get act: {body}");
    body
}

async fn ledger_len(state: &AppState) -> usize {
    state.ledger.read().await.len()
}

fn act_id(id: &str) -> ActId {
    ActId(Uuid::parse_str(id).expect("valid act id"))
}

fn assert_read_only_conflict(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::CONFLICT, "closed-book mutation: {body}");
    let error = body["error"].as_str().expect("error string");
    assert!(
        error.contains("read-only") && error.contains("Closed"),
        "conflict explains closed-book read-only mode: {body}"
    );
}

#[tokio::test]
async fn open_book_act_mutations_continue_to_work() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;
    let act_id = draft_act(&state, &token, &book_id, "Open book control").await;

    patch_required_contents(&state, &token, &act_id).await;
    patch_convening(&state, &token, &act_id).await;

    let (status, dispatched) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/convening/dispatch"),
            &token,
            json!({ "dispatched_at": "2026-03-02", "channel": "Email" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dispatch convening: {dispatched}");

    advance_to_signing(&state, &token, &act_id).await;
    let sealed = seal_act(&state, &token, &act_id).await;
    assert_eq!(sealed["act"]["state"], "Sealed");

    let (status, archived) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/archive"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "archive act: {archived}");
    assert_eq!(archived["state"], "Archived");
}

#[tokio::test]
async fn closed_book_rejects_pre_existing_act_mutations() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let book_id = open_book(&state, &token).await;

    let patch_id = draft_act(&state, &token, &book_id, "Patch remains original").await;
    let advance_id = draft_act(&state, &token, &book_id, "Advance remains draft").await;
    let dispatch_id = draft_act(&state, &token, &book_id, "Dispatch remains unstamped").await;
    patch_convening(&state, &token, &dispatch_id).await;

    let seal_id = draft_act(&state, &token, &book_id, "Seal remains signing").await;
    patch_required_contents(&state, &token, &seal_id).await;
    advance_to_signing(&state, &token, &seal_id).await;

    let archive_id = draft_act(&state, &token, &book_id, "Archive remains sealed").await;
    patch_required_contents(&state, &token, &archive_id).await;
    advance_to_signing(&state, &token, &archive_id).await;
    seal_act(&state, &token, &archive_id).await;

    close_book(&state, &token, &book_id).await;
    let ledger_events_after_close = ledger_len(&state).await;

    let (status, body) = send(
        &state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{patch_id}"),
            &token,
            json!({ "title": "mutated after close" }),
        ),
    )
    .await;
    assert_read_only_conflict(status, &body);
    assert_eq!(
        ledger_len(&state).await,
        ledger_events_after_close,
        "failed closed-book patch must not append ledger events"
    );
    let act = get_act(&state, &token, &patch_id).await;
    assert_eq!(act["title"], "Patch remains original");
    assert_eq!(act["state"], "Draft");

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{advance_id}/advance"),
            &token,
            json!({ "to": "Review" }),
        ),
    )
    .await;
    assert_read_only_conflict(status, &body);
    assert_eq!(
        ledger_len(&state).await,
        ledger_events_after_close,
        "failed closed-book advance must not append ledger events"
    );
    let act = get_act(&state, &token, &advance_id).await;
    assert_eq!(act["state"], "Draft");

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{dispatch_id}/convening/dispatch"),
            &token,
            json!({ "dispatched_at": "2026-03-02", "channel": "Email" }),
        ),
    )
    .await;
    assert_read_only_conflict(status, &body);
    assert_eq!(
        ledger_len(&state).await,
        ledger_events_after_close,
        "failed closed-book convening dispatch must not append ledger events"
    );
    let act = get_act(&state, &token, &dispatch_id).await;
    let recipients = act["convening"]["recipients"]
        .as_array()
        .expect("recipients");
    assert!(recipients.iter().all(|r| r["dispatched_at"].is_null()));

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{seal_id}/seal"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_read_only_conflict(status, &body);
    assert_eq!(
        ledger_len(&state).await,
        ledger_events_after_close,
        "failed closed-book seal must not append ledger events"
    );
    let act = get_act(&state, &token, &seal_id).await;
    assert_eq!(act["state"], "Signing");
    assert!(act["ata_number"].is_null());

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/acts/{archive_id}/archive"),
            &token,
            json!({}),
        ),
    )
    .await;
    assert_read_only_conflict(status, &body);
    assert_eq!(
        ledger_len(&state).await,
        ledger_events_after_close,
        "failed closed-book archive must not append ledger events"
    );
    let act = get_act(&state, &token, &archive_id).await;
    assert_eq!(act["state"], "Sealed");

    let restarted = AppState::with_data_dir(dir.0.clone());
    let acts = restarted.acts.read().await;

    let patch = acts.get(&act_id(&patch_id)).expect("patch act reloads");
    assert_eq!(patch.title, "Patch remains original");
    assert_eq!(patch.state, ActState::Draft);

    let advanced = acts.get(&act_id(&advance_id)).expect("advance act reloads");
    assert_eq!(advanced.state, ActState::Draft);

    let dispatched = acts
        .get(&act_id(&dispatch_id))
        .expect("dispatch act reloads");
    assert!(
        dispatched
            .convening
            .as_ref()
            .expect("convening remains")
            .recipients
            .iter()
            .all(|recipient| recipient.dispatched_at.is_none()),
        "failed dispatch must not persist recipient stamps"
    );

    let seal = acts.get(&act_id(&seal_id)).expect("seal act reloads");
    assert_eq!(seal.state, ActState::Signing);
    assert_eq!(seal.ata_number, None);

    let archive = acts.get(&act_id(&archive_id)).expect("archive act reloads");
    assert_eq!(archive.state, ActState::Sealed);
}
