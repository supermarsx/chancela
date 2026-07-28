//! Archiving an entity retires it from **new authorship** and from nothing else (t60-e3).
//!
//! This is the *enforcement* regression. The core-level freeze lives in
//! `chancela-core/tests/entity_archive_freeze.rs` (t60-e1) and pins the domain guarantees: the
//! `Entity` ledger-payload byte shape, and that neither the `book.opened` genesis digest nor a
//! sealed act's preimage can notice archiving. Nothing here repeats those. What is proved here is
//! the layer above them — that the four production creation paths refuse, that everything else
//! still works through the real router, and that party identity still resolves end to end.
//!
//! # Where party identity actually lives
//!
//! ```text
//! act.book_id  ->  Book.termo_abertura  ->  TermoDeAbertura { entity_name, entity_nipc, entity_seat }
//! ```
//!
//! `ActPayload` — the act's canonical digest preimage — carries **zero** entity-identity fields. A
//! test that looked for a party name inside the act would be asserting something that was never
//! there, and would teach the next reader that the guarantee lives somewhere it does not. So
//! [`frozen_party_identity`] walks that chain explicitly, link by link, and the assertions name it.
//! `TermoDeAbertura` **is** the `book.opened` genesis preimage, which the domain forbids anyone from
//! reordering, renaming or removing a field from — so the snapshot an act's parties resolve through
//! is one that archiving cannot reach even in principle.
//!
//! # The invariant these tests defend
//!
//! **Filtering for archived-ness happens ONLY at the list/picker layer.** It must never enter an
//! `entities.get(...)` resolution path, and an archived entity must never leave `state.entities`.
//! `documents::preview_document` resolves its party name through exactly such a lookup
//! (`entities.get(&book.entity_id).ok_or(ApiError::NotFound)?`), so
//! [`a_document_still_names_its_parties_after_the_entity_is_archived`] is a live tripwire on it: the
//! day archiving leaks into resolution, a sealed act loses the ability to name who was in the room
//! and that test goes red.
//!
//! # Why these tests archive through `state.entities` rather than over HTTP
//!
//! `POST /v1/entities/{id}/archive` is t60-e2's, landing in parallel. Reaching into the read model
//! keeps this file about *enforcement* rather than about the route, and means these guards are
//! covered whatever shape the endpoint finally takes. It uses the real `Entity::archive`, so the
//! state reached is the same state the route will produce.

use crate::common;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chancela_api::{AppState, router};
use chancela_core::{ActId, BookId, EntityId};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

use common::TEST_PASSWORD;

/// The fixture entity's identity, frozen into the termo at book opening and asserted back out of it
/// after archiving. Plain ASCII so a substring assertion over a rendered document cannot fail for a
/// reason that has nothing to do with archiving.
const ENTITY_NAME: &str = "Encosto Estrategico, S.A.";
const ENTITY_NIPC: &str = "503004642";
const ENTITY_SEAT: &str = "Lisboa";

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("chancela-entity-archive-enforcement-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("temp dir created");
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// -------------------------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------------------------

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

/// Seed the first operator. The password is verifiable because `POST /v1/books/{id}/start-over`
/// requires step-up re-auth, and this suite has to reach the guard *behind* that gate.
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

async fn create_entity(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": ENTITY_NAME,
                "nipc": ENTITY_NIPC,
                "seat": ENTITY_SEAT,
                "kind": "SociedadeAnonima"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create entity: {entity}");
    entity["id"].as_str().expect("entity id").to_owned()
}

fn new_book_body(entity_id: &str) -> Value {
    json!({
        "entity_id": entity_id,
        "kind": "AssembleiaGeral",
        "purpose": "livro de atas da assembleia geral",
        "numbering_scheme": "Sequential",
        "opening_date": "2026-01-15",
        "required_signatories": ["Administrador"]
    })
}

/// One-shot open: create + `open_and_seal_book` in a single commit, so the `TermoDeAbertura` that
/// freezes party identity exists from this moment on.
async fn open_book(state: &AppState, token: &str, entity_id: &str) -> String {
    let (status, book) = send(
        state,
        json_req("POST", "/v1/books", token, new_book_body(entity_id)),
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

async fn fill_act(state: &AppState, token: &str, act_id: &str) {
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
                "mesa": { "presidente": "Amelia Marques", "secretarios": ["Rui Ferreira"] },
                "agenda": [{ "number": 1, "text": "Relatorio de gestao e contas do exercicio" }],
                "attendance_reference": "Lista de presencas anexa",
                "deliberations": "Aprovadas as contas do exercicio."
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fill act: {body}");
}

async fn advance_to_signing(state: &AppState, token: &str, act_id: &str) {
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

async fn seal_act(state: &AppState, token: &str, act_id: &str) -> (StatusCode, Value) {
    send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/seal"),
            token,
            json!({
                "manual_signature_original_reference": {
                    "storage_reference": "Arquivo A / Pasta 2026 / Ata 1"
                }
            }),
        ),
    )
    .await
}

/// An entity, an open book, and one sealed act inside it. The state every test below archives from.
async fn entity_with_a_sealed_act(state: &AppState, token: &str) -> (String, String, String) {
    let entity_id = create_entity(state, token).await;
    let book_id = open_book(state, token, &entity_id).await;
    let act_id = draft_act(state, token, &book_id, "Ata da assembleia geral anual").await;
    fill_act(state, token, &act_id).await;
    advance_to_signing(state, token, &act_id).await;
    let (status, sealed) = seal_act(state, token, &act_id).await;
    assert_eq!(status, StatusCode::OK, "seal act: {sealed}");
    assert_eq!(sealed["act"]["state"], "Sealed");
    (entity_id, book_id, act_id)
}

/// Archive through the core transition, exactly as `POST /v1/entities/{id}/archive` will (t60-e2).
async fn archive(state: &AppState, entity_id: &str) {
    let id = EntityId(Uuid::parse_str(entity_id).expect("entity uuid"));
    let mut entities = state.entities.write().await;
    entities
        .get_mut(&id)
        .expect("the entity is in the read model")
        .archive(OffsetDateTime::now_utc())
        .expect("an active entity archives");
}

async fn unarchive(state: &AppState, entity_id: &str) {
    let id = EntityId(Uuid::parse_str(entity_id).expect("entity uuid"));
    let mut entities = state.entities.write().await;
    entities
        .get_mut(&id)
        .expect("the entity is in the read model")
        .unarchive()
        .expect("an archived entity unarchives");
}

/// Walk the identity chain the way the product does, one link at a time:
/// `act.book_id -> Book.termo_abertura -> TermoDeAbertura { entity_name, entity_nipc, entity_seat }`.
///
/// Deliberately **not** read off the entity row, and deliberately not read off the act: the act has
/// no entity-identity fields to read. If this function ever needs to consult `state.entities` to
/// answer, the guarantee has moved and the plan's §2 argument no longer holds.
async fn frozen_party_identity(state: &AppState, act_id: &str) -> (String, String, String) {
    let act_id = ActId(Uuid::parse_str(act_id).expect("act uuid"));
    let book_id = {
        let acts = state.acts.read().await;
        acts.get(&act_id).expect("the sealed act is retained").book_id
    };
    let books = state.books.read().await;
    let book = books.get(&book_id).expect("the act's book is retained");
    let termo = book
        .termo_abertura
        .as_ref()
        .expect("an opened book retains its termo de abertura");
    (
        termo.entity_name.clone(),
        termo.entity_nipc.clone(),
        termo.entity_seat.clone(),
    )
}

/// Every guard speaks the same sentence: it is a `409`, it names the entity, and it names the
/// remedy. A silent no-op or a bare status code would leave an operator guessing whether the work
/// was recorded.
fn assert_archived_refusal(status: StatusCode, body: &Value, context: &str) {
    assert_eq!(status, StatusCode::CONFLICT, "{context}: {body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("is archived"),
        "{context}: the refusal must say the entity is archived: {body}"
    );
    assert!(
        error.contains(ENTITY_NAME),
        "{context}: the refusal must name the entity: {body}"
    );
    assert!(
        error.contains("Unarchive it first"),
        "{context}: the refusal must name the remedy: {body}"
    );
}

// -------------------------------------------------------------------------------------------
// 1. The guarded paths — new authorship is refused, loudly
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn archiving_refuses_a_new_book_on_the_one_shot_path() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;

    archive(&state, &entity_id).await;

    let (status, body) = send(
        &state,
        json_req("POST", "/v1/books", &token, new_book_body(&entity_id)),
    )
    .await;
    assert_archived_refusal(status, &body, "one-shot create_book");
    assert!(
        state.books.read().await.is_empty(),
        "a refused create must not leave a book behind: {body}"
    );
}

#[tokio::test]
async fn archiving_refuses_a_new_book_on_the_two_phase_path() {
    // The twin of the one-shot guard. `build_created_book` is shared by both branches, so this also
    // stands in for `Other`-kind and predecessor-linked creation — every way this API mints a book.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;

    archive(&state, &entity_id).await;

    let mut body = new_book_body(&entity_id);
    body["one_shot"] = json!(false);
    body["required_signatories"] = json!([{ "name": "Amelia Marques", "capacity": "Manager" }]);
    let (status, refusal) = send(&state, json_req("POST", "/v1/books", &token, body)).await;
    assert_archived_refusal(status, &refusal, "two-phase create_book");
    assert!(
        state.books.read().await.is_empty(),
        "a refused two-phase create must not leave a Created shell behind: {refusal}"
    );
}

#[tokio::test]
async fn archiving_refuses_a_new_act_draft() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;
    let book_id = open_book(&state, &token, &entity_id).await;

    archive(&state, &entity_id).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/acts",
            &token,
            json!({ "book_id": book_id, "title": "Ata tardia", "channel": "Physical" }),
        ),
    )
    .await;
    assert_archived_refusal(status, &body, "draft_act");
    assert!(
        state.acts.read().await.is_empty(),
        "a refused draft must not leave an act behind: {body}"
    );
}

#[tokio::test]
async fn archiving_refuses_a_successor_book_from_start_over() {
    // `start_over_book` mints a fresh successor (`Book::new_successor`, a new `book.opened` genesis)
    // from `chancela-store`, entirely outside `books.rs` — a fourth creation path, and the one a
    // guard placed only at the create handler would miss.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let (entity_id, book_id, _act_id) = entity_with_a_sealed_act(&state, &token).await;
    let books_before = state.books.read().await.len();

    archive(&state, &entity_id).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/start-over"),
            &token,
            json!({
                "reason": "livro esgotado",
                "purpose": "livro de atas da assembleia geral (sucessor)",
                "opening_date": "2026-07-08",
                "required_signatories": ["Administrador"],
                "reauth": { "password": TEST_PASSWORD },
            }),
        ),
    )
    .await;
    assert_archived_refusal(status, &body, "start_over_book");
    assert_eq!(
        state.books.read().await.len(),
        books_before,
        "a refused start-over must not mint a successor — and, refused before the blocking task, \
         must not have archived and exported the old book either: {body}"
    );
}

// -------------------------------------------------------------------------------------------
// 2. The unguarded paths — everything already begun still finishes
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_act_already_drafted_still_advances_and_seals_after_its_entity_is_archived() {
    // The whole shape of the decision in one test. Archiving withdraws the invitation to start work;
    // it does not withdraw the ability to finish it. Blocking this would strand a drafted ata.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;
    let book_id = open_book(&state, &token, &entity_id).await;
    let act_id = draft_act(&state, &token, &book_id, "Ata em curso").await;
    fill_act(&state, &token, &act_id).await;

    archive(&state, &entity_id).await;

    advance_to_signing(&state, &token, &act_id).await;
    let (status, sealed) = seal_act(&state, &token, &act_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an act in flight must still seal on an archived entity: {sealed}"
    );
    assert_eq!(sealed["act"]["state"], "Sealed");
}

#[tokio::test]
async fn a_book_still_closes_with_its_termo_de_encerramento_after_its_entity_is_archived() {
    // Refusing this would force a legal instrument to go unexecuted as a side effect of an
    // administrative action, and leave the book open forever.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let (entity_id, book_id, _act_id) = entity_with_a_sealed_act(&state, &token).await;

    archive(&state, &entity_id).await;

    let (status, closed) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/close"),
            &token,
            json!({
                "reason": "BookFull",
                "closing_date": "2026-12-31",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "close book: {closed}");
    assert_eq!(closed["state"], "Closed");
}

#[tokio::test]
async fn opening_a_two_phase_book_from_its_termo_is_deliberately_not_guarded() {
    // A book sitting in `Created` with a drafted — and possibly already signed — termo de abertura is
    // the stranded-legal-instrument case, the same one that keeps book closure permitted. So
    // `termo::open_from_termo` carries NO archived-entity guard, on purpose.
    //
    // This asserts the absence rather than a success, because the open correctly fails closed for an
    // unrelated reason (the termo's required slots are not really signed). What matters is that the
    // reason is never archiving: if a guard is ever added there, this goes red and the reader is sent
    // to the stranding rule instead of "fixing" an oversight that is not one.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;

    let mut body = new_book_body(&entity_id);
    body["one_shot"] = json!(false);
    body["required_signatories"] = json!([{ "name": "Amelia Marques", "capacity": "Manager" }]);
    let (status, book) = send(&state, json_req("POST", "/v1/books", &token, body)).await;
    assert_eq!(status, StatusCode::CREATED, "two-phase create: {book}");
    assert_eq!(book["state"], "Created");
    let book_id = book["id"].as_str().expect("book id").to_owned();

    archive(&state, &entity_id).await;

    let (_status, refusal) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/termo/abertura/open"),
            &token,
            json!({}),
        ),
    )
    .await;
    let error = refusal["error"].as_str().unwrap_or_default();
    assert!(
        !error.contains("is archived"),
        "open_from_termo must not refuse on archiving — a signed termo de abertura would be \
         stranded. Revisit the stranding rule before adding a guard there: {refusal}"
    );
}

// -------------------------------------------------------------------------------------------
// 3. The sealed-act guarantee — identity still resolves, and resolution stays unfiltered
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_sealed_acts_parties_still_resolve_through_the_books_frozen_termo_after_archiving() {
    // THE headline. The chain asserted is:
    //
    //     act.book_id -> Book.termo_abertura -> TermoDeAbertura { entity_name, entity_nipc, entity_seat }
    //
    // Party identity is a documented snapshot taken when the book was opened, and that snapshot IS
    // the `book.opened` genesis digest preimage. Archiving the entity afterwards cannot reach it.
    //
    // If this fails, do NOT relax it and do NOT go looking for the party name inside the act — the
    // act payload has no entity-identity fields at all. Read the chain above and find which link
    // moved.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let (entity_id, book_id, act_id) = entity_with_a_sealed_act(&state, &token).await;

    let before = frozen_party_identity(&state, &act_id).await;
    assert_eq!(
        before,
        (
            ENTITY_NAME.to_owned(),
            ENTITY_NIPC.to_owned(),
            ENTITY_SEAT.to_owned()
        ),
        "the termo froze the parties at opening"
    );

    archive(&state, &entity_id).await;

    let after = frozen_party_identity(&state, &act_id).await;
    assert_eq!(
        before, after,
        "a sealed act lost the ability to name its parties when its entity was archived — the \
         act.book_id -> termo_abertura chain is the evidentiary guarantee, not a convenience"
    );

    // And the row itself is still there. An archived entity that left `state.entities` would break
    // every `entities.get(...)` resolution in the codebase at once.
    let id = EntityId(Uuid::parse_str(&entity_id).expect("entity uuid"));
    let entities = state.entities.read().await;
    let entity = entities
        .get(&id)
        .expect("an archived entity must never be removed from the read model");
    assert!(entity.is_archived());
    assert_eq!(entity.name, ENTITY_NAME);
    drop(entities);

    // The book is still readable and still points at the entity it always did.
    let (status, book) = send(&state, get_req(&format!("/v1/books/{book_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "read book: {book}");
    assert_eq!(book["entity_id"], entity_id);
}

#[tokio::test]
async fn a_document_still_names_its_parties_after_the_entity_is_archived() {
    // `preview_document` resolves the party name through an unfiltered `entities.get(...)`. This is
    // the tripwire on the invariant that archived-ness is filtered ONLY at the list/picker layer: if
    // it ever leaks into the resolution path, a sealed act stops being able to say who was in the
    // room, and that is the evidentiary failure the whole feature is shaped to avoid.
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let (entity_id, _book_id, act_id) = entity_with_a_sealed_act(&state, &token).await;

    archive(&state, &entity_id).await;

    let (status, model) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/preview"), &token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rendering a sealed act's document must not notice archiving: {model}"
    );
    assert!(
        model.to_string().contains(ENTITY_NAME),
        "the rendered document no longer names its parties: {model}"
    );

    // The act itself reads back unchanged, and still sealed.
    let (status, act) = send(&state, get_req(&format!("/v1/acts/{act_id}"), &token)).await;
    assert_eq!(status, StatusCode::OK, "read act: {act}");
    assert_eq!(act["state"], "Sealed");

    // So does the entity, by id. Archiving is not a delete wearing a euphemism.
    let (status, entity) = send(
        &state,
        get_req(&format!("/v1/entities/{entity_id}"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read entity: {entity}");
    assert_eq!(entity["name"], ENTITY_NAME);
}

// -------------------------------------------------------------------------------------------
// 4. Reversibility — the guards are a state, not a verdict
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn unarchiving_restores_new_authorship() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let entity_id = create_entity(&state, &token).await;

    archive(&state, &entity_id).await;
    let (status, refusal) = send(
        &state,
        json_req("POST", "/v1/books", &token, new_book_body(&entity_id)),
    )
    .await;
    assert_archived_refusal(status, &refusal, "create_book while archived");

    unarchive(&state, &entity_id).await;
    let (status, book) = send(
        &state,
        json_req("POST", "/v1/books", &token, new_book_body(&entity_id)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "unarchiving must return the entity to new authorship: {book}"
    );
    assert_eq!(book["state"], "Open");
    let book_id = BookId(Uuid::parse_str(book["id"].as_str().expect("book id")).expect("book uuid"));
    assert!(state.books.read().await.contains_key(&book_id));
}
