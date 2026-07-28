//! Book endpoints (contract §2.4): create-and-open, list/filter, fetch, close, and the
//! acts-in-a-book listing.
//!
//! Opening a book is create + `open_and_seal_book` in one step (WFL-10/11): the sealed termo
//! de abertura is the genesis event of the book's hash chain. Closing appends a `book.closed`
//! event carrying the termo de encerramento. Multi-lock handlers here follow the fixed
//! acquisition order **entities → books → ledger** (a prefix of the global order) to avoid
//! deadlock.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chancela_core::{
    Book, BookId, BookKind, BookState, DEFAULT_TENANT_ID, DocumentLayoutOverrides, Entity,
    EntityId, LegalHold, TermoDeAbertura, TermoDeEncerramento, open_and_seal_book,
    resolve_document_layout,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, require_permission, scope_of_book, scope_of_entity};
use crate::collection_page::{
    CollectionPage, CollectionPageQuery, CursorPosition, apply_keyset, fold_search,
    query_fingerprint,
};
use crate::dto::{
    ActView, BookView, BooksQuery, CloseBook, CreateBook, EntityView, PatchBook,
    normalize_document_layout_override, normalize_termo_signatories, parse_date,
    read_redaction_for_actor,
};
use crate::error::ApiError;

#[derive(Debug, Deserialize)]
pub struct SetLegalHoldRequest {
    reason: String,
    #[serde(default = "default_actor")]
    actor: String,
}

#[derive(Debug, Deserialize)]
pub struct ClearLegalHoldRequest {
    #[serde(default = "default_actor")]
    actor: String,
}

#[derive(Debug, Serialize)]
pub struct LegalHoldView {
    legal_hold: bool,
    reason: Option<String>,
    actor: Option<String>,
    set_at: Option<String>,
    operator_workflow: LegalHoldOperatorWorkflowView,
}

#[derive(Debug, Serialize)]
pub struct LegalHoldOperatorWorkflowView {
    status: &'static str,
    disposal_review_blocked: bool,
    review_note: &'static str,
    next_step: &'static str,
    destructive_disposal_completed: bool,
    disposal_approved: bool,
    legal_compliance_claimed: bool,
}

/// Refuse an operation that would begin **new authorship** on an entity retired from it (t60 §1).
///
/// Archiving an entity is not a soft delete. It withdraws exactly one thing — the invitation to
/// start new work — and withdraws nothing evidentiary: reading, searching, exporting, generating
/// documents, advancing, signing and **sealing an act already drafted**, and **closing a book with
/// its termo de encerramento** all stay open on an archived entity. Blocking any of those would
/// strand a legal instrument unexecuted as a side effect of an administrative action, and an
/// archive that hid records would be a delete wearing a euphemism.
///
/// So this guard is called only from the paths that mint something new: `create_book` (both the
/// one-shot and the two-phase branch), `acts::draft_act`,
/// `paper_import::create_act_draft_from_accepted_paper_book_ocr_draft`, and
/// `bundles::start_over_book` (which mints a successor book) — plus the D3 content-edit freeze on
/// `registry::import_into_entity`, mirroring the `CompanyGroup` precedent's *"archived groups
/// cannot be edited"*.
///
/// **Deliberately NOT called from `termo::open_from_termo`.** A two-phase book sitting in `Created`
/// with a drafted and possibly already-signed termo de abertura is precisely the stranded-instrument
/// case: *creating* a book is authorship beginning and is refused, *opening* one already created is
/// finishing what was begun and is permitted. Do not "fix" that omission without revisiting the
/// stranding rule.
///
/// `refused` names what was refused, in the caller's own words, so the 409 is a sentence and not a
/// code. The refusal is always loud — never a silent no-op that would leave an operator believing
/// work had been recorded.
pub(crate) fn ensure_entity_not_archived(entity: &Entity, refused: &str) -> Result<(), ApiError> {
    if !entity.is_archived() {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "entity {} ({}) is archived: {refused}. Unarchive it first — everything already written \
         about it stays readable, and work already in flight can still be finished.",
        entity.id, entity.name
    )))
}

/// Validate the D3 custom-label rule: `kind == Other` **requires** a non-empty `kind_label`, and any
/// other kind **forbids** one. Returns the trimmed label (assurance value) or `None`.
fn resolve_kind_label(
    kind: BookKind,
    kind_label: Option<String>,
) -> Result<Option<String>, ApiError> {
    let trimmed = kind_label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    match kind {
        BookKind::Other if trimmed.is_none() => Err(ApiError::Unprocessable(
            "kind_label is required when kind is Other".to_owned(),
        )),
        BookKind::Other => Ok(trimmed),
        _ if trimmed.is_some() => Err(ApiError::Unprocessable(
            "kind_label is only allowed when kind is Other".to_owned(),
        )),
        _ => Ok(None),
    }
}

/// Build a `Created` book from the request identity fields, honouring D3 (`kind_label` for `Other`)
/// and D5 (`predecessor_note` assurance). Shared by the one-shot and two-phase paths so both mint
/// the book identically; `Book::new_successor` is inlined as `Book::new` + a predecessor id.
fn build_created_book(
    entity_id: EntityId,
    kind: BookKind,
    kind_label: Option<String>,
    predecessor: Option<Uuid>,
    predecessor_note: Option<String>,
) -> Result<Book, ApiError> {
    let label = resolve_kind_label(kind, kind_label)?;
    let mut book = match &label {
        Some(label) => Book::new_other(entity_id, label.clone()),
        None => Book::new(entity_id, kind),
    };
    if let Some(p) = predecessor {
        book.predecessor = Some(BookId(p));
    }
    book.predecessor_note = predecessor_note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok(book)
}

const BOOK_LAYOUT_SET_JUSTIFICATION: &str = "book document layout override set";
const BOOK_LAYOUT_CLEAR_JUSTIFICATION: &str = "book document layout override cleared";

fn validate_effective_layout(
    instance: &chancela_core::DocumentLayoutPolicy,
    entity: Option<&DocumentLayoutOverrides>,
    book: Option<&DocumentLayoutOverrides>,
) -> Result<(), ApiError> {
    resolve_document_layout(instance, None, entity, book)
        .map(|_| ())
        .map_err(|error| {
            ApiError::Unprocessable(format!("invalid document_layout_override: {error}"))
        })
}

/// Keep `book.opened` as the mandatory genesis of a book chain.
///
/// A two-phase book is persisted in `Created` before its signed termo opens it. Layout edits made
/// during that phase are still audited, but only on the tenant/company chains; once the book is
/// open, the event also joins its now-existing book chain.
fn document_layout_audit_scope(book: &Book, entity: &Entity) -> String {
    if book.state == BookState::Created {
        return format!("tenant:{}/entity:{}", entity.tenant_id, book.entity_id);
    }
    if entity.tenant_id == DEFAULT_TENANT_ID {
        format!("entity:{}/book:{}", book.entity_id, book.id)
    } else {
        format!(
            "tenant:{}/entity:{}/book:{}",
            entity.tenant_id, book.entity_id, book.id
        )
    }
}

/// `POST /v1/books` — create a book and, by default (`one_shot: true`, D2), open it in one commit
/// with a termo de abertura (WFL-10/11). With `one_shot: false`, create only a `Created` book plus a
/// `Draft` termo de abertura for the two-phase flow (nothing enters the hash chain until the termo is
/// filled, signed and the book is explicitly opened).
pub async fn create_book(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateBook>,
) -> Result<(StatusCode, Json<BookView>), ApiError> {
    let CreateBook {
        entity_id,
        kind,
        purpose,
        numbering_scheme,
        opening_date,
        required_signatories,
        predecessor,
        predecessor_note,
        kind_label,
        document_layout_override,
        one_shot,
        actor: req_actor,
    } = req;
    let document_layout_override = normalize_document_layout_override(document_layout_override);
    let entity_id = EntityId(entity_id);
    // RBAC (t64-E3): opening a book is scoped to the owning entity (resolved from the body).
    require_permission(
        &state,
        &actor,
        Permission::BookOpen,
        scope_of_entity(entity_id),
    )
    .await?;
    let actor = actor.resolve(&req_actor);
    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;

    if !one_shot {
        return create_book_two_phase(
            &state,
            entity_id,
            kind,
            kind_label,
            purpose,
            numbering_scheme,
            opening_date,
            required_signatories,
            predecessor,
            predecessor_note,
            document_layout_override,
            &actor,
        )
        .await;
    }

    // --- One-shot (D2 default): create + open + seal in a single commit, byte-for-byte as before.
    // Fail fast on a bad date before taking any lock or minting a book.
    let opening_date = crate::dto::parse_date(&opening_date)?;
    let required_signatory_records =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let required_signatories = required_signatory_records
        .iter()
        .map(chancela_core::book::TermoSignatory::legacy_label)
        .collect();

    let instance_layout = state
        .settings
        .read()
        .await
        .documents
        .layout_defaults
        .clone();
    // entities → books → ledger.
    let entities = state.entities.read().await;
    let entity = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
    // t60: opening a book on an archived entity is new authorship. Checked here, under the entity
    // read lock that is already held, rather than at the top of the handler: hoisting it would move
    // the entity lookup ahead of `parse_date` and turn today's `422` on a malformed date into a
    // `404`. The two-phase branch carries the twin of this check at its own entity lookup.
    ensure_entity_not_archived(entity, "no new book can be opened on it")?;
    validate_effective_layout(
        &instance_layout,
        entity.document_layout_override.as_ref(),
        document_layout_override.as_ref(),
    )?;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;

    // Snapshot the entity's identity into the termo (WFL-11).
    let termo = TermoDeAbertura {
        entity_name: entity.name.clone(),
        entity_nipc: entity.nipc.to_string(),
        entity_seat: entity.seat.clone(),
        purpose,
        numbering_scheme,
        opening_date,
        required_signatories,
        required_signatory_records,
        ..Default::default()
    };
    let mut book = build_created_book(entity_id, kind, kind_label, predecessor, predecessor_note)?;
    book.document_layout_override = document_layout_override;
    // Appends the `book.opened` genesis event; a fresh book always opens cleanly.
    open_and_seal_book(&mut book, entity, termo, &actor, &mut ledger)?;

    // Termo de abertura document (t48 / TPL-10/11): opening a book likewise produces a preserved
    // PDF/A document + a `document.generated` event, in the SAME durable commit as `book.opened`
    // (same transaction discipline as the ata seal). A render/write failure rolls the genesis
    // event back so a failed open leaves no trace. Families without a termo template yet get the
    // genesis event alone (documented fallback), never blocking the open.
    let termo_ref = book
        .termo_abertura
        .as_ref()
        .expect("termo present immediately after open");
    let generated =
        match crate::documents::generate_for_termo(termo_ref, &book, entity, &instance_layout) {
            Ok(g) => g,
            Err(e) => {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(e);
            }
        };
    match generated {
        Some(made) => {
            let scope = format!("entity:{}/book:{}", book.entity_id, book.id);
            let payload = serde_json::to_vec(&made.event_payload)?;
            // Validating append (t54); a rejection rolls back the just-appended `book.opened`
            // genesis so a failed open leaves no trace.
            if let Err(e) = crate::try_append_event(
                &mut ledger,
                &actor,
                &scope,
                "document.generated",
                None,
                &payload,
            ) {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(e);
            }
            let book_for_store = book.clone();
            let stored_for_store = made.stored.clone();
            state
                .persist_write_through(&mut ledger, 2, move |tx| {
                    tx.upsert_book(&book_for_store)?;
                    tx.upsert_document(&stored_for_store)
                })
                .await?;
            crate::documents::replace_owner_document_read_model(&state, &made.stored).await;
        }
        None => {
            // Durably persist the genesis event + the new book row (the prior single-event path).
            let book_for_store = book.clone();
            state
                .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_book(&book_for_store))
                .await?;
        }
    }
    state.attest_latest(&attestor, &ledger).await;

    let view = BookView::from(&book);
    books.insert(book.id, book);
    Ok((StatusCode::CREATED, Json(view)))
}

/// Two-phase create (`one_shot: false`): mint a `Created` book plus a `Draft` termo de abertura,
/// persisted together, WITHOUT any ledger append. The termo is then filled/signed/opened through the
/// termo endpoints. RBAC (`book.open`) and the actor are already resolved by the caller.
#[allow(clippy::too_many_arguments)]
async fn create_book_two_phase(
    state: &AppState,
    entity_id: EntityId,
    kind: BookKind,
    kind_label: Option<String>,
    purpose: String,
    numbering_scheme: chancela_core::NumberingScheme,
    opening_date: String,
    required_signatories: Vec<crate::dto::TermoSignatoryInput>,
    predecessor: Option<Uuid>,
    predecessor_note: Option<String>,
    document_layout_override: Option<DocumentLayoutOverrides>,
    actor: &str,
) -> Result<(StatusCode, Json<BookView>), ApiError> {
    let _ = actor; // no ledger append at this phase; kept for signature symmetry with one-shot.
    // Draft instrumentos are store-backed. Refuse before parsing or minting a BookId when the
    // process is running in the in-memory fallback; otherwise the write-through is a no-op and the
    // API would return a Created book whose termo immediately 404s.
    // t58 — CODED so this does not read as the retryable `503` it shares a status with.
    //
    // `Unavailable` normally means "a leader election is in flight, retry in a second", and
    // `error.rs` puts `Retry-After: 1` on every one of them. This refusal is the opposite: the
    // process is running without durable storage, so retrying cannot ever succeed until the
    // deployment changes. `data_dir_required` is what lets the client say that instead of inviting
    // a retry loop against a permanent configuration state.
    if state.store.is_none() {
        return Err(ApiError::Unavailable(
            "two-phase book creation requires durable storage; no book was created".to_owned(),
        )
        .with_code("data_dir_required"));
    }
    // A two-phase draft may leave the opening date for a later PATCH; seed it only if supplied.
    let opening_date = {
        let trimmed = opening_date.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(crate::dto::parse_date(trimmed)?)
        }
    };
    let required_signatories =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let mut initial_slots = Vec::with_capacity(required_signatories.len());
    for (index, signatory) in required_signatories.into_iter().enumerate() {
        let Some(capacity) = signatory.capacity else {
            return Err(ApiError::Unprocessable(format!(
                "required_signatories[{index}].capacity is required for the two-phase signing workflow"
            )));
        };
        let order = u16::try_from(index).map_err(|_| {
            ApiError::Unprocessable(
                "required_signatories contains more signatories than the signing order supports"
                    .to_owned(),
            )
        })?;
        let mut slot =
            chancela_core::termo::TermoSignatorySlot::required(signatory.name, capacity, order);
        if let Some(email) = signatory.email {
            slot = slot.with_email(email);
        }
        if let Some(note) = signatory.capacity_note {
            slot = slot.with_capacity_note(note);
        }
        initial_slots.push(slot);
    }

    let instance_layout = state
        .settings
        .read()
        .await
        .documents
        .layout_defaults
        .clone();
    // entities → books → ledger (ledger held only to serialize the durable write, no append).
    let entities = state.entities.read().await;
    let entity = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
    // t60: the twin of the one-shot branch's guard. `build_created_book` is shared by both paths,
    // so guarding the two entity lookups covers one-shot, two-phase, `Other`-kind and
    // predecessor-linked creation alike — every way this API mints a book.
    ensure_entity_not_archived(entity, "no new book can be opened on it")?;
    let family = entity.family;
    validate_effective_layout(
        &instance_layout,
        entity.document_layout_override.as_ref(),
        document_layout_override.as_ref(),
    )?;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;

    let mut book = build_created_book(entity_id, kind, kind_label, predecessor, predecessor_note)?;
    book.document_layout_override = document_layout_override;

    // Seed the Draft termo from the family's template `default_body`; the operator may revise all
    // mutable fields via PATCH. The creation choices are retained rather than silently discarded.
    let mut termo =
        crate::documents::seed_draft_abertura(book.id, family, OffsetDateTime::now_utc());
    termo.numbering_scheme = Some(numbering_scheme);
    for slot in initial_slots {
        termo.add_signatory(slot).map_err(|error| {
            ApiError::Unprocessable(format!("invalid required_signatories: {error}"))
        })?;
    }
    let purpose = purpose.trim();
    if !purpose.is_empty() {
        termo.fields.purpose = Some(purpose.to_owned());
    }
    termo.fields.instrument_date = opening_date;
    termo.fields.predecessor_note = book.predecessor_note.clone();

    // Persist the Created book + Draft termo atomically; NOTHING enters the hash chain here.
    let book_for_store = book.clone();
    let termo_for_store = termo.clone();
    state
        .persist_write_through(&mut ledger, 0, move |tx| {
            tx.upsert_book(&book_for_store)?;
            tx.upsert_termo_instrument(&termo_for_store)
        })
        .await?;

    let view = BookView::from(&book);
    books.insert(book.id, book);
    Ok((StatusCode::CREATED, Json(view)))
}

/// `PATCH /v1/books/{id}` — replace or clear the book's document-layout override.
///
/// Authorization deliberately reuses `book.open` at the addressed book scope: changing how future
/// instruments render is part of book operation, not a new or wider RBAC vocabulary.
pub async fn patch_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchBook>,
) -> Result<Json<BookView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;

    let instance_layout = state
        .settings
        .read()
        .await
        .documents
        .layout_defaults
        .clone();
    let actor = actor.resolve("api");
    // entities → books → ledger, matching the global aggregate lock order.
    let entities = state.entities.read().await;
    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut books = state.books.write().await;
    let book = books.get_mut(&book_id).ok_or(ApiError::NotFound)?;
    let entity = entities
        .get(&book.entity_id)
        .ok_or_else(|| ApiError::Internal("book references an absent entity".to_owned()))?;

    let mut next = book.clone();
    if let Some(document_layout_override) = req.document_layout_override {
        next.document_layout_override =
            normalize_document_layout_override(document_layout_override);
    } else {
        return Ok(Json(BookView::from(&*book)));
    }
    validate_effective_layout(
        &instance_layout,
        entity.document_layout_override.as_ref(),
        next.document_layout_override.as_ref(),
    )?;

    let scope = document_layout_audit_scope(&next, entity);
    let payload = serde_json::to_vec(&serde_json::json!({
        "book_id": next.id,
        "document_layout_override": next.document_layout_override.clone(),
    }))?;
    let justification = if next.document_layout_override.is_some() {
        BOOK_LAYOUT_SET_JUSTIFICATION
    } else {
        BOOK_LAYOUT_CLEAR_JUSTIFICATION
    };
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "book.document_layout_updated",
        Some(justification),
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_book(&next_for_store))
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    *book = next;

    Ok(Json(BookView::from(&*book)))
}

/// `GET /v1/books?entity_id=` — list books the caller may read (RBAC list-filtering, plan §3.3
/// note²): requires a valid session and returns only rows the caller holds `book.read` at (a Global
/// reader sees all; a scoped reader only their entity/book), in addition to the optional `entity_id`
/// query filter. No enumeration of unreadable rows.
pub async fn list_books(
    State(state): State<AppState>,
    Query(q): Query<BooksQuery>,
    actor: CurrentActor,
) -> Result<Json<Vec<BookView>>, ApiError> {
    let authz = crate::authz::authorizer(&state, &actor).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let books = state.books.read().await;
    let filter = q.entity_id.map(EntityId);
    let views = books
        .values()
        .filter(|b| filter.is_none_or(|eid| b.entity_id == eid))
        .filter(|b| authz.permits(Permission::BookRead, scope_of_book(b.id)))
        .map(|b| BookView::build(b, redaction))
        .collect();
    Ok(Json(views))
}

#[derive(Debug, Deserialize)]
pub struct BooksPageQuery {
    q: Option<String>,
    #[serde(default)]
    offset: usize,
    cursor: Option<String>,
    limit: Option<usize>,
    sort: Option<String>,
    order: Option<String>,
    entity_id: Option<Uuid>,
    kind: Option<BookKind>,
    state: Option<BookState>,
    activity: Option<String>,
    lineage: Option<String>,
    opened_from: Option<String>,
    opened_to: Option<String>,
}

impl BooksPageQuery {
    fn page(&self) -> CollectionPageQuery {
        CollectionPageQuery {
            q: self.q.clone(),
            offset: self.offset,
            cursor: self.cursor.clone(),
            limit: self.limit,
            sort: self.sort.clone(),
            order: self.order.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct BookPageItemView {
    #[serde(flatten)]
    book: BookView,
    #[serde(skip_serializing_if = "Option::is_none")]
    entity_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind_label: Option<String>,
}

fn book_page_position(book: &BookPageItemView, sort: &str) -> CursorPosition {
    let key = match sort {
        "kind" => format!("{:?}", book.book.kind),
        "state" => format!("{:?}", book.book.state),
        _ => book.book.id.clone(),
    };
    CursorPosition::new(key, book.book.id.clone())
}

fn book_kind_search_labels(kind: BookKind) -> &'static str {
    match kind {
        BookKind::AssembleiaGeral => "Assembleia Geral General Meeting",
        BookKind::GerenciaAdministracao => {
            "Gerência Administração Gerencia Administracao Management Administration"
        }
        BookKind::ConselhoFiscal => "Conselho Fiscal Audit Board",
        BookKind::Condominio => "Condomínio Condominio Condominium",
        BookKind::Other => "Outro Other",
    }
}

fn book_state_search_labels(state: BookState) -> &'static str {
    match state {
        BookState::Created => "Criado Created",
        BookState::Open => "Aberto Open",
        BookState::Closed => "Encerrado Closed",
    }
}

/// Bounded, searchable companion to [`list_books`]. The response deliberately carries no total
/// count: pagination is over the caller-visible set after RBAC filtering.
pub async fn list_books_page(
    State(state): State<AppState>,
    Query(query): Query<BooksPageQuery>,
    actor: CurrentActor,
) -> Result<Json<CollectionPage<BookPageItemView>>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let page_query = query.page();
    let descending = page_query.descending()?;
    let sort = page_query.sort.as_deref().unwrap_or("id");
    if !matches!(sort, "id" | "kind" | "state") {
        return Err(ApiError::Unprocessable(format!(
            "unknown book sort {sort:?}: expected \"id\", \"kind\" or \"state\""
        )));
    }
    let search = page_query.normalized_search();
    let limit = page_query.limit();
    let filter = query.entity_id.map(EntityId);
    if !matches!(
        query.activity.as_deref(),
        None | Some("has-acts" | "no-acts")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown book activity filter: expected \"has-acts\" or \"no-acts\"".to_owned(),
        ));
    }
    if !matches!(
        query.lineage.as_deref(),
        None | Some("successor" | "origin")
    ) {
        return Err(ApiError::Unprocessable(
            "unknown book lineage filter: expected \"successor\" or \"origin\"".to_owned(),
        ));
    }
    let opened_from = query.opened_from.as_deref().map(parse_date).transpose()?;
    let opened_to = query.opened_to.as_deref().map(parse_date).transpose()?;
    let fingerprint = query_fingerprint([
        ("q", search.clone().unwrap_or_default()),
        ("sort", sort.to_owned()),
        ("order", if descending { "desc" } else { "asc" }.to_owned()),
        (
            "entity_id",
            query.entity_id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        (
            "kind",
            query
                .kind
                .map(|value| format!("{value:?}"))
                .unwrap_or_default(),
        ),
        (
            "state",
            query
                .state
                .map(|value| format!("{value:?}"))
                .unwrap_or_default(),
        ),
        ("activity", query.activity.clone().unwrap_or_default()),
        ("lineage", query.lineage.clone().unwrap_or_default()),
        ("opened_from", query.opened_from.clone().unwrap_or_default()),
        ("opened_to", query.opened_to.clone().unwrap_or_default()),
    ]);
    let cursor = page_query.cursor("books", &fingerprint)?;
    let books = state.books.read().await;
    let entities = state.entities.read().await;
    let mut visible: Vec<_> = books
        .values()
        .filter(|book| filter.is_none_or(|entity_id| book.entity_id == entity_id))
        .filter(|book| query.kind.is_none_or(|kind| book.kind == kind))
        .filter(|book| query.state.is_none_or(|state| book.state == state))
        .filter(|book| match query.activity.as_deref() {
            Some("has-acts") => book.last_ata_number > 0,
            Some("no-acts") => book.last_ata_number == 0,
            _ => true,
        })
        .filter(|book| match query.lineage.as_deref() {
            Some("successor") => book.predecessor.is_some(),
            Some("origin") => book.predecessor.is_none(),
            _ => true,
        })
        .filter(|book| {
            let opening_date = book.termo_abertura.as_ref().map(|termo| termo.opening_date);
            opened_from.is_none_or(|from| opening_date.is_some_and(|date| date >= from))
                && opened_to.is_none_or(|to| opening_date.is_some_and(|date| date <= to))
        })
        .filter(|book| authz.permits(Permission::BookRead, scope_of_book(book.id)))
        .map(|book| {
            let entity_name = entities
                .get(&book.entity_id)
                .filter(|entity| authz.permits(Permission::EntityRead, scope_of_entity(entity.id)))
                .map(|entity| EntityView::build(entity, redaction).name);
            BookPageItemView {
                book: BookView::build(book, redaction),
                entity_name,
                kind_label: book.kind_label.clone(),
            }
        })
        .filter(|row| {
            search.as_ref().is_none_or(|needle| {
                let signatories = row
                    .book
                    .required_signatory_records_abertura
                    .iter()
                    .chain(row.book.required_signatory_records_encerramento.iter())
                    .flatten()
                    .flat_map(|record| {
                        [
                            record.name.clone(),
                            record
                                .capacity
                                .as_ref()
                                .map(|capacity| format!("{capacity:?}"))
                                .unwrap_or_default(),
                            record.email.clone().unwrap_or_default(),
                        ]
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .chain(
                        row.book
                            .required_signatories_abertura
                            .iter()
                            .chain(row.book.required_signatories_encerramento.iter())
                            .flatten()
                            .cloned(),
                    )
                    .collect::<Vec<_>>()
                    .join(" ");
                let search_text = [
                    row.book.id.as_str(),
                    row.book.entity_id.as_str(),
                    row.entity_name.as_deref().unwrap_or(""),
                    &format!("{:?}", row.book.kind),
                    &format!("{:?}", row.book.state),
                    book_kind_search_labels(row.book.kind),
                    book_state_search_labels(row.book.state),
                    row.kind_label.as_deref().unwrap_or(""),
                    row.book.purpose.as_deref().unwrap_or(""),
                    row.book.opening_date.as_deref().unwrap_or(""),
                    row.book.closing_date.as_deref().unwrap_or(""),
                    row.book.predecessor.as_deref().unwrap_or(""),
                    &row.book.last_ata_number.to_string(),
                    &signatories,
                ]
                .join(" ");
                fold_search(&search_text).contains(needle)
            })
        })
        .collect();
    visible.sort_by(|left, right| {
        let ordering = match sort {
            "kind" => format!("{:?}", left.book.kind)
                .cmp(&format!("{:?}", right.book.kind))
                .then(left.book.id.cmp(&right.book.id)),
            "state" => format!("{:?}", left.book.state)
                .cmp(&format!("{:?}", right.book.state))
                .then(left.book.id.cmp(&right.book.id)),
            _ => left.book.id.cmp(&right.book.id),
        };
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
    apply_keyset(&mut visible, cursor.as_ref(), descending, |book| {
        book_page_position(book, sort)
    });
    Ok(Json(CollectionPage::from_keyset_sorted(
        visible,
        page_query.offset,
        limit,
        cursor.is_some(),
        "books",
        &fingerprint,
        |book| book_page_position(book, sort),
    )))
}

/// `GET /v1/books/{id}` — one book, or `404`. RBAC (t64-E3): `book.read` scoped to the book.
pub async fn get_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<BookView>, ApiError> {
    require_permission(
        &state,
        &actor,
        Permission::BookRead,
        scope_of_book(BookId(id)),
    )
    .await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let books = state.books.read().await;
    books
        .get(&BookId(id))
        .map(|b| Json(BookView::build(b, redaction)))
        .ok_or(ApiError::NotFound)
}

/// `POST /v1/books/{id}/close` — close an open book with a termo de encerramento (WFL-13).
///
/// By default (`one_shot: true`, DA4) this is the legacy one-commit close: it mints a static termo
/// de encerramento with declared (not collected) signatories and closes in one step. With
/// `one_shot: false` it enters the two-phase CLOSE flow (t44): only a `Draft`
/// [`chancela_core::termo::TermoInstrument`] of kind `Encerramento` is created for the open book, and
/// the book is closed later through the `/termo/encerramento/{advance,sign,sign/pkcs12,close}`
/// endpoints once the termo is co-signed. Nothing enters the hash chain in the two-phase draft.
pub async fn close_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CloseBook>,
) -> Result<Json<BookView>, ApiError> {
    let CloseBook {
        reason,
        closing_date,
        required_signatories,
        one_shot,
        actor: req_actor,
    } = req;
    // RBAC (t64-E3): closing a book is scoped to the book.
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(BookId(id)),
    )
    .await?;

    if !one_shot {
        return close_book_two_phase(
            &state,
            BookId(id),
            reason,
            closing_date,
            required_signatories,
        )
        .await;
    }

    let closing_date = crate::dto::parse_date(&closing_date)?;
    let required_signatory_records =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let required_signatories = required_signatory_records
        .iter()
        .map(chancela_core::book::TermoSignatory::legacy_label)
        .collect();
    let actor = actor.resolve(&req_actor);
    let instance_layout = crate::documents::current_instance_document_layout(&state).await;

    // entities → books → ledger (entities read so the family selects the encerramento template).
    let entities = state.entities.read().await;
    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;
    let book = books.get_mut(&BookId(id)).ok_or(ApiError::NotFound)?;

    // Close a clone, committing to the map only after the durable write. `ata_count` is overwritten
    // by `Book::close` with the authoritative count.
    let mut next = book.clone();
    let termo = TermoDeEncerramento {
        ata_count: 0,
        reason,
        closing_date,
        required_signatories,
        required_signatory_records,
        ..Default::default()
    };
    next.close(termo)?; // BookError::NotClosable → 409

    let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
    let payload = serde_json::to_vec(
        next.termo_encerramento
            .as_ref()
            .expect("termo present immediately after close"),
    )?;
    crate::try_append_event(&mut ledger, &actor, &scope, "book.closed", None, &payload)?;

    // Termo de encerramento document (t53): closing a book produces the family's preserved
    // encerramento PDF/A + a `document.generated` event in the SAME durable commit as `book.closed`
    // (mirrors the book-open abertura path). A render/write failure rolls the just-appended
    // `book.closed` event back so a failed close leaves no trace; a family without an encerramento
    // template (or a book whose entity is gone) gets the domain event alone (documented fallback).
    let termo_ref = next
        .termo_encerramento
        .as_ref()
        .expect("termo present immediately after close");
    let generated = match entities.get(&next.entity_id) {
        Some(entity) => {
            match crate::documents::generate_for_encerramento(
                termo_ref,
                &next,
                entity,
                &instance_layout,
            ) {
                Ok(g) => g,
                Err(e) => {
                    AppState::rollback_ledger_events(&mut ledger, 1);
                    return Err(e);
                }
            }
        }
        None => None,
    };
    match generated {
        Some(made) => {
            let doc_payload = serde_json::to_vec(&made.event_payload)?;
            // Validating append (t54); a rejection rolls back the just-appended `book.closed`.
            if let Err(e) = crate::try_append_event(
                &mut ledger,
                &actor,
                &scope,
                "document.generated",
                None,
                &doc_payload,
            ) {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(e);
            }
            let next_for_store = next.clone();
            let stored_for_store = made.stored.clone();
            state
                .persist_write_through(&mut ledger, 2, move |tx| {
                    tx.upsert_book(&next_for_store)?;
                    tx.upsert_document(&stored_for_store)
                })
                .await?;
            crate::documents::replace_owner_document_read_model(&state, &made.stored).await;
        }
        None => {
            let next_for_store = next.clone();
            state
                .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_book(&next_for_store))
                .await?;
        }
    }
    state.attest_latest(&attestor, &ledger).await;
    *book = next;

    Ok(Json(BookView::from(&*book)))
}

/// Two-phase close (`one_shot: false`, t44): mint a `Draft` termo de encerramento for an **open**
/// book, seeded from the family's encerramento `default_body`, and persist it WITHOUT any ledger
/// append. The book stays `Open`; it is closed later through the two-phase termo endpoints once the
/// termo is filled, co-signed and explicitly sealed. Mirrors [`create_book_two_phase`] on the open
/// side. RBAC (`book.close`) is already checked by the caller.
///
/// The `reason` and `closing_date` from the request seed the draft's initial values (the operator
/// may revise them via PATCH); a blank closing date is left for PATCH. The book-derived facts (ata
/// count, pages used) are never seeded here — they are materialized from the book at `advance`.
async fn close_book_two_phase(
    state: &AppState,
    book_id: BookId,
    reason: chancela_core::ClosingReason,
    closing_date: String,
    required_signatories: Vec<crate::dto::TermoSignatoryInput>,
) -> Result<Json<BookView>, ApiError> {
    // t58: a permanent configuration state, not the retryable leader-election `503` this status
    // otherwise means. See `create_book_two_phase` for the full rationale.
    if state.store.is_none() {
        return Err(ApiError::Unavailable(
            "two-phase book closing requires durable storage; no closing draft was created"
                .to_owned(),
        )
        .with_code("data_dir_required"));
    }
    // A blank closing date defers the choice to a later PATCH; parse only if supplied.
    let closing_date = {
        let trimmed = closing_date.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(crate::dto::parse_date(trimmed)?)
        }
    };
    let required_signatories =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let mut initial_slots = Vec::with_capacity(required_signatories.len());
    for (index, signatory) in required_signatories.into_iter().enumerate() {
        let Some(capacity) = signatory.capacity else {
            return Err(ApiError::Unprocessable(format!(
                "required_signatories[{index}].capacity is required for the two-phase signing workflow"
            )));
        };
        let order = u16::try_from(index).map_err(|_| {
            ApiError::Unprocessable(
                "required_signatories contains more signatories than the signing order supports"
                    .to_owned(),
            )
        })?;
        let mut slot =
            chancela_core::termo::TermoSignatorySlot::required(signatory.name, capacity, order);
        if let Some(email) = signatory.email {
            slot = slot.with_email(email);
        }
        if let Some(note) = signatory.capacity_note {
            slot = slot.with_capacity_note(note);
        }
        initial_slots.push(slot);
    }

    // entities → books → ledger (ledger held only to serialize the durable write, no append).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if !book.is_open() {
        return Err(ApiError::Conflict(
            "book is not Open; only an open book can start a two-phase close".to_owned(),
        )
        .with_code("book_not_open"));
    }
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    let family = entity.family;
    let view = BookView::from(book);
    drop(books);
    let mut ledger = state.ledger.write().await;

    // Seed the Draft termo from the family's encerramento `default_body`; the operator may revise
    // the signatory slots and reason/date via PATCH, but creation inputs are retained.
    let mut termo =
        crate::documents::seed_draft_encerramento(book_id, family, OffsetDateTime::now_utc());
    termo.fields.closing_reason = Some(reason);
    termo.fields.instrument_date = closing_date;
    for slot in initial_slots {
        termo.add_signatory(slot).map_err(|error| {
            ApiError::Unprocessable(format!("invalid required_signatories: {error}"))
        })?;
    }

    // Persist the Draft termo atomically; NOTHING enters the hash chain here. The book is unchanged.
    let termo_for_store = termo.clone();
    state
        .persist_write_through(&mut ledger, 0, move |tx| {
            tx.upsert_termo_instrument(&termo_for_store)
        })
        .await?;

    Ok(Json(view))
}

/// `GET /v1/books/{id}/acts` — acts in a book: sealed first by ata number, then drafts.
pub async fn list_book_acts(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<ActView>>, ApiError> {
    let book_id = BookId(id);
    // RBAC (t64-E3): reading a book's acts is `book.read` scoped to the book.
    require_permission(&state, &actor, Permission::BookRead, scope_of_book(book_id)).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    // books → acts.
    let books = state.books.read().await;
    if !books.contains_key(&book_id) {
        return Err(ApiError::NotFound);
    }
    let acts = state.acts.read().await;
    let mut in_book: Vec<_> = acts.values().filter(|a| a.book_id == book_id).collect();
    // Sealed atas (those with a number) first, ordered by ata number; drafts trail after.
    in_book.sort_by(|a, b| match (a.ata_number, b.ata_number) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    Ok(Json(
        in_book
            .into_iter()
            .map(|act| ActView::build(act, redaction))
            .collect(),
    ))
}

/// `GET /v1/books/{id}/legal-hold` — read the persisted book-level legal hold.
///
/// Readable with EITHER `book.export` (unchanged — visibility of a hold was never the risk, and the
/// export-holding roles have always been able to see one) OR `legal_hold.manage`. The second half
/// matters: t22 seeded the hold verb to Legal Counsel, which deliberately holds no export authority,
/// and an operator who may place a hold but cannot read one back is not a coherent role.
pub async fn get_legal_hold(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<LegalHoldView>, ApiError> {
    let book_id = BookId(id);
    let scope = scope_of_book(book_id);
    let authz = authorizer(&state, &actor).await?;
    if !authz.permits(Permission::BookExport, scope)
        && !authz.permits(Permission::LegalHoldManage, scope)
    {
        return Err(forbidden());
    }
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    Ok(Json(LegalHoldView::from(book.legal_hold.as_ref())))
}

/// `PUT /v1/books/{id}/legal-hold` — set or replace a persisted book-level legal hold.
///
/// Gated by `legal_hold.manage`, NOT the `book.export` verb it shared until t22: a hold is the
/// retention control that stands between a book and disposal, and `book.export` is held by 9 of the
/// 15 seeded roles (including Auditor and API Client) precisely because export is meant to be broad.
pub async fn set_legal_hold(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<SetLegalHoldRequest>,
) -> Result<Json<LegalHoldView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::LegalHoldManage,
        scope_of_book(book_id),
    )
    .await?;
    let reason = req.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::Unprocessable(
            "legal hold reason must not be empty".to_owned(),
        ));
    }
    let actor = actor.resolve(&req.actor);
    let hold = LegalHold {
        reason: reason.to_owned(),
        actor: actor.clone(),
        set_at: OffsetDateTime::now_utc(),
    };

    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;
    let book = books.get_mut(&book_id).ok_or(ApiError::NotFound)?;
    let mut next = book.clone();
    next.legal_hold = Some(hold);
    let payload = serde_json::to_vec(next.legal_hold.as_ref().expect("hold just set"))?;
    let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "book.legal_hold.set",
        None,
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_book(&next_for_store))
        .await?;
    *book = next;

    Ok(Json(LegalHoldView::from(book.legal_hold.as_ref())))
}

/// `DELETE /v1/books/{id}/legal-hold` — clear the persisted book-level legal hold.
///
/// Same `legal_hold.manage` gate as [`set_legal_hold`], and this is the asymmetric-risk half:
/// releasing a hold unblocks destruction of the evidentiary record. Set and release are kept on the
/// SAME verb deliberately — a spurious hold is itself a denial of a lawful disposal, so both
/// directions are compliance decisions, and an operator who may place a hold but never lift it
/// cannot correct their own mistake without escalating.
pub async fn clear_legal_hold(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    body: Option<Json<ClearLegalHoldRequest>>,
) -> Result<Json<LegalHoldView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::LegalHoldManage,
        scope_of_book(book_id),
    )
    .await?;
    let req_actor = body
        .as_ref()
        .map(|Json(req)| req.actor.as_str())
        .unwrap_or("system");
    let actor = actor.resolve(req_actor);

    let _search_source_mutation = crate::search::begin_source_mutation(&state).await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;
    let book = books.get_mut(&book_id).ok_or(ApiError::NotFound)?;
    let mut next = book.clone();
    next.legal_hold = None;
    let payload = serde_json::to_vec(&serde_json::json!({
        "legal_hold": false,
        "actor": actor.clone(),
        "cleared_at": rfc3339(OffsetDateTime::now_utc()),
    }))?;
    let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "book.legal_hold.cleared",
        None,
        &payload,
    )?;
    let next_for_store = next.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| tx.upsert_book(&next_for_store))
        .await?;
    *book = next;

    Ok(Json(LegalHoldView::from(book.legal_hold.as_ref())))
}

impl From<Option<&LegalHold>> for LegalHoldView {
    fn from(hold: Option<&LegalHold>) -> Self {
        match hold {
            Some(hold) => LegalHoldView {
                legal_hold: true,
                reason: Some(hold.reason.clone()),
                actor: Some(hold.actor.clone()),
                set_at: Some(rfc3339(hold.set_at)),
                operator_workflow: legal_hold_operator_workflow(true),
            },
            None => LegalHoldView {
                legal_hold: false,
                reason: None,
                actor: None,
                set_at: None,
                operator_workflow: legal_hold_operator_workflow(false),
            },
        }
    }
}

fn legal_hold_operator_workflow(active: bool) -> LegalHoldOperatorWorkflowView {
    if active {
        LegalHoldOperatorWorkflowView {
            status: "blocked_by_legal_hold",
            disposal_review_blocked: true,
            review_note: "Local operator workflow/status evidence only; active book legal hold blocks retention/disposal review and is not disposal approval or legal compliance.",
            next_step: "Keep disposal blocked and review the legal-hold evidence in a separate authorized workflow before any retention action.",
            destructive_disposal_completed: false,
            disposal_approved: false,
            legal_compliance_claimed: false,
        }
    } else {
        LegalHoldOperatorWorkflowView {
            status: "advisory_only",
            disposal_review_blocked: false,
            review_note: "Local operator workflow/status evidence only; no active book legal hold is recorded here and this is not disposal approval or legal compliance.",
            next_step: "Use retention dry-run/status review before any disposal action; this legal-hold view does not resolve candidates.",
            destructive_disposal_completed: false,
            disposal_approved: false,
            legal_compliance_claimed: false,
        }
    }
}

fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

fn default_actor() -> String {
    "system".to_owned()
}
