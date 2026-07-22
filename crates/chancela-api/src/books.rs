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
    Book, BookId, BookKind, EntityId, LegalHold, TermoDeAbertura, TermoDeEncerramento,
    open_and_seal_book,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, require_permission, scope_of_book, scope_of_entity};
use crate::dto::{
    ActView, BookView, BooksQuery, CloseBook, CreateBook, normalize_termo_signatories,
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
        one_shot,
        actor: req_actor,
    } = req;
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

    if !one_shot {
        return create_book_two_phase(
            &state,
            entity_id,
            kind,
            kind_label,
            purpose,
            opening_date,
            predecessor,
            predecessor_note,
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

    // entities → books → ledger.
    let entities = state.entities.read().await;
    let entity = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
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
    let generated = match crate::documents::generate_for_termo(termo_ref, &book, entity.family) {
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
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
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
    opening_date: String,
    predecessor: Option<Uuid>,
    predecessor_note: Option<String>,
    actor: &str,
) -> Result<(StatusCode, Json<BookView>), ApiError> {
    let _ = actor; // no ledger append at this phase; kept for signature symmetry with one-shot.
    // A two-phase draft may leave the opening date for a later PATCH; seed it only if supplied.
    let opening_date = {
        let trimmed = opening_date.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(crate::dto::parse_date(trimmed)?)
        }
    };

    // entities → books → ledger (ledger held only to serialize the durable write, no append).
    let entities = state.entities.read().await;
    let entity = entities.get(&entity_id).ok_or(ApiError::NotFound)?;
    let family = entity.family;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;

    let book = build_created_book(entity_id, kind, kind_label, predecessor, predecessor_note)?;

    // Seed the Draft termo from the family's template `default_body`; the operator fills the rest via
    // PATCH. Signatory slots are added later (they carry a required capacity + order the create body
    // does not model).
    let mut termo =
        crate::documents::seed_draft_abertura(book.id, family, OffsetDateTime::now_utc());
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
    let closing_date = crate::dto::parse_date(&closing_date)?;
    let required_signatory_records =
        normalize_termo_signatories(required_signatories, "required_signatories")?;
    let required_signatories = required_signatory_records
        .iter()
        .map(chancela_core::book::TermoSignatory::legacy_label)
        .collect();
    let actor = actor.resolve(&req_actor);

    // entities → books → ledger (entities read so the family selects the encerramento template).
    let entities = state.entities.read().await;
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
            match crate::documents::generate_for_encerramento(termo_ref, &next, entity) {
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
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
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
