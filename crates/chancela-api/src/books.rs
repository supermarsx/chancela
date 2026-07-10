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
    Book, BookId, EntityId, LegalHold, TermoDeAbertura, TermoDeEncerramento, open_and_seal_book,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use chancela_authz::Permission;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book, scope_of_entity};
use crate::dto::{ActView, BookView, BooksQuery, CloseBook, CreateBook, read_redaction_for_actor};
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
}

/// `POST /v1/books` — create a book and open it with a termo de abertura (WFL-10/11).
pub async fn create_book(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateBook>,
) -> Result<(StatusCode, Json<BookView>), ApiError> {
    // Fail fast on a bad date before taking any lock or minting a book.
    let opening_date = crate::dto::parse_date(&req.opening_date)?;
    let entity_id = EntityId(req.entity_id);
    // RBAC (t64-E3): opening a book is scoped to the owning entity (resolved from the body).
    require_permission(
        &state,
        &actor,
        Permission::BookOpen,
        scope_of_entity(entity_id),
    )
    .await?;
    let actor = actor.resolve(&req.actor);

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
        purpose: req.purpose,
        numbering_scheme: req.numbering_scheme,
        opening_date,
        required_signatories: req.required_signatories,
    };
    let mut book = match req.predecessor {
        Some(p) => Book::new_successor(entity_id, req.kind, BookId(p)),
        None => Book::new(entity_id, req.kind),
    };
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
            state.persist_write_through(&mut ledger, 2, |tx| {
                tx.upsert_book(&book)?;
                tx.upsert_document(&made.stored)
            })?;
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
        }
        None => {
            // Durably persist the genesis event + the new book row (the prior single-event path).
            state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_book(&book))?;
        }
    }
    state.attest_latest(&attestor, &ledger).await;

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
    // RBAC (t64-E3): closing a book is scoped to the book.
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(BookId(id)),
    )
    .await?;
    let closing_date = crate::dto::parse_date(&req.closing_date)?;
    let actor = actor.resolve(&req.actor);

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
        reason: req.reason,
        closing_date,
        required_signatories: req.required_signatories,
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
            state.persist_write_through(&mut ledger, 2, |tx| {
                tx.upsert_book(&next)?;
                tx.upsert_document(&made.stored)
            })?;
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
        }
        None => {
            state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_book(&next))?;
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
pub async fn get_legal_hold(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<LegalHoldView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(book_id),
    )
    .await?;
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    Ok(Json(LegalHoldView::from(book.legal_hold.as_ref())))
}

/// `PUT /v1/books/{id}/legal-hold` — set or replace a persisted book-level legal hold.
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
        Permission::BookExport,
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
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_book(&next))?;
    *book = next;

    Ok(Json(LegalHoldView::from(book.legal_hold.as_ref())))
}

/// `DELETE /v1/books/{id}/legal-hold` — clear the persisted book-level legal hold.
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
        Permission::BookExport,
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
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_book(&next))?;
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
            },
            None => LegalHoldView {
                legal_hold: false,
                reason: None,
                actor: None,
                set_at: None,
            },
        }
    }
}

fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

fn default_actor() -> String {
    "system".to_owned()
}
