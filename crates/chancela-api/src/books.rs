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
    Book, BookId, EntityId, TermoDeAbertura, TermoDeEncerramento, open_and_seal_book,
};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::dto::{ActView, BookView, BooksQuery, CloseBook, CreateBook};
use crate::error::ApiError;

/// `POST /v1/books` — create a book and open it with a termo de abertura (WFL-10/11).
pub async fn create_book(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateBook>,
) -> Result<(StatusCode, Json<BookView>), ApiError> {
    // Fail fast on a bad date before taking any lock or minting a book.
    let opening_date = crate::dto::parse_date(&req.opening_date)?;
    let actor = actor.resolve(&req.actor);
    let entity_id = EntityId(req.entity_id);

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

/// `GET /v1/books?entity_id=` — list books, optionally filtered to one entity.
pub async fn list_books(
    State(state): State<AppState>,
    Query(q): Query<BooksQuery>,
) -> Json<Vec<BookView>> {
    let books = state.books.read().await;
    let filter = q.entity_id.map(EntityId);
    let views = books
        .values()
        .filter(|b| filter.is_none_or(|eid| b.entity_id == eid))
        .map(BookView::from)
        .collect();
    Json(views)
}

/// `GET /v1/books/{id}` — one book, or `404`.
pub async fn get_book(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BookView>, ApiError> {
    let books = state.books.read().await;
    books
        .get(&BookId(id))
        .map(|b| Json(BookView::from(b)))
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
) -> Result<Json<Vec<ActView>>, ApiError> {
    let book_id = BookId(id);
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
    Ok(Json(in_book.into_iter().map(ActView::from).collect()))
}
