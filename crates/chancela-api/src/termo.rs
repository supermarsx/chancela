//! The termo de abertura as its own signable instrument — the two-phase draft → sign → open
//! lifecycle (t23, completing the API leg t8-A left undelivered).
//!
//! A book created with `one_shot: false` (see [`crate::books::create_book`]) starts as a `Created`
//! book plus a `Draft` [`TermoInstrument`]. These endpoints then fill it, freeze it for signing,
//! collect the signatures, and finally **open** the book — at which point, and only then, the
//! `book.opened` genesis event digests the *final, filled, signed* termo. Nothing enters the hash
//! chain before the open.
//!
//! Persistence is store-backed (e1's `termo_instruments` table): a draft has no in-memory home, so a
//! deployment without a configured store cannot carry a draft across requests. Every real deployment
//! configures a store; the tests do too.
//!
//! ## Relationship to the act signing pipeline
//!
//! The termo reuses the *domain* signing discipline (`chancela_core::termo`: sequential-PAdES slot
//! order, the capacity allow-list, the management floor, the completion policy) and e1's per-slot
//! `instrument_signatures` history. It deliberately does **not** fork the ~20 act crypto handlers:
//! signature collection here drives [`TermoInstrument::mark_slot_signed`] against a `signature_id`
//! reference. Wiring the full per-slot PAdES byte-binding (rendering the frozen termo PDF and
//! extending it signer-by-signer through the CMD/CSC/PKCS pipeline) is a follow-up that reuses the
//! same primitives; the lifecycle contract below is complete either way.

use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

use chancela_authz::Permission;
use chancela_core::book::BookId;
use chancela_core::error::TermoError;
use chancela_core::termo::{TermoClause, TermoInstrument, TermoKind, TermoSignatorySlot};
use chancela_core::{ActId, BookState, open_and_seal_book};
use time::OffsetDateTime;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book};
use crate::dto::{
    BookView, OpenBookFromTermo, PatchTermoAbertura, SignTermoSlot, TermoInstrumentView,
    normalize_capacity_note, parse_date,
};
use crate::error::ApiError;

/// Map a [`TermoError`] onto the API contract: state-transition / precondition failures are
/// `409 Conflict`; content-validation failures are `422 Unprocessable`.
fn map_termo_error(e: TermoError) -> ApiError {
    match e {
        TermoError::NotMutable(_)
        | TermoError::InvalidTransition { .. }
        | TermoError::NotSigning(_)
        | TermoError::SlotAlreadySigned(_)
        | TermoError::SequentialOrderBlocked { .. }
        | TermoError::RequiredSlotsNotSigned { .. }
        | TermoError::SignaturesAlreadyCollected
        | TermoError::WrongKind { .. } => ApiError::Conflict(e.to_string()),
        _ => ApiError::Unprocessable(e.to_string()),
    }
}

/// Trim a free-text value to an assurance value: whitespace-only becomes `None`.
fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Load a book's termo de abertura from the store (drafts have no in-memory home). `404` if the book
/// has no abertura instrument (e.g. a one-shot book, or a store-less deployment).
async fn load_book_abertura(
    state: &AppState,
    book_id: BookId,
) -> Result<TermoInstrument, ApiError> {
    let Some(store) = &state.store else {
        return Err(ApiError::NotFound);
    };
    let termos = store
        .read_blocking_async(move |s| s.termo_instruments_for_book(book_id))
        .await
        .map_err(|e| ApiError::Internal(format!("termo store read failed: {e}")))?;
    termos
        .into_iter()
        .find(|t| t.kind == TermoKind::Abertura)
        .ok_or(ApiError::NotFound)
}

/// **Evidentiary fail-closed gate (binding t23 ruling).** A termo the system presents as `Sealed`,
/// and a book it presents as `Open`, MUST be *really* cryptographically signed: a genuine PAdES
/// signature over the termo PDF, bound by [`crate::signature::ensure_signed_pdf_binds_document`],
/// recorded per slot in e1's `instrument_signatures` history (v23, keyed on the `TermoInstrumentId`
/// cast into an [`ActId`]).
///
/// Real per-slot PAdES *production* over the termo PDF (via the CMD/CSC/PKCS handlers) and its
/// `instrument_signatures` persistence are a **tracked follow-up** — not yet wired.
/// [`TermoInstrument::mark_slot_signed`] records a signature *reference* for completion tracking,
/// which is **not** an evidentiary cryptographic signature. Until real signing lands, this refuses:
/// a book is never opened on a not-really-signed termo. When the real pipeline populates
/// `instrument_signatures`, this gate goes live with no further change.
async fn require_real_signatures(
    state: &AppState,
    termo: &TermoInstrument,
) -> Result<(), ApiError> {
    let required: Vec<Uuid> = termo
        .signatories
        .iter()
        .filter(|slot| slot.required)
        .map(|slot| slot.id)
        .collect();
    let subject = ActId(termo.id.0);
    let real = match &state.store {
        Some(store) => store
            .read_blocking_async(move |s| s.instrument_signatures_for_subject(subject))
            .await
            .map_err(|e| {
                ApiError::Internal(format!("instrument signature store read failed: {e}"))
            })?,
        None => Vec::new(),
    };
    // v23 rows may not carry a `slot_id` yet; fall back to a count check when none do.
    let covered = if real.iter().all(|sig| sig.slot_id.is_none()) {
        real.len()
    } else {
        required
            .iter()
            .filter(|id| {
                let id = id.to_string();
                real.iter()
                    .any(|sig| sig.slot_id.as_deref() == Some(id.as_str()))
            })
            .count()
    };
    if covered < required.len() {
        return Err(ApiError::Conflict(
            "refusing to open the book: the termo de abertura is not cryptographically signed. \
             Every required signatory must have a real PAdES signature over the termo PDF before the \
             book can be opened. Real per-slot signing over the termo is a tracked follow-up (t23); a \
             book is never opened on a not-really-signed termo."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Persist a termo instrument with no ledger append (a draft/signing termo is not on the chain).
async fn persist_termo(state: &AppState, termo: &TermoInstrument) -> Result<(), ApiError> {
    let mut ledger = state.ledger.write().await;
    let termo_for_store = termo.clone();
    state
        .persist_write_through(&mut ledger, 0, move |tx| {
            tx.upsert_termo_instrument(&termo_for_store)
        })
        .await
}

/// `GET /v1/books/{id}/termo/abertura` — read the book's termo de abertura instrument.
pub async fn get_abertura(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookRead, scope_of_book(book_id)).await?;
    let termo = load_book_abertura(&state, book_id).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `PATCH /v1/books/{id}/termo/abertura` — edit the draft (title, body, fields, signatory slots,
/// completion policy). Rejected with `409` once the termo has left `Draft`.
pub async fn patch_abertura(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(patch): Json<PatchTermoAbertura>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;
    let mut termo = load_book_abertura(&state, book_id).await?;
    if !termo.is_mutable() {
        return Err(ApiError::Conflict(
            "termo is frozen; edits are rejected once signing has begun".to_owned(),
        ));
    }
    apply_patch(&mut termo, patch)?;
    persist_termo(&state, &termo).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// Apply a PATCH to a `Draft` termo. Mutability is confirmed by the caller; the core setters
/// re-check it defensively.
fn apply_patch(termo: &mut TermoInstrument, patch: PatchTermoAbertura) -> Result<(), ApiError> {
    if let Some(title) = patch.title {
        termo.set_title(title).map_err(map_termo_error)?;
    }
    if let Some(body) = patch.body {
        let clauses: Vec<TermoClause> = body
            .into_iter()
            .map(|clause| TermoClause::user_added(clause.heading, clause.text))
            .collect();
        termo.set_body(clauses).map_err(map_termo_error)?;
    }
    if let Some(book_number) = patch.book_number {
        termo.fields.book_number = Some(book_number);
    }
    if let Some(place) = patch.place {
        termo.fields.place = non_empty(place);
    }
    if let Some(page_capacity) = patch.page_capacity {
        termo.fields.page_capacity = Some(page_capacity);
    }
    if let Some(purpose) = patch.purpose {
        termo.fields.purpose = non_empty(purpose);
    }
    if let Some(opening_date) = patch.opening_date {
        termo.fields.instrument_date = Some(parse_date(&opening_date)?);
    }
    if let Some(predecessor_note) = patch.predecessor_note {
        termo.fields.predecessor_note = non_empty(predecessor_note);
    }
    if let Some(slots) = patch.signatories {
        // Replace the whole slot set; each input mints a fresh slot id + order.
        termo.signatories.clear();
        for input in slots {
            let mut slot = if input.required {
                TermoSignatorySlot::required(input.name, input.capacity, input.order)
            } else {
                TermoSignatorySlot::optional(input.name, input.capacity, input.order)
            };
            if let Some(email) = input.email.and_then(non_empty) {
                slot = slot.with_email(email);
            }
            if let Some(note) = normalize_capacity_note(input.capacity_note) {
                slot = slot.with_capacity_note(note);
            }
            termo.add_signatory(slot).map_err(map_termo_error)?;
        }
    }
    if let Some(policy) = patch.completion_policy {
        termo
            .set_completion_policy(policy)
            .map_err(map_termo_error)?;
    }
    Ok(())
}

/// `POST /v1/books/{id}/termo/abertura/advance` — freeze the draft for signing (`Draft → Signing`):
/// validate the content + signatory slots (the capacity allow-list, the at-least-one-signatory
/// rule, the management floor, the completion policy) and pin the template.
pub async fn advance_abertura(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;

    // Resolve the family (to pin the template) and confirm the book is still `Created`.
    // Lock order: entities → books.
    let family = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
        if book.state != BookState::Created {
            return Err(ApiError::Conflict(
                "book is not in the Created state; its termo cannot be frozen".to_owned(),
            ));
        }
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        entity.family
    };

    let mut termo = load_book_abertura(&state, book_id).await?;
    if termo.fields.instrument_date.is_none() {
        return Err(ApiError::Unprocessable(
            "opening_date is required before the termo can be frozen for signing".to_owned(),
        ));
    }
    let template_id =
        crate::documents::abertura_template_id(family).unwrap_or("csc-termo-abertura/v1");
    termo
        .advance_to_signing(template_id, OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;
    persist_termo(&state, &termo).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `POST /v1/books/{id}/termo/abertura/sign` — record that a signatory slot signed. Enforces the
/// sequential order (a slot cannot sign while an earlier required slot is unsigned). `signature_id`
/// references the collected signature artifact from the signing pipeline.
pub async fn sign_abertura(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<SignTermoSlot>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;
    let mut termo = load_book_abertura(&state, book_id).await?;
    termo
        .mark_slot_signed(req.slot_id, req.signature_id, OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;
    persist_termo(&state, &termo).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `POST /v1/books/{id}/termo/abertura/open` — seal the signed termo and open the book. Requires the
/// completion policy satisfied; appends the `book.opened` genesis event digesting the *final,
/// filled, signed* termo, and produces the preserved termo PDF/A (same durable commit, same
/// document key as the one-shot path for back-compat).
pub async fn open_from_termo(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<OpenBookFromTermo>,
) -> Result<Json<BookView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;
    let actor = actor.resolve(&req.actor);

    let mut termo = load_book_abertura(&state, book_id).await?;
    // EVIDENTIARY FAIL-CLOSED GATE (binding): refuse to seal/open a termo that is not really
    // cryptographically signed. Runs BEFORE `seal`, so a not-really-signed termo stays `Signing`
    // (retriable) and never appears as `Sealed`.
    require_real_signatures(&state, &termo).await?;
    // Seal the termo (checks the completion policy) — a state-only step; the local clone is
    // discarded if any later precondition fails, leaving the stored Signing termo retriable.
    termo
        .seal(OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;

    // entities → books → ledger.
    let entities = state.entities.read().await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if book.state != BookState::Created {
        return Err(ApiError::Conflict(
            "book is not in the Created state; it cannot be opened".to_owned(),
        ));
    }
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    let projected = termo
        .project_abertura(
            entity.name.clone(),
            entity.nipc.to_string(),
            entity.seat.clone(),
            req.numbering_scheme,
        )
        .map_err(map_termo_error)?;

    let mut next = book.clone();
    // Appends the `book.opened` genesis event digesting the final signed termo.
    open_and_seal_book(&mut next, entity, projected, &actor, &mut ledger)?;

    // Preserved termo PDF/A + `document.generated`, in the SAME durable commit as `book.opened`
    // (mirrors the one-shot path). A render/write failure rolls the genesis event back so a failed
    // open leaves no trace; a family without a termo template gets the genesis event alone.
    let termo_ref = next
        .termo_abertura
        .as_ref()
        .expect("termo present immediately after open");
    let generated = match crate::documents::generate_for_termo(termo_ref, &next, entity.family) {
        Ok(g) => g,
        Err(e) => {
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(e);
        }
    };
    let sealed_termo = termo.clone();
    match generated {
        Some(made) => {
            let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
            let payload = serde_json::to_vec(&made.event_payload)?;
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
            let book_for_store = next.clone();
            let stored_for_store = made.stored.clone();
            state
                .persist_write_through(&mut ledger, 2, move |tx| {
                    tx.upsert_book(&book_for_store)?;
                    tx.upsert_document(&stored_for_store)?;
                    tx.upsert_termo_instrument(&sealed_termo)
                })
                .await?;
            state
                .documents
                .write()
                .await
                .insert(made.stored.act_id, made.stored.clone());
        }
        None => {
            let book_for_store = next.clone();
            state
                .persist_write_through(&mut ledger, 1, move |tx| {
                    tx.upsert_book(&book_for_store)?;
                    tx.upsert_termo_instrument(&sealed_termo)
                })
                .await?;
        }
    }
    state.attest_latest(&attestor, &ledger).await;

    let view = BookView::from(&next);
    if let Some(slot) = books.get_mut(&book_id) {
        *slot = next;
    }
    Ok(Json(view))
}
