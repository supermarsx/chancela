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
//! `instrument_signatures` history. It deliberately does **not** fork the ~20 act crypto handlers;
//! it reuses their *leaf primitives* (`finalize_signed_pdf`, `ensure_signed_pdf_binds_document`, the
//! PAdES prepare/sign seams) over its own sequential-signer loop. The canonical **unsigned** termo
//! PDF snapshot is rendered and pinned at `advance` (t41-e1, [`advance_abertura`] →
//! [`crate::documents::generate_termo_snapshot`]), keyed on the unified signing subject
//! `ActId(book.id.0)`.
//!
//! [`sign_abertura_pkcs12`] (t41-e2) produces a **real** per-slot PAdES signature over that snapshot
//! and records each in the `instrument_signatures` history — exactly the evidence
//! [`require_real_signatures`] requires before a book may open. [`sign_abertura`] remains the bare
//! completion-*reference* path (no crypto); a termo signed only through it stays fail-closed.
//!
//! ## Signing model — parallel co-signature (a phase-1 pades constraint)
//!
//! The plan called for *nested* sequential PAdES (signer *n* extends signer *n-1*'s bytes). That is
//! **not achievable** with the current `chancela-pades`: phase-1 rejects adding a signature to a PDF
//! that already carries an `/AcroForm` (`chancela-pades/src/sign.rs`), so a document can hold exactly
//! one signature. The termo therefore uses **parallel co-signature**: every required signatory
//! independently signs the SAME frozen snapshot, yielding one single-signature PAdES revision per
//! slot (each bound to the snapshot, each independently verifiable). The collection *order* is still
//! enforced; only the cryptographic nesting is dropped.
//!
//! **Open-path (t41-e3, implemented):** there is no single PDF carrying all N signatures — the N
//! signed revisions live as N `instrument_signatures` rows. [`open_from_termo`] therefore preserves
//! the **SET**: the frozen snapshot stays as the preserved base PDF/A and a `document.generated`
//! event digesting the co-signature manifest ([`build_cosignature_manifest`]) binds the N signed
//! digests into the open commit. The termo is not re-rendered at open (that would discard the
//! signatures) and the signed PDF/As are never merged (that would invalidate them) — per
//! [[signed-pdfa-is-the-canonical-unit]]. The gate ([`require_real_signatures`]) is keyed on the
//! unified subject `ActId(book.id.0)` (R1), so it sees e2's real per-slot signatures and now opens a
//! genuinely-signed termo while still failing closed on a reference-only one.
//!
//! **Remaining modes (t41-e2b):** CMD and CSC two-phase real signing over the termo are a follow-up;
//! they need additional act-pipeline primitives (`run_cmd_initiate`, the pending-session envelope
//! helpers, `resolve_cmd_config_for_entry`) promoted out of `signature.rs`, outside this module's
//! reach today. They face the same one-signature-per-PDF constraint (also parallel co-signature).

use axum::Json;
use axum::extract::{Path, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use chancela_authz::Permission;
use chancela_core::book::{BookId, NumberingScheme};
use chancela_core::error::TermoError;
use chancela_core::termo::{
    TermoClause, TermoInstrument, TermoKind, TermoSignatorySlot, TermoState,
};
use chancela_core::{ActId, BookState, open_and_seal_book};
use chancela_pades::{SignOptions, prepare_signature_with_appearance};
use chancela_signing::{Pkcs12IdentitySelector, Pkcs12SigningSource};
use chancela_store::{StoredDocument, StoredInstrumentSignature, StoredSignedDocument};
use serde_json::json;
use time::OffsetDateTime;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book};
use crate::dto::{
    BookView, CloseBookFromTermo, OpenBookFromTermo, PatchTermoAbertura, PatchTermoEncerramento,
    SignTermoSlot, TermoInstrumentView, normalize_capacity_note, parse_date,
};
use crate::error::ApiError;
use crate::signature::{
    LOCAL_PKCS12_SIGN_MAX_BYTES, SealAppearanceRequest, ensure_signed_pdf_binds_document,
    finalize_signed_pdf, seal_appearance_from_request, sha256_hex,
};

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

/// **Evidentiary fail-closed gate (binding t23 ruling), now LIVE (t41-e3).** A termo the system
/// presents as `Sealed`, and a book it presents as `Open`, MUST be *really* cryptographically signed:
/// a genuine PAdES signature over the frozen termo snapshot, bound by
/// [`crate::signature::ensure_signed_pdf_binds_document`], recorded per slot in e1's
/// `instrument_signatures` history (v23).
///
/// **R1 subject unification.** The whole termo signing chain — the snapshot pinned at advance
/// ([`advance_abertura`]), the per-slot `instrument_signatures` rows produced by
/// [`sign_abertura_pkcs12`] (t41-e2), and the preserved PDF/A at open — is keyed on the unified
/// subject `ActId(book.id.0)` (one-shot parity). This gate reads the history at that same subject, so
/// it *sees* the real signatures e2 persisted. (Before e3 it keyed `ActId(termo.id.0)` and could
/// never see them — the change here is what flips it live.)
///
/// [`TermoInstrument::mark_slot_signed`] records a signature *reference* for completion tracking,
/// which is **not** an evidentiary cryptographic signature: a termo advanced through the bare
/// [`sign_abertura`] reference path alone still fails closed here. Real PAdES production over the
/// snapshot (e2's PKCS#12 path) is what populates `instrument_signatures` and lets a book open.
async fn require_real_signatures(
    state: &AppState,
    subject: ActId,
    termo: &TermoInstrument,
) -> Result<(), ApiError> {
    let required: Vec<Uuid> = termo
        .signatories
        .iter()
        .filter(|slot| slot.required)
        .map(|slot| slot.id)
        .collect();
    // The termo signing subject is passed by the caller: `ActId(book.id.0)` for the abertura (one-shot
    // parity, R1), `ActId(termo.id.0)` for the encerramento (kept disjoint from the abertura's
    // book-keyed artifacts). Either way it is the same key the sign handlers persist under and the
    // advance snapshot + preserved PDF/A use.
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
             Every required signatory must have a real PAdES signature over the termo snapshot \
             (recorded in the instrument_signatures history) before the book can be opened; a book is \
             never opened on a not-really-signed termo."
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
        replace_signatory_slots(termo, slots)?;
    }
    if let Some(policy) = patch.completion_policy {
        termo
            .set_completion_policy(policy)
            .map_err(map_termo_error)?;
    }
    Ok(())
}

/// Replace a termo's whole signatory slot set from PATCH input. Shared by the abertura and
/// encerramento patch paths — the slot model is identical (art. 31.º n.º 2 puts both termos on the
/// same signers). Each input mints a fresh slot id; the caller-supplied `order` drives sequential
/// collection. The qualidade-`Other` assurance note (D1) round-trips.
fn replace_signatory_slots(
    termo: &mut TermoInstrument,
    slots: Vec<crate::dto::TermoSlotInput>,
) -> Result<(), ApiError> {
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

    // Resolve the family (to pin the template) and confirm the book is still `Created`, snapshotting
    // the entity + book the canonical unsigned termo PDF is rendered from. Lock order: entities → books.
    let (family, entity, book) = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
        if book.state != BookState::Created {
            return Err(ApiError::Conflict(
                "book is not in the Created state; its termo cannot be frozen".to_owned(),
            ));
        }
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        (entity.family, entity.clone(), book.clone())
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

    // Render + pin the canonical UNSIGNED termo PDF snapshot (t41 §2.1) — the bytes every required
    // signatory signs (sequential PAdES) and the bytes the open path preserves. Keyed on the unified
    // signing subject `ActId(book.id.0)` (R1). A family without a termo template renders nothing; the
    // book then opens on the genesis event alone (one-shot parity).
    //
    // ⚠️ numbering_scheme is not a `TermoInstrument` field yet, so the snapshot is rendered with the
    // codebase-wide default (`Sequential`). The open path (t41-e3) must preserve the signed bytes with
    // the SAME scheme — or the choice must move ahead of `advance` — so the signed snapshot and the
    // genesis-digested projection cannot disagree. See `documents::generate_termo_snapshot`.
    let snapshot = crate::documents::generate_termo_snapshot(
        &termo,
        &book,
        &entity,
        chancela_core::book::NumberingScheme::Sequential,
    )?;

    // Persist the frozen termo + (if the family has a template) its unsigned snapshot in one durable
    // commit. NO ledger append — a Signing termo is not yet on the hash chain (t23 invariant); its
    // signatures are digested only at the open genesis. e2 reloads these bytes to sign over.
    {
        let mut ledger = state.ledger.write().await;
        let termo_for_store = termo.clone();
        let snapshot_stored = snapshot.as_ref().map(|g| g.stored.clone());
        state
            .persist_write_through(&mut ledger, 0, move |tx| {
                tx.upsert_termo_instrument(&termo_for_store)?;
                if let Some(doc) = &snapshot_stored {
                    tx.upsert_document(doc)?;
                }
                Ok(())
            })
            .await?;
    }
    // Mirror the snapshot into the in-memory documents cache (the fast read path `load_document`
    // consults before the store), matching the open path's write-through discipline.
    if let Some(g) = &snapshot {
        state
            .documents
            .write()
            .await
            .insert(g.stored.act_id, g.stored.clone());
    }

    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `POST /v1/books/{id}/termo/abertura/sign` — record that a signatory slot signed by *reference*
/// only. Enforces the sequential order (a slot cannot sign while an earlier required slot is
/// unsigned). `signature_id` references a collected signature artifact; this is completion-tracking
/// metadata, **not** an evidentiary cryptographic signature. A termo signed only through this path
/// stays fail-closed at [`require_real_signatures`] — the book cannot open until a real per-slot
/// PAdES signature over the termo PDF lands in the `instrument_signatures` history (see
/// [`sign_abertura_pkcs12`]).
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

/// The signing family + evidentiary level a termo PKCS#12 software-certificate PAdES signature
/// carries. Mirrors the act pipeline's local-signing labels (`sign_local_pkcs12_signature`): this is
/// advanced **local technical evidence**, not a qualified remote/CMD signature. The strings match
/// the act family so downstream readers treat both uniformly.
const FAMILY_TERMO_LOCAL_PKCS12: &str = "LocalPkcs12SoftwareCertificate";
const EVIDENTIARY_TERMO_ADVANCED_LOCAL: &str = "AdvancedLocalTechnicalEvidence";

/// Body of `POST /v1/books/{id}/termo/abertura/sign/pkcs12`: produce a **real** per-slot PAdES
/// signature over the frozen termo snapshot with a locally supplied PKCS#12/PFX software
/// certificate. The encrypted PFX bytes and passphrase are transient inputs; only the resulting
/// signed PDF plus public certificate evidence is persisted — never the PFX or the passphrase.
///
/// Deliberately does **not** derive `Debug`: the passphrase and PFX bytes are secret material and
/// must never reach a debug log.
#[derive(Deserialize)]
pub struct SignTermoSlotPkcs12 {
    /// The signatory slot this signature satisfies.
    pub slot_id: Uuid,
    /// The base64-encoded PKCS#12/PFX bytes (transient).
    #[serde(alias = "pkcs12", alias = "pfx_base64", alias = "pkcs12_der_base64")]
    pub pkcs12_base64: String,
    /// The PFX passphrase (transient — never persisted or logged).
    pub passphrase: String,
    /// Optional friendly-name selector when the PFX carries multiple identities.
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// The capacity in which the signatory signs (optional, informational; the slot already carries
    /// the structured, allow-listed capacity).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Optional visible-seal appearance, baked into the signed revision.
    #[serde(default)]
    pub seal: Option<SealAppearanceRequest>,
}

/// The PDF `/M` time string (`D:YYYYMMDDHHMMSSZ`) for a signing time. Mirrors the act pipeline's
/// private `pdf_time`; duplicated here (a trivial pure format) so the sign path stays entirely in
/// the termo module without widening the act crypto file's surface.
fn termo_pdf_time(t: OffsetDateTime) -> String {
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The signer leaf-certificate subject DN, if parseable (audit metadata only).
fn termo_signer_subject_dn(der: &[u8]) -> Option<String> {
    use x509_cert::der::Decode;
    x509_cert::Certificate::from_der(der)
        .ok()
        .map(|cert| cert.tbs_certificate.subject.to_string())
}

/// Map a PKCS#12 signing error to a client-safe `422`, never echoing the passphrase (the error type
/// carries none).
fn map_termo_pkcs12_error(e: chancela_signing::SigningError) -> ApiError {
    use chancela_signing::SigningError as S;
    match e {
        S::SoftCertificate(chancela_signing::SoftCertificateError::WrongPassword) => {
            ApiError::Unprocessable("PKCS#12 password is incorrect".to_owned())
        }
        S::SoftCertificate(error) => {
            ApiError::Unprocessable(format!("invalid PKCS#12 signing material: {error}"))
        }
        other => ApiError::Unprocessable(format!("local PKCS#12 signing failed: {other}")),
    }
}

/// `POST /v1/books/{id}/termo/abertura/sign/pkcs12` — produce a **real cryptographic** per-slot
/// PAdES signature over the frozen termo snapshot with a locally supplied PKCS#12/PFX certificate.
///
/// This is the follow-up that flips the fail-closed gate live (t41-e2). Unlike [`sign_abertura`]
/// (which records a bare completion *reference*), this signs the canonical unsigned snapshot pinned
/// at advance and records a genuine PAdES signature per slot in the store's `instrument_signatures`
/// history — the evidence [`require_real_signatures`] requires before a book may open.
///
/// Parallel co-signature: every required signatory independently signs the SAME frozen snapshot, so
/// each row in `instrument_signatures` is its own single-signature PAdES revision over the canonical
/// termo PDF, bound to it by [`ensure_signed_pdf_binds_document`]. Nested "signer n extends signer
/// n-1" PAdES is not achievable with `chancela-pades` phase-1 (it rejects a second signature into an
/// existing `/AcroForm`); this is the achievable model that still yields a genuine signature per
/// slot. Nothing enters the hash chain here — a `Signing` termo is off-chain until the open genesis
/// digests it (the t23 invariant); the signatures live in `instrument_signatures` (durable).
///
/// The collection order is still enforced ([`TermoInstrument::mark_slot_signed`] blocks an
/// out-of-order slot); only the cryptographic nesting is dropped.
///
/// PKCS#12 is the desk-application local-signing flow, so it inherits the `state.local_signing`
/// gate exactly as the act path does.
pub async fn sign_abertura_pkcs12(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<SignTermoSlotPkcs12>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookOpen, scope_of_book(book_id)).await?;

    // PKCS#12 local signing is the desk-application flow (mirrors the act pipeline's gate).
    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura local com certificado PKCS#12 só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    // The unified abertura signing subject (R1): the snapshot, the per-slot history, and the
    // preserved PDF/A are all keyed on `ActId(book.id.0)`.
    let termo = load_book_abertura(&state, book_id).await?;
    sign_termo_slot_pkcs12(&state, ActId(book_id.0), termo, req, "termo de abertura").await
}

/// Shared PKCS#12 per-slot **real-PAdES** signing over a frozen termo snapshot, driving both the
/// abertura and the encerramento `sign/pkcs12` handlers. Each caller loads its own kind-specific
/// termo and resolves the signing subject (`ActId(book.id.0)` for the abertura, `ActId(termo.id.0)`
/// for the encerramento — kept disjoint so the two termos' snapshots + signature sets never collide);
/// everything else is identical, because art. 31.º n.º 2 puts both termos on the same signers with
/// the same parallel co-signature model.
///
/// `subject` keys the snapshot lookup, the per-slot `instrument_signatures` row and the in-memory
/// signed-doc cache. `reason_label` names the instrument in the PDF `/Reason` (pt-PT). Nothing enters
/// the hash chain here — a `Signing` termo is off-chain until its open/close genesis digests it.
async fn sign_termo_slot_pkcs12(
    state: &AppState,
    subject: ActId,
    mut termo: TermoInstrument,
    req: SignTermoSlotPkcs12,
    reason_label: &str,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    if termo.state != TermoState::Signing {
        return Err(ApiError::Conflict(
            "the termo is not collecting signatures; freeze it for signing first".to_owned(),
        ));
    }

    // Fail fast BEFORE any crypto: the slot must be signable in sequential order. The throwaway
    // probe reuses the core's authoritative existence / already-signed / sequence checks without
    // mutating the instrument, so an out-of-order or unknown slot is a clean 409 with no wasted work.
    {
        let mut probe = termo.clone();
        probe
            .mark_slot_signed(req.slot_id, None, OffsetDateTime::now_utc())
            .map_err(map_termo_error)?;
    }

    // The canonical UNSIGNED snapshot pinned at advance (t41-e1), keyed on the subject.
    let snapshot = crate::documents::load_document(state, subject)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict(
                "the termo signing snapshot is missing; freeze the termo for signing first"
                    .to_owned(),
            )
        })?;
    if sha256_hex(&snapshot.pdf_bytes) != snapshot.pdf_digest {
        return Err(ApiError::Conflict(
            "the termo signing snapshot failed its stored SHA-256 fixity check".to_owned(),
        ));
    }

    // Each signatory signs the SAME frozen snapshot independently (a parallel co-signature), and the
    // result is bound to the snapshot byte-for-byte. Nested "signer n extends signer n-1" PAdES is
    // NOT achievable with the current `chancela-pades` layer: phase-1 rejects adding a signature to a
    // PDF that already carries an `/AcroForm` (`sign.rs`). So every real per-slot signature is a
    // single-signature PAdES revision over the canonical snapshot — each independently verifiable,
    // each recorded in `instrument_signatures`. See the module docs for the model + its open-path
    // implication (t41-e3 preserves the SET of signed rows, not one nested PDF).
    let input_bytes = snapshot.pdf_bytes.clone();

    let appearance = seal_appearance_from_request(req.seal)?;

    let pkcs12_der =
        Zeroizing::new(B64.decode(req.pkcs12_base64.trim()).map_err(|e| {
            ApiError::Unprocessable(format!("invalid base64 PKCS#12 content: {e}"))
        })?);
    if pkcs12_der.is_empty() {
        return Err(ApiError::Unprocessable(
            "PKCS#12 upload is empty".to_owned(),
        ));
    }
    if pkcs12_der.len() > LOCAL_PKCS12_SIGN_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "PKCS#12 upload is {} bytes; local signing accepts at most {} bytes",
            pkcs12_der.len(),
            LOCAL_PKCS12_SIGN_MAX_BYTES
        )));
    }

    let passphrase = Zeroizing::new(req.passphrase);
    let friendly_name = req.friendly_name.and_then(|name| {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    });
    let selector = friendly_name
        .map(Pkcs12IdentitySelector::by_friendly_name)
        .unwrap_or_else(Pkcs12IdentitySelector::any);

    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let reason = match req
        .capacity
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(capacity) => {
            format!("Assinatura local avançada do {reason_label} ({capacity})")
        }
        None => format!("Assinatura local avançada do {reason_label}"),
    };
    let opts = SignOptions {
        field_name: Some(format!("AssinaturaTermo-{}", req.slot_id)),
        signing_time: Some(termo_pdf_time(signing_time)),
        reason: Some(reason),
        location: None,
        contact_info: None,
    };

    // Validate any visible-seal placement up-front so a bad page/geometry is a clean 422 rather than
    // surfacing as a generic 500 from inside the blocking sign task.
    if appearance.is_some() {
        prepare_signature_with_appearance(&input_bytes, &opts, appearance.as_ref()).map_err(
            |e| ApiError::Unprocessable(format!("não foi possível preparar o selo visível: {e}")),
        )?;
    }

    let (signed_pdf, identity) = tokio::task::spawn_blocking(move || {
        let source = Pkcs12SigningSource::from_der_with_selector(
            pkcs12_der.as_slice(),
            &passphrase,
            &selector,
        )?;
        let identity = source.identity().clone();
        let signed_pdf = chancela_signing::pipeline::sign_pdf_pades_with_appearance(
            &source,
            &input_bytes,
            signing_time,
            &opts,
            appearance.as_ref(),
        )?;
        Ok::<_, chancela_signing::SigningError>((signed_pdf, identity))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("termo PKCS#12 signing task failed: {e}")))?
    .map_err(map_termo_pkcs12_error)?;

    let final_pdf =
        finalize_signed_pdf(state, signed_pdf, &identity.signing_certificate_der).await?;
    // The signed bytes MUST extend the frozen snapshot byte-for-byte — a valid single-signature
    // incremental PAdES revision over the canonical termo PDF.
    ensure_signed_pdf_binds_document(&snapshot, &final_pdf.bytes)?;

    let signed_pdf_digest = sha256_hex(&final_pdf.bytes);
    let signed_at = OffsetDateTime::now_utc();
    let signer_cert_subject = termo_signer_subject_dn(&identity.signing_certificate_der);
    let stored = StoredSignedDocument {
        act_id: subject,
        document_id: snapshot.id.clone(),
        signed_pdf_digest,
        signature_family: FAMILY_TERMO_LOCAL_PKCS12.to_owned(),
        evidentiary_level: EVIDENTIARY_TERMO_ADVANCED_LOCAL.to_owned(),
        trusted_list_status: None,
        signer_cert_subject,
        signing_time,
        signed_at,
        signer_cert_der: identity.signing_certificate_der.clone(),
        timestamp_token_der: final_pdf.timestamp_token_der.clone(),
        timestamp_trust_report_json: final_pdf.timestamp_trust_report_json.clone(),
        signer_capacity_evidence_json: None,
        signed_pdf_bytes: final_pdf.bytes,
    };

    // Record the collected signature on the slot (completion tracking) and persist BOTH the per-slot
    // `instrument_signatures` history row (the real evidence the gate reads) and the frozen termo in
    // ONE durable commit. NO ledger append — a Signing termo is off-chain until the open genesis.
    let signature_ref = Uuid::new_v4();
    termo
        .mark_slot_signed(req.slot_id, Some(signature_ref), signed_at)
        .map_err(map_termo_error)?;
    {
        let mut ledger = state.ledger.write().await;
        let termo_for_store = termo.clone();
        let doc_for_store = stored.clone();
        let slot_id_str = req.slot_id.to_string();
        state
            .persist_write_through(&mut ledger, 0, move |tx| {
                tx.upsert_signed_termo_slot_signature(&doc_for_store, &slot_id_str)?;
                tx.upsert_termo_instrument(&termo_for_store)
            })
            .await?;
    }
    // Publish the latest signed bytes to the in-memory read model, so the next sequential signer
    // (and the open path) reads them without a store round-trip — the same discipline the act
    // signing handlers apply.
    state.signed_documents.write().await.insert(subject, stored);

    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// Build the **co-signature manifest** binding the frozen termo snapshot to the SET of canonical
/// per-slot signed PDF/As — the preserved-artifact shape for a parallel-co-signed termo (t41-e3, R2).
///
/// Because `chancela-pades` is one-signature-per-PDF (phase-1), N signatories cannot nest into a
/// single PDF; each signs the SAME frozen snapshot independently, yielding N single-signature PAdES
/// revisions recorded in `instrument_signatures`. There is therefore **no single PDF carrying all N
/// signatures** to preserve. The open commit instead preserves the frozen snapshot as the base PDF/A
/// (the exact bytes every signatory signed) and digests THIS manifest — which enumerates each signed
/// revision by slot + SHA-256 digest + signer — into the hash chain, in the same atomic commit as
/// `book.opened`. The N signed PDF/As themselves stay intact in `instrument_signatures` (the
/// canonical units per [[signed-pdfa-is-the-canonical-unit]]); they are never re-rendered (that would
/// discard the signatures) and never merged into one file (that would invalidate every signature).
fn build_cosignature_manifest(
    kind: &str,
    subject: ActId,
    snapshot: &StoredDocument,
    signatures: &[StoredInstrumentSignature],
) -> serde_json::Value {
    let sigs: Vec<serde_json::Value> = signatures
        .iter()
        .map(|s| {
            json!({
                "seq": s.seq,
                "slot_id": s.slot_id,
                "signed_pdf_digest": s.document.signed_pdf_digest,
                "signature_family": s.document.signature_family,
                "evidentiary_level": s.document.evidentiary_level,
                "signer_cert_subject": s.document.signer_cert_subject,
            })
        })
        .collect();
    json!({
        "kind": kind,
        "model": "parallel-co-signature",
        "subject": subject.to_string(),
        "snapshot_document_id": snapshot.id,
        "snapshot_pdf_digest": snapshot.pdf_digest,
        "snapshot_template_id": snapshot.template_id,
        "signature_count": signatures.len(),
        "signatures": sigs,
    })
}

/// `POST /v1/books/{id}/termo/abertura/open` — seal the signed termo and open the book (t41-e3).
///
/// Requires the completion policy satisfied AND — the fail-closed gate now live — every required
/// slot really cryptographically signed. Appends the `book.opened` genesis event digesting the
/// *final, filled, signed* termo projection, and **preserves the SET of co-signature PDF/As** (R2):
/// the frozen snapshot stays as the preserved base PDF/A (keyed `ActId(book.id.0)`, the same key the
/// one-shot path uses) and a `document.generated` event digesting the co-signature manifest
/// ([`build_cosignature_manifest`]) binds the exact set of real signatures into the SAME atomic
/// open commit. The termo is **not** re-rendered at open (a re-render would be unsigned and could
/// digest a projection different from what was signed).
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
    // EVIDENTIARY FAIL-CLOSED GATE (binding, now LIVE): refuse to seal/open a termo that is not really
    // cryptographically signed. Runs BEFORE `seal`, so a not-really-signed termo stays `Signing`
    // (retriable) and never appears as `Sealed`. R1: keyed on `ActId(book.id.0)` so it sees e2's
    // real per-slot signatures.
    require_real_signatures(&state, ActId(book_id.0), &termo).await?;

    // numbering_scheme reconciliation (e1 flag): the snapshot every signatory signed was frozen at
    // advance under the codebase-default `Sequential` scheme (numbering_scheme is not yet a
    // `TermoInstrument` field, so it cannot be chosen before signing). The genesis projection MUST use
    // the SAME scheme, or the signed snapshot and the genesis-digested projection would disagree.
    // Reject a contradicting request rather than silently coercing (reject-never-silently-transform).
    // When the scheme becomes a draft field pinned at advance, this compares against the pinned value.
    if req.numbering_scheme != NumberingScheme::Sequential {
        return Err(ApiError::Unprocessable(
            "the termo snapshot was frozen for signing under sequential numbering; opening the book \
             under a different numbering scheme would contradict the signed document. Sequential is \
             the only scheme available for the two-phase termo until the scheme can be chosen before \
             signing."
                .to_owned(),
        ));
    }

    // Load the SET of co-signature PDF/As recorded at sign time (parallel co-signature: one genuine
    // single-signature PAdES revision per slot, each over the SAME frozen snapshot) and the frozen
    // snapshot itself — BEFORE taking the write locks. These are what the open commit preserves and
    // binds; the gate above already proved they cover every required slot.
    let subject = ActId(book_id.0);
    let signatures: Vec<StoredInstrumentSignature> = match &state.store {
        Some(store) => store
            .read_blocking_async(move |s| s.instrument_signatures_for_subject(subject))
            .await
            .map_err(|e| {
                ApiError::Internal(format!("instrument signature store read failed: {e}"))
            })?,
        None => Vec::new(),
    };
    // The frozen UNSIGNED snapshot pinned at advance is the preserved base PDF/A — the exact bytes
    // every signatory signed. Preserved as-is; deliberately NOT re-rendered.
    let snapshot = crate::documents::load_document(&state, subject).await?;

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
    // Appends the `book.opened` genesis event digesting the final signed termo projection.
    open_and_seal_book(&mut next, entity, projected, &actor, &mut ledger)?;

    let sealed_termo = termo.clone();

    // Preserve the SET of signed PDF/As and bind it into the SAME durable commit as `book.opened`. A
    // write failure rolls the genesis event back so a failed open leaves no trace.
    if signatures.is_empty() {
        // No recorded crypto signatures — a family with no termo-abertura template renders no snapshot
        // and can carry no PAdES evidence, so it opens on the genesis event alone (one-shot parity).
        // (With a template, the gate above guarantees signatures exist, so this branch is the
        // template-less case.)
        let book_for_store = next.clone();
        state
            .persist_write_through(&mut ledger, 1, move |tx| {
                tx.upsert_book(&book_for_store)?;
                tx.upsert_termo_instrument(&sealed_termo)
            })
            .await?;
    } else {
        // Signed: preserve the frozen snapshot as the base PDF/A + digest the co-signature manifest.
        let Some(snapshot_doc) = snapshot else {
            // Signatures exist but the snapshot is gone — an inconsistent store. Fail closed rather
            // than open a book whose signed set we cannot bind; roll the genesis event back.
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(ApiError::Internal(
                "the termo is cryptographically signed but its frozen snapshot is missing; refusing \
                 to open without preserving the signed set"
                    .to_owned(),
            ));
        };
        let manifest = build_cosignature_manifest(
            "termo.abertura.cosignatures",
            subject,
            &snapshot_doc,
            &signatures,
        );
        let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
        let payload = match serde_json::to_vec(&manifest) {
            Ok(payload) => payload,
            Err(e) => {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(e.into());
            }
        };
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
        let snapshot_for_store = snapshot_doc.clone();
        state
            .persist_write_through(&mut ledger, 2, move |tx| {
                tx.upsert_book(&book_for_store)?;
                // Re-affirm the frozen snapshot as the preserved base PDF/A (idempotent; pinned at
                // advance). NOT re-rendered — the signatures bind to exactly these bytes.
                tx.upsert_document(&snapshot_for_store)?;
                tx.upsert_termo_instrument(&sealed_termo)
            })
            .await?;
        // Keep the in-memory documents cache consistent with the preserved base PDF/A.
        state
            .documents
            .write()
            .await
            .insert(snapshot_doc.act_id, snapshot_doc);
    }
    state.attest_latest(&attestor, &ledger).await;

    let view = BookView::from(&next);
    if let Some(slot) = books.get_mut(&book_id) {
        *slot = next;
    }
    Ok(Json(view))
}

// ================================================================================================
// Termo de encerramento — the two-phase CLOSE mirror of the abertura open (t44)
// ================================================================================================
//
// The closing term is "like any other ata": templated (t44-e1 seeds) and signed through the SAME
// parallel co-signature PAdES pipeline the abertura uses (t41). These handlers mirror the abertura
// ones; the differences are deliberate and documented:
//
//   * The book must be **Open** (not `Created`) to close, and stays Open until a genuinely-signed
//     encerramento seals it — a book AT capacity is closeable (t44-e2 blocks new acts, not close),
//     and a book is NEVER auto-closed on a fake signature.
//   * The signing subject is `ActId(termo.id.0)`, NOT the book id the abertura uses, so the
//     encerramento's snapshot + `instrument_signatures` never overwrite/merge the abertura's (which
//     live under `ActId(book.id.0)`). See `documents::generate_encerramento_snapshot`.
//   * `close_from_termo` derives the authoritative facts (F18 ata count, F16 pages used) from the
//     book — `Book::close` overwrites them again — and refuses to seal a signed snapshot whose
//     material ata count no longer matches the book (the stale-fact guard, R12).

/// Load a book's termo de encerramento from the store. `404` if the book has no encerramento draft
/// (e.g. a book closed one-shot, or one never entered into the two-phase close flow).
async fn load_book_encerramento(
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
        .find(|t| t.kind == TermoKind::Encerramento)
        .ok_or(ApiError::NotFound)
}

/// The termo de encerramento signing subject: the encerramento instrument's OWN id, kept disjoint
/// from the abertura's book-keyed subject (see `documents::generate_encerramento_snapshot`).
fn encerramento_subject(termo: &TermoInstrument) -> ActId {
    ActId(termo.id.0)
}

/// `GET /v1/books/{id}/termo/encerramento` — read the book's termo de encerramento instrument.
pub async fn get_encerramento(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(&state, &actor, Permission::BookRead, scope_of_book(book_id)).await?;
    let termo = load_book_encerramento(&state, book_id).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `PATCH /v1/books/{id}/termo/encerramento` — edit the draft (title, body, fields, signatory slots,
/// completion policy). Rejected with `409` once the termo has left `Draft`.
pub async fn patch_encerramento(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(patch): Json<PatchTermoEncerramento>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(book_id),
    )
    .await?;
    let mut termo = load_book_encerramento(&state, book_id).await?;
    if !termo.is_mutable() {
        return Err(ApiError::Conflict(
            "termo is frozen; edits are rejected once signing has begun".to_owned(),
        ));
    }
    apply_patch_encerramento(&mut termo, patch)?;
    persist_termo(&state, &termo).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// Apply a PATCH to a `Draft` termo de encerramento. Mirrors [`apply_patch`], but the fillable
/// fields are the encerramento's (a closing date + a structured closing reason, no page capacity).
fn apply_patch_encerramento(
    termo: &mut TermoInstrument,
    patch: PatchTermoEncerramento,
) -> Result<(), ApiError> {
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
    if let Some(closing_date) = patch.closing_date {
        termo.fields.instrument_date = Some(parse_date(&closing_date)?);
    }
    if let Some(reason) = patch.closing_reason {
        termo.fields.closing_reason = Some(reason);
    }
    if let Some(predecessor_note) = patch.predecessor_note {
        termo.fields.predecessor_note = non_empty(predecessor_note);
    }
    if let Some(slots) = patch.signatories {
        replace_signatory_slots(termo, slots)?;
    }
    if let Some(policy) = patch.completion_policy {
        termo
            .set_completion_policy(policy)
            .map_err(map_termo_error)?;
    }
    Ok(())
}

/// `POST /v1/books/{id}/termo/encerramento/advance` — freeze the draft for signing (`Draft →
/// Signing`): validate the content + signatory slots (the capacity allow-list, the
/// at-least-one-signatory rule, the management floor, the completion policy, the required closing
/// reason), pin the template, and render + pin the canonical **unsigned** encerramento snapshot with
/// the book-derived facts materialized so signatories sign the real figures.
pub async fn advance_encerramento(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(book_id),
    )
    .await?;

    // Resolve the entity/book to render from; the book must be Open to close. The book-derived facts
    // (F18/F16) are materialized here exactly as `Book::close` derives them. Lock order: entities →
    // books.
    let (entity, book, ata_count, pages_used_at_close) = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
        if !book.is_open() {
            return Err(ApiError::Conflict(
                "book is not Open; its termo de encerramento cannot be frozen".to_owned(),
            ));
        }
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        let ata_count = book.last_ata_number;
        let pages_used_at_close = book.has_page_capacity().then_some(book.pages_used);
        (entity.clone(), book.clone(), ata_count, pages_used_at_close)
    };

    let mut termo = load_book_encerramento(&state, book_id).await?;
    if termo.fields.instrument_date.is_none() {
        return Err(ApiError::Unprocessable(
            "closing_date is required before the termo can be frozen for signing".to_owned(),
        ));
    }
    let template_id = crate::documents::encerramento_template_id(entity.family)
        .unwrap_or("csc-termo-encerramento/v1");
    termo
        .advance_to_signing(template_id, OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;

    // Render + pin the canonical UNSIGNED encerramento snapshot, keyed on the encerramento subject
    // `ActId(termo.id.0)`. A family without an encerramento template renders nothing; the book then
    // closes on the domain event alone (one-shot parity).
    let snapshot = crate::documents::generate_encerramento_snapshot(
        &termo,
        &book,
        &entity,
        ata_count,
        pages_used_at_close,
    )?;

    // Persist the frozen termo + (if the family has a template) its unsigned snapshot in one durable
    // commit. NO ledger append — a Signing termo is off-chain until the close genesis digests it.
    {
        let mut ledger = state.ledger.write().await;
        let termo_for_store = termo.clone();
        let snapshot_stored = snapshot.as_ref().map(|g| g.stored.clone());
        state
            .persist_write_through(&mut ledger, 0, move |tx| {
                tx.upsert_termo_instrument(&termo_for_store)?;
                if let Some(doc) = &snapshot_stored {
                    tx.upsert_document(doc)?;
                }
                Ok(())
            })
            .await?;
    }
    if let Some(g) = &snapshot {
        state
            .documents
            .write()
            .await
            .insert(g.stored.act_id, g.stored.clone());
    }

    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `POST /v1/books/{id}/termo/encerramento/sign` — record that a signatory slot signed by *reference*
/// only (completion-tracking metadata, **not** an evidentiary cryptographic signature). A termo
/// signed only through this path stays fail-closed at [`require_real_signatures`] — the book cannot
/// close until a real per-slot PAdES signature over the encerramento PDF lands in the
/// `instrument_signatures` history (see [`sign_encerramento_pkcs12`]).
pub async fn sign_encerramento(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<SignTermoSlot>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(book_id),
    )
    .await?;
    let mut termo = load_book_encerramento(&state, book_id).await?;
    termo
        .mark_slot_signed(req.slot_id, req.signature_id, OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;
    persist_termo(&state, &termo).await?;
    Ok(Json(TermoInstrumentView::from(&termo)))
}

/// `POST /v1/books/{id}/termo/encerramento/sign/pkcs12` — produce a **real cryptographic** per-slot
/// PAdES signature over the frozen encerramento snapshot with a locally supplied PKCS#12/PFX
/// certificate. The closing mirror of [`sign_abertura_pkcs12`]; both delegate to the shared
/// [`sign_termo_slot_pkcs12`] core over the encerramento signing subject `ActId(termo.id.0)`.
pub async fn sign_encerramento_pkcs12(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<SignTermoSlotPkcs12>,
) -> Result<Json<TermoInstrumentView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(book_id),
    )
    .await?;

    // PKCS#12 local signing is the desk-application flow (mirrors the act pipeline's gate).
    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura local com certificado PKCS#12 só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    let termo = load_book_encerramento(&state, book_id).await?;
    let subject = encerramento_subject(&termo);
    sign_termo_slot_pkcs12(&state, subject, termo, req, "termo de encerramento").await
}

/// `POST /v1/books/{id}/termo/encerramento/close` — seal the signed termo de encerramento and close
/// the book (the CLOSE mirror of [`open_from_termo`]).
///
/// Requires the completion policy satisfied AND — the fail-closed gate — every required slot really
/// cryptographically signed. Re-derives the authoritative facts and rejects a snapshot whose material
/// ata count moved under the signers (R12). Appends the `book.closed` event digesting the *final,
/// filled, signed* encerramento projection, and **preserves the SET of co-signature PDF/As** (R2):
/// the frozen snapshot stays as the preserved base PDF/A (keyed `ActId(termo.id.0)`) and a
/// `document.generated` event digesting the co-signature manifest binds the exact set of real
/// signatures into the SAME atomic close commit. The termo is **not** re-rendered into the preserved
/// output at close (a re-render would be unsigned).
pub async fn close_from_termo(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CloseBookFromTermo>,
) -> Result<Json<BookView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookClose,
        scope_of_book(book_id),
    )
    .await?;
    let actor = actor.resolve(&req.actor);

    let mut termo = load_book_encerramento(&state, book_id).await?;
    let subject = encerramento_subject(&termo);
    // EVIDENTIARY FAIL-CLOSED GATE (binding, inherited from the abertura): refuse to seal/close a
    // termo that is not really cryptographically signed. Runs BEFORE `seal`, so a not-really-signed
    // termo stays `Signing` (retriable); the book stays `Open`, never auto-closed on a fake signature.
    require_real_signatures(&state, subject, &termo).await?;

    // Load the SET of co-signature PDF/As recorded at sign time + the frozen snapshot — BEFORE the
    // write locks. The gate above already proved they cover every required slot.
    let signatures: Vec<StoredInstrumentSignature> = match &state.store {
        Some(store) => store
            .read_blocking_async(move |s| s.instrument_signatures_for_subject(subject))
            .await
            .map_err(|e| {
                ApiError::Internal(format!("instrument signature store read failed: {e}"))
            })?,
        None => Vec::new(),
    };
    let snapshot = crate::documents::load_document(&state, subject).await?;

    // Seal the termo (checks the completion policy) on a clone — discarded if any later precondition
    // fails, leaving the stored Signing termo retriable.
    termo
        .seal(OffsetDateTime::now_utc())
        .map_err(map_termo_error)?;

    // entities → books → ledger.
    let entities = state.entities.read().await;
    let mut books = state.books.write().await;
    let mut ledger = state.ledger.write().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if !book.is_open() {
        return Err(ApiError::Conflict(
            "book is not Open; it cannot be closed".to_owned(),
        ));
    }
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    // Authoritative facts (F18 ata count / F16 pages used). `Book::close` overwrites these again; we
    // derive them here for the projection AND the stale-fact guard.
    let ata_count = book.last_ata_number;
    let pages_used_at_close = book.has_page_capacity().then_some(book.pages_used);

    // STALE-FACT GUARD (R12): the snapshot every signatory signed was frozen at advance with the ata
    // count as it then stood. Re-render the encerramento from the CURRENT authoritative facts; if the
    // material figure moved under the signers (a new ata was sealed mid-signing), the re-rendered
    // bytes differ from the signed snapshot — refuse to seal a signed document that would contradict
    // the ledger. A signed false fact is unrecoverable; discarding this attempt is the lesser evil.
    if let Some(snapshot_doc) = &snapshot
        && let Some(rederived) = crate::documents::generate_encerramento_snapshot(
            &termo,
            book,
            entity,
            ata_count,
            pages_used_at_close,
        )?
        && rederived.stored.pdf_digest != snapshot_doc.pdf_digest
    {
        return Err(ApiError::Conflict(
            "o livro registou uma nova ata depois de o termo de encerramento ter sido congelado \
             para assinatura; o número de atas declarado deixou de corresponder ao livro. O termo \
             assinado não pode ser selado porque contradiria o registo — recomece o termo de \
             encerramento com os factos atualizados."
                .to_owned(),
        ));
    }

    let projected = termo
        .project_encerramento(ata_count, pages_used_at_close)
        .map_err(map_termo_error)?;

    let mut next = book.clone();
    // `Book::close` overwrites ata_count/pages_used authoritatively and moves Open → Closed.
    next.close(projected)?;

    let scope = format!("entity:{}/book:{}", next.entity_id, next.id);
    let closed_payload = serde_json::to_vec(
        next.termo_encerramento
            .as_ref()
            .expect("termo present immediately after close"),
    )?;
    // Appends the `book.closed` event digesting the final, filled, signed encerramento projection.
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "book.closed",
        None,
        &closed_payload,
    )?;

    let sealed_termo = termo.clone();

    // Preserve the SET of signed PDF/As and bind it into the SAME durable commit as `book.closed`. A
    // write failure rolls the `book.closed` event back so a failed close leaves no trace.
    if signatures.is_empty() {
        // No recorded crypto signatures — a family with no encerramento template renders no snapshot
        // and can carry no PAdES evidence, so it closes on the domain event alone (one-shot parity).
        // (With a template, the gate above guarantees signatures exist.)
        let book_for_store = next.clone();
        state
            .persist_write_through(&mut ledger, 1, move |tx| {
                tx.upsert_book(&book_for_store)?;
                tx.upsert_termo_instrument(&sealed_termo)
            })
            .await?;
    } else {
        let Some(snapshot_doc) = snapshot else {
            // Signatures exist but the snapshot is gone — an inconsistent store. Fail closed rather
            // than close a book whose signed set we cannot bind; roll the `book.closed` event back.
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(ApiError::Internal(
                "the termo de encerramento is cryptographically signed but its frozen snapshot is \
                 missing; refusing to close without preserving the signed set"
                    .to_owned(),
            ));
        };
        let manifest = build_cosignature_manifest(
            "termo.encerramento.cosignatures",
            subject,
            &snapshot_doc,
            &signatures,
        );
        let payload = match serde_json::to_vec(&manifest) {
            Ok(payload) => payload,
            Err(e) => {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(e.into());
            }
        };
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
        let snapshot_for_store = snapshot_doc.clone();
        state
            .persist_write_through(&mut ledger, 2, move |tx| {
                tx.upsert_book(&book_for_store)?;
                // Re-affirm the frozen snapshot as the preserved base PDF/A (idempotent; pinned at
                // advance). NOT re-rendered — the signatures bind to exactly these bytes.
                tx.upsert_document(&snapshot_for_store)?;
                tx.upsert_termo_instrument(&sealed_termo)
            })
            .await?;
        state
            .documents
            .write()
            .await
            .insert(snapshot_doc.act_id, snapshot_doc);
    }
    state.attest_latest(&attestor, &ledger).await;

    let view = BookView::from(&next);
    if let Some(slot) = books.get_mut(&book_id) {
        *slot = next;
    }
    Ok(Json(view))
}
