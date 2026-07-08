//! Document generation + read endpoints (t48 / DOC-01/03, plan §3.3/§3.4).
//!
//! This module is the api-side application service that wires the template engine
//! (`chancela-templates`) and the PDF/A-2u writer (`chancela-doc`) into the seal / book-open
//! flows and exposes the read surface. The layering guard (plan §D4): `chancela-core` never
//! depends on the PDF crate — the render→write→persist orchestration lives here, called by
//! `seal_act_handler` (ata) and `create_book` (termo de abertura) right after the domain step
//! succeeds, inside the SAME durable transaction so the document is bound into the ledger
//! (`document.generated`) and rolls back with the seal on any failure.
//!
//! **Determinism.** The render context derives `created_at` from a frozen record date (the
//! meeting date for an ata, the opening date for a termo) — never a wall clock — so a sealed
//! record + pinned template version always regenerates byte-identical PDF/A bytes and the same
//! `pdf_digest` (plan D3/§164). The stored row's own `created_at` timestamp is storage metadata
//! and does not enter the document bytes.

use std::sync::LazyLock;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chancela_core::{
    Act, ActId, Book, BookKind, Convening, DocumentModel, Entity, EntityFamily, LifecycleStage,
    NumberingScheme, TermoDeAbertura, TermoDeEncerramento,
};
use chancela_store::StoredDocument;
use chancela_templates::{Registry, TemplateSpec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::dto::{format_date, format_time};
use crate::error::ApiError;

/// The frozen PDF/A profile string bound into every `document.generated` event and stored row
/// (plan §1-D4 step 3 / §3.4). Self-describing: MIME type + PDF/A part+conformance.
pub(crate) const PDFA_PROFILE: &str = "application/pdf; profile=PDF/A-2u";

/// The embedded template registry, loaded once. The assets are compile-time-validated by
/// `chancela-templates` (build.rs embeds them; e1's tests prove the load), so a load failure is
/// a build-invariant violation, not a runtime condition — hence `expect` at first access.
static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    chancela_templates::load_registry().expect("embedded template registry loads")
});

/// The process-wide template registry (loaded once, lazily).
pub(crate) fn registry() -> &'static Registry {
    &REGISTRY
}

/// The **spine** (default) template id for a family + stage — the single deterministic template
/// auto-generated on seal (`Ata`), book-open (`TermoAbertura`), and book-close (`TermoEncerramento`).
///
/// Several `(family, stage)` pairs now carry MORE than one template (e.g. CSC `Ata` = the AG spine
/// plus ~18 subtypes; Foundation `Ata` = `{ata-ca, ata-orgao-fiscal, termo-retificacao}`). Because
/// `registry().find(..)` returns them in load (filename-sort) order, auto-generation must never call
/// `.next()` and pick one arbitrarily — this table pins the family's PRIMARY instrument per stage so
/// a seal / open / close is deterministic. Every other subtype is reachable via the
/// `GET /v1/templates` picker + the on-demand generate endpoint (`?template_id=`) and the seal
/// `template_id` override.
///
/// `None` for a `(family, stage)` with no bound spine — the documented graceful fallback where the
/// domain step proceeds without producing a document (rather than failing the durable step).
fn spine_template_id(family: EntityFamily, stage: LifecycleStage) -> Option<&'static str> {
    use EntityFamily::*;
    use LifecycleStage::*;
    Some(match (family, stage) {
        // Ata — each family's primary ata (CSC art. 63.º / condo DL 268/94 / assoc + fundação CC /
        // cooperativa Cód. Coop.). The many CSC ata subtypes + the per-organ variants are on-demand.
        (CommercialCompany, Ata) => "csc-ata-ag/v1",
        (Condominium, Ata) => "condominio-ata-assembleia/v1",
        (Association, Ata) => "assoc-ata-ga/v1",
        (Foundation, Ata) => "fundacao-ata-ca/v1",
        (Cooperative, Ata) => "cooperativa-ata-ag/v1",
        // Termo de abertura — one per family.
        (CommercialCompany, TermoAbertura) => "csc-termo-abertura/v1",
        (Condominium, TermoAbertura) => "condominio-termo-abertura/v1",
        (Association, TermoAbertura) => "assoc-termo-abertura/v1",
        (Foundation, TermoAbertura) => "fundacao-termo-abertura/v1",
        (Cooperative, TermoAbertura) => "cooperativa-termo-abertura/v1",
        // Termo de encerramento — each family's closing instrument. CSC also carries a
        // `-transporte` variant (successor-book carry-over) reachable on demand; the encerramento is
        // the spine that book-close auto-generates.
        (CommercialCompany, TermoEncerramento) => "csc-termo-encerramento/v1",
        (Condominium, TermoEncerramento) => "condominio-termo-encerramento/v1",
        (Association, TermoEncerramento) => "assoc-termo-encerramento/v1",
        (Foundation, TermoEncerramento) => "fundacao-termo-encerramento/v1",
        (Cooperative, TermoEncerramento) => "cooperativa-termo-encerramento/v1",
        _ => return None,
    })
}

/// The spine [`TemplateSpec`] for a family + stage (see [`spine_template_id`]). `None` when no spine
/// is bound (the documented document-less fallback).
fn default_spec(family: EntityFamily, stage: LifecycleStage) -> Option<&'static TemplateSpec> {
    spine_template_id(family, stage).and_then(|id| registry().get(id))
}

/// Resolve the ata template a seal should generate: an explicit `override_id` if the seal request
/// carried one — validated to be an `Ata` template of the act's own family; an **unknown or
/// mismatched** id is an error (`422`), never a silent fall-back to the spine — else the family's
/// spine ata (`None` if none bound, so the seal proceeds document-less).
fn resolve_ata_template(
    family: EntityFamily,
    override_id: Option<&str>,
) -> Result<Option<&'static TemplateSpec>, ApiError> {
    match override_id {
        Some(id) => {
            let spec = registry()
                .get(id)
                .ok_or_else(|| ApiError::Unprocessable(format!("unknown template id {id:?}")))?;
            if spec.family != family || spec.stage != LifecycleStage::Ata {
                return Err(ApiError::Unprocessable(format!(
                    "template {id:?} is not an Ata template for this entity's family"
                )));
            }
            Ok(Some(spec))
        }
        None => Ok(default_spec(family, LifecycleStage::Ata)),
    }
}

/// A generated document ready to be committed: the row to persist plus the `document.generated`
/// event payload to append. Produced outside the ledger mutation so a generation failure can
/// roll the seal / open back cleanly.
pub(crate) struct Generated {
    /// The row to `Tx::upsert_document` inside the durable commit.
    pub stored: StoredDocument,
    /// The `document.generated` event payload (`{act_id, template_id, pdf_digest, profile}`).
    pub event_payload: Value,
}

/// Render `spec` against `ctx`, write PDF/A-2u bytes, and assemble the [`Generated`] artifact
/// owned by `owner_id`. `created_at` is the stored row's metadata timestamp (not part of the
/// PDF bytes). Any render / write failure is an internal error that the caller turns into a
/// rolled-back seal.
fn generate(
    spec: &TemplateSpec,
    ctx: &Value,
    owner_id: ActId,
    created_at: OffsetDateTime,
) -> Result<Generated, ApiError> {
    let model = chancela_templates::render(spec, ctx)
        .map_err(|e| ApiError::Internal(format!("template render failed: {e}")))?;
    let bytes = chancela_doc::pdfa::write(&model)
        .map_err(|e| ApiError::Internal(format!("PDF/A generation failed: {e}")))?;

    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let pdf_digest = crate::hex::hex(&digest);

    let stored = StoredDocument {
        id: Uuid::new_v4().to_string(),
        act_id: owner_id,
        template_id: spec.id.clone(),
        pdf_digest: pdf_digest.clone(),
        profile: PDFA_PROFILE.to_string(),
        created_at,
        pdf_bytes: bytes,
    };
    let event_payload = json!({
        "act_id": owner_id.to_string(),
        "template_id": spec.id,
        "pdf_digest": pdf_digest,
        "profile": PDFA_PROFILE,
    });
    Ok(Generated {
        stored,
        event_payload,
    })
}

// --- render contexts ---------------------------------------------------------------------------

/// The reserved `entity` object every template reads (`entity.name/nipc/seat`).
fn entity_object(entity: &Entity) -> Value {
    json!({
        "name": entity.name,
        "nipc": entity.nipc.to_string(),
        "seat": entity.seat,
    })
}

/// Build the render context for an act (Ata stage): `serde_json::to_value(&act)` overlaid with
/// the reserved envelope keys the engine requires (`title`, `created_at`, `entity`). The
/// date/time fields are re-emitted as the wire strings templates expect (`YYYY-MM-DD` / `HH:MM`)
/// so the `long_date` filter and `{{ meeting_time }}` render correctly regardless of the domain
/// type's serde form. `created_at` derives from the meeting date (deterministic, no clock).
fn act_ctx(act: &Act, entity: &Entity) -> Result<Value, ApiError> {
    let mut ctx = serde_json::to_value(act)?;
    let map = ctx
        .as_object_mut()
        .ok_or_else(|| ApiError::Internal("act did not serialize to a JSON object".to_string()))?;
    map.insert(
        "meeting_date".to_string(),
        Value::String(act.meeting_date.map(format_date).unwrap_or_default()),
    );
    map.insert(
        "meeting_time".to_string(),
        Value::String(act.meeting_time.map(format_time).unwrap_or_default()),
    );
    map.insert("title".to_string(), Value::String(act.title.clone()));
    map.insert(
        "created_at".to_string(),
        act.meeting_date
            .map(format_date)
            .map_or(Value::Null, Value::String),
    );
    map.insert("entity".to_string(), entity_object(entity));
    // G1 — expose the convening/dispatch record with date/time leaves as wire strings (raw `time`
    // serde would emit `time::Time` as `HH:MM:SS.sub`; templates bind `{{ convening.second_call.time }}`
    // and `{{ ... | long_date }}`). Only overwrite when present; an act without a convening keeps the
    // serde `null` (the convocatória/ata recitals that read it are all `{% if convening.* %}`-guarded).
    if let Some(convening) = &act.convening {
        map.insert("convening".to_string(), convening_object(convening));
    }
    // Re-emit the seal digest as the contract's lowercase hex (raw serde would emit a `[u8; 32]`
    // integer array) so the certidão / extrato templates recite `{{ payload_digest }}` correctly.
    // `null` for an unsealed act (harmless: the ata spine templates never read it). G2 `attendees[]`
    // needs no reshaping — it carries no date fields, so the derived serde shape (`quality`/`presence`
    // as bare names, `weight.Permilage` tagged) is exactly what the lista/ata templates bind.
    map.insert(
        "payload_digest".to_string(),
        act.payload_digest
            .as_ref()
            .map(crate::hex::hex)
            .map_or(Value::Null, Value::String),
    );
    Ok(ctx)
}

/// Reshape an [`Act`]'s [`Convening`] record (G1) into the render context the convocatória / ata
/// templates bind (plan §1e): `convening.{convener, convener_capacity, dispatch_date,
/// antecedence_days, channel, recipients[].{name, channel, reference, dispatched_at}, second_call.
/// {date, time, reduced_quorum}}`. Enum leaves keep their bare serde names (so `convener_capacity |
/// role_label` and `channel` resolve); date/time leaves become the formatted wire strings.
fn convening_object(c: &Convening) -> Value {
    // Start from the derived serde shape (Options → `null`, enums → bare names), then overwrite the
    // date/time leaves — `time` serde has no wire-string contract the templates expect.
    let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "dispatch_date".to_string(),
            c.dispatch_date
                .map(format_date)
                .map_or(Value::Null, Value::String),
        );
        if let Some(sc) = &c.second_call {
            obj.insert(
                "second_call".to_string(),
                json!({
                    "date": sc.date.map(format_date).map_or(Value::Null, Value::String),
                    "time": sc.time.map(format_time).map_or(Value::Null, Value::String),
                    "reduced_quorum": sc.reduced_quorum,
                }),
            );
        }
        if let Some(recipients) = obj.get_mut("recipients").and_then(Value::as_array_mut) {
            for (slot, recipient) in recipients.iter_mut().zip(c.recipients.iter()) {
                if let Some(ro) = slot.as_object_mut() {
                    ro.insert(
                        "dispatched_at".to_string(),
                        recipient
                            .dispatched_at
                            .map(format_date)
                            .map_or(Value::Null, Value::String),
                    );
                }
            }
        }
    }
    v
}

/// Build the render context for a termo de abertura (book-opening instrument). The termo carries
/// its own entity snapshot; `book.kind` names the organ. `required_signatories` are reshaped into
/// signature slots (`{role, name}`) so the `SignatureBlock` template binds one blank-name line per
/// required signatory. `created_at` derives from the opening date (deterministic, no clock).
fn termo_ctx(termo: &TermoDeAbertura, book: &Book) -> Value {
    let signatories: Vec<Value> = termo
        .required_signatories
        .iter()
        .map(|role| json!({ "role": role, "name": "" }))
        .collect();
    json!({
        "title": "Termo de abertura do livro de atas",
        "created_at": format_date(termo.opening_date),
        "entity": {
            "name": termo.entity_name,
            "nipc": termo.entity_nipc,
            "seat": termo.entity_seat,
        },
        "book": { "kind": book_kind_label(book.kind) },
        "purpose": termo.purpose,
        "numbering_scheme": format!("{:?}", termo.numbering_scheme),
        "numbering_label": numbering_label(termo.numbering_scheme),
        "opening_date": format_date(termo.opening_date),
        "required_signatories": signatories,
    })
}

fn book_kind_label(kind: BookKind) -> &'static str {
    match kind {
        BookKind::AssembleiaGeral => "Assembleia geral",
        BookKind::GerenciaAdministracao => "Gerência / administração",
        BookKind::ConselhoFiscal => "Conselho fiscal",
        BookKind::Condominio => "Condomínio",
    }
}

fn numbering_label(scheme: NumberingScheme) -> &'static str {
    match scheme {
        NumberingScheme::Sequential => "Numeração sequencial",
        NumberingScheme::LooseLeaf => "Folhas soltas (numeração e encadeamento de páginas)",
    }
}

// --- generation entry points (called by the seal / book-open handlers) -------------------------

/// Generate the ata document for a freshly-sealed act, or `None` if the entity's family has no Ata
/// spine template (documented fallback). `template_override` is the optional act-carried
/// `template_id` (a specific ata subtype the user picked); an unknown/mismatched override is an
/// error (never a silent spine fall-back). Called inside `seal_act_handler`'s Ok arm.
pub(crate) fn generate_for_act(
    act: &Act,
    entity: &Entity,
    template_override: Option<&str>,
) -> Result<Option<Generated>, ApiError> {
    let Some(spec) = resolve_ata_template(entity.family, template_override)? else {
        return Ok(None);
    };
    let ctx = act_ctx(act, entity)?;
    Ok(Some(generate(
        spec,
        &ctx,
        act.id,
        OffsetDateTime::now_utc(),
    )?))
}

/// Generate the termo de abertura document for a freshly-opened book, or `None` if `family` has
/// no TermoAbertura template yet. Book instruments have no owning act, so the row is keyed by the
/// book id cast into an [`ActId`] (the `documents.act_id` scope column; the ids never collide).
pub(crate) fn generate_for_termo(
    termo: &TermoDeAbertura,
    book: &Book,
    family: EntityFamily,
) -> Result<Option<Generated>, ApiError> {
    let Some(spec) = default_spec(family, LifecycleStage::TermoAbertura) else {
        return Ok(None);
    };
    let ctx = termo_ctx(termo, book);
    let owner = ActId(book.id.0);
    Ok(Some(generate(
        spec,
        &ctx,
        owner,
        OffsetDateTime::now_utc(),
    )?))
}

/// Build the render context for a termo de encerramento (book-closing instrument). Unlike the
/// abertura, the encerramento carries no entity snapshot, so the entity is supplied separately;
/// `book.kind` names the organ, `reason` keeps its bare `ClosingReason` name (templates map it to
/// PT), and `required_signatories` become blank-name signature slots. `created_at` derives from the
/// closing date (deterministic, no clock).
fn encerramento_ctx(termo: &TermoDeEncerramento, book: &Book, entity: &Entity) -> Value {
    let signatories: Vec<Value> = termo
        .required_signatories
        .iter()
        .map(|role| json!({ "role": role, "name": "" }))
        .collect();
    json!({
        "title": "Termo de encerramento do livro de atas",
        "created_at": format_date(termo.closing_date),
        "entity": entity_object(entity),
        "book": { "kind": book_kind_label(book.kind) },
        "ata_count": termo.ata_count,
        "reason": serde_json::to_value(&termo.reason).unwrap_or(Value::Null),
        "closing_date": format_date(termo.closing_date),
        "required_signatories": signatories,
    })
}

/// Generate the termo de encerramento document for a freshly-closed book, or `None` if `entity`'s
/// family has no encerramento spine template yet. Keyed (like the abertura) by the book id cast into
/// an [`ActId`]. Called inside `close_book`'s durable commit (mirrors the book-open abertura path).
pub(crate) fn generate_for_encerramento(
    termo: &TermoDeEncerramento,
    book: &Book,
    entity: &Entity,
) -> Result<Option<Generated>, ApiError> {
    let Some(spec) = default_spec(entity.family, LifecycleStage::TermoEncerramento) else {
        return Ok(None);
    };
    let ctx = encerramento_ctx(termo, book, entity);
    let owner = ActId(book.id.0);
    Ok(Some(generate(
        spec,
        &ctx,
        owner,
        OffsetDateTime::now_utc(),
    )?))
}

// --- read endpoints (§3.3) ---------------------------------------------------------------------

/// Query for `GET /v1/acts/{id}/document/preview` — an optional `template_id` to preview a chosen
/// catalog template (a subtype / non-seal instrument) instead of the family's ata spine default.
#[derive(Deserialize)]
pub struct PreviewQuery {
    pub template_id: Option<String>,
}

/// `GET /v1/acts/{id}/document/preview[?template_id=]` — render the CURRENT record live to a
/// [`DocumentModel`]. Without `template_id`, previews the family's **spine** ata template (a
/// deterministic default, never an arbitrary subtype); with it, previews the named template (`404`
/// if unknown). Works pre-seal for draft preview and does NOT persist. Session-gating mirrors the
/// other reads (open, like `GET /v1/acts/{id}`).
pub async fn preview_document(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<PreviewQuery>,
) -> Result<Json<DocumentModel>, ApiError> {
    // entities → books → acts (read order prefix).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    let spec = match &q.template_id {
        Some(tid) => registry().get(tid).ok_or(ApiError::NotFound)?,
        None => default_spec(entity.family, LifecycleStage::Ata).ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "no document template for family {:?} at stage Ata",
                entity.family
            ))
        })?,
    };
    let ctx = act_render_ctx(act, book, entity)?;
    let model = chancela_templates::render(spec, &ctx)
        .map_err(|e| ApiError::Internal(format!("template render failed: {e}")))?;
    Ok(Json(model))
}

/// The full act render context for non-seal templates: [`act_ctx`] overlaid with the `book` object
/// (`book.kind`, `book.predecessor`) that the certidão / extrato / transporte instruments recite.
/// The ata spine templates ignore `book`, so this is a strict superset safe for every stage.
fn act_render_ctx(act: &Act, book: &Book, entity: &Entity) -> Result<Value, ApiError> {
    let mut ctx = act_ctx(act, entity)?;
    if let Some(obj) = ctx.as_object_mut() {
        obj.insert(
            "book".to_string(),
            json!({
                "kind": book_kind_label(book.kind),
                "predecessor": book
                    .predecessor
                    .map(|p| p.to_string())
                    .map_or(Value::Null, Value::String),
            }),
        );
    }
    Ok(ctx)
}

/// Query for `POST /v1/acts/{id}/document/generate` — the catalog template id to render + persist.
#[derive(Deserialize)]
pub struct GenerateQuery {
    pub template_id: String,
}

/// The metadata the on-demand generate endpoint returns after persisting a document.
#[derive(Serialize)]
pub struct GeneratedDocumentView {
    pub id: String,
    pub act_id: String,
    pub template_id: String,
    pub pdf_digest: String,
    pub profile: String,
    pub download: String,
}

/// `POST /v1/acts/{id}/document/generate?template_id=<id>` — render a CHOSEN catalog template
/// against the act's current record and **persist** it (a new `documents` row + a
/// `document.generated` event in one durable commit), so the non-seal catalog (convocatórias,
/// certidões, extratos, comunicações, ata subtypes) is usable, not only the seal-time ata. Reuses
/// the seal-hook's render→PDF/A→persist→event pipeline. Session-gated like other mutations.
///
/// `404` on an unknown act or template id; `422` when the template belongs to another family, or a
/// certidão / extrato is requested against an act that is not yet sealed (those instruments certify a
/// sealed ata — refused honestly rather than certifying a draft).
pub async fn generate_document(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Query(q): Query<GenerateQuery>,
) -> Result<Response, ApiError> {
    let actor = actor.resolve("api");
    // Unknown template id → 404 before touching any lock.
    let spec = registry().get(&q.template_id).ok_or(ApiError::NotFound)?;

    // entities → books → acts → ledger. The act itself is not mutated, but the document row + event
    // are committed atomically, so the ledger write lock is taken after the read prefix.
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    if spec.family != entity.family {
        return Err(ApiError::Unprocessable(format!(
            "template {:?} is for family {:?}, not this entity's family {:?}",
            spec.id, spec.family, entity.family
        )));
    }
    // Certidão / extrato certify a SEALED ata — refuse honestly against an unsealed draft.
    let certifies_a_seal = matches!(
        spec.stage,
        LifecycleStage::Certidao | LifecycleStage::Extrato
    );
    if certifies_a_seal && act.ata_number.is_none() {
        return Err(ApiError::Unprocessable(format!(
            "template {:?} certifies a sealed ata, but this act is not sealed",
            spec.id
        )));
    }

    let ctx = act_render_ctx(act, book, entity)?;
    // Render + write PDF/A before appending anything to the ledger, so a render/write failure returns
    // cleanly with no ledger mutation to roll back.
    let made = generate(spec, &ctx, act.id, OffsetDateTime::now_utc())?;

    let mut ledger = state.ledger.write().await;
    let scope = format!("entity:{}/book:{}/act:{}", entity.id, act.book_id, act.id);
    let payload = serde_json::to_vec(&made.event_payload)?;
    ledger.append(&actor, &scope, "document.generated", None, &payload);
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_document(&made.stored))?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    // Publish to the live document read model (GET source; the store is durability).
    state
        .documents
        .write()
        .await
        .insert(made.stored.act_id, made.stored.clone());

    let view = GeneratedDocumentView {
        id: made.stored.id,
        act_id: made.stored.act_id.to_string(),
        template_id: made.stored.template_id,
        pdf_digest: made.stored.pdf_digest,
        profile: made.stored.profile,
        download: format!("/v1/acts/{id}/document"),
    };
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// `GET /v1/acts/{id}/document` — the persisted PDF/A bytes (`application/pdf`); `404` until the
/// act is sealed (no document persisted yet).
pub async fn get_document_pdf(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let doc = load_document(&state, ActId(id))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/pdf")], doc.pdf_bytes).into_response())
}

/// Fetch the persisted document for an act, preferring the live in-memory read model and falling
/// back to the durable store (so a document survives a restart even before its map is rehydrated).
async fn load_document(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<StoredDocument>, ApiError> {
    if let Some(doc) = state.documents.read().await.get(&act_id).cloned() {
        return Ok(Some(doc));
    }
    if let Some(store) = &state.store {
        return store
            .document_for_act(act_id)
            .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")));
    }
    Ok(None)
}

/// The DOC-03 preservation bundle for a sealed document: the PDF reference, structured metadata,
/// and the attachments manifest. The **validation-report slot is RESERVED for Wave D** (PAdES
/// signing) — it is always `null` in v1, populated once the signing stack validates the sealed PDF
/// (plan §5.4 / §6).
#[derive(Serialize)]
pub struct DocumentBundle {
    pub act_id: String,
    pub document: BundleDocumentMeta,
    pub pdf: BundlePdfRef,
    pub attachments_manifest: Vec<BundleAttachment>,
    /// RESERVED for Wave D: the PAdES signature validation report. Always `null` in v1.
    pub validation_report: Option<Value>,
}

#[derive(Serialize)]
pub struct BundleDocumentMeta {
    pub id: String,
    pub template_id: String,
    pub pdf_digest: String,
    pub profile: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct BundlePdfRef {
    pub media_type: &'static str,
    pub byte_length: usize,
    pub download: String,
}

#[derive(Serialize)]
pub struct BundleAttachment {
    pub label: String,
    pub kind: chancela_core::AttachmentKind,
    pub digest: Option<String>,
    pub beginning_of_proof: bool,
}

/// `GET /v1/acts/{id}/document/bundle` — the DOC-03 preservation bundle (PDF ref + metadata +
/// attachments manifest + reserved validation-report slot). `404` until sealed.
pub async fn get_document_bundle(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DocumentBundle>, ApiError> {
    let act_id = ActId(id);
    let doc = load_document(&state, act_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Attachments manifest from the owning act (absent for a book instrument → empty manifest).
    let attachments_manifest = {
        let acts = state.acts.read().await;
        acts.get(&act_id)
            .map(|a| {
                a.attachments
                    .iter()
                    .map(|att| BundleAttachment {
                        label: att.label.clone(),
                        kind: att.kind,
                        digest: att.digest.as_ref().map(crate::hex::hex),
                        beginning_of_proof: att.beginning_of_proof,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(Json(DocumentBundle {
        act_id: act_id.to_string(),
        document: BundleDocumentMeta {
            id: doc.id.clone(),
            template_id: doc.template_id.clone(),
            pdf_digest: doc.pdf_digest.clone(),
            profile: doc.profile.clone(),
            created_at: doc.created_at.format(&Rfc3339).unwrap_or_default(),
        },
        pdf: BundlePdfRef {
            media_type: "application/pdf",
            byte_length: doc.pdf_bytes.len(),
            download: format!("/v1/acts/{id}/document"),
        },
        attachments_manifest,
        validation_report: None,
    }))
}

/// Query for `GET /v1/templates` — both filters optional (bare core enum names).
#[derive(Deserialize)]
pub struct TemplatesQuery {
    pub family: Option<EntityFamily>,
    pub stage: Option<LifecycleStage>,
}

/// A template summary for the picker (`GET /v1/templates`).
#[derive(Serialize)]
pub struct TemplateSummary {
    pub id: String,
    pub family: EntityFamily,
    pub stage: LifecycleStage,
    pub locale: String,
}

impl From<&TemplateSpec> for TemplateSummary {
    fn from(s: &TemplateSpec) -> Self {
        TemplateSummary {
            id: s.id.clone(),
            family: s.family,
            stage: s.stage,
            locale: s.locale.clone(),
        }
    }
}

/// `GET /v1/templates?family=&stage=` — available template summaries (id/family/stage/locale) for
/// the picker. Both filters optional.
pub async fn list_templates(Query(q): Query<TemplatesQuery>) -> Json<Vec<TemplateSummary>> {
    let reg = registry();
    let summaries: Vec<TemplateSummary> = match (q.family, q.stage) {
        (Some(family), Some(stage)) => reg
            .find(family, stage)
            .into_iter()
            .map(TemplateSummary::from)
            .collect(),
        _ => reg
            .specs()
            .iter()
            .filter(|s| q.family.is_none_or(|f| s.family == f))
            .filter(|s| q.stage.is_none_or(|st| s.stage == st))
            .map(TemplateSummary::from)
            .collect(),
    };
    Json(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_core::book::ClosingReason;
    use chancela_core::{
        AttendanceWeight, Attendee, Book, BookKind, Convening, DispatchChannel, Entity, EntityKind,
        MeetingChannel, Nipc, PresenceMode, SecondCall, SignatoryCapacity,
    };

    fn nipc() -> Nipc {
        Nipc::parse("503004642").expect("valid NIPC")
    }

    /// Fictional example entity/people only (never "Vogue Homes"/"Mariana").
    fn entity_of(kind: EntityKind) -> Entity {
        Entity::new(
            "Encosto Estratégico Lda",
            nipc(),
            "Rua das Amoreiras, n.º 12, 1250-020 Lisboa",
            kind,
        )
    }

    // --- G1/G2 render-ctx exposure -------------------------------------------------------------

    #[test]
    fn act_ctx_exposes_convening_and_attendees_and_the_spine_ata_binds_them() {
        let entity = entity_of(EntityKind::Condominio);
        let book = Book::new(entity.id, BookKind::Condominio);
        let mut act = Act::draft(
            book.id,
            "Ata da assembleia de condóminos",
            MeetingChannel::Physical,
        );
        act.members_present = Some(2);
        // G2 — structured attendance rows (one in person with permilage, one represented).
        act.attendees = vec![
            Attendee {
                name: "Amélia Marques".to_string(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(250)),
            },
            Attendee {
                name: "Bruno Cardoso".to_string(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Represented,
                represented_by: Some("Amélia Marques".to_string()),
                weight: Some(AttendanceWeight::Permilage(180)),
            },
        ];
        // G1 — convening record with a reduced-quorum second call.
        act.convening = Some(Convening {
            convener: Some("Amélia Marques".to_string()),
            convener_capacity: Some(SignatoryCapacity::CondoOwner),
            dispatch_date: None,
            antecedence_days: Some(15),
            channel: Some(DispatchChannel::RegisteredLetter),
            recipients: vec![],
            second_call: Some(SecondCall {
                date: None,
                time: None,
                reduced_quorum: true,
            }),
        });

        let ctx = act_ctx(&act, &entity).expect("ctx builds");
        // Frozen field paths (plan §1e) resolve.
        assert_eq!(ctx["convening"]["antecedence_days"], 15);
        assert_eq!(ctx["convening"]["convener"], "Amélia Marques");
        assert_eq!(ctx["convening"]["second_call"]["reduced_quorum"], true);
        assert_eq!(ctx["attendees"][0]["name"], "Amélia Marques");
        assert_eq!(ctx["attendees"][0]["presence"], "InPerson");
        assert_eq!(ctx["attendees"][0]["weight"]["Permilage"], 250);
        assert_eq!(ctx["attendees"][1]["represented_by"], "Amélia Marques");
        // Reserved envelope keys still populate.
        assert_eq!(ctx["entity"]["name"], "Encosto Estratégico Lda");
        assert_eq!(ctx["title"], "Ata da assembleia de condóminos");

        // The condominium spine ata actually binds the G1/G2 ctx.
        let spec =
            default_spec(EntityFamily::Condominium, LifecycleStage::Ata).expect("condo spine");
        let doc = chancela_templates::render(spec, &ctx).expect("renders");
        let text = serde_json::to_string(&doc).expect("doc serializes");
        assert!(text.contains("Amélia Marques"), "attendee lista rendered");
        assert!(
            text.contains("permilagem 250"),
            "permilage rendered: {text}"
        );
        assert!(
            text.contains("segunda convoca"),
            "reduced-quorum second-call recital rendered"
        );
    }

    // --- deterministic default mapping + override ----------------------------------------------

    #[test]
    fn spine_defaults_are_deterministic_for_every_family() {
        for (family, id) in [
            (EntityFamily::CommercialCompany, "csc-ata-ag/v1"),
            (EntityFamily::Condominium, "condominio-ata-assembleia/v1"),
            (EntityFamily::Association, "assoc-ata-ga/v1"),
            (EntityFamily::Foundation, "fundacao-ata-ca/v1"),
            (EntityFamily::Cooperative, "cooperativa-ata-ag/v1"),
        ] {
            let spec = default_spec(family, LifecycleStage::Ata).expect("ata spine bound");
            assert_eq!(spec.id, id, "{family:?} ata spine");
            // Every family also has a bound abertura + encerramento spine.
            assert!(default_spec(family, LifecycleStage::TermoAbertura).is_some());
            assert!(default_spec(family, LifecycleStage::TermoEncerramento).is_some());
        }
    }

    #[test]
    fn every_family_ata_seal_generates_its_spine_document() {
        for (kind, id) in [
            (EntityKind::SociedadeAnonima, "csc-ata-ag/v1"),
            (EntityKind::Condominio, "condominio-ata-assembleia/v1"),
            (EntityKind::Associacao, "assoc-ata-ga/v1"),
            (EntityKind::Fundacao, "fundacao-ata-ca/v1"),
            (EntityKind::Cooperativa, "cooperativa-ata-ag/v1"),
        ] {
            let entity = entity_of(kind);
            let book = Book::new(entity.id, BookKind::AssembleiaGeral);
            let act = Act::draft(book.id, "Ata", MeetingChannel::Physical);
            let generated = generate_for_act(&act, &entity, None)
                .expect("generation ok")
                .expect("a spine document");
            assert_eq!(generated.stored.template_id, id, "{kind:?} spine");
            assert!(generated.stored.pdf_bytes.starts_with(b"%PDF-"));
        }
    }

    #[test]
    fn override_selects_the_named_subtype_and_unknown_or_mismatched_errors() {
        // A real CSC ata subtype override is honoured verbatim.
        let spec = resolve_ata_template(
            EntityFamily::CommercialCompany,
            Some("csc-ata-aprovacao-contas/v1"),
        )
        .expect("resolves")
        .expect("some spec");
        assert_eq!(spec.id, "csc-ata-aprovacao-contas/v1");

        // No override → the deterministic spine.
        let spine = resolve_ata_template(EntityFamily::CommercialCompany, None)
            .expect("resolves")
            .expect("spine");
        assert_eq!(spine.id, "csc-ata-ag/v1");

        // An unknown id is an error — never a silent spine fall-back.
        assert!(
            resolve_ata_template(EntityFamily::CommercialCompany, Some("nao-existe/v9")).is_err(),
            "unknown override must error"
        );
        // A real template of the wrong stage errors too (a termo is not an ata).
        assert!(
            resolve_ata_template(
                EntityFamily::CommercialCompany,
                Some("csc-termo-abertura/v1")
            )
            .is_err(),
            "non-Ata override must error"
        );
        // A real ata of another family errors (cross-family).
        assert!(
            resolve_ata_template(EntityFamily::CommercialCompany, Some("assoc-ata-ga/v1")).is_err(),
            "cross-family override must error"
        );
    }

    // --- book-close encerramento ctx -----------------------------------------------------------

    #[test]
    fn encerramento_generation_binds_the_family_termo() {
        let entity = entity_of(EntityKind::Condominio);
        let book = Book::new(entity.id, BookKind::Condominio);
        let termo = TermoDeEncerramento {
            ata_count: 7,
            reason: ClosingReason::BookFull,
            closing_date: time::Date::from_calendar_date(2026, time::Month::December, 31)
                .expect("valid date"),
            required_signatories: vec!["Administrador do condomínio".to_string()],
        };
        let generated = generate_for_encerramento(&termo, &book, &entity)
            .expect("generation ok")
            .expect("a termo document");
        assert_eq!(
            generated.stored.template_id,
            "condominio-termo-encerramento/v1"
        );
        assert!(generated.stored.pdf_bytes.starts_with(b"%PDF-"));
        // Keyed by the book id cast into an ActId (book instruments have no owning act).
        assert_eq!(generated.stored.act_id, ActId(book.id.0));
    }
}
