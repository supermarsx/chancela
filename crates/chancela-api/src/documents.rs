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
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chancela_core::{
    Act, ActId, Book, BookKind, DocumentModel, Entity, EntityFamily, LifecycleStage,
    NumberingScheme, TermoDeAbertura,
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

/// The template bound to a family + stage, if any (v1 binds at most one per pair). Returns `None`
/// for families/stages without a template yet — the documented fallback where a seal / book-open
/// proceeds without producing a document (rather than failing the durable domain step).
fn template_for(family: EntityFamily, stage: LifecycleStage) -> Option<&'static TemplateSpec> {
    registry().find(family, stage).into_iter().next()
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
    Ok(ctx)
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

/// Generate the ata document for a freshly-sealed act, or `None` if the entity's family has no
/// Ata template yet (documented fallback). Called inside `seal_act_handler`'s Ok arm.
pub(crate) fn generate_for_act(act: &Act, entity: &Entity) -> Result<Option<Generated>, ApiError> {
    let Some(spec) = template_for(entity.family, LifecycleStage::Ata) else {
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
    let Some(spec) = template_for(family, LifecycleStage::TermoAbertura) else {
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

// --- read endpoints (§3.3) ---------------------------------------------------------------------

/// `GET /v1/acts/{id}/document/preview` — render the CURRENT record live to a [`DocumentModel`].
/// Works pre-seal for draft preview and does NOT persist. Session-gating mirrors the other reads
/// (open, like `GET /v1/acts/{id}`).
pub async fn preview_document(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DocumentModel>, ApiError> {
    // entities → books → acts (read order prefix).
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    let spec = template_for(entity.family, LifecycleStage::Ata).ok_or_else(|| {
        ApiError::Unprocessable(format!(
            "no document template for family {:?} at stage Ata",
            entity.family
        ))
    })?;
    let ctx = act_ctx(act, entity)?;
    let model = chancela_templates::render(spec, &ctx)
        .map_err(|e| ApiError::Internal(format!("template render failed: {e}")))?;
    Ok(Json(model))
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
