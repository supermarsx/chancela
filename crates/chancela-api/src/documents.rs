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

use std::io::{Cursor, Write};
use std::path::Component;
use std::sync::LazyLock;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_core::{
    Act, ActId, Block, Book, BookKind, Convening, DocumentModel, Entity, EntityFamily,
    LifecycleStage, MeetingChannel, NumberingScheme, Run, SignaturePolicyHint, TermoDeAbertura,
    TermoDeEncerramento,
};
use chancela_store::{
    StoredDocument, StoredImportedDocument, StoredImportedDocumentMeta,
    StoredImportedDocumentReviewStatus, StoredSignedDocument,
};
use chancela_templates::{Registry, TemplateLawReference, TemplateSpec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use chancela_authz::{Permission, Scope};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act};
use crate::dto::{ReadRedaction, format_date, format_time, read_redaction_for_actor};
use crate::error::ApiError;

/// The frozen PDF/A profile string bound into every `document.generated` event and stored row
/// (plan §1-D4 step 3 / §3.4). Self-describing: MIME type + PDF/A part+conformance.
pub(crate) const PDFA_PROFILE: &str = "application/pdf; profile=PDF/A-2u";

/// Decoded candidate byte cap for the first read-only document import validation slice.
pub(crate) const DOCUMENT_IMPORT_VALIDATION_MAX_BYTES: usize = 16 * 1024 * 1024;

/// HTTP envelope cap: enough for the raw candidate limit plus JSON/base64 overhead.
pub(crate) const DOCUMENT_IMPORT_VALIDATION_ENVELOPE_BYTES: usize =
    DOCUMENT_IMPORT_VALIDATION_MAX_BYTES * 4 / 3 + 64 * 1024;

const OLE_CFB_MAGIC: &[u8; 8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1A\n";
const JPEG_MAGIC: &[u8; 3] = b"\xFF\xD8\xFF";
const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_MAGIC: &[u8; 22] =
    b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const ZIP_SPANNED_MAGIC: &[u8; 4] = b"PK\x07\x08";
const ZIP_UNCOMPRESSED_WARNING_BYTES: u64 = 256 * 1024 * 1024;

const NON_CANONICAL_EVIDENCE_WARNING: &str = "Imported bytes are preserved only as \
non-canonical evidence; no legal conversion, PDF/A conformance, signature validity, or canonical \
record replacement is claimed.";

const DOCUMENT_IMPORT_VALIDATION_NOTICE: &str = "This report is a structural import screen only; \
it is not proof of legal validity, PDF/A conformance, or signature validity.";

const DOCUMENT_IMPORTED_NOTICE: &str = "Imported document preserved as non-canonical evidence only; \
it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or \
signature validity is claimed.";

const IMPORTED_DOCUMENT_REVIEW_NOTICE: &str = "Operator review records a preservation workflow \
decision only; it does not run OCR, convert bytes, replace the canonical PDF/A, or claim legal \
acceptance.";

const IMPORTED_DOCUMENT_REVIEW_GUARDRAIL_CHECKLIST: &[&str] = &[
    "preserved_original_bytes_remain_non_canonical_evidence",
    "canonical_pdfa_record_is_not_replaced",
    "signed_pdf_artifact_is_not_created_or_validated",
    "ocr_or_conversion_output_is_not_promoted_to_canonical_records",
];

const DOCUMENT_BUNDLE_VALIDATION_NOTICE: &str = "Technical bundle evidence report only; it does \
not certify legal validity, PDF/A conformance, PDF/UA conformance, qualified-signature status, \
DGLAB certification, or production long-term validation.";
const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND: &str = "external_validator_report_metadata";
const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA: &str =
    "chancela-external-validator-report-evidence/v1";
const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX: &str = "evidence/external-validators/";
const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN: &str =
    "evidence/external-validators/{case_id}-{validator_family}.json";
const TECHNICAL_METADATA_ONLY: &str = "technical_metadata_only";

const MAX_IMPORTED_DOCUMENT_REVIEW_NOTE_CHARS: usize = 2_000;

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

/// JSON envelope accepted by `POST /v1/documents/import/validate`.
#[derive(Deserialize)]
struct DocumentImportValidationRequest {
    #[serde(alias = "bytes_base64", alias = "data_base64", alias = "base64")]
    content_base64: String,
    content_type: Option<String>,
    filename: Option<String>,
    act_id: Option<Uuid>,
    #[serde(alias = "sha256", alias = "digest_sha256")]
    declared_sha256: Option<String>,
    #[serde(alias = "size_bytes")]
    declared_size_bytes: Option<usize>,
}

struct DocumentValidationCandidate {
    bytes: Vec<u8>,
    declared_content_type: Option<String>,
    filename: Option<String>,
    act_id: Option<Uuid>,
    declared_sha256: Option<String>,
    declared_size_bytes: Option<usize>,
}

/// Structured, non-mutating report for a candidate document import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentImportValidationReport {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    pub filename: Option<String>,
    pub size_bytes: usize,
    pub sha256: String,
    pub fixity: DocumentFixityReport,
    pub content_type: DocumentContentTypeReport,
    pub classification: DocumentEvidenceClassificationReport,
    pub preservation_policy: DocumentPreservationPolicyReport,
    pub pdf: PdfRecognitionReport,
    pub legacy_word: LegacyWordDocRecognitionReport,
    pub image: ImageRecognitionReport,
    pub text: TextDocumentRecognitionReport,
    pub zip_bundle: ZipBundleRecognitionReport,
    pub signature: SignedPdfSignalReport,
    pub can_accept_non_canonical_import: bool,
    pub findings: Vec<DocumentValidationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentFixityReport {
    pub size_bytes: usize,
    pub sha256: String,
    pub declared_size_bytes: Option<usize>,
    pub declared_sha256: Option<String>,
    pub size_matches_declared: Option<bool>,
    pub sha256_matches_declared: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentContentTypeReport {
    pub declared: Option<String>,
    pub detected: &'static str,
    pub declared_matches_detected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentEvidenceClassificationReport {
    pub family: &'static str,
    pub classification: &'static str,
    pub non_canonical: bool,
    pub warning: &'static str,
    pub canonical_conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub legal_validity_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentPreservationPolicyReport {
    pub review_state: &'static str,
    pub requires_operator_review: bool,
    pub requires_ocr_review: bool,
    pub canonical_record_status: &'static str,
    pub signed_artifact_status: &'static str,
    pub review_guardrail_checklist: Vec<&'static str>,
    pub canonical_conversion_status: &'static str,
    pub original_bytes_preservation_status: &'static str,
    pub preservation_action: &'static str,
    pub canonical_conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub legal_acceptance_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfRecognitionReport {
    pub is_pdf: bool,
    pub header_offset: Option<usize>,
    pub version: Option<String>,
    pub has_eof_marker: bool,
    pub has_startxref: bool,
    pub pdfa: PdfARecognitionReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfARecognitionReport {
    pub is_pdfa_ish: bool,
    pub part: Option<String>,
    pub conformance: Option<String>,
    pub part_values: Vec<String>,
    pub conformance_values: Vec<String>,
    pub duplicate_metadata: bool,
    pub odd_metadata: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyWordDocRecognitionReport {
    pub is_ole_cfb: bool,
    pub is_legacy_word_doc: bool,
    pub filename_extension_doc: bool,
    pub declared_content_type_msword: bool,
    pub declared_content_type_generic: bool,
    pub filename_extension_conflict: bool,
    pub declared_content_type_conflict: bool,
    pub macro_execution_performed: bool,
    pub conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageRecognitionReport {
    pub is_image: bool,
    pub format: Option<&'static str>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub declared_content_type_image: bool,
    pub filename_extension_image: bool,
    pub conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TextDocumentRecognitionReport {
    pub is_supported_text: bool,
    pub kind: Option<&'static str>,
    pub utf8_valid: bool,
    pub has_nul: bool,
    pub declared_content_type_text: bool,
    pub filename_extension_text: bool,
    pub structure_validation_performed: bool,
    pub conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZipBundleRecognitionReport {
    pub is_zip: bool,
    pub readable: bool,
    pub entry_count: usize,
    pub unsafe_entry_count: usize,
    pub unsafe_entry_names: Vec<String>,
    pub total_uncompressed_size: Option<u64>,
    pub extraction_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedPdfSignalReport {
    pub validation_status: &'static str,
    pub signed_pdf_signal: bool,
    pub has_signature_dictionary_marker: bool,
    pub signature_marker_count: usize,
    pub has_byte_range: bool,
    pub byte_range_marker_count: usize,
    pub byte_range: Option<[i64; 4]>,
    pub byte_range_complete: Option<bool>,
    pub byte_range_digest_sha256: Option<String>,
    pub signed_revision_bytes: Option<usize>,
    pub covered_bytes: Option<usize>,
    pub excluded_bytes: Option<usize>,
    pub has_contents_marker: bool,
    pub cryptographic_validation_performed: bool,
    pub pades_profile: Option<&'static str>,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentValidationFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl DocumentValidationFinding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "error",
            code,
            message: message.into(),
        }
    }

    fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "warning",
            code,
            message: message.into(),
        }
    }

    fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "info",
            code,
            message: message.into(),
        }
    }
}

/// `POST /v1/documents/import/validate` - read-only structural validation for a candidate
/// document import. Accepts raw bytes or a JSON/base64 envelope and never mutates the ledger,
/// preserved documents, or signed-document store.
pub async fn validate_document_import(
    State(state): State<AppState>,
    actor: CurrentActor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DocumentImportValidationReport>, ApiError> {
    // This is an inspection endpoint, not a write/import. Gate it like global document/catalog reads.
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    let candidate = document_validation_candidate_from_request(&headers, &body)?;
    Ok(Json(validate_document_candidate_with_fixity(
        &candidate.bytes,
        candidate.declared_content_type.as_deref(),
        candidate.filename,
        candidate.declared_sha256,
        candidate.declared_size_bytes,
    )))
}

fn document_validation_candidate_from_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<DocumentValidationCandidate, ApiError> {
    let request_content_type = header_content_type(headers);
    let is_json = request_content_type
        .as_deref()
        .map(content_type_base)
        .is_some_and(|ct| ct == "application/json");

    if is_json {
        let req: DocumentImportValidationRequest = serde_json::from_slice(body).map_err(|e| {
            ApiError::Unprocessable(format!("invalid document validation JSON envelope: {e}"))
        })?;
        let bytes = B64.decode(req.content_base64.trim()).map_err(|e| {
            ApiError::Unprocessable(format!("invalid base64 document content: {e}"))
        })?;
        return Ok(DocumentValidationCandidate {
            bytes,
            declared_content_type: non_empty(req.content_type),
            filename: non_empty(req.filename),
            act_id: req.act_id,
            declared_sha256: normalize_sha256(req.declared_sha256)?,
            declared_size_bytes: req.declared_size_bytes,
        });
    }

    Ok(DocumentValidationCandidate {
        bytes: body.to_vec(),
        declared_content_type: request_content_type,
        filename: None,
        act_id: None,
        declared_sha256: None,
        declared_size_bytes: None,
    })
}

#[cfg(test)]
fn validate_document_candidate(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<String>,
) -> DocumentImportValidationReport {
    validate_document_candidate_with_fixity(bytes, declared_content_type, filename, None, None)
}

fn validate_document_candidate_with_fixity(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<String>,
    declared_sha256: Option<String>,
    declared_size_bytes: Option<usize>,
) -> DocumentImportValidationReport {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let sha256 = crate::hex::hex(&digest);
    let fixity = DocumentFixityReport {
        size_bytes: bytes.len(),
        sha256: sha256.clone(),
        declared_size_bytes,
        declared_sha256: declared_sha256.clone(),
        size_matches_declared: declared_size_bytes.map(|declared| declared == bytes.len()),
        sha256_matches_declared: declared_sha256
            .as_deref()
            .map(|declared| declared.eq_ignore_ascii_case(&sha256)),
    };

    let pdf = recognize_pdf(bytes);
    let declared = declared_content_type.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    });
    let legacy_word = recognize_legacy_word_doc(bytes, declared.as_deref(), filename.as_deref());
    let image = recognize_image(bytes, declared.as_deref(), filename.as_deref());
    let text = recognize_text_document(bytes, declared.as_deref(), filename.as_deref());
    let zip_bundle = recognize_zip_bundle(bytes);
    let detected_content_type =
        detect_candidate_content_type(bytes, pdf.is_pdf, &legacy_word, &image, &text, &zip_bundle);
    let declared_matches_detected = declared
        .as_deref()
        .map(|value| content_type_base(value) == detected_content_type);

    let content_type = DocumentContentTypeReport {
        declared,
        detected: detected_content_type,
        declared_matches_detected,
    };
    let classification = document_evidence_classification(content_type.detected);
    let signature = if pdf.is_pdf && !legacy_word.is_ole_cfb {
        recognize_signed_pdf(bytes)
    } else {
        unsigned_pdf_signal_report()
    };
    let mut findings = Vec::new();

    if bytes.is_empty() {
        findings.push(DocumentValidationFinding::error(
            "empty_body",
            "candidate document body is empty",
        ));
    }
    if bytes.len() > DOCUMENT_IMPORT_VALIDATION_MAX_BYTES {
        findings.push(DocumentValidationFinding::error(
            "document_too_large",
            format!(
                "candidate document is {} bytes; validation accepts at most {} bytes",
                bytes.len(),
                DOCUMENT_IMPORT_VALIDATION_MAX_BYTES
            ),
        ));
    }
    if content_type.declared_matches_detected == Some(false) {
        findings.push(DocumentValidationFinding::warning(
            "declared_content_type_mismatch",
            format!(
                "declared content type {:?} does not match detected {}",
                content_type.declared, content_type.detected
            ),
        ));
    }
    if fixity.size_matches_declared == Some(false) {
        findings.push(DocumentValidationFinding::error(
            "declared_size_mismatch",
            "declared document size does not match the received bytes",
        ));
    }
    if fixity.sha256_matches_declared == Some(false) {
        findings.push(DocumentValidationFinding::error(
            "declared_sha256_mismatch",
            "declared SHA-256 digest does not match the received bytes",
        ));
    }
    let known_supported_family = pdf.is_pdf
        || legacy_word.is_ole_cfb
        || image.is_image
        || text.is_supported_text
        || zip_bundle.is_zip;
    if !known_supported_family && !bytes.is_empty() {
        findings.push(DocumentValidationFinding::error(
            "unsupported_document_family",
            "candidate bytes do not match a supported import evidence family",
        ));
    }
    if legacy_word.is_ole_cfb && pdf.is_pdf {
        findings.push(DocumentValidationFinding::error(
            "legacy_word_ambiguous_pdf",
            "candidate starts as an OLE compound file but also contains a PDF header in the first 1024 bytes",
        ));
    }
    if legacy_word.filename_extension_conflict {
        findings.push(DocumentValidationFinding::error(
            "legacy_word_filename_conflict",
            "OLE compound file bytes were supplied with a non-.doc filename extension",
        ));
    }
    if legacy_word.declared_content_type_conflict {
        findings.push(DocumentValidationFinding::error(
            "legacy_word_content_type_conflict",
            "OLE compound file bytes were supplied with a declared content type that is not compatible with legacy Word DOC",
        ));
    }
    if legacy_word.is_ole_cfb
        && !legacy_word.is_legacy_word_doc
        && !legacy_word.filename_extension_conflict
        && !legacy_word.declared_content_type_conflict
        && !pdf.is_pdf
        && !bytes.is_empty()
    {
        findings.push(DocumentValidationFinding::error(
            "legacy_word_ambiguous_ole_cfb",
            "OLE compound file bytes were found, but the request did not identify a legacy Word .doc candidate",
        ));
    }
    if legacy_word.is_legacy_word_doc {
        findings.push(DocumentValidationFinding::info(
            "legacy_word_doc_detected",
            "legacy Microsoft Word .doc/OLE CFB detected; it can be preserved only as non-canonical evidence",
        ));
        findings.push(DocumentValidationFinding::warning(
            "legacy_word_conversion_review_required",
            "legacy DOC import requires operator review before any later canonical conversion workflow; no conversion is performed here",
        ));
        findings.push(DocumentValidationFinding::info(
            "legacy_word_no_macro_execution",
            "OLE CFB bytes were inspected by magic bytes and metadata only; macros and embedded objects were not executed",
        ));
        findings.push(DocumentValidationFinding::info(
            "legacy_word_no_pdfa_conversion",
            "no DOC-to-PDF/A conversion was performed; this import does not become the canonical PDF/A record",
        ));
    }
    if image.is_image {
        findings.push(DocumentValidationFinding::warning(
            "non_canonical_import_only",
            NON_CANONICAL_EVIDENCE_WARNING,
        ));
        findings.push(DocumentValidationFinding::info(
            "image_evidence_detected",
            "image evidence detected; bytes can be preserved unchanged as non-canonical supporting evidence",
        ));
        findings.push(DocumentValidationFinding::warning(
            "requires_ocr_review",
            "image evidence requires operator OCR/content review before any extracted text is used for search, drafting, or canonical records",
        ));
        findings.push(DocumentValidationFinding::info(
            "image_no_pdfa_conversion",
            "no image-to-PDF/A conversion was performed; this import does not become the canonical PDF/A record",
        ));
    }
    if text.is_supported_text {
        findings.push(DocumentValidationFinding::warning(
            "non_canonical_import_only",
            NON_CANONICAL_EVIDENCE_WARNING,
        ));
        findings.push(DocumentValidationFinding::info(
            "text_evidence_detected",
            "XML/CSV text evidence detected; bytes can be preserved unchanged as non-canonical supporting evidence",
        ));
        findings.push(DocumentValidationFinding::info(
            "text_no_structure_or_pdfa_conversion",
            "no XML schema validation, CSV semantic validation, or PDF/A conversion was performed",
        ));
    }
    if zip_bundle.is_zip {
        findings.push(DocumentValidationFinding::warning(
            "non_canonical_import_only",
            NON_CANONICAL_EVIDENCE_WARNING,
        ));
        findings.push(DocumentValidationFinding::info(
            "zip_bundle_detected",
            "ZIP bundle evidence detected; central-directory member names were inspected without extracting files",
        ));
        findings.push(DocumentValidationFinding::info(
            "zip_not_extracted",
            "ZIP members were not extracted or converted; this import does not become the canonical PDF/A record",
        ));
        if !zip_bundle.readable {
            findings.push(DocumentValidationFinding::error(
                "zip_unreadable",
                zip_bundle
                    .validation_error
                    .clone()
                    .unwrap_or_else(|| "ZIP archive could not be read".to_owned()),
            ));
        }
        if zip_bundle.unsafe_entry_count > 0 {
            findings.push(DocumentValidationFinding::error(
                "zip_unsafe_entry_name",
                format!(
                    "ZIP archive contains {} unsafe member path(s); examples: {}",
                    zip_bundle.unsafe_entry_count,
                    zip_bundle.unsafe_entry_names.join(", ")
                ),
            ));
        }
        if zip_bundle
            .total_uncompressed_size
            .is_some_and(|size| size > ZIP_UNCOMPRESSED_WARNING_BYTES)
        {
            findings.push(DocumentValidationFinding::warning(
                "zip_large_uncompressed_size",
                "ZIP central directory reports a large uncompressed size; bytes are preserved only and not extracted",
            ));
        }
    }
    if pdf.is_pdf && !pdf.has_eof_marker {
        findings.push(DocumentValidationFinding::error(
            "pdf_missing_eof",
            "candidate has a PDF header but no %%EOF marker",
        ));
    }
    if pdf.is_pdf && !pdf.has_startxref {
        findings.push(DocumentValidationFinding::warning(
            "pdf_missing_startxref",
            "candidate has no startxref marker; it may not be a complete classic PDF",
        ));
    }
    if pdf.is_pdf && !pdf.pdfa.is_pdfa_ish {
        findings.push(DocumentValidationFinding::info(
            "pdfa_hint_absent",
            "no PDF/A identification markers were found; this is not a PDF/A conformance check",
        ));
    }
    if pdf.pdfa.duplicate_metadata {
        findings.push(DocumentValidationFinding::warning(
            "pdfa_duplicate_metadata",
            "multiple PDF/A identification metadata values were found",
        ));
    }
    if pdf.pdfa.odd_metadata {
        findings.push(DocumentValidationFinding::warning(
            "pdfa_odd_metadata",
            "PDF/A identification metadata is incomplete or outside the expected marker set",
        ));
    }
    if signature.signed_pdf_signal {
        findings.push(DocumentValidationFinding::info(
            "signed_pdf_signal",
            "signature dictionary or ByteRange markers were found; this status is technical evidence only, not a legal-validity conclusion",
        ));
        if signature.byte_range_marker_count > 1 {
            findings.push(DocumentValidationFinding::error(
                "signed_pdf_multiple_signature_markers",
                "multiple ByteRange markers were found; import validation requires a single unambiguous signature candidate",
            ));
        }
        if !signature.has_byte_range {
            findings.push(DocumentValidationFinding::error(
                "signed_pdf_missing_byte_range",
                "signed-looking PDF has no /ByteRange marker",
            ));
        } else if signature.byte_range_complete != Some(true) {
            findings.push(DocumentValidationFinding::error(
                "signed_pdf_incomplete_byte_range",
                "signed-looking PDF has a malformed or incomplete /ByteRange",
            ));
        }
        if !signature.has_contents_marker {
            findings.push(DocumentValidationFinding::error(
                "signed_pdf_missing_contents",
                "signed-looking PDF has no /Contents marker for embedded signature bytes",
            ));
        }
        match signature.validation_status {
            "valid_pades_b" => findings.push(DocumentValidationFinding::info(
                "valid_pades_b",
                "PAdES-B cryptographic validation completed successfully; trust, qualified status, and legal effect are not assessed here",
            )),
            "structurally_signed" => findings.push(DocumentValidationFinding::warning(
                "signed_pdf_structural_only",
                "signature markers are present but this import screen could not establish a valid PAdES-B signature",
            )),
            "invalid" => findings.push(DocumentValidationFinding::error(
                "signed_pdf_invalid",
                signature
                    .validation_error
                    .clone()
                    .unwrap_or_else(|| "signed PDF validation failed".to_owned()),
            )),
            "indeterminate" => findings.push(DocumentValidationFinding::warning(
                "signed_pdf_indeterminate",
                signature
                    .validation_error
                    .clone()
                    .unwrap_or_else(|| "signed PDF validation could not reach a conclusion".to_owned()),
            )),
            _ => {}
        }
    }

    let can_accept_non_canonical_import =
        !findings.iter().any(|finding| finding.severity == "error");
    let preservation_policy = document_preservation_policy(
        content_type.detected,
        can_accept_non_canonical_import,
        false,
    );

    DocumentImportValidationReport {
        report_kind: "document_import_validation",
        scope: "non_canonical_import_candidate",
        legal_notice: DOCUMENT_IMPORT_VALIDATION_NOTICE,
        filename,
        size_bytes: bytes.len(),
        sha256,
        fixity,
        content_type,
        classification,
        preservation_policy,
        pdf,
        legacy_word,
        image,
        text,
        zip_bundle,
        signature,
        can_accept_non_canonical_import,
        findings,
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportedDocumentsQuery {
    pub act_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ImportedDocumentReviewRequest {
    pub review_status: String,
    pub review_note: Option<String>,
}

/// Wire metadata for an imported, non-canonical document. No raw bytes ride in JSON; callers fetch
/// bytes only from `bytes_download`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedDocumentView {
    pub id: String,
    pub act_id: Option<String>,
    pub filename: Option<String>,
    pub size_bytes: usize,
    pub sha256: String,
    pub declared_content_type: Option<String>,
    pub detected_content_type: String,
    pub evidence_family: &'static str,
    pub classification: &'static str,
    pub imported_at: String,
    pub imported_by: String,
    pub operator_review_status: &'static str,
    pub operator_reviewed_at: Option<String>,
    pub operator_reviewed_by: Option<String>,
    pub operator_review_note: Option<String>,
    pub operator_review_notice: &'static str,
    pub non_canonical: bool,
    pub requires_ocr_review: bool,
    pub canonical_record_status: &'static str,
    pub signed_artifact_status: &'static str,
    pub review_guardrail_checklist: Vec<&'static str>,
    pub canonical_conversion_status: &'static str,
    pub canonical_conversion_performed: bool,
    pub legal_acceptance_claimed: bool,
    pub preservation_policy: DocumentPreservationPolicyReport,
    pub legal_notice: &'static str,
    pub bytes_download: String,
}

/// `POST /v1/documents/import` — persist a structurally validated document as non-canonical
/// evidence. This re-runs the validation server-side and refuses any candidate the validation
/// report marked unacceptable. It never replaces the generated PDF/A row nor a signed-PDF variant.
pub async fn import_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ImportedDocumentView>), ApiError> {
    let candidate = document_validation_candidate_from_request(&headers, &body)?;
    let filename = validate_import_filename(candidate.filename)?;
    let act_id = candidate.act_id.map(ActId);
    let target_scope = match act_id {
        Some(act_id) => scope_of_act(&state, act_id).await,
        None => Scope::Global,
    };
    require_permission(&state, &actor, Permission::DocumentGenerate, target_scope).await?;
    let actor_name = actor.resolve("api");
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "document import requires on-disk persistence".to_owned(),
        ));
    }

    let report = validate_document_candidate_with_fixity(
        &candidate.bytes,
        candidate.declared_content_type.as_deref(),
        filename.clone(),
        candidate.declared_sha256.clone(),
        candidate.declared_size_bytes,
    );
    if !report.can_accept_non_canonical_import {
        let codes: Vec<&str> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == "error")
            .map(|finding| finding.code)
            .collect();
        return Err(ApiError::Unprocessable(format!(
            "candidate document failed import validation: {}",
            codes.join(", ")
        )));
    }

    let id = Uuid::new_v4().to_string();
    let imported_at = OffsetDateTime::now_utc();
    let event_scope = imported_document_event_scope(&state, act_id, &id).await?;
    let stored = StoredImportedDocument {
        meta: StoredImportedDocumentMeta {
            id: id.clone(),
            act_id,
            filename,
            declared_content_type: report.content_type.declared.clone(),
            detected_content_type: report.content_type.detected.to_owned(),
            sha256: report.sha256.clone(),
            size_bytes: report.size_bytes,
            imported_at,
            imported_by: actor_name.clone(),
            operator_review_status: imported_document_initial_review_status(
                report.content_type.detected,
            ),
            operator_reviewed_at: None,
            operator_reviewed_by: None,
            operator_review_note: None,
        },
        bytes: candidate.bytes,
    };
    let payload = serde_json::to_vec(&imported_document_event_payload(&stored.meta))?;

    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &event_scope,
        "document.imported",
        None,
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_imported_document(&stored))?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok((
        StatusCode::CREATED,
        Json(imported_document_view(&stored.meta)),
    ))
}

/// `GET /v1/documents/imported[?act_id=...]` — list imported-document metadata. When filtered by
/// act, `act.read` is checked against that act's book scope; the unfiltered feed requires global
/// `act.read`.
pub async fn list_imported_documents(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<ImportedDocumentsQuery>,
) -> Result<Json<Vec<ImportedDocumentView>>, ApiError> {
    let act_id = q.act_id.map(ActId);
    let scope = match act_id {
        Some(act_id) => scope_of_act(&state, act_id).await,
        None => Scope::Global,
    };
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    if let Some(act_id) = act_id {
        if !state.acts.read().await.contains_key(&act_id) {
            return Err(ApiError::NotFound);
        }
    }
    let Some(store) = &state.store else {
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .imported_documents(act_id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?;
    Ok(Json(
        rows.iter()
            .map(|meta| imported_document_view_with_redaction(meta, redaction))
            .collect(),
    ))
}

/// `GET /v1/documents/imported/{id}` — read imported-document metadata only.
pub async fn get_imported_document(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Json<ImportedDocumentView>, ApiError> {
    let doc = load_imported_document_for_actor(&state, &actor, &id).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    Ok(Json(imported_document_view_with_redaction(
        &doc.meta, redaction,
    )))
}

/// `PATCH /v1/documents/imported/{id}/review` — transition the operator review state for a
/// preserved imported document. This is metadata-only: it never runs OCR/conversion, never mutates
/// the canonical generated/signed document rows, and never claims legal acceptance.
pub async fn review_imported_document(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(id): Path<String>,
    Json(req): Json<ImportedDocumentReviewRequest>,
) -> Result<Json<ImportedDocumentView>, ApiError> {
    let id = validate_import_id(&id)?;
    let status = parse_imported_document_review_status(&req.review_status)?;
    let review_note = optional_limited_text(
        req.review_note,
        "review_note",
        MAX_IMPORTED_DOCUMENT_REVIEW_NOTE_CHARS,
    )?;
    let Some(store) = &state.store else {
        require_permission(&state, &actor, Permission::DocumentGenerate, Scope::Global).await?;
        return Err(ApiError::Unprocessable(
            "imported document review requires on-disk persistence".to_owned(),
        ));
    };
    let current = store
        .imported_document(&id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    let scope = match current.meta.act_id {
        Some(act_id) => scope_of_act(&state, act_id).await,
        None => Scope::Global,
    };
    require_permission(&state, &actor, Permission::DocumentGenerate, scope).await?;

    let reviewed_by = actor.resolve("api");
    let reviewed_at = OffsetDateTime::now_utc();
    let event_scope = imported_document_event_scope(&state, current.meta.act_id, &id).await?;
    let payload = serde_json::to_vec(&imported_document_review_event_payload(
        &current.meta,
        status,
        &reviewed_by,
    ))?;

    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &reviewed_by,
        &event_scope,
        "document.imported.review_updated",
        None,
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| {
        tx.review_imported_document(
            &id,
            status,
            Some(reviewed_at),
            Some(&reviewed_by),
            review_note.as_deref(),
        )
    })?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    let reviewed = store
        .imported_document(&id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(imported_document_view(&reviewed.meta)))
}

/// `GET /v1/documents/imported/{id}/bytes` — stream the retained imported bytes. This is explicitly
/// separate from the metadata JSON route so raw bytes never appear in the list/read response body or
/// in the `document.imported` event payload.
pub async fn get_imported_document_bytes(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let doc = load_imported_document_for_actor(&state, &actor, &id).await?;
    let content_type = imported_document_download_content_type(&doc.meta.detected_content_type);
    let filename = imported_document_download_filename(&doc.meta);
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(doc.bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build imported document response: {e}")))
}

async fn load_imported_document_for_actor(
    state: &AppState,
    actor: &CurrentActor,
    raw_id: &str,
) -> Result<StoredImportedDocument, ApiError> {
    let id = validate_import_id(raw_id)?;
    let Some(store) = &state.store else {
        require_permission(state, actor, Permission::ActRead, Scope::Global).await?;
        return Err(ApiError::NotFound);
    };
    let Some(doc) = store
        .imported_document(&id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?
    else {
        require_permission(state, actor, Permission::ActRead, Scope::Global).await?;
        return Err(ApiError::NotFound);
    };
    let scope = match doc.meta.act_id {
        Some(act_id) => scope_of_act(state, act_id).await,
        None => Scope::Global,
    };
    require_permission(state, actor, Permission::ActRead, scope).await?;
    Ok(doc)
}

async fn imported_document_event_scope(
    state: &AppState,
    act_id: Option<ActId>,
    import_id: &str,
) -> Result<String, ApiError> {
    let Some(act_id) = act_id else {
        return Ok(format!("imported-document:{import_id}"));
    };
    let acts = state.acts.read().await;
    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    let book_id = act.book_id;
    drop(acts);
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    Ok(format!(
        "entity:{}/book:{}/act:{}/imported-document:{}",
        book.entity_id, book_id, act_id, import_id
    ))
}

fn imported_document_view(meta: &StoredImportedDocumentMeta) -> ImportedDocumentView {
    let classification = document_evidence_classification(&meta.detected_content_type);
    let preservation_policy = imported_document_preservation_policy(meta);
    ImportedDocumentView {
        id: meta.id.clone(),
        act_id: meta.act_id.as_ref().map(ToString::to_string),
        filename: meta.filename.clone(),
        size_bytes: meta.size_bytes,
        sha256: meta.sha256.clone(),
        declared_content_type: meta.declared_content_type.clone(),
        detected_content_type: meta.detected_content_type.clone(),
        evidence_family: classification.family,
        classification: classification.classification,
        imported_at: meta.imported_at.format(&Rfc3339).unwrap_or_default(),
        imported_by: meta.imported_by.clone(),
        operator_review_status: meta.operator_review_status.as_str(),
        operator_reviewed_at: meta
            .operator_reviewed_at
            .map(|t| t.format(&Rfc3339).unwrap_or_default()),
        operator_reviewed_by: meta.operator_reviewed_by.clone(),
        operator_review_note: meta.operator_review_note.clone(),
        operator_review_notice: IMPORTED_DOCUMENT_REVIEW_NOTICE,
        non_canonical: true,
        requires_ocr_review: preservation_policy.requires_ocr_review,
        canonical_record_status: preservation_policy.canonical_record_status,
        signed_artifact_status: preservation_policy.signed_artifact_status,
        review_guardrail_checklist: preservation_policy.review_guardrail_checklist.clone(),
        canonical_conversion_status: preservation_policy.canonical_conversion_status,
        canonical_conversion_performed: false,
        legal_acceptance_claimed: false,
        preservation_policy,
        legal_notice: DOCUMENT_IMPORTED_NOTICE,
        bytes_download: format!("/v1/documents/imported/{}/bytes", meta.id),
    }
}

fn imported_document_view_with_redaction(
    meta: &StoredImportedDocumentMeta,
    redaction: ReadRedaction,
) -> ImportedDocumentView {
    let mut view = imported_document_view(meta);
    if redaction.is_guest() {
        view.filename = None;
        view.sha256 = crate::dto::REDACTED.to_owned();
        view.imported_by = crate::dto::REDACTED.to_owned();
        view.operator_reviewed_by = view
            .operator_reviewed_by
            .map(|_| crate::dto::REDACTED.to_owned());
        view.operator_review_note = view
            .operator_review_note
            .map(|_| crate::dto::REDACTED.to_owned());
        view.bytes_download = crate::dto::REDACTED.to_owned();
    }
    view
}

fn imported_document_initial_review_status(
    detected_content_type: &str,
) -> StoredImportedDocumentReviewStatus {
    match content_type_base(detected_content_type).as_str() {
        "image/png" | "image/jpeg" => StoredImportedDocumentReviewStatus::OcrReviewRequired,
        "application/msword" => {
            StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired
        }
        _ => StoredImportedDocumentReviewStatus::OperatorReviewRequired,
    }
}

fn imported_document_preservation_policy(
    meta: &StoredImportedDocumentMeta,
) -> DocumentPreservationPolicyReport {
    let mut policy = document_preservation_policy(&meta.detected_content_type, true, true);
    policy.review_state = meta.operator_review_status.as_str();
    match meta.operator_review_status {
        StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly => {
            policy.requires_operator_review = false;
            policy.requires_ocr_review = false;
            policy.preservation_action =
                "preserve_original_bytes_after_operator_review_non_canonical_only";
        }
        StoredImportedDocumentReviewStatus::RejectedNonCanonicalEvidence => {
            policy.requires_operator_review = false;
            policy.requires_ocr_review = false;
            policy.preservation_action =
                "preserve_original_bytes_with_rejected_non_canonical_review";
        }
        StoredImportedDocumentReviewStatus::OperatorReviewRequired
        | StoredImportedDocumentReviewStatus::OcrReviewRequired
        | StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired => {}
    }
    policy
}

fn imported_document_download_filename(meta: &StoredImportedDocumentMeta) -> String {
    format!(
        "imported-document-{}.{}",
        meta.id,
        imported_document_download_extension(&meta.detected_content_type)
    )
}

fn imported_document_download_content_type(detected_content_type: &str) -> &'static str {
    match content_type_base(detected_content_type).as_str() {
        "application/pdf" => "application/pdf",
        "application/msword" => "application/msword",
        "application/zip" => "application/zip",
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "application/xml" | "text/xml" => "application/xml",
        "text/csv" => "text/csv",
        _ => "application/octet-stream",
    }
}

fn imported_document_download_extension(detected_content_type: &str) -> &'static str {
    match content_type_base(detected_content_type).as_str() {
        "application/pdf" => "pdf",
        "application/msword" => "doc",
        "application/zip" => "zip",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "application/xml" | "text/xml" => "xml",
        "text/csv" => "csv",
        _ => "bin",
    }
}

fn imported_document_event_payload(meta: &StoredImportedDocumentMeta) -> Value {
    let classification = document_evidence_classification(&meta.detected_content_type);
    let preservation_policy = imported_document_preservation_policy(meta);
    json!({
        "document_id": meta.id.clone(),
        "act_id": meta.act_id.as_ref().map(ToString::to_string),
        "sha256": meta.sha256.clone(),
        "size_bytes": meta.size_bytes,
        "declared_content_type": meta.declared_content_type.clone(),
        "detected_content_type": meta.detected_content_type.clone(),
        "evidence_family": classification.family,
        "classification": classification.classification,
        "imported_at": meta.imported_at.format(&Rfc3339).unwrap_or_default(),
        "non_canonical": true,
        "operator_review_status": meta.operator_review_status.as_str(),
        "operator_reviewed_at": meta.operator_reviewed_at.map(|t| t.format(&Rfc3339).unwrap_or_default()),
        "operator_reviewed_by": meta.operator_reviewed_by.clone(),
        "operator_review_note_in_payload": false,
        "operator_review_notice": IMPORTED_DOCUMENT_REVIEW_NOTICE,
        "requires_ocr_review": preservation_policy.requires_ocr_review,
        "canonical_record_status": preservation_policy.canonical_record_status,
        "signed_artifact_status": preservation_policy.signed_artifact_status,
        "review_guardrail_checklist": preservation_policy.review_guardrail_checklist.clone(),
        "legal_notice": DOCUMENT_IMPORTED_NOTICE,
        "non_canonical_warning": NON_CANONICAL_EVIDENCE_WARNING,
        "bytes_in_payload": false,
        "pdfa_conformance_validation_performed": false,
        "canonical_conversion_status": preservation_policy.canonical_conversion_status,
        "canonical_conversion_performed": false,
        "canonical_pdfa_generated": false,
        "signature_validation_performed": false,
        "preservation_policy": preservation_policy,
        "legal_acceptance_claimed": false,
        "legal_validity_claimed": false,
    })
}

fn imported_document_review_event_payload(
    meta: &StoredImportedDocumentMeta,
    status: StoredImportedDocumentReviewStatus,
    reviewed_by: &str,
) -> Value {
    json!({
        "document_id": meta.id.clone(),
        "act_id": meta.act_id.as_ref().map(ToString::to_string),
        "previous_operator_review_status": meta.operator_review_status.as_str(),
        "operator_review_status": status.as_str(),
        "reviewed_by": reviewed_by,
        "review_note_in_payload": false,
        "operator_review_notice": IMPORTED_DOCUMENT_REVIEW_NOTICE,
        "non_canonical": true,
        "bytes_in_payload": false,
        "ocr_performed": false,
        "canonical_record_status": "not_canonical_record",
        "signed_artifact_status": "not_signed_artifact",
        "review_guardrail_checklist": imported_document_review_guardrail_checklist(),
        "canonical_conversion_status": "not_performed_non_canonical_original_only",
        "canonical_conversion_performed": false,
        "canonical_pdfa_generated": false,
        "legal_acceptance_claimed": false,
        "legal_validity_claimed": false,
    })
}

fn parse_imported_document_review_status(
    raw: &str,
) -> Result<StoredImportedDocumentReviewStatus, ApiError> {
    match raw.trim() {
        "reviewed_non_canonical_original_only" => {
            Ok(StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly)
        }
        "rejected_non_canonical_evidence" => {
            Ok(StoredImportedDocumentReviewStatus::RejectedNonCanonicalEvidence)
        }
        _ => Err(ApiError::Unprocessable(
            "review_status must be one of reviewed_non_canonical_original_only or rejected_non_canonical_evidence".to_owned(),
        )),
    }
}

fn imported_document_review_guardrail_checklist() -> Vec<&'static str> {
    IMPORTED_DOCUMENT_REVIEW_GUARDRAIL_CHECKLIST.to_vec()
}

fn optional_limited_text(
    value: Option<String>,
    field: &'static str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    Ok(Some(value))
}

fn validate_import_id(raw: &str) -> Result<String, ApiError> {
    let id = raw.trim();
    if id.is_empty() || looks_path_like(id) {
        return Err(ApiError::Unprocessable(
            "invalid imported document id".to_owned(),
        ));
    }
    Uuid::parse_str(id)
        .map_err(|_| ApiError::Unprocessable("invalid imported document id".to_owned()))?;
    Ok(id.to_owned())
}

fn validate_import_filename(filename: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(filename) = non_empty(filename) else {
        return Ok(None);
    };
    if filename.len() > 255 || looks_path_like(&filename) {
        return Err(ApiError::Unprocessable(
            "import filename must be a plain file name, not a path".to_owned(),
        ));
    }
    Ok(Some(filename))
}

fn looks_path_like(value: &str) -> bool {
    value == "."
        || value == ".."
        || value.contains("..")
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
}

fn recognize_pdf(bytes: &[u8]) -> PdfRecognitionReport {
    let header = pdf_header(bytes);
    let pdfa = recognize_pdfa(bytes);
    PdfRecognitionReport {
        is_pdf: header.is_some(),
        header_offset: header.as_ref().map(|(offset, _)| *offset),
        version: header.map(|(_, version)| version),
        has_eof_marker: find_bytes(bytes, b"%%EOF").is_some(),
        has_startxref: find_bytes(bytes, b"startxref").is_some(),
        pdfa,
    }
}

fn recognize_pdfa(bytes: &[u8]) -> PdfARecognitionReport {
    let text = String::from_utf8_lossy(bytes);
    let part_values = extract_xml_tag_values(&text, "pdfaid:part");
    let conformance_values = extract_xml_tag_values(&text, "pdfaid:conformance");
    let has_output_intent_marker = find_bytes(bytes, b"GTS_PDFA").is_some();
    let duplicate_metadata = part_values.len() > 1 || conformance_values.len() > 1;
    let odd_metadata = pdfa_metadata_is_odd(&part_values, &conformance_values);

    PdfARecognitionReport {
        is_pdfa_ish: has_output_intent_marker
            || !part_values.is_empty()
            || !conformance_values.is_empty(),
        part: part_values.first().cloned(),
        conformance: conformance_values.first().cloned(),
        part_values,
        conformance_values,
        duplicate_metadata,
        odd_metadata,
    }
}

fn recognize_legacy_word_doc(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<&str>,
) -> LegacyWordDocRecognitionReport {
    let is_ole_cfb = bytes.starts_with(OLE_CFB_MAGIC);
    let filename_extension_doc = filename
        .and_then(filename_extension)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("doc"));
    let filename_extension_conflict = is_ole_cfb
        && filename
            .and_then(filename_extension)
            .is_some_and(|extension| !extension.eq_ignore_ascii_case("doc"));
    let declared_base = declared_content_type.map(content_type_base);
    let declared_content_type_msword = declared_base
        .as_deref()
        .is_some_and(is_legacy_word_content_type);
    let declared_content_type_generic = declared_base
        .as_deref()
        .is_some_and(is_generic_ole_cfb_content_type);
    let declared_content_type_conflict = is_ole_cfb
        && declared_base.as_deref().is_some_and(|content_type| {
            !is_legacy_word_content_type(content_type)
                && !is_generic_ole_cfb_content_type(content_type)
        });
    let is_legacy_word_doc = is_ole_cfb
        && (filename_extension_doc || declared_content_type_msword)
        && !filename_extension_conflict
        && !declared_content_type_conflict;

    LegacyWordDocRecognitionReport {
        is_ole_cfb,
        is_legacy_word_doc,
        filename_extension_doc,
        declared_content_type_msword,
        declared_content_type_generic,
        filename_extension_conflict,
        declared_content_type_conflict,
        macro_execution_performed: false,
        conversion_performed: false,
        canonical_pdfa_generated: false,
    }
}

fn filename_extension(filename: &str) -> Option<&str> {
    let (_, extension) = filename.rsplit_once('.')?;
    (!extension.is_empty()).then_some(extension)
}

fn is_legacy_word_content_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "application/msword"
            | "application/doc"
            | "application/vnd.ms-word"
            | "application/x-msword"
            | "application/x-ms-word"
    )
}

fn is_generic_ole_cfb_content_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "application/octet-stream"
            | "application/vnd.ms-office"
            | "application/x-ole-storage"
            | "application/ole"
    )
}

fn recognize_image(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<&str>,
) -> ImageRecognitionReport {
    let png = bytes.starts_with(PNG_MAGIC);
    let jpeg = bytes.starts_with(JPEG_MAGIC);
    let (format, dimensions) = if png {
        ("png", png_dimensions(bytes))
    } else if jpeg {
        ("jpeg", jpeg_dimensions(bytes))
    } else {
        ("", None)
    };
    let declared_content_type_image = declared_content_type
        .map(content_type_base)
        .as_deref()
        .is_some_and(is_supported_image_content_type);
    let filename_extension_image = filename
        .and_then(filename_extension)
        .is_some_and(is_supported_image_extension);

    ImageRecognitionReport {
        is_image: png || jpeg,
        format: (!format.is_empty()).then_some(format),
        width: dimensions.map(|(width, _)| width),
        height: dimensions.map(|(_, height)| height),
        declared_content_type_image,
        filename_extension_image,
        conversion_performed: false,
        canonical_pdfa_generated: false,
    }
}

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || !bytes.starts_with(PNG_MAGIC) || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    Some((width, height))
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if !bytes.starts_with(JPEG_MAGIC) {
        return None;
    }
    let mut index = 2;
    while index + 4 <= bytes.len() {
        while index < bytes.len() && bytes[index] == 0xFF {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        let marker = bytes[index];
        index += 1;
        if marker == 0xD9 || marker == 0xDA {
            return None;
        }
        if index + 2 > bytes.len() {
            return None;
        }
        let segment_len = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
        if segment_len < 2 || index + segment_len > bytes.len() {
            return None;
        }
        if is_jpeg_sof_marker(marker) && segment_len >= 7 {
            let height = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]]) as u32;
            let width = u16::from_be_bytes([bytes[index + 5], bytes[index + 6]]) as u32;
            return Some((width, height));
        }
        index += segment_len;
    }
    None
}

fn is_jpeg_sof_marker(marker: u8) -> bool {
    matches!(
        marker,
        0xC0 | 0xC1 | 0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF
    )
}

fn is_supported_image_content_type(content_type: &str) -> bool {
    matches!(content_type, "image/png" | "image/jpeg" | "image/jpg")
}

fn is_supported_image_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg"
    )
}

fn recognize_text_document(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<&str>,
) -> TextDocumentRecognitionReport {
    let has_nul = bytes.contains(&0);
    let text = std::str::from_utf8(bytes).ok();
    let declared_base = declared_content_type.map(content_type_base);
    let declared_kind = declared_base
        .as_deref()
        .and_then(text_kind_from_content_type);
    let filename_kind = filename
        .and_then(filename_extension)
        .and_then(text_kind_from_extension);
    let sniffed_kind = text.and_then(sniff_text_kind);
    let kind = declared_kind.or(filename_kind).or(sniffed_kind);
    let supported = !bytes.is_empty() && !has_nul && text.is_some() && kind.is_some();

    TextDocumentRecognitionReport {
        is_supported_text: supported,
        kind,
        utf8_valid: text.is_some(),
        has_nul,
        declared_content_type_text: declared_kind.is_some(),
        filename_extension_text: filename_kind.is_some(),
        structure_validation_performed: false,
        conversion_performed: false,
        canonical_pdfa_generated: false,
    }
}

fn text_kind_from_content_type(content_type: &str) -> Option<&'static str> {
    match content_type {
        "application/xml" | "text/xml" | "application/xhtml+xml" | "application/rss+xml" => {
            Some("xml")
        }
        "text/csv" | "application/csv" | "application/vnd.ms-excel" => Some("csv"),
        _ => None,
    }
}

fn text_kind_from_extension(extension: &str) -> Option<&'static str> {
    match extension.to_ascii_lowercase().as_str() {
        "xml" => Some("xml"),
        "csv" => Some("csv"),
        _ => None,
    }
}

fn sniff_text_kind(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with("<?xml") || (trimmed.starts_with('<') && trimmed.contains('>')) {
        return Some("xml");
    }
    let first_data_line = trimmed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    if first_data_line.contains(',')
        || first_data_line.contains(';')
        || first_data_line.contains('\t')
    {
        return Some("csv");
    }
    None
}

fn recognize_zip_bundle(bytes: &[u8]) -> ZipBundleRecognitionReport {
    let is_zip = bytes.starts_with(ZIP_MAGIC)
        || bytes.starts_with(ZIP_EMPTY_MAGIC)
        || bytes.starts_with(ZIP_SPANNED_MAGIC);
    if !is_zip {
        return ZipBundleRecognitionReport {
            is_zip: false,
            readable: false,
            entry_count: 0,
            unsafe_entry_count: 0,
            unsafe_entry_names: Vec::new(),
            total_uncompressed_size: None,
            extraction_performed: false,
            canonical_pdfa_generated: false,
            validation_error: None,
        };
    }

    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(err) => {
            return ZipBundleRecognitionReport {
                is_zip: true,
                readable: false,
                entry_count: 0,
                unsafe_entry_count: 0,
                unsafe_entry_names: Vec::new(),
                total_uncompressed_size: None,
                extraction_performed: false,
                canonical_pdfa_generated: false,
                validation_error: Some(format!("ZIP archive could not be read: {err}")),
            };
        }
    };

    let mut unsafe_entry_count = 0usize;
    let mut unsafe_entry_names = Vec::new();
    let mut total_uncompressed_size = 0u64;
    let mut validation_error = None;
    for index in 0..archive.len() {
        let file = match archive.by_index(index) {
            Ok(file) => file,
            Err(err) => {
                validation_error = Some(format!("ZIP member {index} could not be read: {err}"));
                break;
            }
        };
        total_uncompressed_size = total_uncompressed_size.saturating_add(file.size());
        let name = file.name().to_owned();
        if zip_entry_name_is_unsafe(&name, file.enclosed_name().is_none()) {
            unsafe_entry_count += 1;
            if unsafe_entry_names.len() < 5 {
                unsafe_entry_names.push(name);
            }
        }
    }

    ZipBundleRecognitionReport {
        is_zip: true,
        readable: validation_error.is_none(),
        entry_count: archive.len(),
        unsafe_entry_count,
        unsafe_entry_names,
        total_uncompressed_size: Some(total_uncompressed_size),
        extraction_performed: false,
        canonical_pdfa_generated: false,
        validation_error,
    }
}

fn zip_entry_name_is_unsafe(name: &str, enclosed_name_missing: bool) -> bool {
    if enclosed_name_missing
        || name.trim().is_empty()
        || name.contains('\0')
        || name.contains('\\')
        || name.contains(':')
    {
        return true;
    }
    std::path::Path::new(name).components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    })
}

fn recognize_signed_pdf(bytes: &[u8]) -> SignedPdfSignalReport {
    let signature_marker_count = count_signature_markers(bytes);
    let byte_range_marker_count = count_bytes(bytes, b"/ByteRange");
    let has_signature_dictionary_marker = signature_marker_count > 0;
    let has_byte_range = byte_range_marker_count > 0;
    let has_contents_marker = find_bytes(bytes, b"/Contents").is_some();
    let byte_range = parse_byte_range(bytes);
    let byte_range_shape = byte_range.and_then(|range| byte_range_shape(range, bytes.len()));
    let byte_range_digest_sha256 = byte_range_shape
        .and_then(|shape| byte_range.map(|range| byte_range_digest(bytes, range, shape)))
        .map(|digest| crate::hex::hex(&digest));
    let pades_validation =
        classify_pades_validation(bytes, has_signature_dictionary_marker || has_byte_range);

    SignedPdfSignalReport {
        validation_status: pades_validation.status,
        signed_pdf_signal: has_signature_dictionary_marker || has_byte_range,
        has_signature_dictionary_marker,
        signature_marker_count,
        has_byte_range,
        byte_range_marker_count,
        byte_range,
        byte_range_complete: if has_byte_range {
            Some(byte_range_shape.is_some_and(|shape| shape.complete))
        } else {
            None
        },
        byte_range_digest_sha256,
        signed_revision_bytes: pades_validation.signed_revision_bytes,
        covered_bytes: byte_range_shape.map(|shape| shape.covered_bytes),
        excluded_bytes: byte_range_shape.map(|shape| shape.excluded_bytes),
        has_contents_marker,
        cryptographic_validation_performed: pades_validation.performed,
        pades_profile: pades_validation.pades_profile,
        validation_error: pades_validation.error,
    }
}

fn unsigned_pdf_signal_report() -> SignedPdfSignalReport {
    SignedPdfSignalReport {
        validation_status: "unsigned",
        signed_pdf_signal: false,
        has_signature_dictionary_marker: false,
        signature_marker_count: 0,
        has_byte_range: false,
        byte_range_marker_count: 0,
        byte_range: None,
        byte_range_complete: None,
        byte_range_digest_sha256: None,
        signed_revision_bytes: None,
        covered_bytes: None,
        excluded_bytes: None,
        has_contents_marker: false,
        cryptographic_validation_performed: false,
        pades_profile: None,
        validation_error: None,
    }
}

struct PadesValidationSignal {
    status: &'static str,
    performed: bool,
    pades_profile: Option<&'static str>,
    signed_revision_bytes: Option<usize>,
    error: Option<String>,
}

fn classify_pades_validation(bytes: &[u8], signed_pdf_signal: bool) -> PadesValidationSignal {
    if !signed_pdf_signal {
        return PadesValidationSignal {
            status: "unsigned",
            performed: false,
            pades_profile: None,
            signed_revision_bytes: None,
            error: None,
        };
    }

    match chancela_pades::validate_pdf_signature(bytes) {
        Ok(report) => PadesValidationSignal {
            status: "valid_pades_b",
            performed: true,
            pades_profile: Some(if report.has_signature_timestamp {
                "PAdES-B-T"
            } else {
                "PAdES-B-B"
            }),
            signed_revision_bytes: Some(report.signed_revision_len),
            error: None,
        },
        Err(chancela_pades::PadesError::InvalidByteRange) => PadesValidationSignal {
            status: "invalid",
            performed: true,
            pades_profile: None,
            signed_revision_bytes: None,
            error: Some("signature ByteRange is malformed or points outside the file".to_owned()),
        },
        Err(chancela_pades::PadesError::Cades(_))
        | Err(chancela_pades::PadesError::InvalidContents) => PadesValidationSignal {
            status: "invalid",
            performed: true,
            pades_profile: None,
            signed_revision_bytes: None,
            error: Some(
                "embedded signature bytes did not validate against the PDF ByteRange digest"
                    .to_owned(),
            ),
        },
        Err(chancela_pades::PadesError::NoSignature) => PadesValidationSignal {
            status: "structurally_signed",
            performed: true,
            pades_profile: None,
            signed_revision_bytes: None,
            error: Some(
                "signature-like markers were present but no parseable /Sig dictionary was found"
                    .to_owned(),
            ),
        },
        Err(chancela_pades::PadesError::PdfParse(_))
        | Err(chancela_pades::PadesError::MalformedStructure(_)) => PadesValidationSignal {
            status: "indeterminate",
            performed: true,
            pades_profile: None,
            signed_revision_bytes: None,
            error: Some(
                "PDF parsing could not establish whether the signature is valid".to_owned(),
            ),
        },
        Err(err) => PadesValidationSignal {
            status: "indeterminate",
            performed: true,
            pades_profile: None,
            signed_revision_bytes: None,
            error: Some(format!(
                "PAdES validation did not reach a conclusion: {err}"
            )),
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct ByteRangeShape {
    complete: bool,
    covered_bytes: usize,
    excluded_bytes: usize,
}

fn byte_range_shape(range: [i64; 4], total_len: usize) -> Option<ByteRangeShape> {
    let [s1, l1, s2, l2] = range;
    let s1 = usize::try_from(s1).ok()?;
    let l1 = usize::try_from(l1).ok()?;
    let s2 = usize::try_from(s2).ok()?;
    let l2 = usize::try_from(l2).ok()?;
    let e1 = s1.checked_add(l1)?;
    let e2 = s2.checked_add(l2)?;
    let covered_bytes = l1.checked_add(l2)?;
    let excluded_bytes = s2.checked_sub(e1)?;
    let complete = s1 == 0 && e1 <= s2 && e2 == total_len;
    Some(ByteRangeShape {
        complete,
        covered_bytes,
        excluded_bytes,
    })
}

fn byte_range_digest(bytes: &[u8], range: [i64; 4], shape: ByteRangeShape) -> [u8; 32] {
    let [s1, l1, s2, l2] = range;
    let s1 = usize::try_from(s1).expect("validated byte range start1");
    let l1 = usize::try_from(l1).expect("validated byte range len1");
    let s2 = usize::try_from(s2).expect("validated byte range start2");
    let l2 = usize::try_from(l2).expect("validated byte range len2");
    debug_assert_eq!(shape.covered_bytes, l1 + l2);
    let mut hasher = Sha256::new();
    hasher.update(&bytes[s1..s1 + l1]);
    hasher.update(&bytes[s2..s2 + l2]);
    hasher.finalize().into()
}

fn parse_byte_range(bytes: &[u8]) -> Option<[i64; 4]> {
    let marker = find_bytes(bytes, b"/ByteRange")?;
    let mut i = marker + b"/ByteRange".len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    let mut values = Vec::with_capacity(4);
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b']') {
            break;
        }
        let start = i;
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || (i == start + 1 && bytes[start] == b'-') {
            return None;
        }
        let value = std::str::from_utf8(&bytes[start..i])
            .ok()?
            .parse::<i64>()
            .ok()?;
        values.push(value);
        if values.len() > 4 {
            return None;
        }
    }
    if values.len() == 4 {
        Some([values[0], values[1], values[2], values[3]])
    } else {
        None
    }
}

fn count_signature_markers(bytes: &[u8]) -> usize {
    count_bytes(bytes, b"/Type /Sig")
        + count_bytes(bytes, b"/Type/Sig")
        + count_bytes(bytes, b"/FT /Sig")
        + count_bytes(bytes, b"/SubFilter")
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn normalize_sha256(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::Unprocessable(
            "declared SHA-256 must be 64 hexadecimal characters".to_owned(),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn pdf_header(bytes: &[u8]) -> Option<(usize, String)> {
    let limit = bytes.len().min(1024);
    let offset = find_bytes(&bytes[..limit], b"%PDF-")?;
    let start = offset + b"%PDF-".len();
    let mut end = start;
    while end < bytes.len() && matches!(bytes[end], b'0'..=b'9' | b'.') {
        end += 1;
    }
    if end == start {
        return Some((offset, String::new()));
    }
    let version = std::str::from_utf8(&bytes[start..end]).ok()?.to_owned();
    Some((offset, version))
}

fn detect_candidate_content_type(
    bytes: &[u8],
    is_pdf: bool,
    legacy_word: &LegacyWordDocRecognitionReport,
    image: &ImageRecognitionReport,
    text: &TextDocumentRecognitionReport,
    zip_bundle: &ZipBundleRecognitionReport,
) -> &'static str {
    if legacy_word.is_legacy_word_doc {
        "application/msword"
    } else if legacy_word.is_ole_cfb {
        "application/vnd.ms-office"
    } else if is_pdf {
        "application/pdf"
    } else if image.format == Some("png") {
        "image/png"
    } else if image.format == Some("jpeg") {
        "image/jpeg"
    } else if zip_bundle.is_zip || bytes.starts_with(ZIP_MAGIC) {
        "application/zip"
    } else if text.kind == Some("xml") {
        "application/xml"
    } else if text.kind == Some("csv") {
        "text/csv"
    } else {
        "application/octet-stream"
    }
}

fn document_evidence_classification(
    detected_content_type: &str,
) -> DocumentEvidenceClassificationReport {
    let (family, classification) = match content_type_base(detected_content_type).as_str() {
        "application/pdf" => ("pdf", "imported_pdf_non_canonical_evidence"),
        "application/msword" => ("legacy_word_doc", "legacy_word_doc_non_canonical_evidence"),
        "application/vnd.ms-office" => ("ole_compound_file", "ole_cfb_non_canonical_evidence"),
        "image/png" | "image/jpeg" => ("image", "image_non_canonical_evidence"),
        "application/xml" | "text/xml" => ("xml_text", "xml_text_non_canonical_evidence"),
        "text/csv" => ("csv_text", "csv_text_non_canonical_evidence"),
        "application/zip" => ("zip_bundle", "zip_bundle_non_canonical_evidence"),
        _ => ("unknown", "unsupported_document_evidence"),
    };
    DocumentEvidenceClassificationReport {
        family,
        classification,
        non_canonical: true,
        warning: NON_CANONICAL_EVIDENCE_WARNING,
        canonical_conversion_performed: false,
        canonical_pdfa_generated: false,
        legal_validity_claimed: false,
    }
}

fn document_preservation_policy(
    detected_content_type: &str,
    can_accept_non_canonical_import: bool,
    original_bytes_preserved: bool,
) -> DocumentPreservationPolicyReport {
    let base = content_type_base(detected_content_type);
    let requires_ocr_review = matches!(base.as_str(), "image/png" | "image/jpeg");
    let is_legacy_word_doc = base == "application/msword";
    let original_bytes_preservation_status = if original_bytes_preserved {
        "preserved_original_bytes"
    } else {
        "not_preserved_by_validation"
    };
    let canonical_conversion_status = if can_accept_non_canonical_import {
        "not_performed_non_canonical_original_only"
    } else {
        "not_performed_validation_failed"
    };
    let (review_state, preservation_action) = if !can_accept_non_canonical_import {
        (
            "validation_failed",
            "resolve_validation_errors_before_preservation",
        )
    } else if requires_ocr_review {
        (
            "ocr_review_required",
            "preserve_original_bytes_then_operator_review_ocr_if_needed",
        )
    } else if is_legacy_word_doc {
        (
            "canonical_conversion_review_required",
            "preserve_original_bytes_then_operator_review_conversion_if_needed",
        )
    } else {
        (
            "operator_review_required",
            "preserve_original_bytes_as_non_canonical_evidence_if_needed",
        )
    };

    DocumentPreservationPolicyReport {
        review_state,
        requires_operator_review: true,
        requires_ocr_review,
        canonical_record_status: "not_canonical_record",
        signed_artifact_status: "not_signed_artifact",
        review_guardrail_checklist: imported_document_review_guardrail_checklist(),
        canonical_conversion_status,
        original_bytes_preservation_status,
        preservation_action,
        canonical_conversion_performed: false,
        canonical_pdfa_generated: false,
        legal_acceptance_claimed: false,
    }
}

fn extract_xml_tag_values(text: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = text;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(&close) else {
            break;
        };
        values.push(after_open[..end].trim().to_owned());
        rest = &after_open[end + close.len()..];
    }
    values
}

fn pdfa_metadata_is_odd(part_values: &[String], conformance_values: &[String]) -> bool {
    if part_values.is_empty() && conformance_values.is_empty() {
        return false;
    }
    if part_values.is_empty() || conformance_values.is_empty() {
        return true;
    }
    let valid_part = |value: &str| matches!(value, "1" | "2" | "3" | "4");
    let valid_conformance = |value: &str| matches!(value, "A" | "B" | "E" | "F" | "U");
    part_values.iter().any(|value| !valid_part(value))
        || conformance_values
            .iter()
            .any(|value| !valid_conformance(value))
}

fn header_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn content_type_base(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

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
    actor: CurrentActor,
    Query(q): Query<PreviewQuery>,
) -> Result<Json<DocumentModel>, ApiError> {
    // RBAC (t64-E3): previewing an act's document is `act.read` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
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
    // RBAC (t64-E3): generating a document is `document.generate` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::DocumentGenerate, scope).await?;
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
    crate::try_append_event(
        &mut ledger,
        &actor,
        &scope,
        "document.generated",
        None,
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_document(&made.stored))?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    // Publish only a canonical Ata candidate to the live read model. Certidões/extratos remain
    // persisted rows but must not replace the sealed Ata used by download/bundle/signing.
    if spec.stage == LifecycleStage::Ata {
        let mut documents = state.documents.write().await;
        let keep_existing_ata = documents
            .get(&made.stored.act_id)
            .is_some_and(|doc| is_ata_template(&doc.template_id));
        if !keep_existing_ata {
            documents.insert(made.stored.act_id, made.stored.clone());
        }
    }

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
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): reading an act's document is `act.read` scoped to its book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let doc = load_document(&state, ActId(id))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/pdf")], doc.pdf_bytes).into_response())
}

/// `GET /v1/acts/{id}/document/working-copy` — Markdown/TXT/HTML/RTF/ODT convenience export of the
/// sealed generated act document. This is explicitly non-evidentiary: it never changes the
/// preserved PDF/A bytes, the signed variant, or the ledger.
pub async fn export_working_copy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<WorkingCopyQuery>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let act_id = ActId(id);
    // RBAC (DOC-02): working-copy export is a document read, gated like the canonical PDF/BUNDLE.
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;

    let doc = load_document(&state, act_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let model = render_persisted_act_document_model(&state, act_id, &doc.template_id)
        .await
        .map_err(|err| match err {
            ApiError::NotFound => ApiError::Conflict(
                "preserved document exists, but its editable document model is unavailable"
                    .to_owned(),
            ),
            other => other,
        })?;
    let (body, content_type, extension) = match query.format {
        WorkingCopyFormat::Markdown => (
            working_copy_markdown(act_id, &doc, &model).into_bytes(),
            "text/markdown; charset=utf-8",
            "md",
        ),
        WorkingCopyFormat::Txt => (
            working_copy_text(act_id, &doc, &model).into_bytes(),
            "text/plain; charset=utf-8",
            "txt",
        ),
        WorkingCopyFormat::Html => (
            working_copy_html(act_id, &doc, &model).into_bytes(),
            "text/html; charset=utf-8",
            "html",
        ),
        WorkingCopyFormat::Rtf => (
            working_copy_rtf(act_id, &doc, &model).into_bytes(),
            "application/rtf",
            "rtf",
        ),
        WorkingCopyFormat::Odt => (
            working_copy_odt(act_id, &doc, &model)?,
            "application/vnd.oasis.opendocument.text",
            "odt",
        ),
    };
    let filename = format!("act-{id}-working-copy.{extension}");

    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(body))
        .map_err(|e| ApiError::Internal(format!("failed to build working-copy response: {e}")))
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WorkingCopyFormat {
    #[serde(alias = "md")]
    #[default]
    Markdown,
    #[serde(alias = "text")]
    Txt,
    Html,
    Rtf,
    #[serde(alias = "opendocument")]
    Odt,
}

#[derive(Deserialize)]
pub struct WorkingCopyQuery {
    #[serde(default)]
    format: WorkingCopyFormat,
}

/// `GET /v1/acts/{id}/document/office` — deterministic DOCX working-copy export of the preserved
/// sealed act document. The DOCX is office-editable convenience material only: the preserved PDF/A
/// (or signed PDF) remains the evidentiary record, and this endpoint never appends ledger events.
pub async fn export_office_document(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let act_id = ActId(id);
    // RBAC: office export is a document read, gated exactly like the canonical PDF/BUNDLE.
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;

    let doc = load_document(&state, act_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let model = render_persisted_act_document_model(&state, act_id, &doc.template_id)
        .await
        .map_err(|err| match err {
            ApiError::NotFound => ApiError::Conflict(
                "preserved document exists, but its editable document model is unavailable"
                    .to_owned(),
            ),
            other => other,
        })?;
    let bytes = office_docx(act_id, &doc, &model)?;
    let filename = format!("act-{id}-office-working-copy.docx");

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build office export response: {e}")))
}

async fn render_persisted_act_document_model(
    state: &AppState,
    act_id: ActId,
    template_id: &str,
) -> Result<DocumentModel, ApiError> {
    let spec = registry().get(template_id).ok_or_else(|| {
        ApiError::Internal(format!(
            "stored document template {template_id:?} is no longer available"
        ))
    })?;

    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    let ctx = act_render_ctx(act, book, entity)?;

    chancela_templates::render(spec, &ctx)
        .map_err(|e| ApiError::Internal(format!("template render failed: {e}")))
}

fn working_copy_markdown(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut out = String::new();
    out.push_str("# WORKING COPY - NON-EVIDENTIARY\n\n");
    out.push_str(
        "This Markdown export is a working copy for review and editing convenience only. It is not \
         the preserved signed original and must not be used as the canonical record.\n\n",
    );
    out.push_str("## Export notice\n\n");
    out.push_str("- Status: working copy, non-evidentiary\n");
    out.push_str(&format!("- Act ID: `{}`\n", act_id));
    out.push_str(&format!("- Preserved document ID: `{}`\n", doc.id));
    out.push_str(&format!("- Template: `{}`\n", doc.template_id));
    out.push_str(&format!("- Preserved PDF digest: `{}`\n", doc.pdf_digest));
    out.push_str("- Preserved original: use the stored PDF/A or signed PDF endpoint\n\n");
    out.push_str("---\n\n");
    out.push_str(&format!("# {}\n\n", escape_markdown_text(&model.title)));
    if !model.subject.trim().is_empty() {
        out.push_str(&format!("_{}_\n\n", escape_markdown_text(&model.subject)));
    }
    append_blocks_markdown(&mut out, &model.blocks);
    out
}

fn working_copy_text(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut out = String::new();
    out.push_str("WORKING COPY - NON-EVIDENTIARY\n\n");
    out.push_str(
        "This plain-text export is a working copy for review and editing convenience only. It is \
         not the preserved signed original and must not be used as the canonical record.\n\n",
    );
    out.push_str("Export notice\n\n");
    out.push_str("Status: working copy, non-evidentiary\n");
    out.push_str(&format!("Act ID: {act_id}\n"));
    out.push_str(&format!("Preserved document ID: {}\n", doc.id));
    out.push_str(&format!("Template: {}\n", doc.template_id));
    out.push_str(&format!("Preserved PDF digest: {}\n", doc.pdf_digest));
    out.push_str("Preserved original: use the stored PDF/A or signed PDF endpoint\n\n");
    out.push_str("----------\n\n");
    out.push_str(&model.title);
    out.push_str("\n\n");
    if !model.subject.trim().is_empty() {
        out.push_str(&model.subject);
        out.push_str("\n\n");
    }
    append_blocks_text(&mut out, &model.blocks);
    out
}

fn append_blocks_text(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => {
                out.push_str(&format!(
                    "{} {}\n\n",
                    "=".repeat((*level).clamp(1, 6) as usize),
                    text
                ));
            }
            Block::Paragraph { runs } => {
                let paragraph = runs_text(runs);
                if !paragraph.trim().is_empty() {
                    out.push_str(paragraph.trim());
                    out.push_str("\n\n");
                }
            }
            Block::KeyValue { rows } => {
                for row in rows {
                    out.push_str(&format!("{}: {}\n", row.key, row.value));
                }
                out.push('\n');
            }
            Block::VoteTable { rows } => {
                out.push_str("Item | Favor | Against | Abstain\n");
                out.push_str("-----|-------|---------|--------\n");
                for row in rows {
                    out.push_str(&format!(
                        "{} | {} | {} | {}\n",
                        row.label, row.favor, row.against, row.abstain
                    ));
                }
                out.push('\n');
            }
            Block::SignatureBlock { slots } => {
                out.push_str("Signature slots\n\n");
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "blank"
                    } else {
                        slot.name.as_str()
                    };
                    out.push_str(&format!("{}: {name}\n", slot.role));
                }
                out.push('\n');
            }
            Block::PageBreak => out.push_str("[page break]\n\n"),
            Block::Rule => out.push_str("----------\n\n"),
        }
    }
}

fn runs_text(runs: &[Run]) -> String {
    runs.iter().map(|run| run.text.as_str()).collect()
}

fn working_copy_html(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut body = String::new();
    body.push_str("<h1>WORKING COPY - NON-EVIDENTIARY</h1>");
    body.push_str("<p>This HTML export is a working copy for review and editing convenience only. It is not the preserved signed original and must not be used as the canonical record.</p>");
    body.push_str("<section><h2>Export notice</h2><dl>");
    for (term, detail) in [
        ("Status", "working copy, non-evidentiary".to_owned()),
        ("Act ID", act_id.to_string()),
        ("Preserved document ID", doc.id.clone()),
        ("Template", doc.template_id.clone()),
        ("Preserved PDF digest", doc.pdf_digest.clone()),
        (
            "Preserved original",
            "Use the stored PDF/A or signed PDF endpoint".to_owned(),
        ),
    ] {
        body.push_str("<dt>");
        body.push_str(&html_escape(term));
        body.push_str("</dt><dd>");
        body.push_str(&html_escape(&detail));
        body.push_str("</dd>");
    }
    body.push_str("</dl></section><hr>");
    body.push_str("<main>");
    body.push_str("<h1>");
    body.push_str(&html_escape(&model.title));
    body.push_str("</h1>");
    if !model.subject.trim().is_empty() {
        body.push_str("<p><em>");
        body.push_str(&html_escape(&model.subject));
        body.push_str("</em></p>");
    }
    append_blocks_html(&mut body, &model.blocks);
    body.push_str("</main>");

    format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{}</title></head><body>{body}</body></html>",
        html_escape(&model.language),
        html_escape(&format!("{} - working copy", model.title))
    )
}

fn working_copy_rtf(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut out = String::new();
    out.push_str("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Aptos;}}\\uc1\n");
    out.push_str(
        "\\paperw11906\\paperh16838\\margl1440\\margr1440\\margt1440\\margb1440\\f0\\fs22\n",
    );
    append_rtf_heading(&mut out, "WORKING COPY - NON-EVIDENTIARY", 1);
    append_rtf_paragraph_text(
        &mut out,
        "This RTF export is a working copy for review and editing convenience only. It is not the preserved signed original and must not be used as the canonical record.",
        false,
        false,
    );
    append_rtf_heading(&mut out, "Export notice", 2);
    for (term, detail) in working_copy_notice_rows(act_id, doc) {
        append_rtf_paragraph_text(&mut out, &format!("{term}: {detail}"), false, false);
    }
    append_rtf_rule(&mut out);
    append_rtf_heading(&mut out, &model.title, 1);
    if !model.subject.trim().is_empty() {
        append_rtf_paragraph_text(&mut out, &model.subject, false, true);
    }
    append_blocks_rtf(&mut out, &model.blocks);
    out.push_str("}\n");
    out
}

fn append_blocks_rtf(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => append_rtf_heading(out, text, *level),
            Block::Paragraph { runs } => append_rtf_paragraph_runs(out, runs),
            Block::KeyValue { rows } => {
                for row in rows {
                    append_rtf_paragraph_text(
                        out,
                        &format!("{}: {}", row.key, row.value),
                        false,
                        false,
                    );
                }
            }
            Block::VoteTable { rows } => {
                append_rtf_paragraph_text(out, "Item | Favor | Against | Abstain", true, false);
                for row in rows {
                    append_rtf_paragraph_text(
                        out,
                        &format!(
                            "{} | {} | {} | {}",
                            row.label, row.favor, row.against, row.abstain
                        ),
                        false,
                        false,
                    );
                }
            }
            Block::SignatureBlock { slots } => {
                append_rtf_heading(out, "Signature slots", 2);
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "________________"
                    } else {
                        slot.name.as_str()
                    };
                    append_rtf_paragraph_text(out, &format!("{}: {name}", slot.role), false, false);
                }
            }
            Block::PageBreak => out.push_str("\\page\n"),
            Block::Rule => append_rtf_rule(out),
        }
    }
}

fn append_rtf_heading(out: &mut String, text: &str, level: u8) {
    let size = match level {
        0 | 1 => 32,
        2 => 28,
        3 => 24,
        _ => 22,
    };
    out.push_str(&format!(
        "\\pard\\sa120\\b\\fs{size} {}\\b0\\fs22\\par\n",
        rtf_escape(text)
    ));
}

fn append_rtf_paragraph_text(out: &mut String, text: &str, bold: bool, italic: bool) {
    out.push_str("\\pard\\sa120 ");
    if bold {
        out.push_str("\\b ");
    }
    if italic {
        out.push_str("\\i ");
    }
    out.push_str(&rtf_escape(text));
    if italic {
        out.push_str("\\i0 ");
    }
    if bold {
        out.push_str("\\b0 ");
    }
    out.push_str("\\par\n");
}

fn append_rtf_paragraph_runs(out: &mut String, runs: &[Run]) {
    if runs_text(runs).trim().is_empty() {
        return;
    }
    out.push_str("\\pard\\sa120 ");
    for run in runs {
        if run.bold {
            out.push_str("\\b ");
        }
        if run.italic {
            out.push_str("\\i ");
        }
        out.push_str(&rtf_escape(&run.text));
        if run.italic {
            out.push_str("\\i0 ");
        }
        if run.bold {
            out.push_str("\\b0 ");
        }
    }
    out.push_str("\\par\n");
}

fn append_rtf_rule(out: &mut String) {
    append_rtf_paragraph_text(out, "----------", false, false);
}

fn rtf_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.replace('\r', "").chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '\n' => out.push_str("\\line "),
            '\t' => out.push_str("\\tab "),
            ch if ch.is_ascii() && !ch.is_control() => out.push(ch),
            ch if ch.is_control() => out.push(' '),
            ch => {
                let mut buf = [0u16; 2];
                for &unit in ch.encode_utf16(&mut buf).iter() {
                    let signed = unit as i16 as i32;
                    out.push_str(&format!("\\u{signed}?"));
                }
            }
        }
    }
    out
}

fn working_copy_odt(
    act_id: ActId,
    doc: &StoredDocument,
    model: &DocumentModel,
) -> Result<Vec<u8>, ApiError> {
    let options = odt_file_options()?;
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in [
        (
            "mimetype",
            b"application/vnd.oasis.opendocument.text".to_vec(),
        ),
        (
            "content.xml",
            odt_content_xml(act_id, doc, model).into_bytes(),
        ),
        ("styles.xml", odt_styles_xml().as_bytes().to_vec()),
        ("meta.xml", odt_meta_xml(model).into_bytes()),
        (
            "META-INF/manifest.xml",
            odt_manifest_xml().as_bytes().to_vec(),
        ),
    ] {
        zip.start_file(name, options)
            .map_err(|e| ApiError::Internal(format!("ODT export failed: {e}")))?;
        zip.write_all(&content)
            .map_err(|e| ApiError::Internal(format!("ODT export failed: {e}")))?;
    }
    let cursor = zip
        .finish()
        .map_err(|e| ApiError::Internal(format!("ODT export failed: {e}")))?;
    Ok(cursor.into_inner())
}

fn odt_content_xml(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut body = String::new();
    body.push_str(&odt_heading("WORKING COPY - NON-EVIDENTIARY", 1));
    body.push_str(&odt_paragraph_text(
        "This OpenDocument Text export is a working copy for review and editing convenience only. It is not the preserved signed original and must not be used as the canonical record.",
    ));
    body.push_str(&odt_heading("Export notice", 2));
    for (term, detail) in working_copy_notice_rows(act_id, doc) {
        body.push_str(&odt_paragraph_text(&format!("{term}: {detail}")));
    }
    body.push_str(&odt_rule());
    body.push_str(&odt_heading(&model.title, 1));
    if !model.subject.trim().is_empty() {
        body.push_str(&odt_styled_paragraph_text(&model.subject, Some("Italic")));
    }
    append_blocks_odt(&mut body, &model.blocks);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" office:version="1.2"><office:automatic-styles><style:style style:name="Bold" style:family="text"><style:text-properties fo:font-weight="bold"/></style:style><style:style style:name="Italic" style:family="text"><style:text-properties fo:font-style="italic"/></style:style><style:style style:name="BoldItalic" style:family="text"><style:text-properties fo:font-weight="bold" fo:font-style="italic"/></style:style><style:style style:name="PageBreak" style:family="paragraph"><style:paragraph-properties fo:break-before="page"/></style:style></office:automatic-styles><office:body><office:text>{body}</office:text></office:body></office:document-content>"#
    )
}

fn append_blocks_odt(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => out.push_str(&odt_heading(text, *level)),
            Block::Paragraph { runs } => out.push_str(&odt_paragraph_runs(runs)),
            Block::KeyValue { rows } => {
                for row in rows {
                    out.push_str(&odt_paragraph_text(&format!("{}: {}", row.key, row.value)));
                }
            }
            Block::VoteTable { rows } => {
                out.push_str(&odt_styled_paragraph_text(
                    "Item | Favor | Against | Abstain",
                    Some("Bold"),
                ));
                for row in rows {
                    out.push_str(&odt_paragraph_text(&format!(
                        "{} | {} | {} | {}",
                        row.label, row.favor, row.against, row.abstain
                    )));
                }
            }
            Block::SignatureBlock { slots } => {
                out.push_str(&odt_heading("Signature slots", 2));
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "________________"
                    } else {
                        slot.name.as_str()
                    };
                    out.push_str(&odt_paragraph_text(&format!("{}: {name}", slot.role)));
                }
            }
            Block::PageBreak => out.push_str(r#"<text:p text:style-name="PageBreak"/>"#),
            Block::Rule => out.push_str(&odt_rule()),
        }
    }
}

fn odt_heading(text: &str, level: u8) -> String {
    format!(
        r#"<text:h text:outline-level="{}">{}</text:h>"#,
        level.clamp(1, 6),
        odt_text(text)
    )
}

fn odt_paragraph_text(text: &str) -> String {
    odt_styled_paragraph_text(text, None)
}

fn odt_styled_paragraph_text(text: &str, style: Option<&str>) -> String {
    match style {
        Some(style) => format!(
            r#"<text:p><text:span text:style-name="{style}">{}</text:span></text:p>"#,
            odt_text(text)
        ),
        None => format!("<text:p>{}</text:p>", odt_text(text)),
    }
}

fn odt_paragraph_runs(runs: &[Run]) -> String {
    if runs_text(runs).trim().is_empty() {
        return String::new();
    }
    let mut out = String::from("<text:p>");
    for run in runs {
        let style = match (run.bold, run.italic) {
            (true, true) => Some("BoldItalic"),
            (true, false) => Some("Bold"),
            (false, true) => Some("Italic"),
            (false, false) => None,
        };
        match style {
            Some(style) => out.push_str(&format!(
                r#"<text:span text:style-name="{style}">{}</text:span>"#,
                odt_text(&run.text)
            )),
            None => out.push_str(&odt_text(&run.text)),
        }
    }
    out.push_str("</text:p>");
    out
}

fn odt_rule() -> String {
    odt_paragraph_text("----------")
}

fn odt_text(value: &str) -> String {
    let mut out = String::new();
    for ch in value.replace('\r', "").chars() {
        match ch {
            '\n' => out.push_str("<text:line-break/>"),
            '\t' => out.push_str("<text:tab/>"),
            ch => out.push_str(&xml_escape(&ch.to_string())),
        }
    }
    out
}

fn odt_styles_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" office:version="1.2"><office:styles><style:default-style style:family="paragraph"><style:paragraph-properties fo:margin-top="0pt" fo:margin-bottom="6pt"/><style:text-properties fo:font-size="11pt"/></style:default-style></office:styles></office:document-styles>"#
}

fn odt_meta_xml(model: &DocumentModel) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" office:version="1.2"><office:meta><dc:title>{}</dc:title><dc:subject>OpenDocument non-evidentiary export</dc:subject><meta:generator>Chancela</meta:generator><meta:keyword>non-evidentiary</meta:keyword><meta:keyword>working copy</meta:keyword><meta:keyword>preserved PDF/A</meta:keyword></office:meta></office:document-meta>"#,
        xml_escape(&model.title)
    )
}

fn odt_manifest_xml() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="META-INF/manifest.xml" manifest:media-type="text/xml"/></manifest:manifest>"#
}

fn odt_file_options() -> Result<SimpleFileOptions, ApiError> {
    package_file_options("ODT")
}

fn working_copy_notice_rows(act_id: ActId, doc: &StoredDocument) -> [(String, String); 6] {
    [
        (
            "Status".to_owned(),
            "working copy, non-evidentiary".to_owned(),
        ),
        ("Act ID".to_owned(), act_id.to_string()),
        ("Preserved document ID".to_owned(), doc.id.clone()),
        ("Template".to_owned(), doc.template_id.clone()),
        ("Preserved PDF digest".to_owned(), doc.pdf_digest.clone()),
        (
            "Preserved original".to_owned(),
            "Use the stored PDF/A or signed PDF endpoint".to_owned(),
        ),
    ]
}

fn append_blocks_html(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => {
                let level = (*level).clamp(1, 6);
                out.push_str(&format!("<h{level}>"));
                out.push_str(&html_escape(text));
                out.push_str(&format!("</h{level}>"));
            }
            Block::Paragraph { runs } => {
                if runs_text(runs).trim().is_empty() {
                    continue;
                }
                out.push_str("<p>");
                for run in runs {
                    append_run_html(out, run);
                }
                out.push_str("</p>");
            }
            Block::KeyValue { rows } => {
                out.push_str("<table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>");
                for row in rows {
                    out.push_str("<tr><td>");
                    out.push_str(&html_escape(&row.key));
                    out.push_str("</td><td>");
                    out.push_str(&html_escape(&row.value));
                    out.push_str("</td></tr>");
                }
                out.push_str("</tbody></table>");
            }
            Block::VoteTable { rows } => {
                out.push_str("<table><thead><tr><th>Item</th><th>Favor</th><th>Against</th><th>Abstain</th></tr></thead><tbody>");
                for row in rows {
                    out.push_str("<tr><td>");
                    out.push_str(&html_escape(&row.label));
                    out.push_str("</td><td>");
                    out.push_str(&row.favor.to_string());
                    out.push_str("</td><td>");
                    out.push_str(&row.against.to_string());
                    out.push_str("</td><td>");
                    out.push_str(&row.abstain.to_string());
                    out.push_str("</td></tr>");
                }
                out.push_str("</tbody></table>");
            }
            Block::SignatureBlock { slots } => {
                out.push_str("<section><h2>Signature slots</h2><ul>");
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "blank"
                    } else {
                        slot.name.as_str()
                    };
                    out.push_str("<li><strong>");
                    out.push_str(&html_escape(&slot.role));
                    out.push_str("</strong>: ");
                    out.push_str(&html_escape(name));
                    out.push_str("</li>");
                }
                out.push_str("</ul></section>");
            }
            Block::PageBreak => out.push_str("<div data-page-break=\"true\"></div>"),
            Block::Rule => out.push_str("<hr>"),
        }
    }
}

fn append_run_html(out: &mut String, run: &Run) {
    match (run.bold, run.italic) {
        (true, true) => {
            out.push_str("<strong><em>");
            out.push_str(&html_escape(&run.text));
            out.push_str("</em></strong>");
        }
        (true, false) => {
            out.push_str("<strong>");
            out.push_str(&html_escape(&run.text));
            out.push_str("</strong>");
        }
        (false, true) => {
            out.push_str("<em>");
            out.push_str(&html_escape(&run.text));
            out.push_str("</em>");
        }
        (false, false) => out.push_str(&html_escape(&run.text)),
    }
}

fn append_blocks_markdown(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => {
                let level = (*level).clamp(1, 6) as usize;
                out.push_str(&format!(
                    "{} {}\n\n",
                    "#".repeat(level),
                    escape_markdown_text(text)
                ));
            }
            Block::Paragraph { runs } => {
                let paragraph = runs_markdown(runs);
                if !paragraph.trim().is_empty() {
                    out.push_str(paragraph.trim());
                    out.push_str("\n\n");
                }
            }
            Block::KeyValue { rows } => {
                out.push_str("| Field | Value |\n| --- | --- |\n");
                for row in rows {
                    out.push_str(&format!(
                        "| {} | {} |\n",
                        escape_markdown_table_cell(&row.key),
                        escape_markdown_table_cell(&row.value)
                    ));
                }
                out.push('\n');
            }
            Block::VoteTable { rows } => {
                out.push_str(
                    "| Item | Favor | Against | Abstain |\n| --- | ---: | ---: | ---: |\n",
                );
                for row in rows {
                    out.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        escape_markdown_table_cell(&row.label),
                        row.favor,
                        row.against,
                        row.abstain
                    ));
                }
                out.push('\n');
            }
            Block::SignatureBlock { slots } => {
                out.push_str("## Signature slots\n\n");
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "_blank_".to_owned()
                    } else {
                        escape_markdown_text(&slot.name)
                    };
                    out.push_str(&format!(
                        "- {}: {}\n",
                        escape_markdown_text(&slot.role),
                        name
                    ));
                }
                out.push('\n');
            }
            Block::PageBreak => out.push_str("<!-- page break -->\n\n"),
            Block::Rule => out.push_str("---\n\n"),
        }
    }
}

fn runs_markdown(runs: &[Run]) -> String {
    runs.iter()
        .map(|run| {
            let text = escape_markdown_text(&run.text);
            match (run.bold, run.italic) {
                (true, true) => format!("***{text}***"),
                (true, false) => format!("**{text}**"),
                (false, true) => format!("*{text}*"),
                (false, false) => text,
            }
        })
        .collect()
}

fn escape_markdown_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('#', "\\#")
}

fn escape_markdown_table_cell(value: &str) -> String {
    escape_markdown_text(value)
        .replace('|', "\\|")
        .replace('\r', "")
        .replace('\n', "<br>")
}

fn office_docx(
    act_id: ActId,
    doc: &StoredDocument,
    model: &DocumentModel,
) -> Result<Vec<u8>, ApiError> {
    let options = docx_file_options()?;
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in [
        ("[Content_Types].xml", docx_content_types().to_owned()),
        ("_rels/.rels", docx_root_relationships().to_owned()),
        ("docProps/core.xml", docx_core_properties(model)),
        ("docProps/app.xml", docx_app_properties().to_owned()),
        ("word/document.xml", docx_document_xml(act_id, doc, model)),
    ] {
        zip.start_file(name, options)
            .map_err(|e| ApiError::Internal(format!("DOCX export failed: {e}")))?;
        zip.write_all(content.as_bytes())
            .map_err(|e| ApiError::Internal(format!("DOCX export failed: {e}")))?;
    }
    let cursor = zip
        .finish()
        .map_err(|e| ApiError::Internal(format!("DOCX export failed: {e}")))?;
    Ok(cursor.into_inner())
}

fn docx_file_options() -> Result<SimpleFileOptions, ApiError> {
    package_file_options("DOCX")
}

fn package_file_options(kind: &str) -> Result<SimpleFileOptions, ApiError> {
    let timestamp = DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
        .map_err(|e| ApiError::Internal(format!("{kind} timestamp initialization failed: {e}")))?;
    Ok(SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(timestamp))
}

fn docx_content_types() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#
}

fn docx_root_relationships() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"#
}

fn docx_core_properties(model: &DocumentModel) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>{}</dc:title><dc:subject>Office-editable non-evidentiary export</dc:subject><dc:creator>Chancela</dc:creator><cp:keywords>non-evidentiary; working copy; preserved PDF/A</cp:keywords><dc:description>Generated from preserved Chancela document metadata. This DOCX is not the evidentiary record.</dc:description><cp:lastModifiedBy>Chancela</cp:lastModifiedBy><cp:revision>1</cp:revision></cp:coreProperties>"#,
        xml_escape(&model.title)
    )
}

fn docx_app_properties() -> &'static str {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Chancela</Application><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><Company>Chancela</Company></Properties>"#
}

fn docx_document_xml(act_id: ActId, doc: &StoredDocument, model: &DocumentModel) -> String {
    let mut body = String::new();
    body.push_str(&docx_heading("WORKING COPY - NON-EVIDENTIARY", 1));
    body.push_str(&docx_paragraph_text(
        "This office-editable DOCX is for review and drafting convenience only. It is not the preserved signed original and must not be used as the canonical record.",
        false,
        false,
    ));
    body.push_str(&docx_table(&[
        vec![
            "Status".to_owned(),
            "working copy, non-evidentiary".to_owned(),
        ],
        vec!["Act ID".to_owned(), act_id.to_string()],
        vec!["Preserved document ID".to_owned(), doc.id.clone()],
        vec!["Template".to_owned(), doc.template_id.clone()],
        vec!["Preserved PDF digest".to_owned(), doc.pdf_digest.clone()],
        vec![
            "Preserved original".to_owned(),
            "Use the stored PDF/A or signed PDF endpoint".to_owned(),
        ],
    ]));
    body.push_str(&docx_rule());
    body.push_str(&docx_heading(&model.title, 1));
    if !model.subject.trim().is_empty() {
        body.push_str(&docx_paragraph_text(&model.subject, false, true));
    }
    append_blocks_docx(&mut body, &model.blocks);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>"#
    )
}

fn append_blocks_docx(out: &mut String, blocks: &[Block]) {
    for block in blocks {
        match block {
            Block::Heading { level, text } => out.push_str(&docx_heading(text, *level)),
            Block::Paragraph { runs } => out.push_str(&docx_paragraph_runs(runs)),
            Block::KeyValue { rows } => {
                let table_rows: Vec<Vec<String>> = rows
                    .iter()
                    .map(|row| vec![row.key.clone(), row.value.clone()])
                    .collect();
                out.push_str(&docx_table(&table_rows));
            }
            Block::VoteTable { rows } => {
                let mut table_rows = vec![vec![
                    "Item".to_owned(),
                    "Favor".to_owned(),
                    "Against".to_owned(),
                    "Abstain".to_owned(),
                ]];
                table_rows.extend(rows.iter().map(|row| {
                    vec![
                        row.label.clone(),
                        row.favor.to_string(),
                        row.against.to_string(),
                        row.abstain.to_string(),
                    ]
                }));
                out.push_str(&docx_table(&table_rows));
            }
            Block::SignatureBlock { slots } => {
                out.push_str(&docx_heading("Signature slots", 2));
                for slot in slots {
                    let name = if slot.name.trim().is_empty() {
                        "________________".to_owned()
                    } else {
                        slot.name.clone()
                    };
                    out.push_str(&docx_paragraph_text(
                        &format!("{}: {name}", slot.role),
                        false,
                        false,
                    ));
                }
            }
            Block::PageBreak => out.push_str(r#"<w:p><w:r><w:br w:type="page"/></w:r></w:p>"#),
            Block::Rule => out.push_str(&docx_rule()),
        }
    }
}

fn docx_heading(text: &str, level: u8) -> String {
    let size = match level {
        0 | 1 => 32,
        2 => 28,
        3 => 24,
        _ => 22,
    };
    format!(
        r#"<w:p><w:pPr><w:spacing w:before="160" w:after="120"/></w:pPr>{}</w:p>"#,
        docx_run(text, true, false, Some(size))
    )
}

fn docx_paragraph_text(text: &str, bold: bool, italic: bool) -> String {
    format!(
        r#"<w:p><w:pPr><w:spacing w:after="120"/></w:pPr>{}</w:p>"#,
        docx_run(text, bold, italic, None)
    )
}

fn docx_paragraph_runs(runs: &[Run]) -> String {
    let mut out = String::from(r#"<w:p><w:pPr><w:spacing w:after="120"/></w:pPr>"#);
    if runs.is_empty() {
        out.push_str(&docx_run("", false, false, None));
    } else {
        for run in runs {
            out.push_str(&docx_run(&run.text, run.bold, run.italic, None));
        }
    }
    out.push_str("</w:p>");
    out
}

fn docx_rule() -> String {
    docx_paragraph_text("----------", false, false)
}

fn docx_table(rows: &[Vec<String>]) -> String {
    let mut out = String::from(
        r#"<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/></w:tblBorders></w:tblPr>"#,
    );
    for row in rows {
        out.push_str("<w:tr>");
        for cell in row {
            out.push_str("<w:tc><w:tcPr><w:tcW w:w=\"2400\" w:type=\"dxa\"/></w:tcPr>");
            out.push_str(&docx_paragraph_text(cell, false, false));
            out.push_str("</w:tc>");
        }
        out.push_str("</w:tr>");
    }
    out.push_str("</w:tbl>");
    out
}

fn docx_run(text: &str, bold: bool, italic: bool, size: Option<u16>) -> String {
    let mut out = String::from("<w:r>");
    if bold || italic || size.is_some() {
        out.push_str("<w:rPr>");
        if bold {
            out.push_str("<w:b/>");
        }
        if italic {
            out.push_str("<w:i/>");
        }
        if let Some(size) = size {
            out.push_str(&format!(r#"<w:sz w:val="{size}"/>"#));
        }
        out.push_str("</w:rPr>");
    }
    let clean = text.replace('\r', "");
    let mut parts = clean.split('\n').peekable();
    while let Some(part) = parts.next() {
        out.push_str(r#"<w:t xml:space="preserve">"#);
        out.push_str(&xml_escape(part));
        out.push_str("</w:t>");
        if parts.peek().is_some() {
            out.push_str("<w:br/>");
        }
    }
    out.push_str("</w:r>");
    out
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn html_escape(value: &str) -> String {
    xml_escape(value)
}

fn is_ata_template(template_id: &str) -> bool {
    registry()
        .get(template_id)
        .is_some_and(|spec| spec.stage == LifecycleStage::Ata)
}

fn first_ata_document(docs: impl IntoIterator<Item = StoredDocument>) -> Option<StoredDocument> {
    docs.into_iter()
        .find(|doc| is_ata_template(&doc.template_id))
}

/// Fetch the canonical persisted document for an owner. For real acts this is the sealed Ata (the
/// first generated Ata row), so later certidão/extrato generation cannot change signing/download/
/// bundle targets. Book instruments (termos keyed by book id cast to `ActId`) keep the historical
/// newest-by-owner lookup.
pub(crate) async fn load_document(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<StoredDocument>, ApiError> {
    let is_real_act = state.acts.read().await.contains_key(&act_id);
    if is_real_act {
        if let Some(store) = &state.store {
            let docs = store
                .documents_for_act(act_id)
                .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")))?;
            return Ok(first_ata_document(docs));
        }
        return Ok(state
            .documents
            .read()
            .await
            .get(&act_id)
            .cloned()
            .filter(|doc| is_ata_template(&doc.template_id)));
    }

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
/// attachments manifest, and a local technical validation report. The report is evidence-only:
/// it checks stored bytes/metadata consistency and never certifies legal validity, PDF conformance,
/// qualified-signature status, DGLAB status, or production LTV.
#[derive(Serialize)]
pub struct DocumentBundle {
    pub act_id: String,
    pub document: BundleDocumentMeta,
    pub pdf: BundlePdfRef,
    pub attachments_manifest: Vec<BundleAttachment>,
    pub validation_report: DocumentBundleValidationReport,
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

#[derive(Serialize)]
pub struct DocumentBundleValidationReport {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub status: &'static str,
    pub evidence_index: DocumentBundleEvidenceIndex,
    pub legal_notice: &'static str,
    pub bundle_document_consistency: BundleDocumentConsistencyReport,
    pub canonical_pdf: BundleCanonicalPdfReport,
    pub fixity: BundleFixityReport,
    pub signed_document: BundleSignedDocumentReport,
    pub non_certification: BundleNonCertificationReport,
    pub findings: Vec<DocumentValidationFinding>,
}

#[derive(Serialize)]
pub struct DocumentBundleEvidenceIndex {
    pub index_kind: &'static str,
    pub status_scope: &'static str,
    pub document_id: String,
    pub act_id: String,
    pub bundle_paths: DocumentBundleEvidencePaths,
    pub external_validator_reports: DocumentBundleExternalValidatorReportIndex,
}

#[derive(Serialize)]
pub struct DocumentBundleEvidencePaths {
    pub canonical_pdf_download: String,
    pub signed_pdf_download: Option<String>,
    pub attachments_manifest_json_pointer: &'static str,
    pub validation_report_json_pointer: &'static str,
}

#[derive(Serialize)]
pub struct DocumentBundleExternalValidatorReportIndex {
    pub evidence_kind: &'static str,
    pub metadata_schema: &'static str,
    pub archive_path_prefix: &'static str,
    pub archive_path_pattern: &'static str,
    pub bundle_attachment_status: &'static str,
    pub status_scope: &'static str,
    pub attachments: Vec<DocumentBundleExternalValidatorReportAttachment>,
}

#[derive(Serialize)]
pub struct DocumentBundleExternalValidatorReportAttachment {
    pub case_id: String,
    pub validator_family: String,
    pub archive_path: String,
    pub content_type: String,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct BundleDocumentConsistencyReport {
    pub route_act_id: String,
    pub stored_document_act_id: String,
    pub act_id_matches_document: bool,
    pub document_id_present: bool,
    pub template_id_present: bool,
    pub created_at_present: bool,
    pub profile_matches_expected: bool,
    pub attachments_manifest_count: usize,
}

#[derive(Serialize)]
pub struct BundleCanonicalPdfReport {
    pub present: bool,
    pub media_type: &'static str,
    pub byte_length: usize,
    pub download: String,
    pub pdf_header_present: bool,
    pub version: Option<String>,
    pub eof_marker_present: bool,
    pub startxref_present: bool,
    pub pdfa_identification_markers_present: bool,
}

#[derive(Serialize)]
pub struct BundleFixityReport {
    pub canonical_pdf_sha256: String,
    pub stored_pdf_digest: String,
    pub canonical_pdf_digest_matches_metadata: bool,
    pub attachment_count: usize,
    pub attachments_with_digest: usize,
    pub attachments_without_digest: usize,
    pub signed_pdf_sha256: Option<String>,
    pub stored_signed_pdf_digest: Option<String>,
    pub signed_pdf_digest_matches_metadata: Option<bool>,
}

#[derive(Serialize)]
pub struct BundleSignedDocumentReport {
    pub present: bool,
    pub status: &'static str,
    pub document_id: Option<String>,
    pub document_id_matches_canonical: Option<bool>,
    pub byte_length: Option<usize>,
    pub signed_pdf_digest: Option<String>,
    pub signed_pdf_digest_matches_metadata: Option<bool>,
    pub download: Option<String>,
    pub signing_time: Option<String>,
    pub signed_at: Option<String>,
    pub stored_signature_family: Option<String>,
    pub stored_evidentiary_level: Option<String>,
    pub trusted_list_status: Option<String>,
    pub signer_cert_subject_present: Option<bool>,
    pub timestamp_token_present: Option<bool>,
    pub structural_validation: Option<SignedPdfSignalReport>,
}

#[derive(Serialize)]
pub struct BundleNonCertificationReport {
    pub legal_validity_claimed: bool,
    pub pdfa_conformance_certified: bool,
    pub pdfua_conformance_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub production_ltv_claimed: bool,
    pub trust_provider_validation_performed: bool,
}

fn document_bundle_evidence_index(
    act_id: ActId,
    doc: &StoredDocument,
    signed: Option<&StoredSignedDocument>,
) -> DocumentBundleEvidenceIndex {
    DocumentBundleEvidenceIndex {
        index_kind: "document_bundle_evidence_index",
        status_scope: TECHNICAL_METADATA_ONLY,
        document_id: doc.id.clone(),
        act_id: act_id.to_string(),
        bundle_paths: DocumentBundleEvidencePaths {
            canonical_pdf_download: format!("/v1/acts/{act_id}/document"),
            signed_pdf_download: signed.map(|_| format!("/v1/acts/{act_id}/document/signed")),
            attachments_manifest_json_pointer: "/attachments_manifest",
            validation_report_json_pointer: "/validation_report",
        },
        external_validator_reports: DocumentBundleExternalValidatorReportIndex {
            evidence_kind: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND,
            metadata_schema: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA,
            archive_path_prefix: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX,
            archive_path_pattern: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN,
            bundle_attachment_status: "no_external_validator_report_metadata_attached",
            status_scope: TECHNICAL_METADATA_ONLY,
            attachments: Vec::new(),
        },
    }
}

fn build_document_bundle_validation_report(
    act_id: ActId,
    doc: &StoredDocument,
    pdf: &BundlePdfRef,
    attachments_manifest: &[BundleAttachment],
    signed: Option<&StoredSignedDocument>,
) -> DocumentBundleValidationReport {
    let canonical_pdf_sha256 = sha256_hex(&doc.pdf_bytes);
    let canonical_pdf_digest_matches_metadata = canonical_pdf_sha256 == doc.pdf_digest;
    let pdf_recognition = recognize_pdf(&doc.pdf_bytes);
    let attachments_with_digest = attachments_manifest
        .iter()
        .filter(|att| att.digest.is_some())
        .count();
    let attachments_without_digest = attachments_manifest.len() - attachments_with_digest;
    let profile_matches_expected = doc.profile == PDFA_PROFILE;
    let act_id_matches_document = doc.act_id == act_id;
    let created_at = doc.created_at.format(&Rfc3339).unwrap_or_default();

    let mut findings = Vec::new();
    if !act_id_matches_document {
        findings.push(DocumentValidationFinding::error(
            "bundle_document_act_id_mismatch",
            "stored document act_id does not match the bundle route act id",
        ));
    }
    if doc.id.trim().is_empty() {
        findings.push(DocumentValidationFinding::error(
            "bundle_document_id_missing",
            "stored document id is empty",
        ));
    }
    if doc.template_id.trim().is_empty() {
        findings.push(DocumentValidationFinding::error(
            "bundle_template_id_missing",
            "stored document template_id is empty",
        ));
    }
    if created_at.is_empty() {
        findings.push(DocumentValidationFinding::warning(
            "bundle_document_created_at_unavailable",
            "stored document created_at could not be formatted as RFC 3339",
        ));
    }
    if !profile_matches_expected {
        findings.push(DocumentValidationFinding::warning(
            "canonical_pdf_profile_unexpected",
            format!(
                "stored document profile is {:?}; expected {:?}; this is not a PDF/A conformance certification",
                doc.profile, PDFA_PROFILE
            ),
        ));
    }
    if doc.pdf_bytes.is_empty() {
        findings.push(DocumentValidationFinding::error(
            "canonical_pdf_missing",
            "stored canonical PDF bytes are empty",
        ));
    }
    if !pdf_recognition.is_pdf && !doc.pdf_bytes.is_empty() {
        findings.push(DocumentValidationFinding::error(
            "canonical_pdf_not_pdf",
            "stored canonical PDF bytes do not expose a PDF header in the first 1024 bytes",
        ));
    }
    if pdf_recognition.is_pdf && !pdf_recognition.has_eof_marker {
        findings.push(DocumentValidationFinding::warning(
            "canonical_pdf_missing_eof",
            "stored canonical PDF has a PDF header but no %%EOF marker",
        ));
    }
    if pdf_recognition.is_pdf && !pdf_recognition.has_startxref {
        findings.push(DocumentValidationFinding::warning(
            "canonical_pdf_missing_startxref",
            "stored canonical PDF has no startxref marker",
        ));
    }
    if !canonical_pdf_digest_matches_metadata {
        findings.push(DocumentValidationFinding::error(
            "canonical_pdf_digest_mismatch",
            format!(
                "stored pdf_digest does not match canonical PDF bytes: metadata {}, actual {}",
                doc.pdf_digest, canonical_pdf_sha256
            ),
        ));
    }
    if attachments_without_digest > 0 {
        let message = if attachments_without_digest == 1 {
            "1 attachment manifest entry lacks digest evidence".to_owned()
        } else {
            format!("{attachments_without_digest} attachment manifest entries lack digest evidence")
        };
        findings.push(DocumentValidationFinding::warning(
            "attachment_digest_missing",
            message,
        ));
    }

    let (signed_document, signed_pdf_sha256, stored_signed_pdf_digest, signed_pdf_matches) =
        match signed {
            Some(signed) => {
                let mut signed_findings = Vec::new();
                let signed_pdf_sha256 = sha256_hex(&signed.signed_pdf_bytes);
                let signed_pdf_matches = signed_pdf_sha256 == signed.signed_pdf_digest;
                let document_id_matches_canonical = signed.document_id == doc.id;
                let structural_validation = recognize_signed_pdf(&signed.signed_pdf_bytes);

                if !document_id_matches_canonical {
                    signed_findings.push(DocumentValidationFinding::error(
                        "signed_document_id_mismatch",
                        "stored signed document does not reference the canonical document id",
                    ));
                }
                if signed.signed_pdf_bytes.is_empty() {
                    signed_findings.push(DocumentValidationFinding::error(
                        "signed_pdf_missing",
                        "stored signed PDF bytes are empty",
                    ));
                } else if !recognize_pdf(&signed.signed_pdf_bytes).is_pdf {
                    signed_findings.push(DocumentValidationFinding::error(
                        "signed_pdf_not_pdf",
                        "stored signed PDF bytes do not expose a PDF header in the first 1024 bytes",
                    ));
                }
                if !signed_pdf_matches {
                    signed_findings.push(DocumentValidationFinding::error(
                        "signed_pdf_digest_mismatch",
                        format!(
                            "stored signed_pdf_digest does not match signed PDF bytes: metadata {}, actual {}",
                            signed.signed_pdf_digest, signed_pdf_sha256
                        ),
                    ));
                }
                if signed.signed_at < signed.signing_time {
                    signed_findings.push(DocumentValidationFinding::warning(
                        "signed_document_time_order_unexpected",
                        "stored signed_at is earlier than signing_time",
                    ));
                }
                match structural_validation.validation_status {
                    "valid_pades_b" => {}
                    "unsigned" => signed_findings.push(DocumentValidationFinding::warning(
                        "signed_pdf_signature_signal_absent",
                        "a signed-document row exists, but local PDF inspection found no signature markers",
                    )),
                    "structurally_signed" => signed_findings.push(DocumentValidationFinding::warning(
                        "signed_pdf_structural_only",
                        "signature markers are present, but local inspection did not establish a valid PAdES-B signature",
                    )),
                    "invalid" => signed_findings.push(DocumentValidationFinding::error(
                        "signed_pdf_invalid",
                        structural_validation
                            .validation_error
                            .clone()
                            .unwrap_or_else(|| "local signed PDF validation failed".to_owned()),
                    )),
                    "indeterminate" => signed_findings.push(DocumentValidationFinding::warning(
                        "signed_pdf_indeterminate",
                        structural_validation
                            .validation_error
                            .clone()
                            .unwrap_or_else(|| {
                                "local signed PDF validation could not reach a conclusion"
                                    .to_owned()
                            }),
                    )),
                    _ => {}
                }

                let status = report_status(&signed_findings);
                findings.extend(signed_findings);
                (
                    BundleSignedDocumentReport {
                        present: true,
                        status,
                        document_id: Some(signed.document_id.clone()),
                        document_id_matches_canonical: Some(document_id_matches_canonical),
                        byte_length: Some(signed.signed_pdf_bytes.len()),
                        signed_pdf_digest: Some(signed.signed_pdf_digest.clone()),
                        signed_pdf_digest_matches_metadata: Some(signed_pdf_matches),
                        download: Some(format!("/v1/acts/{act_id}/document/signed")),
                        signing_time: Some(
                            signed.signing_time.format(&Rfc3339).unwrap_or_default(),
                        ),
                        signed_at: Some(signed.signed_at.format(&Rfc3339).unwrap_or_default()),
                        stored_signature_family: Some(signed.signature_family.clone()),
                        stored_evidentiary_level: Some(signed.evidentiary_level.clone()),
                        trusted_list_status: signed.trusted_list_status.clone(),
                        signer_cert_subject_present: Some(signed.signer_cert_subject.is_some()),
                        timestamp_token_present: Some(signed.timestamp_token_der.is_some()),
                        structural_validation: Some(structural_validation),
                    },
                    Some(signed_pdf_sha256),
                    Some(signed.signed_pdf_digest.clone()),
                    Some(signed_pdf_matches),
                )
            }
            None => {
                findings.push(DocumentValidationFinding::warning(
                    "signed_document_missing",
                    "no signed PDF variant is present in local storage; no signature, qualified-status, legal-validity, or production-LTV conclusion is claimed",
                ));
                (
                    BundleSignedDocumentReport {
                        present: false,
                        status: "not_present",
                        document_id: None,
                        document_id_matches_canonical: None,
                        byte_length: None,
                        signed_pdf_digest: None,
                        signed_pdf_digest_matches_metadata: None,
                        download: None,
                        signing_time: None,
                        signed_at: None,
                        stored_signature_family: None,
                        stored_evidentiary_level: None,
                        trusted_list_status: None,
                        signer_cert_subject_present: None,
                        timestamp_token_present: None,
                        structural_validation: None,
                    },
                    None,
                    None,
                    None,
                )
            }
        };

    DocumentBundleValidationReport {
        report_kind: "document_bundle_validation",
        scope: "generated_document_bundle",
        status: report_status(&findings),
        evidence_index: document_bundle_evidence_index(act_id, doc, signed),
        legal_notice: DOCUMENT_BUNDLE_VALIDATION_NOTICE,
        bundle_document_consistency: BundleDocumentConsistencyReport {
            route_act_id: act_id.to_string(),
            stored_document_act_id: doc.act_id.to_string(),
            act_id_matches_document,
            document_id_present: !doc.id.trim().is_empty(),
            template_id_present: !doc.template_id.trim().is_empty(),
            created_at_present: !created_at.is_empty(),
            profile_matches_expected,
            attachments_manifest_count: attachments_manifest.len(),
        },
        canonical_pdf: BundleCanonicalPdfReport {
            present: !doc.pdf_bytes.is_empty(),
            media_type: pdf.media_type,
            byte_length: pdf.byte_length,
            download: pdf.download.clone(),
            pdf_header_present: pdf_recognition.is_pdf,
            version: pdf_recognition.version,
            eof_marker_present: pdf_recognition.has_eof_marker,
            startxref_present: pdf_recognition.has_startxref,
            pdfa_identification_markers_present: pdf_recognition.pdfa.is_pdfa_ish,
        },
        fixity: BundleFixityReport {
            canonical_pdf_sha256,
            stored_pdf_digest: doc.pdf_digest.clone(),
            canonical_pdf_digest_matches_metadata,
            attachment_count: attachments_manifest.len(),
            attachments_with_digest,
            attachments_without_digest,
            signed_pdf_sha256,
            stored_signed_pdf_digest,
            signed_pdf_digest_matches_metadata: signed_pdf_matches,
        },
        signed_document,
        non_certification: BundleNonCertificationReport {
            legal_validity_claimed: false,
            pdfa_conformance_certified: false,
            pdfua_conformance_claimed: false,
            qualified_signature_claimed: false,
            dglab_certification_claimed: false,
            production_ltv_claimed: false,
            trust_provider_validation_performed: false,
        },
        findings,
    }
}

async fn load_signed_document_for_bundle(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<StoredSignedDocument>, ApiError> {
    if let Some(doc) = state.signed_documents.read().await.get(&act_id).cloned() {
        return Ok(Some(doc));
    }
    if let Some(store) = &state.store {
        return store
            .signed_document_for_act(act_id)
            .map_err(|e| ApiError::Internal(format!("signed document store read failed: {e}")));
    }
    Ok(None)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    crate::hex::hex(&digest)
}

fn report_status(findings: &[DocumentValidationFinding]) -> &'static str {
    if findings.iter().any(|finding| finding.severity == "error") {
        "technical_error"
    } else if findings.iter().any(|finding| finding.severity == "warning") {
        "technical_warning"
    } else {
        "technical_consistent"
    }
}

/// `GET /v1/acts/{id}/document/bundle` — the DOC-03 preservation bundle (PDF ref + metadata +
/// attachments manifest + technical validation report). `404` until sealed.
pub async fn get_document_bundle(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<DocumentBundle>, ApiError> {
    let act_id = ActId(id);
    // RBAC (t64-E3): reading an act's preservation bundle is `act.read` scoped to its book.
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let doc = load_document(&state, act_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Attachments manifest from the owning act (absent for a book instrument → empty manifest).
    let attachments_manifest: Vec<BundleAttachment> = {
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
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let signed = load_signed_document_for_bundle(&state, act_id).await?;
    let pdf = BundlePdfRef {
        media_type: "application/pdf",
        byte_length: doc.pdf_bytes.len(),
        download: format!("/v1/acts/{id}/document"),
    };
    let validation_report = build_document_bundle_validation_report(
        act_id,
        &doc,
        &pdf,
        &attachments_manifest,
        signed.as_ref(),
    );

    Ok(Json(DocumentBundle {
        act_id: act_id.to_string(),
        document: BundleDocumentMeta {
            id: doc.id.clone(),
            template_id: doc.template_id.clone(),
            pdf_digest: doc.pdf_digest.clone(),
            profile: doc.profile.clone(),
            created_at: doc.created_at.format(&Rfc3339).unwrap_or_default(),
        },
        pdf,
        attachments_manifest,
        validation_report,
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
    pub channels: Vec<MeetingChannel>,
    pub signature_policy: SignaturePolicyHint,
    pub rule_pack_id: String,
    pub law_references: Vec<TemplateLawReference>,
    pub locale: String,
}

impl From<&TemplateSpec> for TemplateSummary {
    fn from(s: &TemplateSpec) -> Self {
        TemplateSummary {
            id: s.id.clone(),
            family: s.family,
            stage: s.stage,
            channels: s.channels.clone(),
            signature_policy: s.signature_policy,
            rule_pack_id: s.rule_pack_id.clone(),
            law_references: s.law_references.clone(),
            locale: s.locale.clone(),
        }
    }
}

/// `GET /v1/templates?family=&stage=` — available template summaries for the picker. Both filters
/// optional. The summary mirrors the catalog metadata authors put in the template asset:
/// family/stage binding, channel tags, signature-policy hint, rule-pack id, and locale.
pub async fn list_templates(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<TemplatesQuery>,
) -> Result<Json<Vec<TemplateSummary>>, ApiError> {
    // RBAC (t64-E3): the template catalog is `act.read` at Global (drives ata drafting).
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
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
    Ok(Json(summaries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path as FsPath, PathBuf};
    use std::str::FromStr;
    use std::time::Duration as StdDuration;

    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
    use chancela_cades::{
        RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
    };
    use chancela_core::book::ClosingReason;
    use chancela_core::{
        ActState, AgendaItem, AttendanceWeight, Attendee, Book, BookKind, Convening,
        DispatchChannel, Entity, EntityKind, KvRow, MeetingChannel, Nipc, PresenceMode, SecondCall,
        SignatoryCapacity, SignatureSlot, VoteRow,
    };
    use der::Encode;
    use der::asn1::{Any, BitString, ObjectIdentifier};
    use time::format_description::well_known::Rfc3339;
    use time::macros::{date, time};
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::Validity;

    use crate::users::{User, UserId};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-api-documents-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temp dir created");
            TempDir { path }
        }

        fn path(&self) -> &FsPath {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

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

    async fn seed_owner(state: &AppState) -> CurrentActor {
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let username = "document.owner".to_owned();
        let user = User {
            id: uid,
            username: username.clone(),
            display_name: "Document Owner".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);
        CurrentActor::from_session_username(Some(username))
    }

    fn sealed_csc_act(book: &Book) -> Act {
        let mut act = Act::draft(
            book.id,
            "Ata da assembleia geral anual",
            MeetingChannel::Physical,
        );
        act.meeting_date = Some(date!(2026 - 03 - 30));
        act.meeting_time = Some(time!(10:00));
        act.place = Some("Sede social".to_owned());
        act.mesa.presidente = Some("Ana Presidente".to_owned());
        act.mesa.secretarios = vec!["Rui Secretário".to_owned()];
        act.agenda = vec![AgendaItem {
            number: 1,
            text: "Aprovação das contas".to_owned(),
        }];
        act.attendance_reference = Some("Lista de presenças".to_owned());
        act.deliberations = "Aprovadas as contas do exercício.".to_owned();
        act.state = ActState::Sealed;
        act.ata_number = Some(1);
        act.payload_digest = Some([7u8; 32]);
        act.seal_event_seq = Some(2);
        act
    }

    fn minimal_pdf() -> Vec<u8> {
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nstartxref\n0\n%%EOF\n".to_vec()
    }

    fn legacy_doc_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..OLE_CFB_MAGIC.len()].copy_from_slice(OLE_CFB_MAGIC);
        let word_stream = b"WordDocument";
        bytes[64..64 + word_stream.len()].copy_from_slice(word_stream);
        let vba_marker = b"VBA project marker";
        bytes[128..128 + vba_marker.len()].copy_from_slice(vba_marker);
        bytes
    }

    fn png_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PNG_MAGIC);
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[8, 2, 0, 0, 0]);
        bytes.extend_from_slice(&[0x90, 0x77, 0x53, 0xde]);
        bytes
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, bytes) in entries {
            zip.start_file(*name, opts).expect("start zip member");
            zip.write_all(bytes).expect("write zip member");
        }
        zip.finish().expect("finish zip").into_inner()
    }

    fn signable_pdf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
        let objects = [
            (1u32, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            ),
        ];
        let mut offsets = Vec::new();
        for (id, body) in objects {
            offsets.push((id, buf.len()));
            buf.extend_from_slice(format!("{id} 0 obj\n{body}\nendobj\n").as_bytes());
        }
        let xref_off = buf.len();
        buf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f\r\n");
        for id in 1..=3 {
            let off = offsets
                .iter()
                .find(|(object_id, _)| *object_id == id)
                .map(|(_, offset)| *offset)
                .unwrap();
            buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }
        buf.extend_from_slice(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
                .as_bytes(),
        );
        buf
    }

    fn signed_pades_pdf() -> Vec<u8> {
        const OID_SHA256_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];

        fn sign_rsa_digest_info(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
            let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
            digest_info.extend_from_slice(digest);
            key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
                .expect("rsa sign")
        }

        use rsa::rand_core::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let name = Name::from_str("CN=Document Import Test").expect("name");
        let validity =
            Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[1]).expect("serial"),
            signature: sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let tbs_der = tbs.to_der().expect("tbs der");
        let signature = sign_rsa_digest_info(&key, &Sha256::digest(&tbs_der).into());
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&signature).expect("bitstring"),
        };
        let cert_der = cert.to_der().expect("cert der");

        chancela_pades::sign_pdf(
            &signable_pdf(),
            &chancela_pades::SignOptions::default(),
            |digest| {
                let signing_time =
                    OffsetDateTime::from_unix_timestamp(1_750_000_000).expect("fixed signing time");
                let attrs = signed_attributes_digest(digest, &cert_der, signing_time)?;
                let raw = RawSignature::new(
                    SignatureAlgorithm::RsaPkcs1Sha256,
                    sign_rsa_digest_info(&key, &attrs),
                    cert_der.clone(),
                    vec![],
                );
                assemble_cades_b(&raw, digest, signing_time)
            },
        )
        .expect("signed pdf")
    }

    fn has_finding(report: &DocumentImportValidationReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    fn assert_imported_review_guardrails(policy: &DocumentPreservationPolicyReport) {
        assert_eq!(policy.canonical_record_status, "not_canonical_record");
        assert_eq!(policy.signed_artifact_status, "not_signed_artifact");
        assert_eq!(
            policy.review_guardrail_checklist,
            imported_document_review_guardrail_checklist()
        );
    }

    fn assert_imported_review_guardrail_payload(payload: &Value) {
        assert_eq!(payload["canonical_record_status"], "not_canonical_record");
        assert_eq!(payload["signed_artifact_status"], "not_signed_artifact");
        assert_eq!(
            payload["review_guardrail_checklist"],
            json!(imported_document_review_guardrail_checklist())
        );
    }

    fn report_sha256(bytes: &[u8]) -> String {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        crate::hex::hex(&digest)
    }

    fn export_fixture() -> (ActId, StoredDocument, DocumentModel) {
        let act_id = ActId(Uuid::new_v4());
        let doc = StoredDocument {
            id: "doc-fixture".to_owned(),
            act_id,
            template_id: "csc-ata-ag/v1".to_owned(),
            pdf_digest: "ab".repeat(32),
            profile: PDFA_PROFILE.to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            pdf_bytes: b"%PDF-1.7\nfixture\n%%EOF\n".to_vec(),
        };
        let model = DocumentModel {
            title: "Ata <Especial>".to_owned(),
            entity_name: "Encosto Estratégico, S.A.".to_owned(),
            entity_nipc: Some("503004642".to_owned()),
            subject: "Revisão & aprovação".to_owned(),
            language: "pt-PT".to_owned(),
            created_at: Some("2026-03-30T10:00:00Z".to_owned()),
            blocks: vec![
                Block::Heading {
                    level: 2,
                    text: "Deliberação <1>".to_owned(),
                },
                Block::Paragraph {
                    runs: vec![
                        Run {
                            text: "Aprovado por ".to_owned(),
                            bold: false,
                            italic: false,
                        },
                        Run {
                            text: "<script>alert(1)</script>".to_owned(),
                            bold: true,
                            italic: false,
                        },
                    ],
                },
                Block::KeyValue {
                    rows: vec![KvRow {
                        key: "Local".to_owned(),
                        value: "Lisboa & Porto".to_owned(),
                    }],
                },
                Block::VoteTable {
                    rows: vec![VoteRow {
                        label: "Ponto 1".to_owned(),
                        favor: 3,
                        against: 1,
                        abstain: 0,
                    }],
                },
                Block::SignatureBlock {
                    slots: vec![SignatureSlot {
                        role: "Presidente da mesa".to_owned(),
                        name: "".to_owned(),
                    }],
                },
            ],
        };
        (act_id, doc, model)
    }

    #[test]
    fn text_working_copy_renders_from_model_with_notice_metadata_and_body() {
        let (act_id, doc, model) = export_fixture();

        let text = working_copy_text(act_id, &doc, &model);

        assert!(text.contains("WORKING COPY - NON-EVIDENTIARY"));
        assert!(text.contains("plain-text export"));
        assert!(text.contains("Status: working copy, non-evidentiary"));
        assert!(text.contains(&doc.id));
        assert!(text.contains(&doc.pdf_digest));
        assert!(text.contains("Ata <Especial>"));
        assert!(text.contains("Aprovado por <script>alert(1)</script>"));
        assert!(text.contains("Local: Lisboa & Porto"));
        assert!(
            !text.starts_with("%PDF-"),
            "working-copy TXT is not canonical PDF bytes"
        );
    }

    #[test]
    fn html_working_copy_escapes_model_text_and_labels_non_evidentiary() {
        let (act_id, doc, model) = export_fixture();

        let html = working_copy_html(act_id, &doc, &model);

        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("WORKING COPY - NON-EVIDENTIARY"));
        assert!(html.contains("HTML export"));
        assert!(html.contains("working copy, non-evidentiary"));
        assert!(html.contains(&doc.id));
        assert!(html.contains(&doc.pdf_digest));
        assert!(html.contains("Ata &lt;Especial&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "HTML export must escape model text"
        );
        assert!(
            !html.starts_with("%PDF-"),
            "working-copy HTML is not canonical PDF bytes"
        );
    }

    #[test]
    fn document_import_rejects_path_like_filename() {
        assert!(validate_import_filename(Some("../secret.pdf".to_owned())).is_err());
        assert!(validate_import_filename(Some("folder\\secret.pdf".to_owned())).is_err());
        assert!(validate_import_filename(Some("C:\\secret.pdf".to_owned())).is_err());
        assert_eq!(
            validate_import_filename(Some(" evidence.pdf ".to_owned())).unwrap(),
            Some("evidence.pdf".to_owned())
        );
    }

    #[test]
    fn document_import_ledger_payload_is_metadata_only() {
        let meta = StoredImportedDocumentMeta {
            id: "11111111-1111-4111-8111-111111111111".to_owned(),
            act_id: Some(ActId(Uuid::new_v4())),
            filename: Some("access-code-secret.pdf".to_owned()),
            declared_content_type: Some("application/pdf".to_owned()),
            detected_content_type: "application/pdf".to_owned(),
            sha256: "ab".repeat(32),
            size_bytes: 42,
            imported_at: time::OffsetDateTime::UNIX_EPOCH,
            imported_by: "document.owner".to_owned(),
            operator_review_status: StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            operator_reviewed_at: None,
            operator_reviewed_by: None,
            operator_review_note: None,
        };

        let payload = imported_document_event_payload(&meta);
        let text = serde_json::to_string(&payload).expect("payload serializes");

        assert!(text.contains(&meta.sha256));
        assert!(text.contains("\"bytes_in_payload\":false"));
        assert!(!text.contains("access-code-secret.pdf"));
        assert!(!text.contains("access_code"));
        assert!(!text.contains("%PDF"));
        assert!(!text.contains("document.owner"));
    }

    #[test]
    fn guest_imported_document_metadata_redacts_filename_digest_importer_and_download() {
        let meta = StoredImportedDocumentMeta {
            id: "11111111-1111-4111-8111-111111111112".to_owned(),
            act_id: Some(ActId(Uuid::new_v4())),
            filename: Some("medical-report-joana.pdf".to_owned()),
            declared_content_type: Some("application/pdf".to_owned()),
            detected_content_type: "application/pdf".to_owned(),
            sha256: "cd".repeat(32),
            size_bytes: 2048,
            imported_at: time::OffsetDateTime::UNIX_EPOCH,
            imported_by: "amelia.marques".to_owned(),
            operator_review_status: StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            operator_reviewed_at: None,
            operator_reviewed_by: None,
            operator_review_note: None,
        };

        let view = imported_document_view_with_redaction(&meta, ReadRedaction::Guest);
        assert_eq!(view.filename, None);
        assert_eq!(view.sha256, crate::dto::REDACTED);
        assert_eq!(view.imported_by, crate::dto::REDACTED);
        assert_eq!(view.bytes_download, crate::dto::REDACTED);
        let raw = serde_json::to_string(&view).expect("imported document view JSON");
        assert!(!raw.contains("medical-report-joana.pdf"));
        assert!(!raw.contains("amelia.marques"));
        assert!(!raw.contains(&"cd".repeat(32)));
    }

    #[test]
    fn document_import_validation_reports_empty_body() {
        let report = validate_document_candidate(b"", None, None);

        assert_eq!(report.size_bytes, 0);
        assert_eq!(report.content_type.detected, "application/octet-stream");
        assert!(!report.pdf.is_pdf);
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "empty_body"));
    }

    #[test]
    fn document_import_validation_rejects_oversized_candidate() {
        let oversized = vec![b'x'; DOCUMENT_IMPORT_VALIDATION_MAX_BYTES + 1];

        let report = validate_document_candidate(&oversized, Some("application/pdf"), None);

        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "document_too_large"));
    }

    #[test]
    fn document_import_validation_reports_non_pdf_bytes() {
        let report = validate_document_candidate(
            b"this is not a PDF",
            Some("text/plain; charset=utf-8"),
            None,
        );

        assert_eq!(report.content_type.detected, "application/octet-stream");
        assert!(!report.pdf.is_pdf);
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "unsupported_document_family"));
    }

    #[test]
    fn document_import_validation_accepts_png_as_non_canonical_evidence() {
        let png = png_bytes();

        let report =
            validate_document_candidate(&png, Some("image/png"), Some("scan-page.png".to_owned()));

        assert_eq!(report.content_type.detected, "image/png");
        assert_eq!(report.classification.family, "image");
        assert_eq!(
            report.classification.classification,
            "image_non_canonical_evidence"
        );
        assert!(report.image.is_image);
        assert_eq!(report.image.format, Some("png"));
        assert_eq!(report.image.width, Some(1));
        assert_eq!(report.image.height, Some(1));
        assert!(report.can_accept_non_canonical_import);
        assert_imported_review_guardrails(&report.preservation_policy);
        assert!(has_finding(&report, "non_canonical_import_only"));
        assert!(has_finding(&report, "image_no_pdfa_conversion"));
        assert!(!report.image.conversion_performed);
        assert!(!report.image.canonical_pdfa_generated);
    }

    #[test]
    fn document_import_validation_accepts_xml_and_csv_text_as_non_canonical_evidence() {
        let xml = br#"<?xml version="1.0"?><minutes><item>Aprovado</item></minutes>"#;
        let csv = b"ata,deliberacao\n1,aprovado\n";

        let xml_report =
            validate_document_candidate(xml, Some("application/xml"), Some("extract.xml".into()));
        let csv_report =
            validate_document_candidate(csv, Some("text/csv"), Some("extract.csv".into()));

        assert_eq!(xml_report.content_type.detected, "application/xml");
        assert_eq!(xml_report.classification.family, "xml_text");
        assert!(xml_report.text.is_supported_text);
        assert_eq!(xml_report.text.kind, Some("xml"));
        assert!(xml_report.can_accept_non_canonical_import);
        assert!(has_finding(
            &xml_report,
            "text_no_structure_or_pdfa_conversion"
        ));

        assert_eq!(csv_report.content_type.detected, "text/csv");
        assert_eq!(csv_report.classification.family, "csv_text");
        assert!(csv_report.text.is_supported_text);
        assert_eq!(csv_report.text.kind, Some("csv"));
        assert!(csv_report.can_accept_non_canonical_import);
        assert!(has_finding(&csv_report, "non_canonical_import_only"));
        assert!(!csv_report.text.structure_validation_performed);
        assert!(!csv_report.text.canonical_pdfa_generated);
    }

    #[test]
    fn document_import_validation_accepts_safe_zip_bundle_without_extraction() {
        let zip = zip_bytes(&[
            ("manifest.json", br#"{"kind":"support"}"#),
            ("evidence/page-1.txt", b"page one"),
        ]);

        let report = validate_document_candidate(
            &zip,
            Some("application/zip"),
            Some("supporting-evidence.zip".to_owned()),
        );

        assert_eq!(report.content_type.detected, "application/zip");
        assert_eq!(report.classification.family, "zip_bundle");
        assert!(report.zip_bundle.is_zip);
        assert!(report.zip_bundle.readable);
        assert_eq!(report.zip_bundle.entry_count, 2);
        assert_eq!(report.zip_bundle.unsafe_entry_count, 0);
        assert!(!report.zip_bundle.extraction_performed);
        assert!(report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "zip_bundle_detected"));
        assert!(has_finding(&report, "zip_not_extracted"));
    }

    #[test]
    fn document_import_validation_rejects_zip_traversal_and_absolute_paths() {
        let traversal = zip_bytes(&[("../secret.txt", b"secret")]);
        let absolute = zip_bytes(&[("/absolute.txt", b"secret")]);
        let windows_absolute = zip_bytes(&[("C:\\absolute.txt", b"secret")]);

        for zip in [traversal, absolute, windows_absolute] {
            let report = validate_document_candidate(&zip, Some("application/zip"), None);

            assert_eq!(report.content_type.detected, "application/zip");
            assert!(report.zip_bundle.is_zip);
            assert!(report.zip_bundle.unsafe_entry_count > 0);
            assert!(!report.can_accept_non_canonical_import);
            assert!(has_finding(&report, "zip_unsafe_entry_name"));
        }
    }

    #[test]
    fn document_import_validation_accepts_legacy_doc_as_non_canonical_evidence() {
        let doc = legacy_doc_bytes();

        let report = validate_document_candidate(
            &doc,
            Some("application/msword"),
            Some("board-minutes.doc".to_owned()),
        );

        assert_eq!(report.content_type.detected, "application/msword");
        assert_eq!(report.content_type.declared_matches_detected, Some(true));
        assert!(!report.pdf.is_pdf);
        assert!(report.legacy_word.is_ole_cfb);
        assert!(report.legacy_word.is_legacy_word_doc);
        assert!(report.legacy_word.filename_extension_doc);
        assert!(report.legacy_word.declared_content_type_msword);
        assert!(!report.legacy_word.macro_execution_performed);
        assert!(!report.legacy_word.conversion_performed);
        assert!(!report.legacy_word.canonical_pdfa_generated);
        assert_eq!(report.signature.validation_status, "unsigned");
        assert!(report.can_accept_non_canonical_import);
        assert_imported_review_guardrails(&report.preservation_policy);
        assert!(has_finding(&report, "legacy_word_doc_detected"));
        assert!(has_finding(&report, "legacy_word_no_macro_execution"));
        assert!(has_finding(&report, "legacy_word_no_pdfa_conversion"));
        assert!(!has_finding(&report, "not_pdf"));
    }

    #[test]
    fn document_import_validation_rejects_ambiguous_ole_cfb_pdf_claim() {
        let mut doc = legacy_doc_bytes();
        doc.extend_from_slice(b"\n%PDF-1.7\nstartxref\n0\n%%EOF\n");

        let report = validate_document_candidate(
            &doc,
            Some("application/pdf"),
            Some("board-minutes.pdf".to_owned()),
        );

        assert_eq!(report.content_type.detected, "application/vnd.ms-office");
        assert_eq!(report.content_type.declared_matches_detected, Some(false));
        assert!(report.pdf.is_pdf);
        assert!(report.legacy_word.is_ole_cfb);
        assert!(!report.legacy_word.is_legacy_word_doc);
        assert!(report.legacy_word.filename_extension_conflict);
        assert!(report.legacy_word.declared_content_type_conflict);
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "legacy_word_ambiguous_pdf"));
        assert!(has_finding(&report, "legacy_word_filename_conflict"));
        assert!(has_finding(&report, "legacy_word_content_type_conflict"));
    }

    #[test]
    fn document_import_validation_reports_pdf_header_without_eof() {
        let report = validate_document_candidate(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n", None, None);

        assert!(report.pdf.is_pdf);
        assert_eq!(report.pdf.version.as_deref(), Some("1.7"));
        assert!(!report.pdf.has_eof_marker);
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "pdf_missing_eof"));
    }

    #[test]
    fn document_import_validation_flags_signed_pdf_with_incomplete_byte_range() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Sig /ByteRange [0 12 40 3] /Contents <00> >>\nendobj\nstartxref\n0\n%%EOF\n";

        let report = validate_document_candidate(pdf, Some("application/pdf"), None);

        assert!(report.pdf.is_pdf);
        assert!(report.signature.signed_pdf_signal);
        assert_eq!(report.signature.validation_status, "indeterminate");
        assert_eq!(report.signature.byte_range, Some([0, 12, 40, 3]));
        assert_eq!(report.signature.byte_range_complete, Some(false));
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "signed_pdf_incomplete_byte_range"));
        assert!(
            report.signature.cryptographic_validation_performed,
            "PAdES validator should be attempted when signature markers are present"
        );
    }

    #[test]
    fn document_import_validation_reports_valid_pades_b_with_byte_range_digest() {
        let pdf = signed_pades_pdf();
        let report = validate_document_candidate(&pdf, Some("application/pdf"), None);

        assert!(report.can_accept_non_canonical_import);
        assert_eq!(report.signature.validation_status, "valid_pades_b");
        assert_eq!(report.signature.pades_profile, Some("PAdES-B-B"));
        assert!(report.signature.byte_range_digest_sha256.is_some());
        assert!(report.signature.cryptographic_validation_performed);
        assert!(has_finding(&report, "valid_pades_b"));
    }

    #[test]
    fn document_import_validation_fails_closed_on_truncated_byte_range() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Sig /ByteRange [0 12 40] /Contents <00> >>\nendobj\nstartxref\n0\n%%EOF\n";

        let report = validate_document_candidate(pdf, Some("application/pdf"), None);

        assert_eq!(report.signature.validation_status, "indeterminate");
        assert_eq!(report.signature.byte_range, None);
        assert_eq!(report.signature.byte_range_complete, Some(false));
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "signed_pdf_incomplete_byte_range"));
    }

    #[test]
    fn document_import_validation_fails_closed_on_multiple_signature_markers() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Sig /ByteRange [0 10 20 5] /Contents <00> >>\nendobj\n2 0 obj\n<< /Type /Sig /ByteRange [0 10 20 5] /Contents <00> >>\nendobj\nstartxref\n0\n%%EOF\n";

        let report = validate_document_candidate(pdf, Some("application/pdf"), None);

        assert!(report.signature.signature_marker_count > 1);
        assert!(report.signature.byte_range_marker_count > 1);
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(
            &report,
            "signed_pdf_multiple_signature_markers"
        ));
    }

    #[test]
    fn document_import_validation_rejects_mismatched_declared_digest() {
        let pdf = minimal_pdf();
        let report = validate_document_candidate_with_fixity(
            &pdf,
            Some("application/pdf"),
            None,
            Some("00".repeat(32)),
            Some(pdf.len()),
        );

        assert_eq!(report.fixity.sha256_matches_declared, Some(false));
        assert_eq!(report.fixity.size_matches_declared, Some(true));
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "declared_sha256_mismatch"));
    }

    #[test]
    fn document_import_validation_rejects_declared_small_payload() {
        let pdf = minimal_pdf();
        let report = validate_document_candidate_with_fixity(
            &pdf,
            Some("application/pdf"),
            None,
            Some(report_sha256(&pdf)),
            Some(1),
        );

        assert_eq!(report.fixity.sha256_matches_declared, Some(true));
        assert_eq!(report.fixity.size_matches_declared, Some(false));
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "declared_size_mismatch"));
    }

    #[test]
    fn document_import_validation_rejects_signed_pdf_digest_mismatch() {
        let mut pdf = signed_pades_pdf();
        pdf[11] ^= 0xff;

        let report = validate_document_candidate(&pdf, Some("application/pdf"), None);

        assert_eq!(report.signature.validation_status, "invalid");
        assert!(!report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "signed_pdf_invalid"));
    }

    #[test]
    fn document_import_validation_warns_on_duplicate_or_odd_pdfa_metadata() {
        let pdf = b"%PDF-1.7\n<x:xmpmeta><pdfaid:part>2</pdfaid:part><pdfaid:part>999</pdfaid:part><pdfaid:conformance>Z</pdfaid:conformance></x:xmpmeta>\nstartxref\n0\n%%EOF\n";

        let report = validate_document_candidate(pdf, Some("application/pdf"), None);

        assert!(report.can_accept_non_canonical_import);
        assert!(report.pdf.pdfa.is_pdfa_ish);
        assert!(report.pdf.pdfa.duplicate_metadata);
        assert!(report.pdf.pdfa.odd_metadata);
        assert!(has_finding(&report, "pdfa_duplicate_metadata"));
        assert!(has_finding(&report, "pdfa_odd_metadata"));
    }

    #[tokio::test]
    async fn document_import_validation_accepts_json_base64_without_mutation() {
        let state = AppState::default();
        let actor = seed_owner(&state).await;
        let pdf = minimal_pdf();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("content-type"),
        );
        let body = json!({
            "filename": "incoming.pdf",
            "content_type": "application/pdf",
            "content_base64": B64.encode(&pdf),
        });

        let Json(report) = validate_document_import(
            State(state.clone()),
            actor,
            headers,
            Bytes::from(body.to_string()),
        )
        .await
        .expect("validation succeeds");

        assert_eq!(report.filename.as_deref(), Some("incoming.pdf"));
        assert_eq!(
            report.content_type.declared.as_deref(),
            Some("application/pdf")
        );
        assert_eq!(report.content_type.detected, "application/pdf");
        assert!(report.can_accept_non_canonical_import);
        assert_eq!(state.documents.read().await.len(), 0);
        assert!(
            state.ledger.read().await.events().is_empty(),
            "validation is read-only and must not append ledger events"
        );
    }

    #[tokio::test]
    async fn document_import_preserves_legacy_doc_as_non_canonical_evidence() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let doc = legacy_doc_bytes();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("content-type"),
        );
        let body = json!({
            "filename": "board-minutes.doc",
            "content_type": "application/msword",
            "content_base64": B64.encode(&doc),
        });

        let (status, Json(imported)) = import_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            headers,
            Bytes::from(body.to_string()),
        )
        .await
        .expect("legacy DOC import succeeds");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(imported.filename.as_deref(), Some("board-minutes.doc"));
        assert_eq!(
            imported.declared_content_type.as_deref(),
            Some("application/msword")
        );
        assert_eq!(imported.detected_content_type, "application/msword");
        assert_eq!(imported.size_bytes, doc.len());
        assert!(imported.non_canonical);
        assert_eq!(imported.canonical_record_status, "not_canonical_record");
        assert_eq!(imported.signed_artifact_status, "not_signed_artifact");
        assert_eq!(
            imported.review_guardrail_checklist,
            imported_document_review_guardrail_checklist()
        );
        assert_imported_review_guardrails(&imported.preservation_policy);
        assert!(imported.legal_notice.contains("does not replace"));
        assert!(
            state.documents.read().await.is_empty(),
            "legacy DOC import must not create or replace canonical PDF/A documents"
        );

        let stored = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("imported doc stored");
        assert_eq!(stored.bytes, doc);
        assert_eq!(stored.meta.detected_content_type, "application/msword");

        let event = state
            .ledger
            .read()
            .await
            .events()
            .last()
            .expect("document.imported event")
            .clone();
        assert_eq!(event.kind, "document.imported");

        let response = get_imported_document_bytes(
            State(state.clone()),
            Path(imported.id.clone()),
            actor.clone(),
        )
        .await
        .expect("legacy DOC bytes stream");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/msword")
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|value| value.contains(".doc\""))
        );
        let downloaded = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("download body");
        assert_eq!(downloaded.as_ref(), stored.bytes.as_slice());
    }

    #[tokio::test]
    async fn imported_document_review_transition_is_metadata_only_and_honest() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let doc = legacy_doc_bytes();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("content-type"),
        );
        let body = json!({
            "filename": "board-minutes.doc",
            "content_type": "application/msword",
            "content_base64": B64.encode(&doc),
        });

        let (_, Json(imported)) = import_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            headers,
            Bytes::from(body.to_string()),
        )
        .await
        .expect("legacy DOC import succeeds");
        assert_eq!(
            imported.operator_review_status,
            "canonical_conversion_review_required"
        );
        assert!(!imported.canonical_conversion_performed);
        assert!(!imported.legal_acceptance_claimed);
        assert_imported_review_guardrails(&imported.preservation_policy);

        let before = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("imported doc stored");
        let review_note = "Reviewed only as preserved non-canonical evidence.".to_owned();
        let Json(reviewed) = review_imported_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(imported.id.clone()),
            Json(ImportedDocumentReviewRequest {
                review_status: "reviewed_non_canonical_original_only".to_owned(),
                review_note: Some(review_note.clone()),
            }),
        )
        .await
        .expect("review transition succeeds");

        assert_eq!(
            reviewed.operator_review_status,
            "reviewed_non_canonical_original_only"
        );
        assert_eq!(
            reviewed.operator_reviewed_by.as_deref(),
            Some("document.owner")
        );
        assert_eq!(
            reviewed.operator_review_note.as_deref(),
            Some(review_note.as_str())
        );
        assert!(!reviewed.preservation_policy.requires_operator_review);
        assert_eq!(
            reviewed.preservation_policy.canonical_conversion_status,
            "not_performed_non_canonical_original_only"
        );
        assert!(!reviewed.canonical_conversion_performed);
        assert!(!reviewed.preservation_policy.canonical_conversion_performed);
        assert!(!reviewed.legal_acceptance_claimed);
        assert!(!reviewed.preservation_policy.legal_acceptance_claimed);
        assert_eq!(reviewed.canonical_record_status, "not_canonical_record");
        assert_eq!(reviewed.signed_artifact_status, "not_signed_artifact");
        assert_imported_review_guardrails(&reviewed.preservation_policy);
        assert!(state.documents.read().await.is_empty());

        let after = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("reviewed import stored");
        assert_eq!(after.bytes, before.bytes);
        assert_eq!(
            after.meta.operator_review_status,
            StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly
        );

        let event = state
            .ledger
            .read()
            .await
            .events()
            .last()
            .expect("document.imported.review_updated event")
            .clone();
        assert_eq!(event.kind, "document.imported.review_updated");

        let payload = imported_document_review_event_payload(
            &before.meta,
            StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly,
            "document.owner",
        );
        assert_eq!(
            payload["previous_operator_review_status"],
            before.meta.operator_review_status.as_str()
        );
        assert_eq!(
            payload["operator_review_status"],
            "reviewed_non_canonical_original_only"
        );
        assert_eq!(payload["ocr_performed"], false);
        assert_imported_review_guardrail_payload(&payload);
        assert_eq!(payload["canonical_conversion_performed"], false);
        assert_eq!(payload["canonical_pdfa_generated"], false);
        assert_eq!(payload["legal_acceptance_claimed"], false);
        assert_eq!(payload["legal_validity_claimed"], false);
        assert_eq!(payload["review_note_in_payload"], false);
        let payload_text = serde_json::to_string(&payload).expect("payload serializes");
        assert!(!payload_text.contains(&review_note));
    }

    #[test]
    fn imported_document_review_status_rejects_legal_acceptance_wording() {
        assert!(parse_imported_document_review_status("accepted").is_err());
        assert!(parse_imported_document_review_status("legal_acceptance_claimed").is_err());
    }

    #[tokio::test]
    async fn document_import_preserves_png_as_act_scoped_non_canonical_evidence() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let act = sealed_csc_act(&book);
        let act_id = act.id;
        {
            let mut ledger = state.ledger.write().await;
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &entity.id.to_string(),
                "entity.created",
                None,
                b"entity",
            )
            .expect("entity genesis");
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &format!("entity:{}/book:{}", entity.id, book.id),
                "book.opened",
                None,
                b"book",
            )
            .expect("book genesis");
            let events = ledger.events().to_vec();
            state
                .store
                .as_ref()
                .expect("store")
                .persist(|tx| {
                    for event in &events {
                        tx.append_event(event)?;
                    }
                    tx.upsert_entity(&entity)?;
                    tx.upsert_book(&book)?;
                    tx.upsert_act(&act)
                })
                .expect("seed persisted");
        }
        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act_id, act);

        let png = png_bytes();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("content-type"),
        );
        let body = json!({
            "act_id": act_id.to_string(),
            "filename": "scan-page.png",
            "content_type": "image/png",
            "content_base64": B64.encode(&png),
        });

        let (status, Json(imported)) = import_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            headers,
            Bytes::from(body.to_string()),
        )
        .await
        .expect("PNG import succeeds");

        assert_eq!(status, StatusCode::CREATED);
        let act_id_string = act_id.to_string();
        assert_eq!(imported.act_id.as_deref(), Some(act_id_string.as_str()));
        assert_eq!(imported.detected_content_type, "image/png");
        assert_eq!(imported.evidence_family, "image");
        assert_eq!(imported.classification, "image_non_canonical_evidence");
        assert_eq!(imported.size_bytes, png.len());
        assert_eq!(
            imported.bytes_download,
            format!("/v1/documents/imported/{}/bytes", imported.id)
        );
        assert!(imported.non_canonical);
        assert_imported_review_guardrails(&imported.preservation_policy);
        assert!(state.documents.read().await.is_empty());

        let event = state
            .ledger
            .read()
            .await
            .events()
            .last()
            .expect("document.imported event")
            .clone();
        assert_eq!(event.kind, "document.imported");
        assert!(event.scope.contains(&format!("act:{act_id}")));
        assert!(
            event
                .scope
                .contains(&format!("imported-document:{}", imported.id))
        );

        let stored = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("imported PNG stored");
        assert_eq!(stored.bytes, png);
        assert_eq!(stored.meta.sha256, imported.sha256);
        assert_eq!(stored.meta.detected_content_type, "image/png");

        let payload = imported_document_event_payload(&stored.meta);
        assert_eq!(payload["evidence_family"], "image");
        assert_eq!(payload["classification"], "image_non_canonical_evidence");
        assert_imported_review_guardrail_payload(&payload);
        assert_eq!(payload["canonical_conversion_performed"], false);
        assert_eq!(payload["canonical_pdfa_generated"], false);
        assert_eq!(payload["legal_validity_claimed"], false);

        let response =
            get_imported_document_bytes(State(state.clone()), Path(imported.id.clone()), actor)
                .await
                .expect("PNG bytes stream");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|value| value.contains(".png\""))
        );
        let downloaded = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("download body");
        assert_eq!(downloaded.as_ref(), stored.bytes.as_slice());
    }

    #[tokio::test]
    async fn document_import_rejects_unsafe_zip_without_partial_mutation() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let zip = zip_bytes(&[("../secret.txt", b"secret")]);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("content-type"),
        );
        let body = json!({
            "filename": "unsafe.zip",
            "content_type": "application/zip",
            "content_base64": B64.encode(&zip),
        });
        let ledger_before = state.ledger.read().await.len();

        let err = import_document(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            headers,
            Bytes::from(body.to_string()),
        )
        .await
        .expect_err("unsafe ZIP import is rejected");

        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("zip_unsafe_entry_name"))
        );
        assert_eq!(state.ledger.read().await.len(), ledger_before);
        assert!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .all(|event| event.kind != "document.imported")
        );
        assert!(
            state
                .store
                .as_ref()
                .expect("store")
                .imported_documents(None)
                .expect("import list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn certidao_generation_does_not_replace_canonical_ata_document() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let book = Book::new(entity.id, BookKind::AssembleiaGeral);
        let act = sealed_csc_act(&book);
        let ata = generate_for_act(&act, &entity, None)
            .expect("ata generation ok")
            .expect("ata document");
        let ata_id = ata.stored.id.clone();
        let ata_digest = ata.stored.pdf_digest.clone();

        {
            let mut ledger = state.ledger.write().await;
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &entity.id.to_string(),
                "entity.created",
                None,
                b"entity",
            )
            .expect("entity genesis");
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &format!("entity:{}/book:{}", entity.id, book.id),
                "book.opened",
                None,
                b"book",
            )
            .expect("book genesis");
            let events = ledger.events().to_vec();
            state
                .store
                .as_ref()
                .expect("store")
                .persist(|tx| {
                    for event in &events {
                        tx.append_event(event)?;
                    }
                    tx.upsert_entity(&entity)?;
                    tx.upsert_book(&book)?;
                    tx.upsert_act(&act)?;
                    tx.upsert_document(&ata.stored)
                })
                .expect("seed persisted");
        }
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act.clone());
        state
            .documents
            .write()
            .await
            .insert(act.id, ata.stored.clone());

        let response = generate_document(
            State(state.clone()),
            Path(act.id.0),
            actor,
            CurrentAttestor::default(),
            Query(GenerateQuery {
                template_id: "csc-certidao-ata/v1".to_owned(),
            }),
        )
        .await
        .expect("certidao generation succeeds");
        assert_eq!(response.status(), StatusCode::CREATED);

        let rows = state
            .store
            .as_ref()
            .expect("store")
            .documents_for_act(act.id)
            .expect("documents read");
        assert_eq!(rows.len(), 2, "ata + certidao rows are both preserved");
        assert!(
            rows.iter()
                .any(|doc| doc.template_id == "csc-certidao-ata/v1"),
            "certidao row was generated"
        );

        let live_slot = state
            .documents
            .read()
            .await
            .get(&act.id)
            .expect("live canonical doc")
            .clone();
        assert_eq!(live_slot.id, ata_id);

        let loaded = load_document(&state, act.id)
            .await
            .expect("load ok")
            .expect("canonical doc");
        assert_eq!(loaded.id, ata_id);
        assert_eq!(loaded.pdf_digest, ata_digest);
        assert_eq!(loaded.template_id, "csc-ata-ag/v1");

        let restarted = AppState::with_data_dir(tmp.path());
        let loaded_after_restart = load_document(&restarted, act.id)
            .await
            .expect("reload load ok")
            .expect("canonical doc after restart");
        assert_eq!(loaded_after_restart.id, ata_id);
        assert_eq!(loaded_after_restart.pdf_digest, ata_digest);
        assert_eq!(loaded_after_restart.template_id, "csc-ata-ag/v1");
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
            evidence_reference: Some("doc:convocatoria-condominio".to_string()),
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
        assert_eq!(
            ctx["convening"]["evidence_reference"],
            "doc:convocatoria-condominio"
        );
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
    fn template_summary_exposes_structured_law_references() {
        let csc =
            default_spec(EntityFamily::CommercialCompany, LifecycleStage::Ata).expect("csc spine");
        let csc_summary = TemplateSummary::from(csc);
        assert!(csc_summary.law_references.iter().any(|r| {
            r.source == chancela_templates::TemplateLawReferenceSource::RulePack
                && r.source_id == "csc"
                && r.article.as_deref() == Some("63")
                && r.citation == "Código das Sociedades Comerciais, Artigo 63.º"
        }));

        let condominium = default_spec(EntityFamily::Condominium, LifecycleStage::Ata)
            .expect("condominium spine");
        let condominium_summary = TemplateSummary::from(condominium);
        assert!(condominium_summary.law_references.iter().any(|r| {
            r.source == chancela_templates::TemplateLawReferenceSource::ThresholdRegistry
                && r.threshold_id.as_deref() == Some("condominio.deliberacao.maioria_permilagem")
                && r.citation == "CC art. 1432.º"
        }));

        let association = default_spec(EntityFamily::Association, LifecycleStage::Ata)
            .expect("association spine");
        let association_summary = TemplateSummary::from(association);
        assert!(association_summary.law_references.iter().any(|r| {
            r.threshold_id.as_deref() == Some("assoc.convocatoria_maioria")
                && r.citation == "CC arts. 173.º e 175.º"
                && r.verification == chancela_templates::TemplateLawReferenceVerification::Pending
        }));
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
