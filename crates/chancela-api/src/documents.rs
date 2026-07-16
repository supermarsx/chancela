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

use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
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
    Act, ActId, ActState, Block, Book, BookKind, Convening, DispatchChannel, DocumentModel, Entity,
    EntityFamily, LifecycleStage, MeetingChannel, NumberingScheme, PresenceMode, Run,
    SignaturePolicyHint, TermoDeAbertura, TermoDeEncerramento,
};
use chancela_signing::{
    BaselineProfile, EvidentiaryLevel, SignatureArtifact, SignatureFormat, SigningFamily,
    validate_asic_container, validate_signature,
};
use chancela_store::{
    StoredDocument, StoredGeneratedDocumentDispatchEvidence, StoredImportedDocument,
    StoredImportedDocumentMeta, StoredImportedDocumentReviewHistoryEntry,
    StoredImportedDocumentReviewStatus, StoredSignedDocument,
};
use chancela_templates::authoring::{TemplateValidationError, validate_user_template};
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
use crate::external_validator_evidence::{
    EXTERNAL_VALIDATOR_RAW_REPORT_ARCHIVE_PATH_PATTERN,
    EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN, EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX,
    EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND, EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA,
    ExternalValidatorEvidenceAttachment, ExternalValidatorRawReportAttachmentIndex,
    TECHNICAL_METADATA_ONLY, attachment_indexes, matching_attachments,
};

/// The frozen PDF/A profile string bound into every `document.generated` event and stored row
/// (plan §1-D4 step 3 / §3.4). Self-describing: MIME type + PDF/A part+conformance.
pub(crate) const PDFA_PROFILE: &str = "application/pdf; profile=PDF/A-2u";

/// Post-act communication automatically generated for absent condominium owners after sealing.
pub(crate) const CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID: &str =
    "condominio-comunicacao-ausentes/v1";

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
/// Hard in-memory extraction limits for untrusted office/bundle evidence. Extraction is inspection
/// only: no member is written to disk or promoted to a canonical document.
const DOCUMENT_CONTAINER_MAX_MEMBERS: usize = 256;
const DOCUMENT_CONTAINER_MAX_MEMBER_BYTES: u64 = 8 * 1024 * 1024;
const DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES: u64 = 32 * 1024 * 1024;
const DOCUMENT_MAIL_MAX_HEADER_BYTES: usize = 64 * 1024;
const DOCUMENT_MAIL_MAX_HEADERS: usize = 200;
const DOCUMENT_MAIL_MAX_PARTS: usize = 128;
const DOCUMENT_MAIL_MAX_DEPTH: usize = 4;
const DOCUMENT_MAIL_MAX_BOUNDARY_BYTES: usize = 200;

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
pub(crate) const PDF_ACCESSIBILITY_EVIDENCE_KIND: &str = "pdf_accessibility_report";
pub(crate) const PDF_ACCESSIBILITY_EVIDENCE_SCHEMA: &str = "chancela-pdf-accessibility-evidence/v1";
pub(crate) const PDF_ACCESSIBILITY_ARCHIVE_PATH_PREFIX: &str = "evidence/pdf-accessibility/";
pub(crate) const PDF_ACCESSIBILITY_ARCHIVE_PATH_PATTERN: &str =
    "evidence/pdf-accessibility/{document_id}.json";
pub(crate) const PDF_ACCESSIBILITY_REPORT_ATTACHED: &str = "pdf_accessibility_report_attached";
pub(crate) const PDF_ACCESSIBILITY_REPORT_UNAVAILABLE: &str =
    "pdf_accessibility_report_unavailable";
const MAX_IMPORTED_DOCUMENT_REVIEW_NOTE_CHARS: usize = 2_000;
const MAX_DISPATCH_EVIDENCE_LOCATOR_CHARS: usize = 512;
const MAX_DISPATCH_EVIDENCE_NOTE_CHARS: usize = 2_000;
const ABSENT_OWNER_DISPATCH_EVIDENCE_EVENT_KIND: &str =
    "absent_owner_communication.dispatch_evidence_recorded";
const GENERATED_DOCUMENT_DISPATCH_EVIDENCE_EVENT_KIND: &str =
    "generated_document.dispatch_evidence_recorded";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedDispatchEvidenceProfile {
    AbsentOwnerCommunication,
    GeneratedConveningNotice,
}

impl GeneratedDispatchEvidenceProfile {
    fn event_kind(self) -> &'static str {
        match self {
            Self::AbsentOwnerCommunication => ABSENT_OWNER_DISPATCH_EVIDENCE_EVENT_KIND,
            Self::GeneratedConveningNotice => GENERATED_DOCUMENT_DISPATCH_EVIDENCE_EVENT_KIND,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::AbsentOwnerCommunication => "condominium_absent_owner_communication",
            Self::GeneratedConveningNotice => "generated_convening_notice",
        }
    }

    fn recipient_error_label(self) -> &'static str {
        match self {
            Self::AbsentOwnerCommunication => "absent attendee",
            Self::GeneratedConveningNotice => "convening recipient",
        }
    }

    fn recipient_error_label_with_article(self) -> &'static str {
        match self {
            Self::AbsentOwnerCommunication => "an absent attendee",
            Self::GeneratedConveningNotice => "a convening recipient",
        }
    }

    fn empty_recipients_message(self) -> &'static str {
        match self {
            Self::AbsentOwnerCommunication => {
                "act has no absent attendees for absent-owner dispatch evidence"
            }
            Self::GeneratedConveningNotice => {
                "act has no convening recipients for generated convening notice dispatch evidence"
            }
        }
    }

    fn uncovered_note(self) -> String {
        match self {
            Self::AbsentOwnerCommunication => {
                "communication generated automatically; operator-recorded dispatch evidence does not cover every required absent recipient"
                    .to_owned()
            }
            Self::GeneratedConveningNotice => {
                "generated convening notice has operator-recorded dispatch evidence pending for one or more required recipients; no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
        }
    }

    fn covered_note(self) -> String {
        match self {
            Self::AbsentOwnerCommunication => {
                "operator-recorded dispatch evidence covers all absent recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
            Self::GeneratedConveningNotice => {
                "operator-recorded dispatch evidence covers all generated convening notice recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
                    .to_owned()
            }
        }
    }
}

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

/// Whether `id` names a currently available built-in or durable user-authored template. Group
/// library revisions validate every reference through this shared source of truth before append.
pub(crate) fn template_id_exists(state: &AppState, id: &str) -> Result<bool, ApiError> {
    if registry().get(id).is_some() {
        return Ok(true);
    }
    let Some(store) = &state.store else {
        return Ok(false);
    };
    store
        .user_template(id)
        .map(|value| value.is_some())
        .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))
}

pub(crate) fn generated_dispatch_evidence_profile_for_template(
    template_id: &str,
) -> Option<GeneratedDispatchEvidenceProfile> {
    if template_id == CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID {
        return Some(GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication);
    }
    let spec = registry().get(template_id)?;
    if spec.stage == LifecycleStage::Convocatoria {
        return Some(GeneratedDispatchEvidenceProfile::GeneratedConveningNotice);
    }
    None
}

pub(crate) fn generated_dispatch_required_recipient_names(
    act: &Act,
    template_id: &str,
) -> Option<Vec<String>> {
    let profile = generated_dispatch_evidence_profile_for_template(template_id)?;
    Some(match profile {
        GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication => {
            absent_owner_recipient_names(act)
        }
        GeneratedDispatchEvidenceProfile::GeneratedConveningNotice => {
            convening_recipient_names(act)
        }
    })
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

/// Honest status for generated communications whose dispatch proof is still outside this slice.
#[derive(Clone, Serialize)]
pub struct DispatchEvidenceStatusView {
    pub status: String,
    pub required: bool,
    pub evidence_attached: bool,
    pub dispatch_completed: bool,
    pub completion_basis: &'static str,
    pub required_recipients: Vec<String>,
    pub recorded_recipients: Vec<String>,
    pub missing_recipients: Vec<String>,
    pub note: String,
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
/// antecedence_days, channel, recipients[].{name, contact, channel, reference, dispatched_at},
/// second_call.{date, time, reduced_quorum}}`. Enum leaves keep their bare serde names (so `convener_capacity |
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

/// Generate a specific catalog template against a sealed act without going through the HTTP
/// handler. Used by post-seal hooks and by the on-demand endpoint to share the same validation and
/// render context.
pub(crate) fn generate_for_act_template(
    act: &Act,
    book: &Book,
    entity: &Entity,
    template_id: &str,
) -> Result<Generated, ApiError> {
    let spec = registry().get(template_id).ok_or(ApiError::NotFound)?;
    if spec.family != entity.family {
        return Err(ApiError::Unprocessable(format!(
            "template {:?} is for family {:?}, not this entity's family {:?}",
            spec.id, spec.family, entity.family
        )));
    }
    // Certidão / extrato-style post-act instruments certify a sealed ata. Refuse drafts honestly.
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
    let mut made = generate(spec, &ctx, act.id, OffsetDateTime::now_utc())?;
    if let Some(required_recipients) =
        generated_dispatch_required_recipient_names(act, &made.stored.template_id)
        && !required_recipients.is_empty()
        && let Some(status) = dispatch_evidence_status_for_template(
            &made.stored.template_id,
            &required_recipients,
            &[],
        )
        && let Some(obj) = made.event_payload.as_object_mut()
    {
        obj.insert(
            "dispatch_evidence_status".to_owned(),
            serde_json::to_value(status)?,
        );
    }
    Ok(made)
}

/// Generate the automatic absent-owner communication required for sealed condominium acts that
/// record absent attendees. This only creates the communication document; no dispatch is claimed.
pub(crate) fn generate_condominium_absent_owner_communication(
    act: &Act,
    book: &Book,
    entity: &Entity,
) -> Result<Generated, ApiError> {
    generate_for_act_template(
        act,
        book,
        entity,
        CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID,
    )
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
    pub canonical_conversion_preflight: DocumentCanonicalConversionPreflightReport,
    pub pdf: PdfRecognitionReport,
    pub legacy_word: LegacyWordDocRecognitionReport,
    pub image: ImageRecognitionReport,
    pub text: TextDocumentRecognitionReport,
    pub office: OfficeDocumentRecognitionReport,
    pub rtf: RtfRecognitionReport,
    pub email: EmailRecognitionReport,
    pub zip_bundle: ZipBundleRecognitionReport,
    pub signature: SignedPdfSignalReport,
    pub signature_evidence: DocumentSignatureEvidenceReport,
    pub extraction_limits: DocumentExtractionLimitsReport,
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
pub struct DocumentCanonicalConversionPreflightReport {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub status: &'static str,
    pub source_format: &'static str,
    pub review_state: &'static str,
    pub bounded_evidence_status: &'static str,
    pub evidence_basis: Vec<&'static str>,
    pub blockers: Vec<&'static str>,
    pub next_step: &'static str,
    pub local_metadata_only: bool,
    pub original_bytes_preserved: bool,
    pub canonical_conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub signature_validation_performed: bool,
    pub ocr_performed: bool,
    pub legal_acceptance_claimed: bool,
    pub external_provider_contacted: bool,
    pub canonical_record_replaced: bool,
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
    pub file_count: usize,
    pub extracted_entry_count: usize,
    pub unsafe_entry_count: usize,
    pub unsafe_entry_names: Vec<String>,
    pub duplicate_entry_count: usize,
    pub duplicate_entry_names: Vec<String>,
    pub total_uncompressed_size: Option<u64>,
    pub total_extracted_size: u64,
    pub extraction_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub members: Vec<ContainerMemberReport>,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfficeDocumentRecognitionReport {
    pub is_office_document: bool,
    pub format: Option<&'static str>,
    pub package_readable: bool,
    pub required_members_present: bool,
    pub macro_payload_detected: bool,
    pub package_members_extracted_for_inspection: bool,
    pub conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RtfRecognitionReport {
    pub claimed: bool,
    pub is_rtf: bool,
    pub structurally_valid: bool,
    pub maximum_group_depth: usize,
    pub object_or_package_control_word_detected: bool,
    pub conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmailRecognitionReport {
    pub claimed: bool,
    pub is_email: bool,
    pub readable: bool,
    pub header_count: usize,
    pub mime_part_count: usize,
    pub attachment_count: usize,
    pub decoded_attachment_bytes: u64,
    pub extraction_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub attachments: Vec<ContainerMemberReport>,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerMemberReport {
    pub path: String,
    pub media_type: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub signature_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentExtractionLimitsReport {
    pub upload_max_bytes: usize,
    pub archive_max_members: usize,
    pub extracted_member_max_bytes: u64,
    pub extracted_total_max_bytes: u64,
    pub mail_header_max_bytes: usize,
    pub mail_header_max_count: usize,
    pub mail_part_max_count: usize,
    pub mail_nesting_max_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentSignatureEvidenceReport {
    pub signature_claim_detected: bool,
    pub claimed_signature_count: usize,
    pub validation_performed_count: usize,
    pub cryptographically_valid_count: usize,
    pub all_claimed_signatures_valid: Option<bool>,
    pub trust_validation: &'static str,
    pub legal_validity_claimed: bool,
    pub validations: Vec<DocumentSignatureValidationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentSignatureValidationEntry {
    pub format: &'static str,
    pub status: &'static str,
    pub signature_path: String,
    pub signed_content_path: Option<String>,
    pub signed_content_sha256: Option<String>,
    pub validation_performed: bool,
    pub cryptographically_valid: bool,
    pub signer_certificate_sha256: Option<String>,
    pub signing_time: Option<String>,
    pub validation_error: Option<String>,
    pub trust_validation: &'static str,
    pub legal_validity_claimed: bool,
}

#[derive(Debug, Clone)]
struct ExtractedEvidenceMember {
    path: String,
    media_type: String,
    bytes: Vec<u8>,
}

impl ExtractedEvidenceMember {
    fn report(&self) -> ContainerMemberReport {
        ContainerMemberReport {
            path: self.path.clone(),
            media_type: self.media_type.clone(),
            size_bytes: self.bytes.len(),
            sha256: sha256_hex(&self.bytes),
            signature_claimed: claimed_signature_format(
                &self.path,
                Some(&self.media_type),
                &self.bytes,
            )
            .is_some(),
        }
    }
}

#[derive(Debug, Clone)]
struct ZipInspection {
    report: ZipBundleRecognitionReport,
    members: Vec<ExtractedEvidenceMember>,
}

#[derive(Debug, Clone)]
struct MailInspection {
    report: EmailRecognitionReport,
    parts: Vec<ExtractedEvidenceMember>,
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
    let zip_inspection = inspect_zip_bundle(bytes);
    let zip_bundle = zip_inspection.report.clone();
    let office = recognize_office_document(&zip_inspection);
    let rtf = recognize_rtf_document(bytes, declared.as_deref(), filename.as_deref());
    let mail_inspection = inspect_email_document(bytes, declared.as_deref(), filename.as_deref());
    let email = mail_inspection.report.clone();
    let top_level_signature_claim = claimed_signature_format(
        filename.as_deref().unwrap_or("candidate"),
        declared.as_deref(),
        bytes,
    );
    let detected_content_type = detect_candidate_content_type(
        bytes,
        pdf.is_pdf,
        &legacy_word,
        &image,
        &text,
        &office,
        &rtf,
        &email,
        top_level_signature_claim,
        &zip_bundle,
    );
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
    let signature_evidence = validate_document_signature_evidence(
        bytes,
        detected_content_type,
        filename.as_deref(),
        &signature,
        &zip_inspection.members,
        &mail_inspection.parts,
    );
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
        || office.is_office_document
        || rtf.is_rtf
        || email.is_email
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
    if office.is_office_document {
        findings.push(DocumentValidationFinding::warning(
            "non_canonical_import_only",
            NON_CANONICAL_EVIDENCE_WARNING,
        ));
        findings.push(DocumentValidationFinding::info(
            "office_package_detected",
            format!(
                "{} package members were extracted under fixed in-memory limits for inspection only",
                office.format.unwrap_or("office document")
            ),
        ));
        if office.macro_payload_detected {
            findings.push(DocumentValidationFinding::warning(
                "office_macro_payload_preserved_not_executed",
                "a macro payload is present; it was preserved as opaque evidence and was not executed",
            ));
        }
    }
    if rtf.claimed {
        if !rtf.structurally_valid {
            findings.push(DocumentValidationFinding::error(
                "rtf_structure_invalid",
                rtf.validation_error
                    .clone()
                    .unwrap_or_else(|| "RTF structure validation failed".to_owned()),
            ));
        } else {
            findings.push(DocumentValidationFinding::info(
                "rtf_detected",
                "RTF evidence was structurally screened without executing objects, packages, fields, or macros",
            ));
        }
    }
    if email.claimed {
        if !email.readable {
            findings.push(DocumentValidationFinding::error(
                "email_malformed_or_unsafe",
                email
                    .validation_error
                    .clone()
                    .unwrap_or_else(|| "email/MIME parsing failed".to_owned()),
            ));
        } else {
            findings.push(DocumentValidationFinding::info(
                "email_evidence_extracted",
                format!(
                    "email structure and {} attachment(s) were decoded under fixed in-memory limits for inspection only",
                    email.attachment_count
                ),
            ));
        }
    }
    if zip_bundle.is_zip {
        findings.push(DocumentValidationFinding::warning(
            "non_canonical_import_only",
            NON_CANONICAL_EVIDENCE_WARNING,
        ));
        findings.push(DocumentValidationFinding::info(
            "zip_bundle_detected",
            "ZIP bundle evidence detected; safe members were extracted in memory under fixed member/count/total limits",
        ));
        findings.push(DocumentValidationFinding::info(
            "zip_bounded_inspection_only",
            "ZIP members were not written to disk or converted; this import does not become the canonical PDF/A record",
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
        if zip_bundle.duplicate_entry_count > 0 {
            findings.push(DocumentValidationFinding::error(
                "zip_duplicate_entry_name",
                format!(
                    "ZIP archive contains {} duplicate member path(s); examples: {}",
                    zip_bundle.duplicate_entry_count,
                    zip_bundle.duplicate_entry_names.join(", ")
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
    for validation in &signature_evidence.validations {
        match validation.status {
            "valid" => findings.push(DocumentValidationFinding::info(
                "signature_evidence_valid_local_technical",
                format!(
                    "{} signature evidence at {} passed local cryptographic validation; trust and legal effect were not assessed",
                    validation.format, validation.signature_path
                ),
            )),
            "invalid" => findings.push(DocumentValidationFinding::error(
                "signature_evidence_invalid",
                format!(
                    "{} signature evidence at {} is invalid: {}",
                    validation.format,
                    validation.signature_path,
                    validation
                        .validation_error
                        .as_deref()
                        .unwrap_or("local cryptographic validation failed")
                ),
            )),
            _ => findings.push(DocumentValidationFinding::error(
                "signature_evidence_unvalidated",
                format!(
                    "{} signature evidence at {} could not be validated: {}",
                    validation.format,
                    validation.signature_path,
                    validation
                        .validation_error
                        .as_deref()
                        .unwrap_or("required signed content was unavailable or ambiguous")
                ),
            )),
        }
    }

    let can_accept_non_canonical_import =
        !findings.iter().any(|finding| finding.severity == "error");
    let preservation_policy = document_preservation_policy(
        content_type.detected,
        can_accept_non_canonical_import,
        false,
    );
    let canonical_conversion_preflight = document_canonical_conversion_preflight(
        content_type.detected,
        &legacy_word,
        preservation_policy.review_state,
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
        canonical_conversion_preflight,
        pdf,
        legacy_word,
        image,
        text,
        office,
        rtf,
        email,
        zip_bundle,
        signature,
        signature_evidence,
        extraction_limits: document_extraction_limits(),
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
    #[serde(
        default,
        alias = "acknowledged_guardrails",
        alias = "guardrail_acknowledgements",
        alias = "acknowledged_review_guardrail_ids"
    )]
    pub acknowledged_guardrail_ids: Vec<String>,
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
    pub acknowledged_guardrail_ids: Vec<String>,
    /// Persisted bounded recognition/extraction/signature report linked to the original bytes.
    pub technical_validation: Value,
    pub review_history: Vec<ImportedDocumentReviewHistoryEntryView>,
    pub operator_review_notice: &'static str,
    pub non_canonical: bool,
    pub requires_ocr_review: bool,
    pub canonical_record_status: &'static str,
    pub signed_artifact_status: &'static str,
    pub review_guardrail_checklist: Vec<&'static str>,
    pub canonical_conversion_status: &'static str,
    pub canonical_conversion_performed: bool,
    pub canonical_conversion_preflight: DocumentCanonicalConversionPreflightReport,
    pub legal_acceptance_claimed: bool,
    pub preservation_policy: DocumentPreservationPolicyReport,
    pub legal_notice: &'static str,
    pub bytes_download: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedDocumentReviewHistoryEntryView {
    pub decision_index: usize,
    pub review_status: &'static str,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
    pub review_note: Option<String>,
    pub acknowledged_guardrail_ids: Vec<String>,
    pub bytes_in_payload: bool,
    pub ocr_performed: bool,
    pub canonical_conversion_performed: bool,
    pub canonical_pdfa_generated: bool,
    pub signed_artifact_created_or_validated: bool,
    pub legal_acceptance_claimed: bool,
    pub certification_claimed: bool,
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
    let technical_validation_report_json = serde_json::to_string(&report)?;
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
            operator_acknowledged_guardrail_ids: Vec::new(),
            technical_validation_report_json,
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
        Json(imported_document_view(&stored.meta, &[])),
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
    if let Some(act_id) = act_id
        && !state.acts.read().await.contains_key(&act_id)
    {
        return Err(ApiError::NotFound);
    }
    let Some(store) = &state.store else {
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .imported_documents(act_id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?;
    let mut views = Vec::with_capacity(rows.len());
    for meta in &rows {
        let history = store
            .imported_document_review_history(&meta.id)
            .map_err(|e| {
                ApiError::Internal(format!(
                    "imported document review history store read failed: {e}"
                ))
            })?;
        views.push(imported_document_view_with_redaction(
            meta, &history, redaction,
        ));
    }
    Ok(Json(views))
}

/// `GET /v1/documents/imported/{id}` — read imported-document metadata only.
pub async fn get_imported_document(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Json<ImportedDocumentView>, ApiError> {
    let doc = load_imported_document_for_actor(&state, &actor, &id).await?;
    let redaction = read_redaction_for_actor(&state, &actor).await?;
    let history = imported_document_review_history_for_state(&state, &doc.meta.id)?;
    Ok(Json(imported_document_view_with_redaction(
        &doc.meta, &history, redaction,
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
    let acknowledged_guardrail_ids =
        validate_imported_document_review_acknowledgements(req.acknowledged_guardrail_ids)?;
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
        &acknowledged_guardrail_ids,
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
            &acknowledged_guardrail_ids,
        )
    })?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    let reviewed = store
        .imported_document(&id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    let history = store.imported_document_review_history(&id).map_err(|e| {
        ApiError::Internal(format!(
            "imported document review history store read failed: {e}"
        ))
    })?;
    Ok(Json(imported_document_view(&reviewed.meta, &history)))
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

fn imported_document_view(
    meta: &StoredImportedDocumentMeta,
    history: &[StoredImportedDocumentReviewHistoryEntry],
) -> ImportedDocumentView {
    let classification = document_evidence_classification(&meta.detected_content_type);
    let preservation_policy = imported_document_preservation_policy(meta);
    let canonical_conversion_preflight =
        imported_document_canonical_conversion_preflight(meta, preservation_policy.review_state);
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
        acknowledged_guardrail_ids: meta.operator_acknowledged_guardrail_ids.clone(),
        technical_validation: serde_json::from_str(&meta.technical_validation_report_json)
            .expect("store validates imported-document technical report JSON"),
        review_history: imported_document_review_history_view(history),
        operator_review_notice: IMPORTED_DOCUMENT_REVIEW_NOTICE,
        non_canonical: true,
        requires_ocr_review: preservation_policy.requires_ocr_review,
        canonical_record_status: preservation_policy.canonical_record_status,
        signed_artifact_status: preservation_policy.signed_artifact_status,
        review_guardrail_checklist: preservation_policy.review_guardrail_checklist.clone(),
        canonical_conversion_status: preservation_policy.canonical_conversion_status,
        canonical_conversion_performed: false,
        canonical_conversion_preflight,
        legal_acceptance_claimed: false,
        preservation_policy,
        legal_notice: DOCUMENT_IMPORTED_NOTICE,
        bytes_download: format!("/v1/documents/imported/{}/bytes", meta.id),
    }
}

fn imported_document_view_with_redaction(
    meta: &StoredImportedDocumentMeta,
    history: &[StoredImportedDocumentReviewHistoryEntry],
    redaction: ReadRedaction,
) -> ImportedDocumentView {
    let mut view = imported_document_view(meta, history);
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
        view.technical_validation = json!({ "redacted": true });
        for entry in &mut view.review_history {
            entry.reviewed_by = entry
                .reviewed_by
                .take()
                .map(|_| crate::dto::REDACTED.to_owned());
            entry.review_note = entry
                .review_note
                .take()
                .map(|_| crate::dto::REDACTED.to_owned());
        }
        view.bytes_download = crate::dto::REDACTED.to_owned();
    }
    view
}

fn imported_document_review_history_for_state(
    state: &AppState,
    imported_document_id: &str,
) -> Result<Vec<StoredImportedDocumentReviewHistoryEntry>, ApiError> {
    let Some(store) = &state.store else {
        return Ok(Vec::new());
    };
    store
        .imported_document_review_history(imported_document_id)
        .map_err(|e| {
            ApiError::Internal(format!(
                "imported document review history store read failed: {e}"
            ))
        })
}

fn imported_document_review_history_view(
    history: &[StoredImportedDocumentReviewHistoryEntry],
) -> Vec<ImportedDocumentReviewHistoryEntryView> {
    history
        .iter()
        .enumerate()
        .map(|(idx, entry)| ImportedDocumentReviewHistoryEntryView {
            decision_index: idx + 1,
            review_status: entry.review_status.as_str(),
            reviewed_at: entry
                .reviewed_at
                .map(|t| t.format(&Rfc3339).unwrap_or_default()),
            reviewed_by: entry.reviewed_by.clone(),
            review_note: entry.review_note.clone(),
            acknowledged_guardrail_ids: entry.acknowledged_guardrail_ids.clone(),
            bytes_in_payload: false,
            ocr_performed: false,
            canonical_conversion_performed: false,
            canonical_pdfa_generated: false,
            signed_artifact_created_or_validated: false,
            legal_acceptance_claimed: false,
            certification_claimed: false,
        })
        .collect()
}

fn imported_document_initial_review_status(
    detected_content_type: &str,
) -> StoredImportedDocumentReviewStatus {
    match content_type_base(detected_content_type).as_str() {
        "image/png" | "image/jpeg" => StoredImportedDocumentReviewStatus::OcrReviewRequired,
        "application/msword"
        | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.oasis.opendocument.text"
        | "application/rtf" => {
            StoredImportedDocumentReviewStatus::CanonicalConversionReviewRequired
        }
        _ => StoredImportedDocumentReviewStatus::OperatorReviewRequired,
    }
}

fn imported_document_preservation_policy(
    meta: &StoredImportedDocumentMeta,
) -> DocumentPreservationPolicyReport {
    let mut policy = document_preservation_policy(&meta.detected_content_type, true, true);
    let signature_state = imported_document_signature_validation_state(meta);
    if signature_state.claim_detected && signature_state.all_claimed_valid {
        policy.signed_artifact_status = "locally_validated_signature_evidence_non_canonical";
    } else if signature_state.claim_detected {
        policy.signed_artifact_status = "signature_evidence_validation_incomplete";
    }
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

fn imported_document_canonical_conversion_preflight(
    meta: &StoredImportedDocumentMeta,
    review_state: &'static str,
) -> DocumentCanonicalConversionPreflightReport {
    let base = content_type_base(&meta.detected_content_type);
    document_canonical_conversion_preflight_from_flags(
        base.as_str(),
        matches!(
            base.as_str(),
            "application/msword"
                | "application/vnd.ms-office"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.oasis.opendocument.text"
                | "application/rtf"
        ),
        matches!(
            base.as_str(),
            "application/msword"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.oasis.opendocument.text"
                | "application/rtf"
        ),
        review_state,
        true,
    )
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
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "application/vnd.oasis.opendocument.text" => "application/vnd.oasis.opendocument.text",
        "application/rtf" | "text/rtf" => "application/rtf",
        "message/rfc822" => "message/rfc822",
        "application/vnd.etsi.asic-e+zip" => "application/vnd.etsi.asic-e+zip",
        "application/vnd.etsi.asic-s+zip" => "application/vnd.etsi.asic-s+zip",
        "application/pkcs7-signature" => "application/pkcs7-signature",
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
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.oasis.opendocument.text" => "odt",
        "application/rtf" | "text/rtf" => "rtf",
        "message/rfc822" => "eml",
        "application/vnd.etsi.asic-e+zip" => "asice",
        "application/vnd.etsi.asic-s+zip" => "asics",
        "application/pkcs7-signature" => "p7s",
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
    let signature_state = imported_document_signature_validation_state(meta);
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
        "acknowledged_guardrail_ids": meta.operator_acknowledged_guardrail_ids.clone(),
        "technical_validation_report_sha256": sha256_hex(
            meta.technical_validation_report_json.as_bytes()
        ),
        "signature_claim_detected": signature_state.claim_detected,
        "all_claimed_signatures_valid": signature_state.claim_detected
            .then_some(signature_state.all_claimed_valid),
        "guardrail_acknowledgement": {
            "required_guardrail_ids": imported_document_review_guardrail_checklist(),
            "acknowledged_guardrail_ids": meta.operator_acknowledged_guardrail_ids.clone(),
            "all_required_guardrails_acknowledged": meta.operator_acknowledged_guardrail_ids
                == imported_document_review_guardrail_ids_as_strings(),
        },
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
        "canonical_conversion_preflight": imported_document_canonical_conversion_preflight(
            meta,
            preservation_policy.review_state,
        ),
        "canonical_pdfa_generated": false,
        "signature_validation_performed": signature_state.validation_performed,
        "preservation_policy": preservation_policy,
        "legal_acceptance_claimed": false,
        "legal_validity_claimed": false,
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct ImportedDocumentSignatureValidationState {
    claim_detected: bool,
    validation_performed: bool,
    all_claimed_valid: bool,
}

fn imported_document_signature_validation_state(
    meta: &StoredImportedDocumentMeta,
) -> ImportedDocumentSignatureValidationState {
    let Ok(report) = serde_json::from_str::<Value>(&meta.technical_validation_report_json) else {
        return ImportedDocumentSignatureValidationState::default();
    };
    let signature = &report["signature_evidence"];
    ImportedDocumentSignatureValidationState {
        claim_detected: signature["signature_claim_detected"]
            .as_bool()
            .unwrap_or(false),
        validation_performed: signature["validation_performed_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        all_claimed_valid: signature["all_claimed_signatures_valid"]
            .as_bool()
            .unwrap_or(false),
    }
}

fn imported_document_review_event_payload(
    meta: &StoredImportedDocumentMeta,
    status: StoredImportedDocumentReviewStatus,
    reviewed_by: &str,
    acknowledged_guardrail_ids: &[String],
) -> Value {
    json!({
        "document_id": meta.id.clone(),
        "act_id": meta.act_id.as_ref().map(ToString::to_string),
        "previous_operator_review_status": meta.operator_review_status.as_str(),
        "operator_review_status": status.as_str(),
        "reviewed_by": reviewed_by,
        "review_note_in_payload": false,
        "acknowledged_guardrail_ids": acknowledged_guardrail_ids,
        "guardrail_acknowledgement": {
            "required_guardrail_ids": imported_document_review_guardrail_checklist(),
            "acknowledged_guardrail_ids": acknowledged_guardrail_ids,
            "all_required_guardrails_acknowledged": true,
        },
        "operator_review_notice": IMPORTED_DOCUMENT_REVIEW_NOTICE,
        "non_canonical": true,
        "bytes_in_payload": false,
        "ocr_performed": false,
        "canonical_record_status": "not_canonical_record",
        "signed_artifact_status": "not_signed_artifact",
        "review_guardrail_checklist": imported_document_review_guardrail_checklist(),
        "canonical_conversion_status": "not_performed_non_canonical_original_only",
        "canonical_conversion_performed": false,
        "canonical_conversion_preflight": imported_document_canonical_conversion_preflight(
            meta,
            status.as_str(),
        ),
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

fn validate_imported_document_review_acknowledgements(
    raw: Vec<String>,
) -> Result<Vec<String>, ApiError> {
    normalize_required_guardrail_acknowledgements(
        raw,
        IMPORTED_DOCUMENT_REVIEW_GUARDRAIL_CHECKLIST,
        "acknowledged_guardrail_ids",
    )
}

fn normalize_required_guardrail_acknowledgements(
    raw: Vec<String>,
    required: &[&'static str],
    field: &'static str,
) -> Result<Vec<String>, ApiError> {
    let mut acknowledged = Vec::new();
    for raw_id in raw {
        let id = raw_id.trim();
        if id.is_empty() {
            return Err(ApiError::Unprocessable(format!(
                "{field} cannot contain empty guardrail ids"
            )));
        }
        if !required.contains(&id) {
            return Err(ApiError::Unprocessable(format!(
                "{field} contains unknown guardrail id {id:?}; expected ids: {}",
                required.join(", ")
            )));
        }
        if !acknowledged.iter().any(|existing: &String| existing == id) {
            acknowledged.push(id.to_owned());
        }
    }

    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|required_id| {
            !acknowledged
                .iter()
                .any(|acknowledged_id| acknowledged_id == required_id)
        })
        .collect();
    if !missing.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "{field} must include all required imported-document review guardrail ids: {}",
            missing.join(", ")
        )));
    }

    Ok(required.iter().map(|id| (*id).to_owned()).collect())
}

fn imported_document_review_guardrail_ids_as_strings() -> Vec<String> {
    IMPORTED_DOCUMENT_REVIEW_GUARDRAIL_CHECKLIST
        .iter()
        .map(|id| (*id).to_owned())
        .collect()
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

fn inspect_zip_bundle(bytes: &[u8]) -> ZipInspection {
    let is_zip = bytes.starts_with(ZIP_MAGIC)
        || bytes.starts_with(ZIP_EMPTY_MAGIC)
        || bytes.starts_with(ZIP_SPANNED_MAGIC);
    if !is_zip {
        return ZipInspection {
            report: empty_zip_recognition_report(false),
            members: Vec::new(),
        };
    }

    let mut archive = match ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(err) => {
            let mut report = empty_zip_recognition_report(true);
            report.validation_error = Some(format!("ZIP archive could not be read: {err}"));
            return ZipInspection {
                report,
                members: Vec::new(),
            };
        }
    };

    let mut unsafe_entry_count = 0usize;
    let mut unsafe_entry_names = Vec::new();
    let mut duplicate_entry_count = 0usize;
    let mut duplicate_entry_names = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_uncompressed_size = 0u64;
    let mut total_extracted_size = 0u64;
    let mut file_count = 0usize;
    let mut validation_errors = Vec::new();
    let mut members = Vec::new();
    if archive.len() > DOCUMENT_CONTAINER_MAX_MEMBERS {
        validation_errors.push(format!(
            "ZIP archive has {} members; at most {} are accepted",
            archive.len(),
            DOCUMENT_CONTAINER_MAX_MEMBERS
        ));
    }
    let inspected_members = archive.len().min(DOCUMENT_CONTAINER_MAX_MEMBERS);
    for index in 0..inspected_members {
        let mut file = match archive.by_index(index) {
            Ok(file) => file,
            Err(err) => {
                validation_errors.push(format!("ZIP member {index} could not be read: {err}"));
                continue;
            }
        };
        total_uncompressed_size = total_uncompressed_size.saturating_add(file.size());
        let name = file.name().to_owned();
        let is_symlink = file
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000);
        if zip_entry_name_is_unsafe(&name, file.enclosed_name().is_none()) || is_symlink {
            unsafe_entry_count += 1;
            if unsafe_entry_names.len() < 5 {
                unsafe_entry_names.push(name);
            }
            continue;
        }
        let normalized_name = name.to_ascii_lowercase();
        if !names.insert(normalized_name) {
            duplicate_entry_count += 1;
            if duplicate_entry_names.len() < 5 {
                duplicate_entry_names.push(name);
            }
            continue;
        }
        if file.is_dir() {
            continue;
        }
        file_count += 1;
        if file.size() > DOCUMENT_CONTAINER_MAX_MEMBER_BYTES {
            validation_errors.push(format!(
                "ZIP member {name} declares {} bytes; the per-member limit is {} bytes",
                file.size(),
                DOCUMENT_CONTAINER_MAX_MEMBER_BYTES
            ));
            continue;
        }
        let remaining_total =
            DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES.saturating_sub(total_extracted_size);
        if file.size() > remaining_total {
            validation_errors.push(format!(
                "ZIP members exceed the {}-byte total extraction limit",
                DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES
            ));
            continue;
        }
        let bounded_read_limit = DOCUMENT_CONTAINER_MAX_MEMBER_BYTES.min(remaining_total);
        let mut extracted = Vec::with_capacity(usize::try_from(file.size()).unwrap_or_default());
        match (&mut file)
            .take(bounded_read_limit + 1)
            .read_to_end(&mut extracted)
        {
            Ok(_) if extracted.len() as u64 <= bounded_read_limit => {}
            Ok(_) => {
                validation_errors.push(
                    if bounded_read_limit < DOCUMENT_CONTAINER_MAX_MEMBER_BYTES {
                        format!(
                            "ZIP members expanded beyond the {}-byte total extraction limit",
                            DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES
                        )
                    } else {
                        format!(
                            "ZIP member {name} expanded beyond the {}-byte per-member limit",
                            DOCUMENT_CONTAINER_MAX_MEMBER_BYTES
                        )
                    },
                );
                continue;
            }
            Err(err) => {
                validation_errors.push(format!(
                    "ZIP member {name} could not be extracted safely: {err}"
                ));
                continue;
            }
        }
        total_extracted_size = total_extracted_size.saturating_add(extracted.len() as u64);
        members.push(ExtractedEvidenceMember {
            media_type: content_type_for_embedded_member(&name, &extracted).to_owned(),
            path: name,
            bytes: extracted,
        });
    }

    let report_members = members
        .iter()
        .map(ExtractedEvidenceMember::report)
        .collect();
    ZipInspection {
        report: ZipBundleRecognitionReport {
            is_zip: true,
            readable: validation_errors.is_empty()
                && unsafe_entry_count == 0
                && duplicate_entry_count == 0,
            entry_count: archive.len(),
            file_count,
            extracted_entry_count: members.len(),
            unsafe_entry_count,
            unsafe_entry_names,
            duplicate_entry_count,
            duplicate_entry_names,
            total_uncompressed_size: Some(total_uncompressed_size),
            total_extracted_size,
            extraction_performed: !members.is_empty(),
            canonical_pdfa_generated: false,
            members: report_members,
            validation_error: (!validation_errors.is_empty()).then(|| validation_errors.join("; ")),
        },
        members,
    }
}

fn empty_zip_recognition_report(is_zip: bool) -> ZipBundleRecognitionReport {
    ZipBundleRecognitionReport {
        is_zip,
        readable: false,
        entry_count: 0,
        file_count: 0,
        extracted_entry_count: 0,
        unsafe_entry_count: 0,
        unsafe_entry_names: Vec::new(),
        duplicate_entry_count: 0,
        duplicate_entry_names: Vec::new(),
        total_uncompressed_size: None,
        total_extracted_size: 0,
        extraction_performed: false,
        canonical_pdfa_generated: false,
        members: Vec::new(),
        validation_error: None,
    }
}

fn recognize_office_document(zip: &ZipInspection) -> OfficeDocumentRecognitionReport {
    let member = |path: &str| zip.members.iter().find(|member| member.path == path);
    let docx_content_types = member("[Content_Types].xml").is_some_and(|member| {
        find_bytes(
            &member.bytes,
            b"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        )
        .is_some()
    });
    let is_docx = docx_content_types && member("word/document.xml").is_some();
    let is_odt = member("mimetype")
        .is_some_and(|member| member.bytes == b"application/vnd.oasis.opendocument.text")
        && member("content.xml").is_some();
    let format = if is_docx {
        Some("docx")
    } else if is_odt {
        Some("odt")
    } else {
        None
    };
    OfficeDocumentRecognitionReport {
        is_office_document: format.is_some(),
        format,
        package_readable: zip.report.readable,
        required_members_present: format.is_some(),
        macro_payload_detected: zip.members.iter().any(|member| {
            let name = member.path.to_ascii_lowercase();
            name == "word/vbaproject.bin" || name.starts_with("scripts/")
        }),
        package_members_extracted_for_inspection: format.is_some()
            && zip.report.extraction_performed,
        conversion_performed: false,
        canonical_pdfa_generated: false,
    }
}

fn recognize_rtf_document(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<&str>,
) -> RtfRecognitionReport {
    let declared = declared_content_type
        .map(content_type_base)
        .is_some_and(|value| value == "application/rtf" || value == "text/rtf");
    let extension = filename
        .and_then(filename_extension)
        .is_some_and(|value| value.eq_ignore_ascii_case("rtf"));
    let trimmed = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(bytes, |offset| &bytes[offset..]);
    let magic = trimmed.starts_with(br#"{\rtf"#);
    let claimed = declared || extension || magic;
    if !claimed {
        return RtfRecognitionReport {
            claimed: false,
            is_rtf: false,
            structurally_valid: false,
            maximum_group_depth: 0,
            object_or_package_control_word_detected: false,
            conversion_performed: false,
            canonical_pdfa_generated: false,
            validation_error: None,
        };
    }
    if !magic || bytes.contains(&0) {
        return RtfRecognitionReport {
            claimed: true,
            is_rtf: magic,
            structurally_valid: false,
            maximum_group_depth: 0,
            object_or_package_control_word_detected: false,
            conversion_performed: false,
            canonical_pdfa_generated: false,
            validation_error: Some(
                "RTF claim does not contain a NUL-free {\\rtf document header".to_owned(),
            ),
        };
    }
    let mut depth = 0usize;
    let mut maximum_group_depth = 0usize;
    let mut escaped = false;
    let mut valid = true;
    for byte in trimmed {
        if escaped {
            escaped = false;
            continue;
        }
        if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'{' {
            depth = depth.saturating_add(1);
            maximum_group_depth = maximum_group_depth.max(depth);
            if depth > 512 {
                valid = false;
                break;
            }
        } else if *byte == b'}' {
            let Some(next) = depth.checked_sub(1) else {
                valid = false;
                break;
            };
            depth = next;
        }
    }
    valid &= depth == 0;
    let lower = String::from_utf8_lossy(trimmed).to_ascii_lowercase();
    RtfRecognitionReport {
        claimed,
        is_rtf: true,
        structurally_valid: valid,
        maximum_group_depth,
        object_or_package_control_word_detected: lower.contains("\\object")
            || lower.contains("\\objdata")
            || lower.contains("\\package"),
        conversion_performed: false,
        canonical_pdfa_generated: false,
        validation_error: (!valid)
            .then(|| "RTF groups are unbalanced or excessively nested".to_owned()),
    }
}

#[derive(Default)]
struct MailParseState {
    parts_seen: usize,
    attachments_seen: usize,
    total_decoded_bytes: u64,
    decoded_attachment_bytes: u64,
    next_part: usize,
    extracted: Vec<ExtractedEvidenceMember>,
}

fn inspect_email_document(
    bytes: &[u8],
    declared_content_type: Option<&str>,
    filename: Option<&str>,
) -> MailInspection {
    let explicit_claim = declared_content_type
        .map(content_type_base)
        .is_some_and(|value| value == "message/rfc822")
        || filename
            .and_then(filename_extension)
            .is_some_and(|value| value.eq_ignore_ascii_case("eml"));
    let header_shape = bytes
        .get(..bytes.len().min(DOCUMENT_MAIL_MAX_HEADER_BYTES))
        .is_some_and(|prefix| {
            [
                b"From:".as_slice(),
                b"Date:".as_slice(),
                b"Message-ID:".as_slice(),
            ]
            .iter()
            .filter(|needle| find_bytes(prefix, needle).is_some())
            .count()
                >= 2
        });
    let claimed = explicit_claim || header_shape;
    if !claimed {
        return MailInspection {
            report: empty_email_recognition_report(false),
            parts: Vec::new(),
        };
    }

    let (headers, _) = match parse_mail_headers(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut report = empty_email_recognition_report(true);
            report.is_email = header_shape;
            report.validation_error = Some(error);
            return MailInspection {
                report,
                parts: Vec::new(),
            };
        }
    };
    let header_count = headers.len();
    let mut state = MailParseState::default();
    let result = parse_mime_entity(bytes, 0, &mut state);
    let attachments = state
        .extracted
        .iter()
        .filter(|member| member.path.starts_with("attachment:"))
        .map(|member| {
            let mut report = member.report();
            report.path = report
                .path
                .strip_prefix("attachment:")
                .unwrap_or(&report.path)
                .to_owned();
            report
        })
        .collect::<Vec<_>>();
    let internal_parts = state
        .extracted
        .into_iter()
        .map(|mut member| {
            if let Some(path) = member.path.strip_prefix("attachment:") {
                member.path = path.to_owned();
            }
            member
        })
        .collect::<Vec<_>>();
    MailInspection {
        report: EmailRecognitionReport {
            claimed: true,
            is_email: true,
            readable: result.is_ok(),
            header_count,
            mime_part_count: state.parts_seen,
            attachment_count: state.attachments_seen,
            decoded_attachment_bytes: state.decoded_attachment_bytes,
            extraction_performed: !internal_parts.is_empty(),
            canonical_pdfa_generated: false,
            attachments,
            validation_error: result.err(),
        },
        parts: internal_parts,
    }
}

fn empty_email_recognition_report(claimed: bool) -> EmailRecognitionReport {
    EmailRecognitionReport {
        claimed,
        is_email: false,
        readable: false,
        header_count: 0,
        mime_part_count: 0,
        attachment_count: 0,
        decoded_attachment_bytes: 0,
        extraction_performed: false,
        canonical_pdfa_generated: false,
        attachments: Vec::new(),
        validation_error: None,
    }
}

fn parse_mime_entity(bytes: &[u8], depth: usize, state: &mut MailParseState) -> Result<(), String> {
    if depth > DOCUMENT_MAIL_MAX_DEPTH {
        return Err(format!(
            "MIME nesting exceeds the depth limit of {}",
            DOCUMENT_MAIL_MAX_DEPTH
        ));
    }
    state.parts_seen = state.parts_seen.saturating_add(1);
    if state.parts_seen > DOCUMENT_MAIL_MAX_PARTS {
        return Err(format!(
            "email contains more than {} MIME parts",
            DOCUMENT_MAIL_MAX_PARTS
        ));
    }
    let (headers, body) = parse_mail_headers(bytes)?;
    let content_type_value = mail_header(&headers, "content-type").unwrap_or("text/plain");
    let media_type = content_type_base(content_type_value);
    if media_type.starts_with("multipart/") {
        let boundary = mime_parameter(content_type_value, "boundary")
            .ok_or_else(|| "multipart email part has no boundary parameter".to_owned())?;
        if boundary.is_empty() || boundary.len() > DOCUMENT_MAIL_MAX_BOUNDARY_BYTES {
            return Err(format!(
                "MIME boundary must contain 1 to {} bytes",
                DOCUMENT_MAIL_MAX_BOUNDARY_BYTES
            ));
        }
        let children = split_multipart_body(body, boundary.as_bytes())?;
        if children.is_empty() {
            return Err("multipart email contains no bounded child parts".to_owned());
        }
        for child in children {
            parse_mime_entity(child, depth + 1, state)?;
        }
        return Ok(());
    }

    let transfer_encoding = mail_header(&headers, "content-transfer-encoding").unwrap_or("7bit");
    let decoded = decode_mail_body(body, transfer_encoding)?;
    if decoded.len() as u64 > DOCUMENT_CONTAINER_MAX_MEMBER_BYTES {
        return Err(format!(
            "decoded MIME part exceeds the {}-byte per-part limit",
            DOCUMENT_CONTAINER_MAX_MEMBER_BYTES
        ));
    }
    if state
        .total_decoded_bytes
        .saturating_add(decoded.len() as u64)
        > DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES
    {
        return Err(format!(
            "decoded MIME parts exceed the {}-byte total extraction limit",
            DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES
        ));
    }
    state.total_decoded_bytes = state
        .total_decoded_bytes
        .saturating_add(decoded.len() as u64);

    if media_type == "message/rfc822" {
        return parse_mime_entity(&decoded, depth + 1, state);
    }

    let disposition = mail_header(&headers, "content-disposition").unwrap_or("");
    let filename = mime_parameter(disposition, "filename")
        .or_else(|| mime_parameter(content_type_value, "name"));
    if filename.as_deref().is_some_and(looks_path_like) {
        return Err("email attachment filename must be a plain file name, not a path".to_owned());
    }
    let signature_part = signature_format_from_media_type(&media_type).is_some();
    let is_attachment =
        content_type_base(disposition) == "attachment" || filename.is_some() || signature_part;
    state.next_part = state.next_part.saturating_add(1);
    let generated = format!("mime-part-{}", state.next_part);
    let path = filename.unwrap_or(generated);
    if is_attachment {
        state.attachments_seen = state.attachments_seen.saturating_add(1);
        state.decoded_attachment_bytes = state
            .decoded_attachment_bytes
            .saturating_add(decoded.len() as u64);
    }
    state.extracted.push(ExtractedEvidenceMember {
        path: if is_attachment {
            format!("attachment:{path}")
        } else {
            path
        },
        media_type,
        bytes: decoded,
    });
    Ok(())
}

type MailHeaders = Vec<(String, String)>;
type ParsedMailEntity<'a> = (MailHeaders, &'a [u8]);

fn parse_mail_headers(bytes: &[u8]) -> Result<ParsedMailEntity<'_>, String> {
    let (header_end, separator_len) = find_header_separator(bytes)
        .ok_or_else(|| "email/MIME entity has no header/body separator".to_owned())?;
    if header_end > DOCUMENT_MAIL_MAX_HEADER_BYTES {
        return Err(format!(
            "email headers exceed the {}-byte limit",
            DOCUMENT_MAIL_MAX_HEADER_BYTES
        ));
    }
    let raw = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "email headers are not valid UTF-8/ASCII".to_owned())?;
    let normalized = raw.replace("\r\n", "\n");
    let mut unfolded = Vec::<String>::new();
    for line in normalized.split('\n') {
        if line.len() > 8 * 1024 {
            return Err("email contains an overlong header line".to_owned());
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let previous = unfolded
                .last_mut()
                .ok_or_else(|| "email starts with an orphan header continuation".to_owned())?;
            previous.push(' ');
            previous.push_str(line.trim());
        } else if !line.is_empty() {
            unfolded.push(line.to_owned());
        }
    }
    if unfolded.len() > DOCUMENT_MAIL_MAX_HEADERS {
        return Err(format!(
            "email contains more than {} headers",
            DOCUMENT_MAIL_MAX_HEADERS
        ));
    }
    let mut headers = Vec::with_capacity(unfolded.len());
    for line in unfolded {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "email contains a malformed header without ':'".to_owned())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("email contains an invalid header name".to_owned());
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((headers, &bytes[header_end + separator_len..]))
}

fn find_header_separator(bytes: &[u8]) -> Option<(usize, usize)> {
    find_bytes(bytes, b"\r\n\r\n")
        .map(|offset| (offset, 4))
        .or_else(|| find_bytes(bytes, b"\n\n").map(|offset| (offset, 2)))
}

fn mail_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn mime_parameter(value: &str, name: &str) -> Option<String> {
    split_mime_segments(value)
        .into_iter()
        .skip(1)
        .find_map(|segment| {
            let (key, raw) = segment.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| raw.trim().trim_matches('"').trim_matches('\'').to_owned())
        })
}

fn split_mime_segments(value: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    for (index, ch) in value.char_indices() {
        if matches!(ch, '"' | '\'') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        } else if ch == ';' && quote.is_none() {
            segments.push(&value[start..index]);
            start = index + 1;
        }
    }
    segments.push(&value[start..]);
    segments
}

fn split_multipart_body<'a>(body: &'a [u8], boundary: &[u8]) -> Result<Vec<&'a [u8]>, String> {
    let mut marker = Vec::with_capacity(boundary.len() + 2);
    marker.extend_from_slice(b"--");
    marker.extend_from_slice(boundary);
    let mut parts = Vec::new();
    let mut part_start = None;
    let mut cursor = 0usize;
    let mut saw_closing = false;
    while cursor <= body.len() {
        let line_end = body[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(body.len(), |offset| cursor + offset);
        let mut line = &body[cursor..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        let closing = line == [marker.as_slice(), b"--"].concat();
        if line == marker.as_slice() || closing {
            if let Some(start) = part_start.take() {
                let mut end = cursor;
                while end > start && matches!(body[end - 1], b'\r' | b'\n') {
                    end -= 1;
                }
                if end > start {
                    parts.push(&body[start..end]);
                }
            }
            if closing {
                saw_closing = true;
                break;
            }
            part_start = Some((line_end + usize::from(line_end < body.len())).min(body.len()));
        }
        if line_end == body.len() {
            break;
        }
        cursor = line_end + 1;
    }
    if !saw_closing {
        return Err("multipart email has no closing boundary".to_owned());
    }
    Ok(parts)
}

fn decode_mail_body(body: &[u8], transfer_encoding: &str) -> Result<Vec<u8>, String> {
    match transfer_encoding.trim().to_ascii_lowercase().as_str() {
        "" | "7bit" | "8bit" | "binary" => Ok(body.to_vec()),
        "base64" => {
            let compact = body
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
            if compact.len() > DOCUMENT_CONTAINER_MAX_MEMBER_BYTES as usize * 2 {
                return Err("base64 MIME part exceeds the bounded encoded-size limit".to_owned());
            }
            B64.decode(compact)
                .map_err(|_| "MIME part contains invalid base64".to_owned())
        }
        "quoted-printable" => decode_quoted_printable(body),
        other => Err(format!(
            "unsupported Content-Transfer-Encoding {other:?}; attachment was not decoded"
        )),
    }
}

fn decode_quoted_printable(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'=' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if bytes.get(index + 1..index + 3) == Some(b"\r\n") {
            index += 3;
            continue;
        }
        if bytes.get(index + 1) == Some(&b'\n') {
            index += 2;
            continue;
        }
        let Some(pair) = bytes.get(index + 1..index + 3) else {
            return Err("quoted-printable MIME part ends with an incomplete escape".to_owned());
        };
        let high = hex_nibble(pair[0])
            .ok_or_else(|| "quoted-printable MIME part contains an invalid escape".to_owned())?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| "quoted-printable MIME part contains an invalid escape".to_owned())?;
        out.push(high << 4 | low);
        index += 3;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn document_extraction_limits() -> DocumentExtractionLimitsReport {
    DocumentExtractionLimitsReport {
        upload_max_bytes: DOCUMENT_IMPORT_VALIDATION_MAX_BYTES,
        archive_max_members: DOCUMENT_CONTAINER_MAX_MEMBERS,
        extracted_member_max_bytes: DOCUMENT_CONTAINER_MAX_MEMBER_BYTES,
        extracted_total_max_bytes: DOCUMENT_CONTAINER_MAX_EXTRACTED_BYTES,
        mail_header_max_bytes: DOCUMENT_MAIL_MAX_HEADER_BYTES,
        mail_header_max_count: DOCUMENT_MAIL_MAX_HEADERS,
        mail_part_max_count: DOCUMENT_MAIL_MAX_PARTS,
        mail_nesting_max_depth: DOCUMENT_MAIL_MAX_DEPTH,
    }
}

fn content_type_for_embedded_member(path: &str, bytes: &[u8]) -> &'static str {
    let extension = filename_extension(path).map(|value| value.to_ascii_lowercase());
    match extension.as_deref() {
        Some("pdf") => "application/pdf",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        Some("rtf") => "application/rtf",
        Some("eml") => "message/rfc822",
        Some("p7s" | "p7m" | "cades") => "application/pkcs7-signature",
        Some("asice") => "application/vnd.etsi.asic-e+zip",
        Some("asics") => "application/vnd.etsi.asic-s+zip",
        Some("xml" | "xades") => "application/xml",
        Some("txt") => "text/plain",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        _ if bytes.starts_with(b"%PDF-") => "application/pdf",
        _ if bytes.starts_with(ZIP_MAGIC) => "application/zip",
        _ if bytes.starts_with(br#"{\rtf"#) => "application/rtf",
        _ => "application/octet-stream",
    }
}

fn signature_format_from_media_type(media_type: &str) -> Option<&'static str> {
    match content_type_base(media_type).as_str() {
        "application/pkcs7-signature"
        | "application/x-pkcs7-signature"
        | "application/pkcs7-mime"
        | "application/x-pkcs7-mime" => Some("cades"),
        "application/vnd.etsi.asic-e+zip" => Some("asic_e"),
        "application/vnd.etsi.asic-s+zip" => Some("asic_s"),
        _ => None,
    }
}

fn claimed_signature_format(
    path: &str,
    media_type: Option<&str>,
    bytes: &[u8],
) -> Option<&'static str> {
    if let Some(format) = media_type.and_then(signature_format_from_media_type) {
        return Some(format);
    }
    let extension = filename_extension(path).map(|value| value.to_ascii_lowercase());
    if matches!(extension.as_deref(), Some("p7s" | "p7m" | "cades")) {
        return Some("cades");
    }
    if extension.as_deref() == Some("asice") {
        return Some("asic_e");
    }
    if extension.as_deref() == Some("asics") {
        return Some("asic_s");
    }
    if bytes.starts_with(ZIP_MAGIC) && find_bytes(bytes, b"application/vnd.etsi.asic").is_some() {
        return Some("asic");
    }
    if bytes.starts_with(b"%PDF-")
        && (count_signature_markers(bytes) > 0 || count_bytes(bytes, b"/ByteRange") > 0)
    {
        return Some("pades");
    }
    let xades_marker = find_bytes(bytes, b"http://uri.etsi.org/01903").is_some()
        && (find_bytes(bytes, b"<ds:Signature").is_some()
            || find_bytes(bytes, b"<Signature").is_some());
    if xades_marker
        || (extension.as_deref() == Some("xades") && find_bytes(bytes, b"Signature").is_some())
    {
        return Some("xades");
    }
    None
}

fn is_asic_signature_format(format: &'static str) -> bool {
    matches!(format, "asic" | "asic_e" | "asic_s")
}

fn validate_document_signature_evidence(
    bytes: &[u8],
    detected_content_type: &str,
    filename: Option<&str>,
    pades: &SignedPdfSignalReport,
    zip_members: &[ExtractedEvidenceMember],
    mail_parts: &[ExtractedEvidenceMember],
) -> DocumentSignatureEvidenceReport {
    let top_path = filename.unwrap_or("top-level-import");
    let top_claim = claimed_signature_format(top_path, Some(detected_content_type), bytes);
    let mut validations = Vec::new();
    if pades.signed_pdf_signal {
        validations.push(pades_signature_entry(top_path, pades));
    } else if let Some(format) = top_claim {
        validations.push(validate_signature_claim(format, top_path, bytes, None, &[]));
    }

    // A self-contained ASiC top-level import already validates every signature member as a unit.
    // Revalidating its internal .p7s/.xml members as detached siblings would be ambiguous.
    if !top_claim.is_some_and(is_asic_signature_format) {
        let members = zip_members
            .iter()
            .chain(mail_parts.iter())
            .collect::<Vec<_>>();
        for member in &members {
            let Some(format) =
                claimed_signature_format(&member.path, Some(&member.media_type), &member.bytes)
            else {
                continue;
            };
            let signed_content = (format == "cades")
                .then(|| find_detached_signed_content(member, &members))
                .flatten();
            validations.push(validate_signature_claim(
                format,
                &member.path,
                &member.bytes,
                signed_content,
                &members,
            ));
        }
    }

    let claimed_signature_count = validations.len();
    let validation_performed_count = validations
        .iter()
        .filter(|entry| entry.validation_performed)
        .count();
    let cryptographically_valid_count = validations
        .iter()
        .filter(|entry| entry.cryptographically_valid)
        .count();
    DocumentSignatureEvidenceReport {
        signature_claim_detected: claimed_signature_count > 0,
        claimed_signature_count,
        validation_performed_count,
        cryptographically_valid_count,
        all_claimed_signatures_valid: (claimed_signature_count > 0).then_some(
            claimed_signature_count == cryptographically_valid_count
                && validation_performed_count == claimed_signature_count,
        ),
        trust_validation: "not_performed",
        legal_validity_claimed: false,
        validations,
    }
}

fn pades_signature_entry(
    path: &str,
    report: &SignedPdfSignalReport,
) -> DocumentSignatureValidationEntry {
    let (status, valid) = match report.validation_status {
        "valid_pades_b" => ("valid", true),
        "invalid" => ("invalid", false),
        _ => ("indeterminate", false),
    };
    DocumentSignatureValidationEntry {
        format: "pades",
        status,
        signature_path: path.to_owned(),
        signed_content_path: Some(path.to_owned()),
        signed_content_sha256: report.byte_range_digest_sha256.clone(),
        validation_performed: report.cryptographic_validation_performed,
        cryptographically_valid: valid,
        signer_certificate_sha256: None,
        signing_time: None,
        validation_error: report.validation_error.clone(),
        trust_validation: "not_performed",
        legal_validity_claimed: false,
    }
}

fn validate_signature_claim(
    format: &'static str,
    signature_path: &str,
    signature_bytes: &[u8],
    signed_content: Option<&ExtractedEvidenceMember>,
    _all_members: &[&ExtractedEvidenceMember],
) -> DocumentSignatureValidationEntry {
    match format {
        "pades" => pades_signature_entry(signature_path, &recognize_signed_pdf(signature_bytes)),
        "asic" | "asic_e" | "asic_s" => match validate_asic_container(signature_bytes) {
            Ok(report) => {
                let valid = report.is_valid();
                let first = report.signatures.first();
                DocumentSignatureValidationEntry {
                    format,
                    status: if valid { "valid" } else { "invalid" },
                    signature_path: signature_path.to_owned(),
                    signed_content_path: first
                        .and_then(|entry| entry.covered_data_objects.first().cloned()),
                    signed_content_sha256: None,
                    validation_performed: true,
                    cryptographically_valid: valid,
                    signer_certificate_sha256: first
                        .and_then(|entry| entry.signer_cert_der.as_deref())
                        .map(sha256_hex),
                    signing_time: first
                        .and_then(|entry| entry.signing_time)
                        .and_then(|value| value.format(&Rfc3339).ok()),
                    validation_error: (!valid).then(|| {
                        let mut reasons = report.failure_reasons;
                        for signature in report.signatures {
                            reasons.extend(signature.failure_reasons);
                        }
                        if reasons.is_empty() {
                            "ASiC signature validation failed".to_owned()
                        } else {
                            reasons.join("; ")
                        }
                    }),
                    trust_validation: "not_performed",
                    legal_validity_claimed: false,
                }
            }
            Err(error) => invalid_signature_entry(
                format,
                signature_path,
                true,
                format!("ASiC validation failed: {error}"),
            ),
        },
        "xades" => match chancela_xades::validate_xades(signature_bytes) {
            Ok(report) => {
                let all_references_checked = report.references_checked == report.reference_count;
                let valid = report.is_valid_b() && all_references_checked;
                DocumentSignatureValidationEntry {
                    format,
                    status: if valid {
                        "valid"
                    } else if !all_references_checked {
                        "indeterminate"
                    } else {
                        "invalid"
                    },
                    signature_path: signature_path.to_owned(),
                    signed_content_path: None,
                    signed_content_sha256: None,
                    validation_performed: true,
                    cryptographically_valid: valid,
                    signer_certificate_sha256: report.signer_cert_der.as_deref().map(sha256_hex),
                    signing_time: report
                        .signing_time
                        .and_then(|value| value.format(&Rfc3339).ok()),
                    validation_error: (!valid).then(|| {
                        if !all_references_checked {
                            format!(
                                "XAdES external references were unavailable; validation checked only {}/{} references",
                                report.references_checked, report.reference_count
                            )
                        } else {
                            format!(
                                "XAdES-B requirements were not satisfied (references checked {}/{}, signed properties signed: {})",
                                report.references_checked,
                                report.reference_count,
                                report.signed_properties_signed
                            )
                        }
                    }),
                    trust_validation: "not_performed",
                    legal_validity_claimed: false,
                }
            }
            Err(error) => invalid_signature_entry(
                format,
                signature_path,
                true,
                format!("XAdES validation failed: {error}"),
            ),
        },
        "cades" => {
            let Some(content) = signed_content else {
                return invalid_signature_entry(
                    format,
                    signature_path,
                    false,
                    "detached CAdES content is unavailable or ambiguous".to_owned(),
                );
            };
            let digest: [u8; 32] = Sha256::digest(&content.bytes).into();
            let artifact = SignatureArtifact {
                id: Uuid::nil(),
                slot: 0,
                family: SigningFamily::QualifiedCertificate,
                format: SignatureFormat::CAdES,
                profile: BaselineProfile::B_B,
                evidentiary_level: EvidentiaryLevel::Advanced,
                signed_at: None,
                signature: signature_bytes.to_vec(),
                trusted_list_status: None,
                timestamp_token_der: None,
            };
            match validate_signature(&artifact, Some(&digest)) {
                Ok(report) => DocumentSignatureValidationEntry {
                    format,
                    status: "valid",
                    signature_path: signature_path.to_owned(),
                    signed_content_path: Some(content.path.clone()),
                    signed_content_sha256: Some(sha256_hex(&content.bytes)),
                    validation_performed: true,
                    cryptographically_valid: report.cryptographically_valid,
                    signer_certificate_sha256: Some(sha256_hex(&report.signer_cert_der)),
                    signing_time: report
                        .signing_time
                        .and_then(|value| value.format(&Rfc3339).ok()),
                    validation_error: None,
                    trust_validation: "not_performed",
                    legal_validity_claimed: false,
                },
                Err(error) => invalid_signature_entry(
                    format,
                    signature_path,
                    true,
                    format!("CAdES validation failed: {error}"),
                ),
            }
        }
        _ => invalid_signature_entry(
            format,
            signature_path,
            false,
            "unsupported claimed signature format".to_owned(),
        ),
    }
}

fn invalid_signature_entry(
    format: &'static str,
    signature_path: &str,
    performed: bool,
    error: String,
) -> DocumentSignatureValidationEntry {
    DocumentSignatureValidationEntry {
        format,
        status: if performed {
            "invalid"
        } else {
            "indeterminate"
        },
        signature_path: signature_path.to_owned(),
        signed_content_path: None,
        signed_content_sha256: None,
        validation_performed: performed,
        cryptographically_valid: false,
        signer_certificate_sha256: None,
        signing_time: None,
        validation_error: Some(error),
        trust_validation: "not_performed",
        legal_validity_claimed: false,
    }
}

fn find_detached_signed_content<'a>(
    signature: &ExtractedEvidenceMember,
    members: &[&'a ExtractedEvidenceMember],
) -> Option<&'a ExtractedEvidenceMember> {
    let lower = signature.path.to_ascii_lowercase();
    let expected = [".p7s", ".p7m", ".cades"]
        .iter()
        .find_map(|suffix| lower.strip_suffix(suffix));
    if let Some(expected) = expected
        && let Some(member) = members
            .iter()
            .copied()
            .find(|member| member.path.to_ascii_lowercase() == expected)
    {
        return Some(member);
    }
    let candidates = members
        .iter()
        .copied()
        .filter(|member| member.path != signature.path)
        .filter(|member| {
            claimed_signature_format(&member.path, Some(&member.media_type), &member.bytes)
                .is_none()
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [only] => Some(*only),
        _ => None,
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

#[allow(
    clippy::too_many_arguments,
    reason = "the ordered detector precedence is safer to audit with each recognition signal explicit"
)]
fn detect_candidate_content_type(
    bytes: &[u8],
    is_pdf: bool,
    legacy_word: &LegacyWordDocRecognitionReport,
    image: &ImageRecognitionReport,
    text: &TextDocumentRecognitionReport,
    office: &OfficeDocumentRecognitionReport,
    rtf: &RtfRecognitionReport,
    email: &EmailRecognitionReport,
    top_level_signature_claim: Option<&'static str>,
    zip_bundle: &ZipBundleRecognitionReport,
) -> &'static str {
    if legacy_word.is_legacy_word_doc {
        "application/msword"
    } else if legacy_word.is_ole_cfb {
        "application/vnd.ms-office"
    } else if is_pdf {
        "application/pdf"
    } else if office.format == Some("docx") {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    } else if office.format == Some("odt") {
        "application/vnd.oasis.opendocument.text"
    } else if rtf.is_rtf {
        "application/rtf"
    } else if email.is_email {
        "message/rfc822"
    } else if top_level_signature_claim == Some("asic_s") {
        "application/vnd.etsi.asic-s+zip"
    } else if matches!(top_level_signature_claim, Some("asic" | "asic_e")) {
        "application/vnd.etsi.asic-e+zip"
    } else if top_level_signature_claim == Some("cades") {
        "application/pkcs7-signature"
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
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            ("docx", "docx_non_canonical_evidence")
        }
        "application/vnd.oasis.opendocument.text" => ("odt", "odt_non_canonical_evidence"),
        "application/rtf" | "text/rtf" => ("rtf", "rtf_non_canonical_evidence"),
        "message/rfc822" => ("email", "email_non_canonical_evidence"),
        "application/vnd.etsi.asic-e+zip" | "application/vnd.etsi.asic-s+zip" => {
            ("asic", "asic_signed_non_canonical_evidence")
        }
        "application/pkcs7-signature" => ("cades", "cades_signed_non_canonical_evidence"),
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
    let requires_conversion_review = matches!(
        base.as_str(),
        "application/msword"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.oasis.opendocument.text"
            | "application/rtf"
    );
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
    } else if requires_conversion_review {
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

fn document_canonical_conversion_preflight(
    detected_content_type: &str,
    legacy_word: &LegacyWordDocRecognitionReport,
    review_state: &'static str,
    original_bytes_preserved: bool,
) -> DocumentCanonicalConversionPreflightReport {
    document_canonical_conversion_preflight_from_flags(
        content_type_base(detected_content_type).as_str(),
        legacy_word.is_ole_cfb,
        legacy_word.is_legacy_word_doc,
        review_state,
        original_bytes_preserved,
    )
}

fn document_canonical_conversion_preflight_from_flags(
    detected_content_type: &str,
    is_ole_cfb: bool,
    is_legacy_word_doc: bool,
    review_state: &'static str,
    original_bytes_preserved: bool,
) -> DocumentCanonicalConversionPreflightReport {
    let mut evidence_basis = Vec::new();
    let (status, source_format, bounded_evidence_status, blockers, next_step) =
        if is_legacy_word_doc {
            evidence_basis.push("ole_cfb_magic_detected");
            evidence_basis.push("legacy_word_doc_metadata_or_extension_detected");
            evidence_basis.push(if original_bytes_preserved {
                "original_bytes_preserved"
            } else {
                "validation_candidate_bytes_not_persisted"
            });
            (
                "blocked",
                "legacy_word_doc",
                "metadata_only_legacy_doc_preflight",
                vec![
                    "non_canonical_import_only",
                    "operator_conversion_review_required",
                    "no_canonical_conversion_workflow_executed",
                ],
                "separate_operator_review_required_before_any_canonical_conversion_workflow",
            )
        } else if is_ole_cfb || detected_content_type == "application/vnd.ms-office" {
            evidence_basis.push("ole_cfb_magic_detected");
            evidence_basis.push(if original_bytes_preserved {
                "original_bytes_preserved"
            } else {
                "validation_candidate_bytes_not_persisted"
            });
            (
                "blocked",
                "ole_compound_file",
                "metadata_only_ole_preflight",
                vec![
                    "ambiguous_ole_compound_file",
                    "non_canonical_import_only",
                    "no_canonical_conversion_workflow_executed",
                ],
                "resolve_ole_identity_before_any_separate_canonical_conversion_workflow",
            )
        } else {
            (
                "not_attempted",
                "not_legacy_doc_or_ole",
                "not_applicable_to_import_format",
                vec!["not_legacy_doc_or_ole_import"],
                "no_legacy_doc_canonical_conversion_preflight_action",
            )
        };

    DocumentCanonicalConversionPreflightReport {
        report_kind: "legacy_imported_document_canonical_conversion_preflight",
        scope: "local_metadata_only",
        status,
        source_format,
        review_state,
        bounded_evidence_status,
        evidence_basis,
        blockers,
        next_step,
        local_metadata_only: true,
        original_bytes_preserved,
        canonical_conversion_performed: false,
        canonical_pdfa_generated: false,
        signature_validation_performed: false,
        ocr_performed: false,
        legal_acceptance_claimed: false,
        external_provider_contacted: false,
        canonical_record_replaced: false,
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
    pub created_at: String,
    pub download: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_evidence_status: Option<DispatchEvidenceStatusView>,
}

#[derive(Clone, Deserialize)]
pub struct GeneratedDocumentDispatchEvidenceRequest {
    pub actor: String,
    pub dispatched_at: String,
    pub channel: Option<DispatchChannel>,
    pub reference: Option<String>,
    pub recipients: Option<Vec<String>>,
    pub evidence_reference: Option<String>,
    pub imported_document_id: Option<String>,
    pub operator_note: Option<String>,
}

#[derive(Serialize)]
pub struct GeneratedDocumentDispatchEvidenceView {
    pub document_id: String,
    pub idempotency_key: String,
    pub act_id: String,
    pub template_id: String,
    pub actor: String,
    pub dispatched_at: String,
    pub channel: Option<String>,
    pub reference: Option<String>,
    pub evidence_reference: Option<String>,
    pub imported_document_id: Option<String>,
    pub recipients: Vec<String>,
    pub operator_note: Option<String>,
    pub recorded_at: String,
    pub sending_performed_by_chancela: bool,
    pub delivery_confirmed: bool,
    pub legal_sufficiency_claimed: bool,
    pub legal_notice_completion_claimed: bool,
    pub bytes_in_payload: bool,
}

#[derive(Serialize)]
pub struct GeneratedDocumentDispatchEvidenceResponse {
    pub evidence: GeneratedDocumentDispatchEvidenceView,
    pub dispatch_evidence_status: DispatchEvidenceStatusView,
}

#[derive(Serialize)]
pub struct GeneratedDocumentDispatchEvidenceListView {
    pub document_id: String,
    pub act_id: String,
    pub template_id: String,
    pub dispatch_evidence_status: DispatchEvidenceStatusView,
    pub evidence: Vec<GeneratedDocumentDispatchEvidenceView>,
}

pub(crate) const GENERATED_DISPATCH_EVIDENCE_METADATA_KIND: &str =
    "generated_document_dispatch_evidence_metadata";
pub(crate) const GENERATED_DISPATCH_EVIDENCE_METADATA_SCHEMA: &str =
    "chancela-generated-document-dispatch-evidence-metadata/v1";

#[derive(Clone, Serialize)]
pub(crate) struct GeneratedDispatchEvidencePreservationIndex {
    pub evidence_kind: &'static str,
    pub metadata_schema: &'static str,
    pub status_scope: &'static str,
    pub generated_document_id: String,
    pub act_id: String,
    pub template_id: String,
    pub generated_document_download: String,
    pub dispatch_evidence_status: DispatchEvidenceStatusView,
    pub coverage: GeneratedDispatchEvidenceCoverage,
    pub records: Vec<GeneratedDispatchEvidencePreservationRecord>,
    pub sending_performed_by_chancela: bool,
    pub delivery_confirmed: bool,
    pub dispatch_completed: bool,
    pub completion_basis: &'static str,
    pub legal_notice_completion_claimed: bool,
    pub legal_sufficiency_claimed: bool,
    pub provider_execution_claimed: bool,
    pub registry_filing_claimed: bool,
    pub bundle_readiness_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub legal_archive_acceptance_claimed: bool,
    pub proof_bytes_included: bool,
    pub operator_note_included: bool,
}

#[derive(Clone, Serialize)]
pub(crate) struct GeneratedDispatchEvidenceCoverage {
    pub required_recipients: Vec<String>,
    pub recorded_recipients: Vec<String>,
    pub missing_recipients: Vec<String>,
    pub evidence_attached: bool,
    pub all_required_recipients_covered: bool,
}

#[derive(Clone, Serialize)]
pub(crate) struct GeneratedDispatchEvidencePreservationRecord {
    pub dispatched_at: String,
    pub recorded_at: String,
    pub channel: Option<String>,
    pub reference: Option<String>,
    pub evidence_reference: Option<String>,
    pub imported_document_id: Option<String>,
    pub recipients: Vec<String>,
    pub sending_performed_by_chancela: bool,
    pub delivery_confirmed: bool,
    pub legal_notice_completion_claimed: bool,
    pub legal_sufficiency_claimed: bool,
    pub dispatch_completed: bool,
    pub completion_basis: &'static str,
    pub bytes_included: bool,
    pub operator_note_included: bool,
}

pub(crate) fn dispatch_evidence_status_for_template(
    template_id: &str,
    required_recipients: &[String],
    recorded_recipients: &[String],
) -> Option<DispatchEvidenceStatusView> {
    let profile = generated_dispatch_evidence_profile_for_template(template_id)?;
    let required_set: BTreeSet<&str> = required_recipients
        .iter()
        .map(String::as_str)
        .filter(|name| !name.trim().is_empty())
        .collect();
    let recorded_set: BTreeSet<&str> = recorded_recipients
        .iter()
        .map(String::as_str)
        .filter(|name| required_set.contains(name))
        .collect();
    let recorded = required_recipients
        .iter()
        .filter(|name| recorded_set.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let missing = required_recipients
        .iter()
        .filter(|name| !recorded_set.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let evidence_attached = !recorded.is_empty();
    let all_required_recipients_covered = !required_set.is_empty() && missing.is_empty();
    Some(DispatchEvidenceStatusView {
        status: if all_required_recipients_covered {
            "operator_evidence_covered".to_owned()
        } else if recorded.is_empty() {
            "required_pending".to_owned()
        } else {
            "operator_evidence_partial".to_owned()
        },
        required: !required_set.is_empty(),
        evidence_attached,
        dispatch_completed: false,
        completion_basis: "none",
        required_recipients: required_recipients.to_vec(),
        recorded_recipients: recorded,
        missing_recipients: missing,
        note: if all_required_recipients_covered {
            profile.covered_note()
        } else {
            profile.uncovered_note()
        },
    })
}

pub(crate) fn absent_owner_recipient_names(act: &Act) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for attendee in &act.attendees {
        if attendee.presence != PresenceMode::Absent {
            continue;
        }
        let name = attendee.name.trim();
        if name.is_empty() || !seen.insert(name.to_owned()) {
            continue;
        }
        recipients.push(name.to_owned());
    }
    recipients
}

pub(crate) fn convening_recipient_names(act: &Act) -> Vec<String> {
    let Some(convening) = &act.convening else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for recipient in &convening.recipients {
        let name = recipient.name.trim();
        if name.is_empty() || !seen.insert(name.to_owned()) {
            continue;
        }
        recipients.push(name.to_owned());
    }
    recipients
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
    // entities → books → acts → ledger. The act itself is not mutated, but the document row + event
    // are committed atomically, so the ledger write lock is taken after the read prefix.
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;

    let act = acts.get(&ActId(id)).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    if is_ata_template(&q.template_id) {
        return Err(ApiError::Conflict(
            "Ata templates become the canonical signing snapshot only through POST /v1/acts/{id}/advance with to=Signing and optional template_id; ad-hoc generation cannot create or replace that snapshot"
                .to_owned(),
        ));
    }

    // Render + write PDF/A before appending anything to the ledger, so a render/write failure returns
    // cleanly with no ledger mutation to roll back.
    let made = generate_for_act_template(act, book, entity, &q.template_id)?;

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

    publish_generated_document_read_model(&state, &made.stored).await;

    let view = generated_document_view(&state, made.stored).await?;
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// `GET /v1/acts/{act_id}/documents/generated` — list persisted generated-document summaries
/// for one act, including the absent-owner dispatch-evidence coverage status where applicable.
pub async fn list_generated_documents_for_act(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<GeneratedDocumentView>>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    if !state.acts.read().await.contains_key(&act_id) {
        return Err(ApiError::NotFound);
    }

    let docs = load_documents_for_act(&state, act_id).await?;
    let mut views = Vec::with_capacity(docs.len());
    for doc in docs {
        views.push(generated_document_view(&state, doc).await?);
    }
    Ok(Json(views))
}

async fn load_documents_for_act(
    state: &AppState,
    act_id: ActId,
) -> Result<Vec<StoredDocument>, ApiError> {
    if let Some(store) = &state.store {
        return store
            .documents_for_act(act_id)
            .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")));
    }

    let mut docs = state
        .documents
        .read()
        .await
        .values()
        .filter(|doc| doc.act_id == act_id)
        .cloned()
        .collect::<Vec<_>>();
    docs.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(docs)
}

async fn generated_document_view(
    state: &AppState,
    doc: StoredDocument,
) -> Result<GeneratedDocumentView, ApiError> {
    let dispatch_evidence_status =
        dispatch_evidence_status_for_generated_document(state, &doc).await?;
    let document_id = doc.id.clone();
    Ok(GeneratedDocumentView {
        id: document_id.clone(),
        act_id: doc.act_id.to_string(),
        template_id: doc.template_id,
        pdf_digest: doc.pdf_digest,
        profile: doc.profile,
        created_at: doc.created_at.format(&Rfc3339).unwrap_or_default(),
        download: format!("/v1/documents/generated/{document_id}"),
        dispatch_evidence_status,
    })
}

/// `GET /v1/documents/generated/{document_id}` — stream one generated document row by its own id.
/// This is for on-demand generated post-act outputs (certidões, extratos, comunicações, and other
/// non-canonical catalog artifacts). It intentionally does not use [`load_document`], because that
/// helper preserves `/v1/acts/{id}/document` as the canonical sealed Ata target for signing/bundles.
pub async fn get_generated_document_pdf(
    State(state): State<AppState>,
    Path(document_id): Path<String>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let doc = load_document_by_id(&state, &document_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    // RBAC: by-id generated-document reads inherit `act.read` from the document's owning act.
    let scope = scope_of_act(&state, doc.act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;

    let act_id = doc.act_id.to_string();
    let dispatch_status = dispatch_evidence_status_for_generated_document(&state, &doc).await?;
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/pdf")
        .header("x-chancela-document-id", doc.id)
        .header("x-chancela-act-id", act_id)
        .header("x-chancela-template-id", doc.template_id)
        .header("x-chancela-pdf-digest", doc.pdf_digest)
        .header("x-chancela-profile", doc.profile);
    if let Some(status) = dispatch_status {
        builder = builder
            .header(
                "x-chancela-dispatch-evidence-status",
                status.status.as_str(),
            )
            .header(
                "x-chancela-dispatch-evidence-required",
                status.required.to_string(),
            )
            .header(
                "x-chancela-dispatch-evidence-attached",
                status.evidence_attached.to_string(),
            )
            .header(
                "x-chancela-dispatch-completed",
                status.dispatch_completed.to_string(),
            );
    }
    builder.body(Body::from(doc.pdf_bytes)).map_err(|e| {
        ApiError::Internal(format!("failed to build generated document response: {e}"))
    })
}

/// `POST /v1/documents/generated/{document_id}/dispatch-evidence` — record metadata-only operator
/// evidence for a generated absent-owner condominium communication. This never sends anything,
/// never confirms delivery, never completes legal notice, and never mutates sealed act/PDF bytes.
pub async fn record_generated_document_dispatch_evidence(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(document_id): Path<String>,
    Json(req): Json<GeneratedDocumentDispatchEvidenceRequest>,
) -> Result<Response, ApiError> {
    let doc = load_document_by_id(&state, &document_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let scope = scope_of_act(&state, doc.act_id).await;
    require_permission(&state, &actor, Permission::DocumentGenerate, scope).await?;
    let context = generated_dispatch_context_for_doc(&state, doc).await?;
    ensure_book_open_for_dispatch_evidence(&context.book)?;
    let Some(store) = &state.store else {
        return Err(ApiError::Unprocessable(
            "generated document dispatch evidence requires on-disk persistence".to_owned(),
        ));
    };

    let request = normalize_generated_dispatch_evidence_request(
        req,
        &context.required_recipients,
        context.profile,
    )?;
    if let Some(imported_document_id) = &request.imported_document_id {
        validate_dispatch_evidence_import(store, imported_document_id, context.doc.act_id)?;
    }
    let resolved_actor = actor.resolve(&request.actor);
    let idempotency_key =
        generated_dispatch_evidence_idempotency_key(&context.doc, &resolved_actor, &request)?;

    let evidence = StoredGeneratedDocumentDispatchEvidence {
        document_id: context.doc.id.clone(),
        idempotency_key,
        act_id: context.doc.act_id,
        template_id: context.doc.template_id.clone(),
        actor: resolved_actor.clone(),
        dispatched_at: request.dispatched_at,
        channel: request.channel.clone(),
        reference: request.reference.clone(),
        evidence_reference: request.evidence_reference.clone(),
        imported_document_id: request.imported_document_id.clone(),
        recipients: request.recipients.clone(),
        operator_note: request.operator_note.clone(),
        recorded_at: OffsetDateTime::now_utc(),
    };
    let payload = serde_json::to_vec(&generated_dispatch_evidence_event_payload(
        &context, &evidence,
    ))?;
    let event_scope = format!(
        "entity:{}/book:{}/act:{}",
        context.entity.id, context.book.id, context.act.id
    );
    let justification = format!(
        "operator-recorded dispatch evidence for {} {} recipient(s)",
        evidence.recipients.len(),
        context.profile.code()
    );

    let mut ledger = state.ledger.write().await;
    if let Some(existing) = store
        .generated_document_dispatch_evidence_by_key(&context.doc.id, &evidence.idempotency_key)
        .map_err(|e| ApiError::Internal(format!("dispatch evidence store read failed: {e}")))?
    {
        drop(ledger);
        return generated_dispatch_evidence_response(StatusCode::OK, &context, store, &existing);
    }
    crate::try_append_event(
        &mut ledger,
        &resolved_actor,
        &event_scope,
        context.profile.event_kind(),
        Some(&justification),
        &payload,
    )?;
    let event = ledger
        .events()
        .last()
        .expect("just-appended dispatch evidence event")
        .clone();
    let upsert = match store.persist_result(|tx| {
        let upsert = tx.upsert_generated_document_dispatch_evidence(&evidence)?;
        if upsert.inserted() {
            tx.append_event(&event)?;
        }
        Ok(upsert)
    }) {
        Ok(upsert) => upsert,
        Err(e) => {
            AppState::rollback_ledger_events(&mut ledger, 1);
            return Err(AppState::map_store_write_error(
                "failed to persist generated document dispatch evidence",
                e,
            ));
        }
    };
    let response_status = if upsert.inserted() {
        state.attest_latest(&attestor, &ledger).await;
        StatusCode::CREATED
    } else {
        AppState::rollback_ledger_events(&mut ledger, 1);
        StatusCode::OK
    };
    let stored_evidence = upsert.evidence().clone();
    drop(ledger);

    generated_dispatch_evidence_response(response_status, &context, store, &stored_evidence)
}

fn generated_dispatch_evidence_response(
    status_code: StatusCode,
    context: &GeneratedDispatchContext,
    store: &chancela_store::Store,
    evidence: &StoredGeneratedDocumentDispatchEvidence,
) -> Result<Response, ApiError> {
    let rows = store
        .generated_document_dispatch_evidence(&context.doc.id)
        .map_err(|e| ApiError::Internal(format!("dispatch evidence store read failed: {e}")))?;
    let status = dispatch_evidence_status_from_rows(context, &rows);
    Ok((
        status_code,
        Json(GeneratedDocumentDispatchEvidenceResponse {
            evidence: generated_dispatch_evidence_view(evidence),
            dispatch_evidence_status: status,
        }),
    )
        .into_response())
}

/// `GET /v1/documents/generated/{document_id}/dispatch-evidence` — read back metadata-only
/// operator dispatch evidence and the derived absent-recipient coverage status.
pub async fn get_generated_document_dispatch_evidence(
    State(state): State<AppState>,
    Path(document_id): Path<String>,
    actor: CurrentActor,
) -> Result<Json<GeneratedDocumentDispatchEvidenceListView>, ApiError> {
    let doc = load_document_by_id(&state, &document_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let scope = scope_of_act(&state, doc.act_id).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let context = generated_dispatch_context_for_doc(&state, doc).await?;
    let rows = match &state.store {
        Some(store) => store
            .generated_document_dispatch_evidence(&context.doc.id)
            .map_err(|e| ApiError::Internal(format!("dispatch evidence store read failed: {e}")))?,
        None => Vec::new(),
    };
    Ok(Json(GeneratedDocumentDispatchEvidenceListView {
        document_id: context.doc.id.clone(),
        act_id: context.doc.act_id.to_string(),
        template_id: context.doc.template_id.clone(),
        dispatch_evidence_status: dispatch_evidence_status_from_rows(&context, &rows),
        evidence: rows.iter().map(generated_dispatch_evidence_view).collect(),
    }))
}

struct GeneratedDispatchContext {
    profile: GeneratedDispatchEvidenceProfile,
    doc: StoredDocument,
    act: Act,
    book: Book,
    entity: Entity,
    required_recipients: Vec<String>,
}

async fn generated_dispatch_context_for_doc(
    state: &AppState,
    doc: StoredDocument,
) -> Result<GeneratedDispatchContext, ApiError> {
    generated_dispatch_context_for_doc_inner(state, doc, true)
        .await?
        .ok_or_else(unsupported_generated_dispatch_evidence_error)
}

async fn maybe_generated_dispatch_context_for_doc(
    state: &AppState,
    doc: StoredDocument,
) -> Result<Option<GeneratedDispatchContext>, ApiError> {
    generated_dispatch_context_for_doc_inner(state, doc, false).await
}

async fn generated_dispatch_context_for_doc_inner(
    state: &AppState,
    doc: StoredDocument,
    strict_required_recipients: bool,
) -> Result<Option<GeneratedDispatchContext>, ApiError> {
    let Some(profile) = generated_dispatch_evidence_profile_for_template(&doc.template_id) else {
        return if strict_required_recipients {
            Err(unsupported_generated_dispatch_evidence_error())
        } else {
            Ok(None)
        };
    };
    let act = state
        .acts
        .read()
        .await
        .get(&doc.act_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let book = state
        .books
        .read()
        .await
        .get(&act.book_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let entity = state
        .entities
        .read()
        .await
        .get(&book.entity_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let required_recipients = match profile {
        GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication => {
            if entity.family != EntityFamily::Condominium {
                return Err(ApiError::Unprocessable(
                    "absent-owner dispatch evidence requires a condominium act".to_owned(),
                ));
            }
            if act.state != ActState::Sealed || act.ata_number.is_none() {
                return Err(ApiError::Unprocessable(
                    "absent-owner dispatch evidence requires a sealed act".to_owned(),
                ));
            }
            absent_owner_recipient_names(&act)
        }
        GeneratedDispatchEvidenceProfile::GeneratedConveningNotice => {
            if !registry()
                .get(&doc.template_id)
                .is_some_and(|spec| spec.family == entity.family)
            {
                return Err(ApiError::Unprocessable(
                    "generated convening notice dispatch evidence requires a template for this entity family"
                        .to_owned(),
                ));
            }
            convening_recipient_names(&act)
        }
    };
    if required_recipients.is_empty() {
        return if strict_required_recipients {
            Err(ApiError::Unprocessable(
                profile.empty_recipients_message().to_owned(),
            ))
        } else {
            Ok(None)
        };
    }
    Ok(Some(GeneratedDispatchContext {
        profile,
        doc,
        act,
        book,
        entity,
        required_recipients,
    }))
}

fn unsupported_generated_dispatch_evidence_error() -> ApiError {
    ApiError::Unprocessable(
        "dispatch evidence is only supported for condominio-comunicacao-ausentes/v1 or generated Convocatoria documents"
            .to_owned(),
    )
}

async fn dispatch_evidence_status_for_generated_document(
    state: &AppState,
    doc: &StoredDocument,
) -> Result<Option<DispatchEvidenceStatusView>, ApiError> {
    if generated_dispatch_evidence_profile_for_template(&doc.template_id).is_none() {
        return Ok(None);
    }
    let Some(context) = maybe_generated_dispatch_context_for_doc(state, doc.clone()).await? else {
        return Ok(None);
    };
    let rows = match &state.store {
        Some(store) => store
            .generated_document_dispatch_evidence(&doc.id)
            .map_err(|e| ApiError::Internal(format!("dispatch evidence store read failed: {e}")))?,
        None => Vec::new(),
    };
    Ok(Some(dispatch_evidence_status_from_rows(&context, &rows)))
}

pub(crate) async fn generated_dispatch_evidence_preservation_indexes_for_act(
    state: &AppState,
    act_id: ActId,
) -> Result<Vec<GeneratedDispatchEvidencePreservationIndex>, ApiError> {
    let docs = load_documents_for_act(state, act_id).await?;
    let mut indexes = Vec::new();
    for doc in docs
        .into_iter()
        .filter(|doc| generated_dispatch_evidence_profile_for_template(&doc.template_id).is_some())
    {
        let Some(context) = maybe_generated_dispatch_context_for_doc(state, doc).await? else {
            continue;
        };
        let rows = match &state.store {
            Some(store) => store
                .generated_document_dispatch_evidence(&context.doc.id)
                .map_err(|e| {
                    ApiError::Internal(format!("dispatch evidence store read failed: {e}"))
                })?,
            None => Vec::new(),
        };
        indexes.push(generated_dispatch_evidence_preservation_index(
            &context, &rows,
        ));
    }
    indexes.sort_by(|left, right| {
        left.act_id
            .cmp(&right.act_id)
            .then_with(|| left.generated_document_id.cmp(&right.generated_document_id))
    });
    Ok(indexes)
}

fn dispatch_evidence_status_from_rows(
    context: &GeneratedDispatchContext,
    rows: &[StoredGeneratedDocumentDispatchEvidence],
) -> DispatchEvidenceStatusView {
    let recorded = rows
        .iter()
        .flat_map(|row| row.recipients.iter().cloned())
        .collect::<Vec<_>>();
    dispatch_evidence_status_for_template(
        &context.doc.template_id,
        &context.required_recipients,
        &recorded,
    )
    .expect("generated dispatch context uses a supported template")
}

fn generated_dispatch_evidence_preservation_index(
    context: &GeneratedDispatchContext,
    rows: &[StoredGeneratedDocumentDispatchEvidence],
) -> GeneratedDispatchEvidencePreservationIndex {
    let status = dispatch_evidence_status_from_rows(context, rows);
    let all_required_recipients_covered = status.required && status.missing_recipients.is_empty();
    GeneratedDispatchEvidencePreservationIndex {
        evidence_kind: GENERATED_DISPATCH_EVIDENCE_METADATA_KIND,
        metadata_schema: GENERATED_DISPATCH_EVIDENCE_METADATA_SCHEMA,
        status_scope: crate::external_validator_evidence::TECHNICAL_METADATA_ONLY,
        generated_document_id: context.doc.id.clone(),
        act_id: context.doc.act_id.to_string(),
        template_id: context.doc.template_id.clone(),
        generated_document_download: format!("/v1/documents/generated/{}", context.doc.id),
        coverage: GeneratedDispatchEvidenceCoverage {
            required_recipients: status.required_recipients.clone(),
            recorded_recipients: status.recorded_recipients.clone(),
            missing_recipients: status.missing_recipients.clone(),
            evidence_attached: status.evidence_attached,
            all_required_recipients_covered,
        },
        dispatch_evidence_status: status,
        records: rows
            .iter()
            .map(generated_dispatch_evidence_preservation_record)
            .collect(),
        sending_performed_by_chancela: false,
        delivery_confirmed: false,
        dispatch_completed: false,
        completion_basis: "none",
        legal_notice_completion_claimed: false,
        legal_sufficiency_claimed: false,
        provider_execution_claimed: false,
        registry_filing_claimed: false,
        bundle_readiness_claimed: false,
        dglab_certification_claimed: false,
        legal_archive_acceptance_claimed: false,
        proof_bytes_included: false,
        operator_note_included: false,
    }
}

fn generated_dispatch_evidence_preservation_record(
    evidence: &StoredGeneratedDocumentDispatchEvidence,
) -> GeneratedDispatchEvidencePreservationRecord {
    GeneratedDispatchEvidencePreservationRecord {
        dispatched_at: evidence.dispatched_at.format(&Rfc3339).unwrap_or_default(),
        recorded_at: evidence.recorded_at.format(&Rfc3339).unwrap_or_default(),
        channel: evidence.channel.clone(),
        reference: evidence.reference.clone(),
        evidence_reference: evidence.evidence_reference.clone(),
        imported_document_id: evidence.imported_document_id.clone(),
        recipients: evidence.recipients.clone(),
        sending_performed_by_chancela: false,
        delivery_confirmed: false,
        legal_notice_completion_claimed: false,
        legal_sufficiency_claimed: false,
        dispatch_completed: false,
        completion_basis: "none",
        bytes_included: false,
        operator_note_included: false,
    }
}

struct NormalizedGeneratedDispatchEvidenceRequest {
    actor: String,
    dispatched_at: OffsetDateTime,
    channel: Option<String>,
    reference: Option<String>,
    recipients: Vec<String>,
    evidence_reference: Option<String>,
    imported_document_id: Option<String>,
    operator_note: Option<String>,
}

fn normalize_generated_dispatch_evidence_request(
    req: GeneratedDocumentDispatchEvidenceRequest,
    required_recipients: &[String],
    profile: GeneratedDispatchEvidenceProfile,
) -> Result<NormalizedGeneratedDispatchEvidenceRequest, ApiError> {
    let actor = non_empty(Some(req.actor)).unwrap_or_else(|| "api".to_owned());
    let dispatched_at_raw = req.dispatched_at.trim();
    let dispatched_at = OffsetDateTime::parse(dispatched_at_raw, &Rfc3339).map_err(|e| {
        ApiError::Unprocessable(format!("dispatched_at must be an RFC 3339 timestamp: {e}"))
    })?;
    let reference = optional_limited_text(
        req.reference,
        "reference",
        MAX_DISPATCH_EVIDENCE_LOCATOR_CHARS,
    )?;
    let evidence_reference = optional_limited_text(
        req.evidence_reference,
        "evidence_reference",
        MAX_DISPATCH_EVIDENCE_LOCATOR_CHARS,
    )?;
    let imported_document_id = optional_limited_text(
        req.imported_document_id,
        "imported_document_id",
        MAX_DISPATCH_EVIDENCE_LOCATOR_CHARS,
    )?
    .map(|id| validate_import_id(&id))
    .transpose()?;
    if reference.is_none() && evidence_reference.is_none() && imported_document_id.is_none() {
        return Err(ApiError::Unprocessable(
            "dispatch evidence requires at least one locator: reference, evidence_reference, or imported_document_id"
                .to_owned(),
        ));
    }
    let operator_note = optional_limited_text(
        req.operator_note,
        "operator_note",
        MAX_DISPATCH_EVIDENCE_NOTE_CHARS,
    )?;
    let recipients =
        normalize_generated_dispatch_recipients(req.recipients, required_recipients, profile)?;
    Ok(NormalizedGeneratedDispatchEvidenceRequest {
        actor,
        dispatched_at,
        channel: req.channel.map(dispatch_channel_code),
        reference,
        recipients,
        evidence_reference,
        imported_document_id,
        operator_note,
    })
}

fn normalize_generated_dispatch_recipients(
    recipients: Option<Vec<String>>,
    required_recipients: &[String],
    profile: GeneratedDispatchEvidenceProfile,
) -> Result<Vec<String>, ApiError> {
    let required: BTreeSet<&str> = required_recipients.iter().map(String::as_str).collect();
    let Some(recipients) = recipients else {
        return Ok(required_recipients.to_vec());
    };
    if recipients.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "recipients must name at least one {}",
            profile.recipient_error_label()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for raw in recipients {
        let name = raw.trim();
        if name.is_empty() {
            return Err(ApiError::Unprocessable(
                "recipients must not contain empty names".to_owned(),
            ));
        }
        if !required.contains(name) {
            return Err(ApiError::Unprocessable(format!(
                "recipient {name:?} is not {} for this act",
                profile.recipient_error_label_with_article()
            )));
        }
        if !seen.insert(name.to_owned()) {
            return Err(ApiError::Unprocessable(format!(
                "recipient {name:?} is listed more than once"
            )));
        }
        selected.push(name.to_owned());
    }
    Ok(selected)
}

fn validate_dispatch_evidence_import(
    store: &chancela_store::Store,
    imported_document_id: &str,
    act_id: ActId,
) -> Result<(), ApiError> {
    let imported = store
        .imported_document(imported_document_id)
        .map_err(|e| ApiError::Internal(format!("imported document store read failed: {e}")))?
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "imported_document_id must reference an existing non-canonical imported document"
                    .to_owned(),
            )
        })?;
    if imported.meta.act_id != Some(act_id) {
        return Err(ApiError::Unprocessable(
            "imported_document_id must be linked to the same act as the generated document"
                .to_owned(),
        ));
    }
    Ok(())
}

fn generated_dispatch_evidence_idempotency_key(
    doc: &StoredDocument,
    actor: &str,
    request: &NormalizedGeneratedDispatchEvidenceRequest,
) -> Result<String, ApiError> {
    let dispatched_at = request
        .dispatched_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let material = json!({
        "schema": "generated_document_dispatch_evidence_idempotency/v1",
        "document_id": &doc.id,
        "act_id": doc.act_id.to_string(),
        "template_id": &doc.template_id,
        "actor": actor,
        "dispatched_at": dispatched_at,
        "channel": &request.channel,
        "reference": &request.reference,
        "recipients": &request.recipients,
        "evidence_reference": &request.evidence_reference,
        "imported_document_id": &request.imported_document_id,
        "operator_note": &request.operator_note,
    });
    let digest: [u8; 32] = Sha256::digest(&serde_json::to_vec(&material)?).into();
    Ok(crate::hex::hex(&digest))
}

fn generated_dispatch_evidence_event_payload(
    context: &GeneratedDispatchContext,
    evidence: &StoredGeneratedDocumentDispatchEvidence,
) -> Value {
    let mut payload = json!({
        "document_id": &evidence.document_id,
        "act_id": evidence.act_id.to_string(),
        "template_id": &evidence.template_id,
        "idempotency_key": &evidence.idempotency_key,
        "dispatch_evidence_profile": context.profile.code(),
        "selected_recipients": &evidence.recipients,
        "required_recipients": &context.required_recipients,
        "metadata": {
            "actor": &evidence.actor,
            "dispatched_at": evidence.dispatched_at.format(&Rfc3339).unwrap_or_default(),
            "channel": &evidence.channel,
            "reference": &evidence.reference,
            "evidence_reference": &evidence.evidence_reference,
            "imported_document_id": &evidence.imported_document_id,
            "operator_note_in_payload": false,
        },
        "sending_performed_by_chancela": false,
        "delivery_confirmed": false,
        "legal_sufficiency_claimed": false,
        "legal_notice_completion_claimed": false,
        "bytes_in_payload": false,
    });
    if let Some(obj) = payload.as_object_mut() {
        match context.profile {
            GeneratedDispatchEvidenceProfile::AbsentOwnerCommunication => {
                obj.insert(
                    "selected_absent_recipients".to_owned(),
                    json!(&evidence.recipients),
                );
                obj.insert(
                    "required_absent_recipients".to_owned(),
                    json!(&context.required_recipients),
                );
            }
            GeneratedDispatchEvidenceProfile::GeneratedConveningNotice => {
                obj.insert(
                    "selected_convening_recipients".to_owned(),
                    json!(&evidence.recipients),
                );
                obj.insert(
                    "required_convening_recipients".to_owned(),
                    json!(&context.required_recipients),
                );
            }
        }
    }
    payload
}

fn generated_dispatch_evidence_view(
    evidence: &StoredGeneratedDocumentDispatchEvidence,
) -> GeneratedDocumentDispatchEvidenceView {
    GeneratedDocumentDispatchEvidenceView {
        document_id: evidence.document_id.clone(),
        idempotency_key: evidence.idempotency_key.clone(),
        act_id: evidence.act_id.to_string(),
        template_id: evidence.template_id.clone(),
        actor: evidence.actor.clone(),
        dispatched_at: evidence.dispatched_at.format(&Rfc3339).unwrap_or_default(),
        channel: evidence.channel.clone(),
        reference: evidence.reference.clone(),
        evidence_reference: evidence.evidence_reference.clone(),
        imported_document_id: evidence.imported_document_id.clone(),
        recipients: evidence.recipients.clone(),
        operator_note: evidence.operator_note.clone(),
        recorded_at: evidence.recorded_at.format(&Rfc3339).unwrap_or_default(),
        sending_performed_by_chancela: false,
        delivery_confirmed: false,
        legal_sufficiency_claimed: false,
        legal_notice_completion_claimed: false,
        bytes_in_payload: false,
    }
}

fn dispatch_channel_code(channel: DispatchChannel) -> String {
    serde_json::to_value(channel)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{channel:?}"))
}

fn ensure_book_open_for_dispatch_evidence(book: &Book) -> Result<(), ApiError> {
    if book.is_open() {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "book {} is {:?}; acts in a non-open book are read-only",
        book.id, book.state
    )))
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

async fn load_document_by_id(
    state: &AppState,
    document_id: &str,
) -> Result<Option<StoredDocument>, ApiError> {
    if let Some(store) = &state.store {
        return store
            .document_by_id(document_id)
            .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")));
    }

    Ok(state
        .documents
        .read()
        .await
        .values()
        .find(|doc| doc.id == document_id)
        .cloned())
}

/// Publish a just-persisted generated document into the live read model. Durable states read by id
/// from SQLite; pure in-memory states need an extra synthetic key so non-Ata outputs remain
/// addressable without replacing the canonical Ata owner slot.
pub(crate) async fn publish_generated_document_read_model(
    state: &AppState,
    stored: &StoredDocument,
) {
    let stage = registry().get(&stored.template_id).map(|spec| spec.stage);
    if state.store.is_none() && stage != Some(LifecycleStage::Ata) {
        let mut documents = state.documents.write().await;
        if let Some(mut key) = in_memory_generated_document_key(stored) {
            while documents.get(&key).is_some_and(|doc| doc.id != stored.id) {
                key = ActId(Uuid::new_v4());
            }
            documents.insert(key, stored.clone());
        }
    }
    if stage == Some(LifecycleStage::Ata) {
        let mut documents = state.documents.write().await;
        let keep_existing_ata = documents
            .get(&stored.act_id)
            .is_some_and(|doc| is_ata_template(&doc.template_id));
        if !keep_existing_ata {
            documents.insert(stored.act_id, stored.clone());
        }
    }
}

fn in_memory_generated_document_key(doc: &StoredDocument) -> Option<ActId> {
    Uuid::parse_str(&doc.id).ok().map(ActId)
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

pub(crate) fn is_ata_template(template_id: &str) -> bool {
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

    if let Some(doc) = state
        .documents
        .read()
        .await
        .get(&act_id)
        .cloned()
        .filter(|doc| doc.act_id == act_id)
    {
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
    pub pdf_accessibility: PdfAccessibilityEvidenceReport,
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
    pub pdf_accessibility: DocumentBundlePdfAccessibilityEvidenceIndex,
    pub external_validator_reports: DocumentBundleExternalValidatorReportIndex,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub generated_dispatch_evidence: Vec<GeneratedDispatchEvidencePreservationIndex>,
}

#[derive(Serialize)]
pub struct DocumentBundleEvidencePaths {
    pub canonical_pdf_download: String,
    pub signed_pdf_download: Option<String>,
    pub attachments_manifest_json_pointer: &'static str,
    pub validation_report_json_pointer: &'static str,
}

#[derive(Serialize)]
pub struct DocumentBundlePdfAccessibilityEvidenceIndex {
    pub evidence_kind: &'static str,
    pub metadata_schema: &'static str,
    pub bundle_report_json_pointer: &'static str,
    pub archive_path_pattern: &'static str,
    pub evidence_status: &'static str,
    pub status_scope: &'static str,
    pub pdf_ua_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub legal_validity_claimed: bool,
    pub pdf_ua_blockers: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct PdfAccessibilityEvidenceReport {
    pub evidence_kind: &'static str,
    pub metadata_schema: &'static str,
    pub status_scope: &'static str,
    pub evidence_status: &'static str,
    pub document_id: String,
    pub act_id: Option<String>,
    pub template_id: String,
    pub report_source: &'static str,
    pub pdf_ua_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub legal_validity_claimed: bool,
    pub report_version: Option<u64>,
    pub pdf_ua_blockers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessibility_report_json: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Serialize)]
pub struct DocumentBundleExternalValidatorReportIndex {
    pub evidence_kind: &'static str,
    pub metadata_schema: &'static str,
    pub archive_path_prefix: &'static str,
    pub archive_path_pattern: &'static str,
    pub raw_report_path_pattern: &'static str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_report: Option<ExternalValidatorRawReportAttachmentIndex>,
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

pub(crate) fn pdf_accessibility_archive_path(document_id: &str) -> String {
    format!("{PDF_ACCESSIBILITY_ARCHIVE_PATH_PREFIX}{document_id}.json")
}

pub(crate) fn unavailable_pdf_accessibility_evidence(
    doc: &StoredDocument,
    act_id: Option<ActId>,
    reason: impl Into<String>,
) -> PdfAccessibilityEvidenceReport {
    PdfAccessibilityEvidenceReport {
        evidence_kind: PDF_ACCESSIBILITY_EVIDENCE_KIND,
        metadata_schema: PDF_ACCESSIBILITY_EVIDENCE_SCHEMA,
        status_scope: TECHNICAL_METADATA_ONLY,
        evidence_status: PDF_ACCESSIBILITY_REPORT_UNAVAILABLE,
        document_id: doc.id.clone(),
        act_id: act_id.map(|id| id.to_string()),
        template_id: doc.template_id.clone(),
        report_source: "unavailable",
        pdf_ua_claimed: false,
        dglab_certification_claimed: false,
        legal_validity_claimed: false,
        report_version: None,
        pdf_ua_blockers: Vec::new(),
        accessibility_report_json: None,
        unavailable_reason: Some(reason.into()),
    }
}

fn pdf_accessibility_evidence_from_model(
    doc: &StoredDocument,
    act_id: Option<ActId>,
    model: &DocumentModel,
) -> Result<PdfAccessibilityEvidenceReport, ApiError> {
    let report = chancela_doc::pdfa::accessibility_report(model);
    let report_json: Value = serde_json::from_str(&report.to_json()).map_err(|e| {
        ApiError::Internal(format!("PDF accessibility report JSON parse failed: {e}"))
    })?;
    let pdf_ua_claimed = report_json
        .get("pdf_ua_claimed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let report_version = report_json.get("version").and_then(Value::as_u64);
    let pdf_ua_blockers = report_json
        .get("pdf_ua_blockers")
        .and_then(Value::as_array)
        .map(|blockers| {
            blockers
                .iter()
                .filter_map(|blocker| blocker.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(PdfAccessibilityEvidenceReport {
        evidence_kind: PDF_ACCESSIBILITY_EVIDENCE_KIND,
        metadata_schema: PDF_ACCESSIBILITY_EVIDENCE_SCHEMA,
        status_scope: TECHNICAL_METADATA_ONLY,
        evidence_status: PDF_ACCESSIBILITY_REPORT_ATTACHED,
        document_id: doc.id.clone(),
        act_id: act_id.map(|id| id.to_string()),
        template_id: doc.template_id.clone(),
        report_source: "chancela_doc_pdfa_accessibility_report",
        pdf_ua_claimed,
        dglab_certification_claimed: false,
        legal_validity_claimed: false,
        report_version,
        pdf_ua_blockers,
        accessibility_report_json: Some(report_json),
        unavailable_reason: None,
    })
}

pub(crate) async fn pdf_accessibility_evidence_for_act_document(
    state: &AppState,
    act_id: ActId,
    doc: &StoredDocument,
) -> PdfAccessibilityEvidenceReport {
    let model = match render_persisted_act_document_model(state, act_id, &doc.template_id).await {
        Ok(model) => model,
        Err(ApiError::NotFound) => {
            return unavailable_pdf_accessibility_evidence(
                doc,
                Some(act_id),
                "act_document_model_unavailable",
            );
        }
        Err(err) => {
            return unavailable_pdf_accessibility_evidence(
                doc,
                Some(act_id),
                format!("act_document_model_render_failed: {err:?}"),
            );
        }
    };
    match pdf_accessibility_evidence_from_model(doc, Some(act_id), &model) {
        Ok(evidence) => evidence,
        Err(err) => unavailable_pdf_accessibility_evidence(
            doc,
            Some(act_id),
            format!("pdf_accessibility_report_unavailable: {err:?}"),
        ),
    }
}

fn document_bundle_evidence_index(
    act_id: ActId,
    doc: &StoredDocument,
    signed: Option<&StoredSignedDocument>,
    pdf_accessibility: &PdfAccessibilityEvidenceReport,
    external_validator_reports: &[ExternalValidatorEvidenceAttachment],
    generated_dispatch_evidence: &[GeneratedDispatchEvidencePreservationIndex],
) -> DocumentBundleEvidenceIndex {
    let attachments = attachment_indexes(external_validator_reports)
        .into_iter()
        .map(
            |attachment| DocumentBundleExternalValidatorReportAttachment {
                case_id: attachment.case_id,
                validator_family: attachment.validator_family,
                archive_path: attachment.path,
                content_type: attachment.content_type,
                sha256: attachment.sha256,
                raw_report: attachment.raw_report,
            },
        )
        .collect::<Vec<_>>();
    let bundle_attachment_status = if attachments.is_empty() {
        "no_external_validator_report_metadata_attached"
    } else {
        "external_validator_report_metadata_attached"
    };
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
        pdf_accessibility: DocumentBundlePdfAccessibilityEvidenceIndex {
            evidence_kind: PDF_ACCESSIBILITY_EVIDENCE_KIND,
            metadata_schema: PDF_ACCESSIBILITY_EVIDENCE_SCHEMA,
            bundle_report_json_pointer: "/validation_report/pdf_accessibility",
            archive_path_pattern: PDF_ACCESSIBILITY_ARCHIVE_PATH_PATTERN,
            evidence_status: pdf_accessibility.evidence_status,
            status_scope: TECHNICAL_METADATA_ONLY,
            pdf_ua_claimed: pdf_accessibility.pdf_ua_claimed,
            dglab_certification_claimed: false,
            legal_validity_claimed: false,
            pdf_ua_blockers: pdf_accessibility.pdf_ua_blockers.clone(),
        },
        external_validator_reports: DocumentBundleExternalValidatorReportIndex {
            evidence_kind: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND,
            metadata_schema: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA,
            archive_path_prefix: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX,
            archive_path_pattern: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN,
            raw_report_path_pattern: EXTERNAL_VALIDATOR_RAW_REPORT_ARCHIVE_PATH_PATTERN,
            bundle_attachment_status,
            status_scope: TECHNICAL_METADATA_ONLY,
            attachments,
        },
        generated_dispatch_evidence: generated_dispatch_evidence.to_vec(),
    }
}

struct DocumentBundleValidationReportInput<'a> {
    act_id: ActId,
    doc: &'a StoredDocument,
    pdf: &'a BundlePdfRef,
    attachments_manifest: &'a [BundleAttachment],
    signed: Option<&'a StoredSignedDocument>,
    pdf_accessibility: PdfAccessibilityEvidenceReport,
    external_validator_reports: &'a [ExternalValidatorEvidenceAttachment],
    generated_dispatch_evidence: &'a [GeneratedDispatchEvidencePreservationIndex],
}

fn build_document_bundle_validation_report(
    input: DocumentBundleValidationReportInput<'_>,
) -> DocumentBundleValidationReport {
    let DocumentBundleValidationReportInput {
        act_id,
        doc,
        pdf,
        attachments_manifest,
        signed,
        pdf_accessibility,
        external_validator_reports,
        generated_dispatch_evidence,
    } = input;

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
    if pdf_accessibility.evidence_status != PDF_ACCESSIBILITY_REPORT_ATTACHED {
        findings.push(DocumentValidationFinding::warning(
            "pdf_accessibility_report_unavailable",
            pdf_accessibility
                .unavailable_reason
                .clone()
                .unwrap_or_else(|| {
                    "PDF accessibility evidence could not be derived from the persisted document model"
                        .to_owned()
                }),
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
        evidence_index: document_bundle_evidence_index(
            act_id,
            doc,
            signed,
            &pdf_accessibility,
            external_validator_reports,
            generated_dispatch_evidence,
        ),
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
        pdf_accessibility,
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
    let external_validator_report_metadata = state.external_validator_report_metadata.read().await;
    let mut observed_pdf_sha256 = vec![sha256_hex(&doc.pdf_bytes)];
    if let Some(signed) = signed.as_ref() {
        observed_pdf_sha256.push(sha256_hex(&signed.signed_pdf_bytes));
    }
    let external_validator_reports =
        matching_attachments(&external_validator_report_metadata, observed_pdf_sha256);
    let generated_dispatch_evidence =
        generated_dispatch_evidence_preservation_indexes_for_act(&state, act_id).await?;
    let pdf_accessibility = pdf_accessibility_evidence_for_act_document(&state, act_id, &doc).await;
    let pdf = BundlePdfRef {
        media_type: "application/pdf",
        byte_length: doc.pdf_bytes.len(),
        download: format!("/v1/acts/{id}/document"),
    };
    let validation_report =
        build_document_bundle_validation_report(DocumentBundleValidationReportInput {
            act_id,
            doc: &doc,
            pdf: &pdf,
            attachments_manifest: &attachments_manifest,
            signed: signed.as_ref(),
            pdf_accessibility,
            external_validator_reports: &external_validator_reports,
            generated_dispatch_evidence: &generated_dispatch_evidence,
        });

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
///
/// wp23: the picker now merges the read-only built-in catalog with user-authored templates, so
/// each summary self-describes its provenance: `source` is `"builtin"` or `"user"`, and `editable`
/// is `true` only for user templates (built-ins are never editable/deletable over HTTP). The
/// `law_references` remain server-derived — they are never authored, stored, or imported.
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
    /// Whether this template can be edited/deleted over HTTP — `true` only for user templates.
    pub editable: bool,
    /// Provenance: `"builtin"` (read-only catalog) or `"user"` (authored, CRUD-able).
    pub source: &'static str,
}

impl From<&TemplateSpec> for TemplateSummary {
    /// Built-in defaults: a catalog spec is read-only (`editable: false`, `source: "builtin"`).
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
            editable: false,
            source: "builtin",
        }
    }
}

/// A [`TemplateSummary`] for a user-authored template: same shape, but marked editable and
/// sourced `"user"`. Built from a validated [`TemplateSpec`] (its server-derived `law_references`
/// are recomputed by validation, never trusted from the stored bytes).
fn user_template_summary(spec: &TemplateSpec) -> TemplateSummary {
    TemplateSummary {
        editable: true,
        source: "user",
        ..TemplateSummary::from(spec)
    }
}

/// `GET /v1/templates?family=&stage=` — available template summaries for the picker. Both filters
/// optional. The summary mirrors the catalog metadata authors put in the template asset:
/// family/stage binding, channel tags, signature-policy hint, rule-pack id, and locale.
///
/// wp23: the response **merges** the read-only built-in catalog (`source: "builtin"`) with the
/// user-authored templates persisted in the store (`source: "user"`, `editable: true`). A stored
/// user row that no longer validates is skipped and logged rather than failing the whole listing.
/// Built-ins keep their catalog (filename-sort) order; user templates follow, sorted by id. The
/// same family/stage filter is applied to the merged set.
pub async fn list_templates(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<TemplatesQuery>,
) -> Result<Json<Vec<TemplateSummary>>, ApiError> {
    // RBAC (t64-E3): the template catalog is `act.read` at Global (drives ata drafting).
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;

    // Built-in catalog, in load order.
    let mut summaries: Vec<TemplateSummary> = registry()
        .specs()
        .iter()
        .map(TemplateSummary::from)
        .collect();

    // User-authored templates (schema v17). Parse each stored row through the same authoring guard
    // the mutations use; a row that no longer validates is skipped + logged, never 500-ing the list.
    let mut user_summaries: Vec<TemplateSummary> = Vec::new();
    if let Some(store) = &state.store {
        let rows = store
            .user_templates()
            .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))?;
        for (id, json) in rows {
            match validate_user_template(&json) {
                Ok(spec) => user_summaries.push(user_template_summary(&spec)),
                Err(err) => {
                    eprintln!("chancela-api: skipping malformed stored user template {id:?}: {err}")
                }
            }
        }
    }
    user_summaries.sort_by(|a, b| a.id.cmp(&b.id));
    summaries.extend(user_summaries);

    // The same optional family/stage filter, applied to the merged set.
    summaries.retain(|s| q.family.is_none_or(|f| s.family == f));
    summaries.retain(|s| q.stage.is_none_or(|st| s.stage == st));

    Ok(Json(summaries))
}

/// The ledger scope every user-template mutation is appended at: an application-audit event on the
/// global spine. The ledger's application/global chains do not prescribe a genesis kind, unlike
/// company/book chains, so a template-management event can safely be the first event in a fresh
/// instance.
const TEMPLATE_EVENT_SCOPE: &str = "global";

/// Query for `POST /v1/templates/import` — `?dry_run=true` runs validation + uniqueness and
/// returns a verdict WITHOUT persisting (the web import preflight).
#[derive(Deserialize)]
pub struct TemplateImportQuery {
    #[serde(default)]
    pub dry_run: bool,
}

/// Error body for the template authoring endpoints (`{code, field?, message}`). Distinct from the
/// base `{error}` envelope: the web editor branches on the machine-readable `code`/`field` to point
/// at the offending input. Used for 422 (validation), 409 (id conflict), and inside the import
/// dry-run verdict.
#[derive(Serialize)]
struct TemplateErrorBody {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    message: String,
}

/// The `POST /v1/templates/import?dry_run=true` verdict: `ok` plus, when it would be rejected, the
/// same `{code, field?, message}` the non-dry-run path would return as its error body.
#[derive(Serialize)]
struct TemplateImportVerdict {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<TemplateErrorBody>,
}

/// Map an authoring [`TemplateValidationError`] to the `{code, field?, message}` body.
fn template_validation_error_body(err: &TemplateValidationError) -> TemplateErrorBody {
    TemplateErrorBody {
        code: err.code(),
        field: err.field(),
        message: err.to_string(),
    }
}

/// The `{code: "conflict", field: "id", message}` body for a duplicate template id.
fn template_conflict_body(id: &str) -> TemplateErrorBody {
    TemplateErrorBody {
        code: "conflict",
        field: Some("id".to_owned()),
        message: format!("a template with id `{id}` already exists"),
    }
}

/// The ledger payload recorded for a `template.created`/`template.updated` mutation.
fn template_event_payload(spec: &TemplateSpec, action: &str) -> Value {
    json!({
        "template_id": spec.id,
        "action": action,
        "family": spec.family,
        "stage": spec.stage,
        "locale": spec.locale,
        "source": "user",
    })
}

/// The ledger payload recorded for a `template.deleted` mutation (only the id survives deletion).
fn template_deleted_payload(id: &str) -> Value {
    json!({ "template_id": id, "action": "deleted", "source": "user" })
}

/// Read a raw request body as UTF-8 template JSON, mapping non-UTF-8 to a 422.
fn user_template_body_str(body: &[u8]) -> Result<&str, ApiError> {
    std::str::from_utf8(body)
        .map_err(|_| ApiError::Unprocessable("template body must be valid UTF-8".to_owned()))
}

/// Whether `id` is already taken — by a built-in catalog id or an existing user-template row. The
/// reserved `user-` id namespace means a valid user id can never collide with a built-in, but the
/// built-in check is kept as defence-in-depth so an id can never shadow the read-only catalog.
fn user_template_id_taken(state: &AppState, id: &str) -> Result<bool, ApiError> {
    if registry().get(id).is_some() {
        return Ok(true);
    }
    if let Some(store) = &state.store {
        let taken = store
            .user_templates()
            .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))?
            .iter()
            .any(|(existing, _)| existing == id);
        if taken {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Sanitize a template id into a safe download filename (`user-x/v1` → `user-x-v1.json`).
fn sanitized_template_filename(id: &str) -> String {
    let stem: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{stem}.json")
}

/// Validate a body, enforce uniqueness, then append `template.created` + upsert the STORED
/// CANONICAL JSON (the author's exact input, so export→import round-trips losslessly under the
/// `deny_unknown_fields` DTO — the server-derived `law_references` are never stored). Shared by
/// `POST /v1/templates` and the non-dry-run `POST /v1/templates/import`. Returns `201` with the
/// summary; a validation failure is a `422 {code, field?, message}` and a duplicate id a `409`.
async fn persist_created_user_template(
    state: &AppState,
    attestor: &CurrentAttestor,
    actor_name: &str,
    body: &[u8],
) -> Result<Response, ApiError> {
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "user template management requires on-disk persistence".to_owned(),
        ));
    }
    let json = user_template_body_str(body)?;
    let spec = match validate_user_template(json) {
        Ok(spec) => spec,
        Err(err) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(template_validation_error_body(&err)),
            )
                .into_response());
        }
    };
    let id = spec.id.clone();
    if user_template_id_taken(state, &id)? {
        return Ok((StatusCode::CONFLICT, Json(template_conflict_body(&id))).into_response());
    }
    let stored_json = json.to_owned();
    let summary = user_template_summary(&spec);
    let payload = serde_json::to_vec(&template_event_payload(&spec, "created"))?;

    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        actor_name,
        TEMPLATE_EVENT_SCOPE,
        "template.created",
        Some(&id),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| {
        tx.upsert_user_template(&id, &stored_json)
    })?;
    state.attest_latest(attestor, &ledger).await;
    drop(ledger);

    Ok((StatusCode::CREATED, Json(summary)).into_response())
}

/// `POST /v1/templates` — create a user-authored template (gate `template.manage@Global`).
pub async fn create_template(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::TemplateManage, Scope::Global).await?;
    let actor_name = actor.resolve("api");
    persist_created_user_template(&state, &attestor, &actor_name, &body).await
}

/// `PUT /v1/templates/{id}` — replace an existing user template (gate `template.manage@Global`).
/// `404` on a built-in id or an unknown user id; the body's own id MUST equal the path id (else
/// `422 {code:"id_mismatch"}`); appends `template.updated` + upserts the canonical stored JSON.
pub async fn replace_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::TemplateManage, Scope::Global).await?;
    let actor_name = actor.resolve("api");
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "user template management requires on-disk persistence".to_owned(),
        ));
    }
    // A built-in is read-only (404, never editable); an unknown user id is also a 404.
    if registry().get(&id).is_some() {
        return Err(ApiError::NotFound);
    }
    let store = state.store.as_ref().expect("store present");
    if store
        .user_template(&id)
        .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))?
        .is_none()
    {
        return Err(ApiError::NotFound);
    }

    let json = user_template_body_str(&body)?;
    let spec = match validate_user_template(json) {
        Ok(spec) => spec,
        Err(err) => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(template_validation_error_body(&err)),
            )
                .into_response());
        }
    };
    if spec.id != id {
        let body = TemplateErrorBody {
            code: "id_mismatch",
            field: Some("id".to_owned()),
            message: format!(
                "template id in body (`{}`) does not match the path id (`{id}`)",
                spec.id
            ),
        };
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response());
    }

    let stored_json = json.to_owned();
    let summary = user_template_summary(&spec);
    let payload = serde_json::to_vec(&template_event_payload(&spec, "updated"))?;

    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        TEMPLATE_EVENT_SCOPE,
        "template.updated",
        Some(&id),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| {
        tx.upsert_user_template(&id, &stored_json)
    })?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok((StatusCode::OK, Json(summary)).into_response())
}

/// `DELETE /v1/templates/{id}` — delete a user template (gate `template.manage@Global`). User-only:
/// `404` on a built-in id or an unknown user id. Appends `template.deleted` + removes the row.
/// Returns `204`.
pub async fn delete_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::TemplateManage, Scope::Global).await?;
    let actor_name = actor.resolve("api");
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "user template management requires on-disk persistence".to_owned(),
        ));
    }
    if registry().get(&id).is_some() {
        return Err(ApiError::NotFound);
    }
    let store = state.store.as_ref().expect("store present");
    if store
        .user_template(&id)
        .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))?
        .is_none()
    {
        return Err(ApiError::NotFound);
    }

    let payload = serde_json::to_vec(&template_deleted_payload(&id))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        TEMPLATE_EVENT_SCOPE,
        "template.deleted",
        Some(&id),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |tx| tx.delete_user_template(&id))?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /v1/templates/{id}/export` — return a template's canonical JSON as a download (gate
/// `act.read@Global`). A user template exports its verbatim stored JSON (lossless re-import); a
/// built-in exports its canonical spec JSON. `Content-Type: application/json` + a
/// `Content-Disposition: attachment` filename derived from the sanitized id.
pub async fn export_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;

    let json = if let Some(spec) = registry().get(&id) {
        serde_json::to_string_pretty(spec)?
    } else {
        let stored = match &state.store {
            Some(store) => store
                .user_template(&id)
                .map_err(|e| ApiError::Internal(format!("user template store read failed: {e}")))?,
            None => None,
        };
        stored.ok_or(ApiError::NotFound)?
    };

    let filename = sanitized_template_filename(&id);
    let mut response = (StatusCode::OK, json).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|e| ApiError::Internal(format!("invalid content-disposition: {e}")))?,
    );
    Ok(response)
}

/// Run the import dry-run preflight: validate + uniqueness only, no persistence. Always `200` with
/// a `{ok, error?}` verdict.
fn template_import_dry_run(state: &AppState, body: &[u8]) -> Result<Response, ApiError> {
    let verdict = match std::str::from_utf8(body) {
        Err(_) => TemplateImportVerdict {
            ok: false,
            error: Some(TemplateErrorBody {
                code: "malformed",
                field: None,
                message: "template body must be valid UTF-8".to_owned(),
            }),
        },
        Ok(json) => match validate_user_template(json) {
            Err(err) => TemplateImportVerdict {
                ok: false,
                error: Some(template_validation_error_body(&err)),
            },
            Ok(spec) => {
                if user_template_id_taken(state, &spec.id)? {
                    TemplateImportVerdict {
                        ok: false,
                        error: Some(template_conflict_body(&spec.id)),
                    }
                } else {
                    TemplateImportVerdict {
                        ok: true,
                        error: None,
                    }
                }
            }
        },
    };
    Ok((StatusCode::OK, Json(verdict)).into_response())
}

/// `POST /v1/templates/import` — import a canonical template JSON (gate `template.manage@Global`).
/// `?dry_run=true` runs the validation + uniqueness preflight and returns a `{ok, error?}` verdict
/// WITHOUT persisting; without it, behaves exactly like `POST /v1/templates` (create).
pub async fn import_template(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Query(q): Query<TemplateImportQuery>,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::TemplateManage, Scope::Global).await?;
    let actor_name = actor.resolve("api");
    if q.dry_run {
        return template_import_dry_run(&state, &body);
    }
    persist_created_user_template(&state, &attestor, &actor_name, &body).await
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
        ConveningRecipient, DeliberationItem, DispatchChannel, Entity, EntityKind, KvRow,
        MeetingChannel, Nipc, PresenceMode, SecondCall, SignatoryCapacity, SignatureSlot, VoteRow,
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
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        };
        state.users.write().await.insert(uid, user);
        CurrentActor::from_session_username(Some(username))
    }

    async fn seed_powerless_actor(state: &AppState) -> CurrentActor {
        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let uid = UserId(Uuid::new_v4());
        let username = format!("document.no-perms.{}", Uuid::new_v4());
        let user = User {
            id: uid,
            username: username.clone(),
            display_name: "Document No Perms".to_owned(),
            email: None,
            created_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            active: true,
            password_hash: Some(crate::attestation::hash_secret("Teste-Forte7!X").unwrap()),
            attestation_key: None,
            secret_source: Default::default(),
            recovery_hash: None,
            role_assignments: vec![],
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
        zip_bytes_with_compression(entries, CompressionMethod::Stored)
    }

    fn deflated_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        zip_bytes_with_compression(entries, CompressionMethod::Deflated)
    }

    fn zip_bytes_with_compression(
        entries: &[(&str, &[u8])],
        compression_method: CompressionMethod,
    ) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let opts = SimpleFileOptions::default().compression_method(compression_method);
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

    fn detached_test_rsa_identity() -> (rsa::RsaPrivateKey, Vec<u8>) {
        const OID_SHA256_WITH_RSA: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        use rsa::rand_core::OsRng;

        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let spki =
            SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let name = Name::from_str("CN=Document Import Detached Test").expect("name");
        let validity =
            Validity::from_now(StdDuration::from_secs(365 * 24 * 3600)).expect("validity");
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[2]).expect("serial"),
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
        let signature = sign_test_rsa_digest(&key, &Sha256::digest(&tbs_der).into());
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&signature).expect("bitstring"),
        };
        (key, cert.to_der().expect("cert der"))
    }

    fn sign_test_rsa_digest(key: &rsa::RsaPrivateKey, digest: &[u8; 32]) -> Vec<u8> {
        const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(digest);
        key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .expect("rsa sign")
    }

    fn detached_cades(content: &[u8]) -> Vec<u8> {
        let (key, cert_der) = detached_test_rsa_identity();
        let content_digest: [u8; 32] = Sha256::digest(content).into();
        let signing_time =
            OffsetDateTime::from_unix_timestamp(1_750_000_000).expect("fixed signing time");
        let attrs = signed_attributes_digest(&content_digest, &cert_der, signing_time)
            .expect("signed attributes");
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_test_rsa_digest(&key, &attrs),
            cert_der,
            vec![],
        );
        assemble_cades_b(&raw, &content_digest, signing_time).expect("assemble detached CAdES")
    }

    fn enveloping_xades() -> Vec<u8> {
        let (key, cert_der) = detached_test_rsa_identity();
        let prepared = chancela_xades::prepare_xades(chancela_xades::XadesSignRequest {
            signature_id: "import-xades-1".to_owned(),
            signing_cert_der: cert_der.clone(),
            sig_alg: SignatureAlgorithm::RsaPkcs1Sha256,
            level: chancela_xades::XadesLevel::B,
            context: chancela_xades::XadesContext {
                signing_time: OffsetDateTime::from_unix_timestamp(1_750_000_000)
                    .expect("fixed signing time"),
            },
            packaging: chancela_xades::SignaturePackaging::Enveloping(vec![
                chancela_xades::EnvelopingObject {
                    id: "minutes-object".to_owned(),
                    content: chancela_xades::ObjectContent::Text(
                        "Approved meeting minutes".to_owned(),
                    ),
                },
            ]),
        })
        .expect("prepare XAdES");
        let signed_info_digest: [u8; 32] = prepared
            .signed_info_digest()
            .try_into()
            .expect("RSA XAdES uses SHA-256");
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_test_rsa_digest(&key, &signed_info_digest),
            cert_der,
            vec![],
        );
        prepared
            .assemble(&raw)
            .expect("assemble XAdES")
            .into_bytes()
            .expect("XAdES-B bytes")
    }

    fn detached_xades(content: &[u8]) -> Vec<u8> {
        let (key, cert_der) = detached_test_rsa_identity();
        let prepared = chancela_xades::prepare_xades(chancela_xades::XadesSignRequest {
            signature_id: "import-xades-detached-1".to_owned(),
            signing_cert_der: cert_der.clone(),
            sig_alg: SignatureAlgorithm::RsaPkcs1Sha256,
            level: chancela_xades::XadesLevel::B,
            context: chancela_xades::XadesContext {
                signing_time: OffsetDateTime::from_unix_timestamp(1_750_000_000)
                    .expect("fixed signing time"),
            },
            packaging: chancela_xades::SignaturePackaging::Detached(vec![
                chancela_xades::DetachedRef {
                    uri: "minutes.txt".to_owned(),
                    bytes: content.to_vec(),
                },
            ]),
        })
        .expect("prepare detached XAdES");
        let signed_info_digest: [u8; 32] = prepared
            .signed_info_digest()
            .try_into()
            .expect("RSA XAdES uses SHA-256");
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            sign_test_rsa_digest(&key, &signed_info_digest),
            cert_der,
            vec![],
        );
        prepared
            .assemble(&raw)
            .expect("assemble detached XAdES")
            .into_bytes()
            .expect("detached XAdES-B bytes")
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

    fn assert_legacy_doc_canonical_conversion_preflight(
        preflight: &DocumentCanonicalConversionPreflightReport,
        original_bytes_preserved: bool,
    ) {
        assert_eq!(
            preflight.report_kind,
            "legacy_imported_document_canonical_conversion_preflight"
        );
        assert_eq!(preflight.scope, "local_metadata_only");
        assert_eq!(preflight.status, "blocked");
        assert_eq!(preflight.source_format, "legacy_word_doc");
        assert_eq!(
            preflight.bounded_evidence_status,
            "metadata_only_legacy_doc_preflight"
        );
        assert!(preflight.local_metadata_only);
        assert_eq!(preflight.original_bytes_preserved, original_bytes_preserved);
        assert!(preflight.evidence_basis.contains(&"ole_cfb_magic_detected"));
        assert!(
            preflight
                .evidence_basis
                .contains(&"legacy_word_doc_metadata_or_extension_detected")
        );
        assert!(
            preflight
                .blockers
                .contains(&"no_canonical_conversion_workflow_executed")
        );
        assert!(!preflight.canonical_conversion_performed);
        assert!(!preflight.canonical_pdfa_generated);
        assert!(!preflight.signature_validation_performed);
        assert!(!preflight.ocr_performed);
        assert!(!preflight.legal_acceptance_claimed);
        assert!(!preflight.external_provider_contacted);
        assert!(!preflight.canonical_record_replaced);
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
            operator_acknowledged_guardrail_ids: Vec::new(),
            technical_validation_report_json: r#"{"filename":"access-code-secret.pdf"}"#.to_owned(),
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
            operator_acknowledged_guardrail_ids: Vec::new(),
            technical_validation_report_json:
                r#"{"filename":"medical-report-joana.pdf","sha256":"private"}"#.to_owned(),
        };

        let history = vec![StoredImportedDocumentReviewHistoryEntry {
            id: 1,
            imported_document_id: meta.id.clone(),
            review_status: StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly,
            reviewed_at: Some(time::OffsetDateTime::UNIX_EPOCH),
            reviewed_by: Some("amelia.reviewer".to_owned()),
            review_note: Some("Private review note.".to_owned()),
            acknowledged_guardrail_ids: imported_document_review_guardrail_ids_as_strings(),
        }];
        let view = imported_document_view_with_redaction(&meta, &history, ReadRedaction::Guest);
        assert_eq!(view.filename, None);
        assert_eq!(view.sha256, crate::dto::REDACTED);
        assert_eq!(view.imported_by, crate::dto::REDACTED);
        assert_eq!(view.bytes_download, crate::dto::REDACTED);
        assert_eq!(
            view.review_history[0].reviewed_by.as_deref(),
            Some(crate::dto::REDACTED)
        );
        assert_eq!(
            view.review_history[0].review_note.as_deref(),
            Some(crate::dto::REDACTED)
        );
        let raw = serde_json::to_string(&view).expect("imported document view JSON");
        assert!(!raw.contains("medical-report-joana.pdf"));
        assert!(!raw.contains("amelia.marques"));
        assert!(!raw.contains("amelia.reviewer"));
        assert!(!raw.contains("Private review note."));
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
    fn document_import_validation_accepts_safe_zip_bundle_with_bounded_in_memory_extraction() {
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
        assert!(report.zip_bundle.extraction_performed);
        assert_eq!(report.zip_bundle.extracted_entry_count, 2);
        assert_eq!(
            report.zip_bundle.total_extracted_size,
            (br#"{"kind":"support"}"#.len() + b"page one".len()) as u64
        );
        assert!(report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "zip_bundle_detected"));
        assert!(has_finding(&report, "zip_bounded_inspection_only"));
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
    fn document_import_validation_recognizes_docx_and_odt_without_conversion() {
        let docx = zip_bytes(&[
            (
                "[Content_Types].xml",
                br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
            ),
            (
                "word/document.xml",
                br#"<w:document xmlns:w="urn:test"><w:body/></w:document>"#,
            ),
        ]);
        let odt = zip_bytes(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text"),
            (
                "content.xml",
                br#"<office:document-content xmlns:office="urn:test"/>"#,
            ),
        ]);

        let docx_report = validate_document_candidate(
            &docx,
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            Some("minutes.docx".to_owned()),
        );
        let odt_report = validate_document_candidate(
            &odt,
            Some("application/vnd.oasis.opendocument.text"),
            Some("minutes.odt".to_owned()),
        );

        for (report, format, detected) in [
            (
                docx_report,
                "docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            (odt_report, "odt", "application/vnd.oasis.opendocument.text"),
        ] {
            assert_eq!(report.content_type.detected, detected);
            assert!(report.office.is_office_document);
            assert_eq!(report.office.format, Some(format));
            assert!(report.office.package_readable);
            assert!(report.office.required_members_present);
            assert!(report.office.package_members_extracted_for_inspection);
            assert!(!report.office.conversion_performed);
            assert!(!report.office.canonical_pdfa_generated);
            assert!(report.can_accept_non_canonical_import);
            assert_eq!(
                report.preservation_policy.review_state,
                "canonical_conversion_review_required"
            );
            assert!(has_finding(&report, "office_package_detected"));
        }
    }

    #[test]
    fn document_import_validation_screens_valid_and_malformed_rtf() {
        let valid = br#"{\rtf1\ansi Minutes {approved} {\object opaque}}"#;
        let malformed = br#"{\rtf1\ansi Minutes {unclosed}"#;

        let valid_report = validate_document_candidate(
            valid,
            Some("application/rtf"),
            Some("minutes.rtf".to_owned()),
        );
        let malformed_report = validate_document_candidate(
            malformed,
            Some("application/rtf"),
            Some("minutes.rtf".to_owned()),
        );

        assert!(valid_report.rtf.is_rtf);
        assert!(valid_report.rtf.structurally_valid);
        assert!(valid_report.rtf.object_or_package_control_word_detected);
        assert!(valid_report.can_accept_non_canonical_import);
        assert!(!valid_report.rtf.conversion_performed);
        assert!(has_finding(&valid_report, "rtf_detected"));

        assert!(malformed_report.rtf.is_rtf);
        assert!(!malformed_report.rtf.structurally_valid);
        assert!(!malformed_report.can_accept_non_canonical_import);
        assert!(has_finding(&malformed_report, "rtf_structure_invalid"));
    }

    #[test]
    fn document_import_validation_decodes_bounded_eml_attachment_inventory() {
        let email = concat!(
            "From: clerk@example.test\r\n",
            "Date: Thu, 16 Jul 2026 10:00:00 +0000\r\n",
            "Message-ID: <minutes-1@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=chancela-boundary\r\n",
            "\r\n",
            "--chancela-boundary\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Please archive the attached minutes.\r\n",
            "--chancela-boundary\r\n",
            "Content-Type: text/plain; name=minutes.txt\r\n",
            "Content-Disposition: attachment; filename=minutes.txt\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "QXBwcm92ZWQgbWludXRlcw==\r\n",
            "--chancela-boundary--\r\n"
        );

        let report = validate_document_candidate(
            email.as_bytes(),
            Some("message/rfc822"),
            Some("minutes.eml".to_owned()),
        );

        assert_eq!(report.content_type.detected, "message/rfc822");
        assert!(report.email.is_email);
        assert!(report.email.readable);
        assert_eq!(report.email.attachment_count, 1);
        assert_eq!(report.email.decoded_attachment_bytes, 16);
        assert_eq!(report.email.attachments[0].path, "minutes.txt");
        assert_eq!(report.email.attachments[0].size_bytes, 16);
        assert!(report.email.extraction_performed);
        assert!(report.can_accept_non_canonical_import);
        assert!(has_finding(&report, "email_evidence_extracted"));
    }

    #[test]
    fn document_import_validation_rejects_malformed_or_traversing_eml() {
        let missing_closing_boundary = concat!(
            "From: clerk@example.test\r\n",
            "Date: Thu, 16 Jul 2026 10:00:00 +0000\r\n",
            "Message-ID: <minutes-2@example.test>\r\n",
            "Content-Type: multipart/mixed; boundary=missing-close\r\n",
            "\r\n",
            "--missing-close\r\n",
            "Content-Type: text/plain\r\n\r\nbody\r\n"
        );
        let traversing_attachment = concat!(
            "From: clerk@example.test\r\n",
            "Date: Thu, 16 Jul 2026 10:00:00 +0000\r\n",
            "Message-ID: <minutes-3@example.test>\r\n",
            "Content-Type: application/octet-stream; name=../secret.txt\r\n",
            "Content-Disposition: attachment; filename=../secret.txt\r\n",
            "\r\n",
            "secret"
        );

        for email in [missing_closing_boundary, traversing_attachment] {
            let report = validate_document_candidate(
                email.as_bytes(),
                Some("message/rfc822"),
                Some("evidence.eml".to_owned()),
            );
            assert!(report.email.claimed);
            assert!(!report.email.readable);
            assert!(!report.can_accept_non_canonical_import);
            assert!(has_finding(&report, "email_malformed_or_unsafe"));
        }
    }

    #[test]
    fn document_import_validation_rejects_zip_bombs_duplicates_and_malformed_archives() {
        let oversized_member = vec![0u8; DOCUMENT_CONTAINER_MAX_MEMBER_BYTES as usize + 1];
        let bomb = deflated_zip_bytes(&[("oversized.bin", &oversized_member)]);
        let duplicate = zip_bytes(&[("same.txt", b"one"), ("SAME.TXT", b"two")]);
        let malformed = b"PK\x03\x04not-a-complete-archive";

        let bomb_report = validate_document_candidate(&bomb, Some("application/zip"), None);
        assert!(!bomb_report.zip_bundle.readable);
        assert_eq!(bomb_report.zip_bundle.extracted_entry_count, 0);
        assert!(!bomb_report.can_accept_non_canonical_import);
        assert!(has_finding(&bomb_report, "zip_unreadable"));

        let duplicate_report =
            validate_document_candidate(&duplicate, Some("application/zip"), None);
        assert_eq!(duplicate_report.zip_bundle.duplicate_entry_count, 1);
        assert!(!duplicate_report.can_accept_non_canonical_import);
        assert!(has_finding(&duplicate_report, "zip_duplicate_entry_name"));

        let malformed_report =
            validate_document_candidate(malformed, Some("application/zip"), None);
        assert!(malformed_report.zip_bundle.is_zip);
        assert!(!malformed_report.zip_bundle.readable);
        assert!(!malformed_report.can_accept_non_canonical_import);
        assert!(has_finding(&malformed_report, "zip_unreadable"));
    }

    #[test]
    fn document_import_validation_validates_detached_cades_and_rejects_tamper_or_ambiguity() {
        let content = b"Approved minutes";
        let cades = detached_cades(content);
        let valid_bundle = zip_bytes(&[("minutes.txt", content), ("minutes.txt.p7s", &cades)]);
        let tampered_bundle = zip_bytes(&[
            ("minutes.txt", b"Tampered minutes"),
            ("minutes.txt.p7s", &cades),
        ]);
        let unpaired_bundle = zip_bytes(&[("minutes.txt.p7s", &cades)]);

        let valid = validate_document_candidate(
            &valid_bundle,
            Some("application/zip"),
            Some("signed-evidence.zip".to_owned()),
        );
        assert!(valid.can_accept_non_canonical_import);
        assert_eq!(valid.signature_evidence.claimed_signature_count, 1);
        assert_eq!(valid.signature_evidence.validation_performed_count, 1);
        assert_eq!(valid.signature_evidence.cryptographically_valid_count, 1);
        assert_eq!(
            valid.signature_evidence.all_claimed_signatures_valid,
            Some(true)
        );
        assert_eq!(
            valid.signature_evidence.validations[0]
                .signed_content_path
                .as_deref(),
            Some("minutes.txt")
        );

        for candidate in [tampered_bundle, unpaired_bundle] {
            let report = validate_document_candidate(&candidate, Some("application/zip"), None);
            assert!(report.signature_evidence.signature_claim_detected);
            assert!(!report.can_accept_non_canonical_import);
            assert!(
                has_finding(&report, "signature_evidence_invalid")
                    || has_finding(&report, "signature_evidence_unvalidated")
            );
        }

    }

    #[test]
    fn document_import_validation_validates_asic_s_and_rejects_tampered_payload() {
        let content = b"Approved minutes";
        let cades = detached_cades(content);
        let valid_container =
            chancela_signing::create_asic_s_container("minutes.txt", content, &cades)
                .expect("valid ASiC-S");
        let tampered_container =
            chancela_signing::create_asic_s_container("minutes.txt", b"Tampered minutes", &cades)
                .expect("structurally valid tampered ASiC-S");

        let valid = validate_document_candidate(
            &valid_container,
            Some("application/vnd.etsi.asic-s+zip"),
            Some("minutes.asics".to_owned()),
        );
        assert_eq!(
            valid.content_type.detected,
            "application/vnd.etsi.asic-s+zip"
        );
        assert!(valid.can_accept_non_canonical_import);
        assert_eq!(valid.signature_evidence.cryptographically_valid_count, 1);
        assert_eq!(
            valid.signature_evidence.all_claimed_signatures_valid,
            Some(true)
        );

        let tampered = validate_document_candidate(
            &tampered_container,
            Some("application/vnd.etsi.asic-s+zip"),
            Some("minutes.asics".to_owned()),
        );
        assert!(!tampered.can_accept_non_canonical_import);
        assert_eq!(
            tampered.signature_evidence.all_claimed_signatures_valid,
            Some(false)
        );
        assert!(has_finding(&tampered, "signature_evidence_invalid"));
    }

    #[test]
    fn document_import_validation_validates_xades_and_rejects_tamper() {
        let valid_xml = enveloping_xades();
        let detached_xml = detached_xades(b"Approved minutes");
        let mut tampered_xml = valid_xml.clone();
        let offset = find_bytes(&tampered_xml, b"Approved").expect("signed object text");
        tampered_xml[offset] = b'B';

        let valid = validate_document_candidate(
            &valid_xml,
            Some("application/xml"),
            Some("minutes.xades".to_owned()),
        );
        assert!(valid.can_accept_non_canonical_import);
        assert_eq!(valid.signature_evidence.claimed_signature_count, 1);
        assert_eq!(valid.signature_evidence.cryptographically_valid_count, 1);
        assert_eq!(valid.signature_evidence.validations[0].format, "xades");

        let detached = validate_document_candidate(
            &detached_xml,
            Some("application/xml"),
            Some("minutes.xades".to_owned()),
        );
        assert!(!detached.can_accept_non_canonical_import);
        assert_eq!(
            detached.signature_evidence.validations[0].status,
            "indeterminate"
        );
        assert!(has_finding(&detached, "signature_evidence_unvalidated"));

        let tampered = validate_document_candidate(
            &tampered_xml,
            Some("application/xml"),
            Some("minutes.xades".to_owned()),
        );
        assert!(!tampered.can_accept_non_canonical_import);
        assert_eq!(
            tampered.signature_evidence.all_claimed_signatures_valid,
            Some(false)
        );
        assert!(has_finding(&tampered, "signature_evidence_invalid"));
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
        assert_eq!(
            report.canonical_conversion_preflight.review_state,
            "canonical_conversion_review_required"
        );
        assert_legacy_doc_canonical_conversion_preflight(
            &report.canonical_conversion_preflight,
            false,
        );
        assert!(has_finding(&report, "legacy_word_doc_detected"));
        assert!(has_finding(&report, "legacy_word_no_macro_execution"));
        assert!(has_finding(&report, "legacy_word_no_pdfa_conversion"));
        assert!(!has_finding(&report, "not_pdf"));
    }

    #[test]
    fn document_import_validation_reports_legacy_doc_canonical_conversion_preflight_evidence() {
        let doc = legacy_doc_bytes();

        let report = validate_document_candidate(
            &doc,
            Some("application/msword"),
            Some("board-minutes.doc".to_owned()),
        );

        assert_eq!(report.content_type.detected, "application/msword");
        assert_eq!(report.canonical_conversion_preflight.status, "blocked");
        assert_eq!(
            report
                .canonical_conversion_preflight
                .bounded_evidence_status,
            "metadata_only_legacy_doc_preflight"
        );
        assert!(
            report
                .canonical_conversion_preflight
                .evidence_basis
                .contains(&"validation_candidate_bytes_not_persisted")
        );
        assert!(
            report
                .canonical_conversion_preflight
                .blockers
                .contains(&"operator_conversion_review_required")
        );
        assert_legacy_doc_canonical_conversion_preflight(
            &report.canonical_conversion_preflight,
            false,
        );
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
        assert_eq!(
            imported.canonical_conversion_preflight.review_state,
            "canonical_conversion_review_required"
        );
        assert!(
            imported
                .canonical_conversion_preflight
                .evidence_basis
                .contains(&"original_bytes_preserved")
        );
        assert_legacy_doc_canonical_conversion_preflight(
            &imported.canonical_conversion_preflight,
            true,
        );
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
        let payload = imported_document_event_payload(&stored.meta);
        assert_eq!(
            payload["canonical_conversion_preflight"]["status"],
            "blocked"
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["canonical_conversion_performed"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["canonical_pdfa_generated"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["signature_validation_performed"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["ocr_performed"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["legal_acceptance_claimed"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["external_provider_contacted"],
            false
        );
        assert_eq!(
            payload["canonical_conversion_preflight"]["canonical_record_replaced"],
            false
        );

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
        assert!(
            imported.review_history.is_empty(),
            "fresh imports should not fabricate review history"
        );

        let before = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("imported doc stored");
        let ledger_before_missing_ack = state.ledger.read().await.events().len();
        let err = review_imported_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(imported.id.clone()),
            Json(ImportedDocumentReviewRequest {
                review_status: "reviewed_non_canonical_original_only".to_owned(),
                review_note: None,
                acknowledged_guardrail_ids: Vec::new(),
            }),
        )
        .await
        .expect_err("missing guardrail acknowledgements are rejected");
        assert!(
            matches!(err, ApiError::Unprocessable(ref message) if message.contains("acknowledged_guardrail_ids")),
            "error names acknowledgement field: {err:?}"
        );
        assert_eq!(
            state.ledger.read().await.events().len(),
            ledger_before_missing_ack,
            "rejected review must not append an audit event"
        );
        let unchanged = state
            .store
            .as_ref()
            .expect("store")
            .imported_document(&imported.id)
            .expect("store read")
            .expect("imported doc remains");
        assert_eq!(
            unchanged.meta.operator_review_status,
            before.meta.operator_review_status
        );
        assert!(
            unchanged
                .meta
                .operator_acknowledged_guardrail_ids
                .is_empty()
        );

        let review_note = "Reviewed only as preserved non-canonical evidence.".to_owned();
        let Json(reviewed) = review_imported_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(imported.id.clone()),
            Json(ImportedDocumentReviewRequest {
                review_status: "reviewed_non_canonical_original_only".to_owned(),
                review_note: Some(review_note.clone()),
                acknowledged_guardrail_ids: imported_document_review_guardrail_ids_as_strings(),
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
        assert_eq!(
            reviewed.acknowledged_guardrail_ids,
            imported_document_review_guardrail_ids_as_strings()
        );
        assert_eq!(reviewed.review_history.len(), 1);
        assert_eq!(reviewed.review_history[0].decision_index, 1);
        assert_eq!(
            reviewed.review_history[0].review_status,
            "reviewed_non_canonical_original_only"
        );
        assert_eq!(
            reviewed.review_history[0].review_note.as_deref(),
            Some(review_note.as_str())
        );
        assert_eq!(
            reviewed.review_history[0].acknowledged_guardrail_ids,
            imported_document_review_guardrail_ids_as_strings()
        );
        assert!(!reviewed.review_history[0].bytes_in_payload);
        assert!(!reviewed.review_history[0].ocr_performed);
        assert!(!reviewed.review_history[0].canonical_conversion_performed);
        assert!(!reviewed.review_history[0].canonical_pdfa_generated);
        assert!(!reviewed.review_history[0].signed_artifact_created_or_validated);
        assert!(!reviewed.review_history[0].legal_acceptance_claimed);
        assert!(!reviewed.review_history[0].certification_claimed);
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
        assert_eq!(
            after.meta.operator_acknowledged_guardrail_ids,
            imported_document_review_guardrail_ids_as_strings()
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
            &imported_document_review_guardrail_ids_as_strings(),
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
        assert_eq!(
            payload["acknowledged_guardrail_ids"],
            json!(imported_document_review_guardrail_checklist())
        );
        assert_eq!(
            payload["guardrail_acknowledgement"]["all_required_guardrails_acknowledged"],
            true
        );
        let payload_text = serde_json::to_string(&payload).expect("payload serializes");
        assert!(!payload_text.contains(&review_note));

        let second_review_note = "Rejected after later preservation review.".to_owned();
        let Json(second_reviewed) = review_imported_document(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(imported.id.clone()),
            Json(ImportedDocumentReviewRequest {
                review_status: "rejected_non_canonical_evidence".to_owned(),
                review_note: Some(second_review_note.clone()),
                acknowledged_guardrail_ids: imported_document_review_guardrail_ids_as_strings(),
            }),
        )
        .await
        .expect("second review transition succeeds");
        assert_eq!(
            second_reviewed.operator_review_status,
            "rejected_non_canonical_evidence"
        );
        assert_eq!(
            second_reviewed.operator_review_note.as_deref(),
            Some(second_review_note.as_str())
        );
        assert_eq!(second_reviewed.review_history.len(), 2);
        assert_eq!(second_reviewed.review_history[0].decision_index, 1);
        assert_eq!(second_reviewed.review_history[1].decision_index, 2);
        assert_eq!(
            second_reviewed.review_history[0].review_status,
            "reviewed_non_canonical_original_only"
        );
        assert_eq!(
            second_reviewed.review_history[1].review_status,
            "rejected_non_canonical_evidence"
        );
        assert_eq!(
            second_reviewed.review_history[1].review_note.as_deref(),
            Some(second_review_note.as_str())
        );
        assert!(!second_reviewed.review_history[1].legal_acceptance_claimed);
        assert!(!second_reviewed.review_history[1].certification_claimed);
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

    #[tokio::test]
    async fn condominium_absent_owner_communication_generation_preserves_canonical_ata() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let entity = entity_of(EntityKind::Condominio);
        let book = Book::new(entity.id, BookKind::Condominio);
        let mut act = sealed_csc_act(&book);
        act.title = "Ata da assembleia de condóminos".to_owned();
        act.attendees = vec![
            Attendee {
                name: "Ana Rocha".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(520)),
            },
            Attendee {
                name: "Bruno Dias".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(125)),
            },
        ];
        act.deliberation_items = vec![DeliberationItem {
            agenda_number: Some(1),
            text: "Aprovada a realização de obras de conservação.".to_owned(),
            vote: None,
            statements: vec![],
        }];
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
                template_id: "condominio-comunicacao-ausentes/v1".to_owned(),
            }),
        )
        .await
        .expect("absent-owner communication generation succeeds");
        assert_eq!(response.status(), StatusCode::CREATED);

        let rows = state
            .store
            .as_ref()
            .expect("store")
            .documents_for_act(act.id)
            .expect("documents read");
        assert_eq!(
            rows.len(),
            2,
            "canonical ata plus absent-owner communication are both preserved"
        );
        assert!(
            rows.iter()
                .any(|doc| doc.template_id == "condominio-comunicacao-ausentes/v1"),
            "absent-owner communication row was generated"
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
        assert_eq!(loaded.template_id, "condominio-ata-assembleia/v1");
        assert!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .filter(|event| event.kind == "document.generated")
                .count()
                >= 1,
            "document.generated event was appended for the communication"
        );
    }

    async fn seed_absent_owner_dispatch_fixture(
        state: &AppState,
    ) -> (
        CurrentActor,
        Entity,
        Book,
        Act,
        StoredDocument,
        StoredDocument,
    ) {
        let actor = seed_owner(state).await;
        let entity = entity_of(EntityKind::Condominio);
        let mut book = Book::new(entity.id, BookKind::Condominio);
        book.state = chancela_core::BookState::Open;
        let mut act = sealed_csc_act(&book);
        act.title = "Ata da assembleia de condóminos".to_owned();
        act.attendees = vec![
            Attendee {
                name: "Fração A".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::InPerson,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(600)),
            },
            Attendee {
                name: "Fração B".to_owned(),
                quality: SignatoryCapacity::CondoOwner,
                presence: PresenceMode::Absent,
                represented_by: None,
                weight: Some(AttendanceWeight::Permilage(400)),
            },
        ];
        let ata = generate_for_act(&act, &entity, None)
            .expect("ata generation ok")
            .expect("ata document")
            .stored;
        let communication = generate_condominium_absent_owner_communication(&act, &book, &entity)
            .expect("communication generation ok")
            .stored;

        let events = {
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
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &format!("entity:{}/book:{}/act:{}", entity.id, book.id, act.id),
                "act.sealed",
                None,
                b"act",
            )
            .expect("act genesis");
            ledger.events().to_vec()
        };
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
                tx.upsert_document(&ata)?;
                tx.upsert_document(&communication)
            })
            .expect("fixture persists");
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        state.books.write().await.insert(book.id, book.clone());
        state.acts.write().await.insert(act.id, act.clone());
        (actor, entity, book, act, ata, communication)
    }

    async fn seed_generated_convening_dispatch_fixture(
        state: &AppState,
        recipient_names: Vec<&str>,
    ) -> (
        CurrentActor,
        Entity,
        Book,
        Act,
        StoredDocument,
        StoredDocument,
    ) {
        let actor = seed_owner(state).await;
        let entity = entity_of(EntityKind::SociedadeAnonima);
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = chancela_core::BookState::Open;
        let mut act = sealed_csc_act(&book);
        act.convening = Some(Convening {
            convener: Some("Ana Presidente".to_owned()),
            convener_capacity: Some(SignatoryCapacity::Chair),
            dispatch_date: Some(date!(2026 - 03 - 01)),
            antecedence_days: Some(21),
            channel: Some(DispatchChannel::Email),
            evidence_reference: Some("convening-ledger:seed".to_owned()),
            recipients: recipient_names
                .into_iter()
                .map(|name| ConveningRecipient {
                    name: name.to_owned(),
                    contact: None,
                    channel: Some(DispatchChannel::Email),
                    reference: None,
                    dispatched_at: Some(date!(2026 - 03 - 01)),
                })
                .collect(),
            second_call: None,
        });
        let ata = generate_for_act(&act, &entity, None)
            .expect("ata generation ok")
            .expect("ata document")
            .stored;
        let notice = generate_for_act_template(&act, &book, &entity, "csc-convocatoria-ag/v1")
            .expect("convocatoria generation ok")
            .stored;

        let events = {
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
            crate::try_append_event(
                &mut ledger,
                "document.owner",
                &format!("entity:{}/book:{}/act:{}", entity.id, book.id, act.id),
                "act.sealed",
                None,
                b"act",
            )
            .expect("act genesis");
            ledger.events().to_vec()
        };
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
                tx.upsert_document(&ata)?;
                tx.upsert_document(&notice)
            })
            .expect("fixture persists");
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        state.books.write().await.insert(book.id, book.clone());
        state.acts.write().await.insert(act.id, act.clone());
        state.documents.write().await.insert(act.id, ata.clone());
        (actor, entity, book, act, ata, notice)
    }

    fn absent_owner_dispatch_request(
        recipients: Vec<&str>,
    ) -> GeneratedDocumentDispatchEvidenceRequest {
        GeneratedDocumentDispatchEvidenceRequest {
            actor: "operator.fixture".to_owned(),
            dispatched_at: "2026-04-01T10:00:00Z".to_owned(),
            channel: Some(DispatchChannel::RegisteredLetter),
            reference: Some("RR123456789PT".to_owned()),
            recipients: Some(recipients.into_iter().map(str::to_owned).collect()),
            evidence_reference: Some("archive:dispatch-proof-1".to_owned()),
            imported_document_id: None,
            operator_note: Some("Operator recorded an external postal locator only.".to_owned()),
        }
    }

    fn generated_convening_dispatch_request(
        recipients: Vec<&str>,
    ) -> GeneratedDocumentDispatchEvidenceRequest {
        GeneratedDocumentDispatchEvidenceRequest {
            actor: "operator.fixture".to_owned(),
            dispatched_at: "2026-03-01T09:00:00Z".to_owned(),
            channel: Some(DispatchChannel::Email),
            reference: Some(format!("MSG-{}", recipients.join("-"))),
            recipients: Some(recipients.into_iter().map(str::to_owned).collect()),
            evidence_reference: Some("archive:convening-notice-dispatch".to_owned()),
            imported_document_id: None,
            operator_note: Some(
                "Generated convening notice operator note must not enter the ledger.".to_owned(),
            ),
        }
    }

    async fn response_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn generated_convening_notice_dispatch_evidence_records_partial_covered_idempotently_and_preserves_act_pdf()
     {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, _entity, _book, act, ata, notice) =
            seed_generated_convening_dispatch_fixture(&state, vec!["Ana Sócia", "Bruno Sócio"])
                .await;
        let act_before = act.clone();
        let ledger_before = state.ledger.read().await.len();

        let Json(generated) =
            list_generated_documents_for_act(State(state.clone()), Path(act.id.0), actor.clone())
                .await
                .expect("generated documents list");
        let notice_view = generated
            .iter()
            .find(|doc| doc.id == notice.id)
            .expect("generated convening notice view");
        let status = notice_view
            .dispatch_evidence_status
            .as_ref()
            .expect("dispatch status present for generated convocatória");
        assert_eq!(status.status, "required_pending");
        assert_eq!(
            status.required_recipients,
            vec!["Ana Sócia".to_owned(), "Bruno Sócio".to_owned()]
        );
        assert!(!status.dispatch_completed);
        assert_eq!(status.completion_basis, "none");
        assert!(
            status
                .note
                .contains("no sending, delivery, legal notice completion, or legal sufficiency")
        );

        let partial = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(notice.id.clone()),
            Json(generated_convening_dispatch_request(vec!["Ana Sócia"])),
        )
        .await
        .expect("partial generated convening evidence recorded");
        assert_eq!(partial.status(), StatusCode::CREATED);
        let partial_body = response_json(partial).await;
        assert_eq!(
            partial_body["dispatch_evidence_status"]["status"],
            "operator_evidence_partial"
        );
        assert_eq!(
            partial_body["dispatch_evidence_status"]["recorded_recipients"],
            json!(["Ana Sócia"])
        );
        assert_eq!(
            partial_body["dispatch_evidence_status"]["missing_recipients"],
            json!(["Bruno Sócio"])
        );
        assert_eq!(
            partial_body["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(
            partial_body["dispatch_evidence_status"]["completion_basis"],
            "none"
        );
        for flag in [
            "sending_performed_by_chancela",
            "delivery_confirmed",
            "legal_sufficiency_claimed",
            "legal_notice_completion_claimed",
            "bytes_in_payload",
        ] {
            assert_eq!(
                partial_body["evidence"][flag], false,
                "{flag} must remain false"
            );
        }

        let covered_request = generated_convening_dispatch_request(vec!["Bruno Sócio"]);
        let covered = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(notice.id.clone()),
            Json(covered_request.clone()),
        )
        .await
        .expect("covered generated convening evidence recorded");
        assert_eq!(covered.status(), StatusCode::CREATED);
        let covered_body = response_json(covered).await;
        assert_eq!(
            covered_body["dispatch_evidence_status"]["status"],
            "operator_evidence_covered"
        );
        assert_eq!(
            covered_body["dispatch_evidence_status"]["recorded_recipients"],
            json!(["Ana Sócia", "Bruno Sócio"])
        );
        assert_eq!(
            covered_body["dispatch_evidence_status"]["missing_recipients"],
            json!([])
        );
        assert_eq!(
            covered_body["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(
            covered_body["dispatch_evidence_status"]["completion_basis"],
            "none"
        );

        let ledger_after_second = state.ledger.read().await.len();
        assert_eq!(ledger_after_second, ledger_before + 2);
        assert_eq!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .filter(|event| event.kind == GENERATED_DOCUMENT_DISPATCH_EVIDENCE_EVENT_KIND)
                .count(),
            2,
            "generated convening evidence uses the generated-document event kind"
        );

        let retry = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(notice.id.clone()),
            Json(covered_request),
        )
        .await
        .expect("exact generated convening retry returns existing row");
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(
            state.ledger.read().await.len(),
            ledger_after_second,
            "exact retry must not append another ledger event"
        );

        let list = get_generated_document_dispatch_evidence(
            State(state.clone()),
            Path(notice.id.clone()),
            actor.clone(),
        )
        .await
        .expect("dispatch evidence list")
        .0;
        assert_eq!(
            list.dispatch_evidence_status.status,
            "operator_evidence_covered"
        );
        assert_eq!(list.evidence.len(), 2);

        let canonical = load_document(&state, act.id)
            .await
            .expect("canonical load")
            .expect("canonical ata");
        assert_eq!(canonical.id, ata.id);
        assert_eq!(canonical.pdf_digest, ata.pdf_digest);
        assert_eq!(canonical.pdf_bytes, ata.pdf_bytes);
        assert_eq!(
            state.acts.read().await.get(&act.id),
            Some(&act_before),
            "recording generated-document dispatch evidence must not mutate the act"
        );
        let generated_pdf =
            get_generated_document_pdf(State(state.clone()), Path(notice.id.clone()), actor)
                .await
                .expect("generated notice PDF response");
        assert_eq!(
            generated_pdf
                .headers()
                .get("x-chancela-dispatch-evidence-status")
                .and_then(|v| v.to_str().ok()),
            Some("operator_evidence_covered")
        );
        assert_eq!(
            generated_pdf
                .headers()
                .get("x-chancela-dispatch-completed")
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
        let generated_bytes = axum::body::to_bytes(generated_pdf.into_body(), usize::MAX)
            .await
            .expect("generated notice PDF body");
        assert_eq!(generated_bytes.as_ref(), notice.pdf_bytes.as_slice());

        let rows = state
            .store
            .as_ref()
            .expect("store")
            .generated_document_dispatch_evidence(&notice.id)
            .expect("evidence rows");
        let context = generated_dispatch_context_for_doc(&state, notice)
            .await
            .expect("generated convening context");
        let payload = generated_dispatch_evidence_event_payload(&context, &rows[0]);
        assert_eq!(
            payload["dispatch_evidence_profile"],
            "generated_convening_notice"
        );
        assert_eq!(
            payload["required_convening_recipients"],
            json!(["Ana Sócia", "Bruno Sócio"])
        );
        assert_eq!(
            payload["selected_convening_recipients"],
            json!(["Ana Sócia"])
        );
        assert_eq!(payload["sending_performed_by_chancela"], false);
        assert_eq!(payload["delivery_confirmed"], false);
        assert_eq!(payload["legal_sufficiency_claimed"], false);
        assert_eq!(payload["legal_notice_completion_claimed"], false);
        assert_eq!(payload["bytes_in_payload"], false);
        assert_eq!(payload["metadata"]["operator_note_in_payload"], false);
        assert!(
            !payload
                .to_string()
                .contains("Generated convening notice operator note"),
            "operator note must not be serialized into ledger payload: {payload}"
        );
    }

    #[tokio::test]
    async fn generated_convening_notice_dispatch_evidence_unavailable_and_rejected_without_convening_recipients()
     {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, _entity, _book, act, _ata, notice) =
            seed_generated_convening_dispatch_fixture(&state, Vec::new()).await;
        let ledger_before = state.ledger.read().await.len();

        let Json(generated) =
            list_generated_documents_for_act(State(state.clone()), Path(act.id.0), actor.clone())
                .await
                .expect("generated documents list");
        let notice_view = generated
            .iter()
            .find(|doc| doc.id == notice.id)
            .expect("generated convening notice view");
        assert!(
            notice_view.dispatch_evidence_status.is_none(),
            "generated convening notice without recipients should not expose dispatch evidence UI status"
        );

        let pdf_response = get_generated_document_pdf(
            State(state.clone()),
            Path(notice.id.clone()),
            actor.clone(),
        )
        .await
        .expect("generated notice PDF response");
        assert!(
            pdf_response
                .headers()
                .get("x-chancela-dispatch-evidence-status")
                .is_none(),
            "unavailable dispatch status must not be advertised on the generated PDF"
        );

        let get_err = match get_generated_document_dispatch_evidence(
            State(state.clone()),
            Path(notice.id.clone()),
            actor.clone(),
        )
        .await
        {
            Ok(_) => panic!("GET dispatch evidence should require convening recipients"),
            Err(err) => err,
        };
        assert!(
            matches!(get_err, ApiError::Unprocessable(message) if message.contains("no convening recipients"))
        );

        let post_err = match record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Path(notice.id),
            Json(generated_convening_dispatch_request(vec!["Ana Sócia"])),
        )
        .await
        {
            Ok(_) => panic!("POST dispatch evidence should require convening recipients"),
            Err(err) => err,
        };
        assert!(
            matches!(post_err, ApiError::Unprocessable(message) if message.contains("no convening recipients"))
        );
        assert_eq!(
            state.ledger.read().await.len(),
            ledger_before,
            "unavailable generated convening evidence path must not append ledger events"
        );
    }

    #[tokio::test]
    async fn absent_owner_dispatch_evidence_records_status_idempotently_and_preserves_bytes() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, _entity, _book, act, ata, communication) =
            seed_absent_owner_dispatch_fixture(&state).await;
        let ledger_before = state.ledger.read().await.len();

        let response = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(communication.id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        )
        .await
        .expect("dispatch evidence recorded");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response_json(response).await;
        assert_eq!(body["evidence"]["document_id"], communication.id);
        assert_eq!(body["evidence"]["recipients"], json!(["Fração B"]));
        assert_eq!(body["evidence"]["sending_performed_by_chancela"], false);
        assert_eq!(body["evidence"]["delivery_confirmed"], false);
        assert_eq!(body["evidence"]["legal_sufficiency_claimed"], false);
        assert_eq!(body["evidence"]["legal_notice_completion_claimed"], false);
        assert_eq!(body["evidence"]["bytes_in_payload"], false);
        assert_eq!(
            body["dispatch_evidence_status"]["status"],
            "operator_evidence_covered"
        );
        assert_eq!(body["dispatch_evidence_status"]["evidence_attached"], true);
        assert_eq!(
            body["dispatch_evidence_status"]["dispatch_completed"],
            false
        );
        assert_eq!(body["dispatch_evidence_status"]["completion_basis"], "none");

        let ledger_after_first = state.ledger.read().await.len();
        assert_eq!(ledger_after_first, ledger_before + 1);
        assert_eq!(
            state
                .ledger
                .read()
                .await
                .events()
                .iter()
                .filter(|event| event.kind == ABSENT_OWNER_DISPATCH_EVIDENCE_EVENT_KIND)
                .count(),
            1,
            "one bounded dispatch evidence event is appended"
        );

        let pdf_response = get_generated_document_pdf(
            State(state.clone()),
            Path(communication.id.clone()),
            actor.clone(),
        )
        .await
        .expect("generated PDF response");
        assert_eq!(
            pdf_response
                .headers()
                .get("x-chancela-dispatch-evidence-status")
                .and_then(|v| v.to_str().ok()),
            Some("operator_evidence_covered")
        );
        assert_eq!(
            pdf_response
                .headers()
                .get("x-chancela-dispatch-evidence-attached")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            pdf_response
                .headers()
                .get("x-chancela-dispatch-completed")
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
        let generated_bytes = axum::body::to_bytes(pdf_response.into_body(), usize::MAX)
            .await
            .expect("generated body");
        assert_eq!(generated_bytes.as_ref(), communication.pdf_bytes.as_slice());

        let canonical = load_document(&state, act.id)
            .await
            .expect("canonical load")
            .expect("canonical ata");
        assert_eq!(canonical.id, ata.id);
        assert_eq!(canonical.pdf_bytes, ata.pdf_bytes);

        let retry = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Path(communication.id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        )
        .await
        .expect("exact retry returns existing");
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(
            state.ledger.read().await.len(),
            ledger_after_first,
            "exact retry must not append a duplicate ledger event"
        );
        let rows = state
            .store
            .as_ref()
            .expect("store")
            .generated_document_dispatch_evidence(&communication.id)
            .expect("evidence rows");
        assert_eq!(rows.len(), 1);
        let context = generated_dispatch_context_for_doc(&state, communication)
            .await
            .expect("dispatch context");
        let payload = generated_dispatch_evidence_event_payload(&context, &rows[0]);
        assert_eq!(payload["sending_performed_by_chancela"], false);
        assert_eq!(payload["delivery_confirmed"], false);
        assert_eq!(payload["legal_sufficiency_claimed"], false);
        assert_eq!(payload["legal_notice_completion_claimed"], false);
        assert_eq!(payload["bytes_in_payload"], false);
        assert_eq!(payload["metadata"]["operator_note_in_payload"], false);
        assert!(
            !payload
                .to_string()
                .contains("Operator recorded an external postal locator only."),
            "operator note must not be serialized into the ledger payload: {payload}"
        );
    }

    #[tokio::test]
    async fn absent_owner_dispatch_evidence_concurrent_exact_retries_share_row_and_event() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, _entity, _book, _act, _ata, communication) =
            seed_absent_owner_dispatch_fixture(&state).await;
        let ledger_before = state.ledger.read().await.len();
        let document_id = communication.id.clone();

        let call1 = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(document_id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        );
        let call2 = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(document_id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        );
        let call3 = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(document_id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        );
        let call4 = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Path(document_id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        );

        let (r1, r2, r3, r4) = tokio::join!(call1, call2, call3, call4);
        let responses = [r1, r2, r3, r4]
            .into_iter()
            .map(|response| response.expect("concurrent exact retry must not fail"))
            .collect::<Vec<_>>();
        let statuses = responses
            .iter()
            .map(|response| response.status())
            .collect::<Vec<_>>();
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1,
            "exact concurrent retries should have one creator: {statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            3,
            "exact concurrent retries should return existing rows after the first insert: {statuses:?}"
        );
        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.len(),
            ledger_before + 1,
            "concurrent exact retries must append one ledger event total"
        );
        assert_eq!(
            ledger
                .events()
                .iter()
                .filter(|event| event.kind == ABSENT_OWNER_DISPATCH_EVIDENCE_EVENT_KIND)
                .count(),
            1,
            "concurrent exact retries must not duplicate durable dispatch evidence events"
        );
        drop(ledger);
        let rows = state
            .store
            .as_ref()
            .expect("store")
            .generated_document_dispatch_evidence(&document_id)
            .expect("evidence rows");
        assert_eq!(
            rows.len(),
            1,
            "concurrent exact retries must retain one dispatch evidence row"
        );
    }

    #[tokio::test]
    async fn absent_owner_dispatch_evidence_rejects_invalid_requests_without_mutation() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (actor, _entity, book, _act, ata, communication) =
            seed_absent_owner_dispatch_fixture(&state).await;

        let mut missing_locator = absent_owner_dispatch_request(vec!["Fração B"]);
        missing_locator.reference = None;
        missing_locator.evidence_reference = None;
        let ledger_before = state.ledger.read().await.len();
        let err = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(communication.id.clone()),
            Json(missing_locator),
        )
        .await
        .expect_err("missing locator rejected");
        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("at least one locator"))
        );
        assert_eq!(state.ledger.read().await.len(), ledger_before);

        let err = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(communication.id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração A"])),
        )
        .await
        .expect_err("non-absent recipient rejected");
        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("not an absent attendee"))
        );
        assert_eq!(state.ledger.read().await.len(), ledger_before);

        let err = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(ata.id.clone()),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        )
        .await
        .expect_err("wrong template rejected");
        assert!(
            matches!(err, ApiError::Unprocessable(message) if message.contains("condominio-comunicacao-ausentes"))
        );
        assert_eq!(state.ledger.read().await.len(), ledger_before);

        let imported_bytes = minimal_pdf();
        let imported_digest: [u8; 32] = Sha256::digest(&imported_bytes).into();
        let imported = StoredImportedDocument {
            meta: StoredImportedDocumentMeta {
                id: Uuid::new_v4().to_string(),
                act_id: Some(ActId::new()),
                filename: Some("wrong-act-proof.pdf".to_owned()),
                declared_content_type: Some("application/pdf".to_owned()),
                detected_content_type: "application/pdf".to_owned(),
                sha256: crate::hex::hex(&imported_digest),
                size_bytes: imported_bytes.len(),
                imported_at: OffsetDateTime::now_utc(),
                imported_by: "document.owner".to_owned(),
                operator_review_status: StoredImportedDocumentReviewStatus::OperatorReviewRequired,
                operator_reviewed_at: None,
                operator_reviewed_by: None,
                operator_review_note: None,
                operator_acknowledged_guardrail_ids: Vec::new(),
                technical_validation_report_json: "{}".to_owned(),
            },
            bytes: imported_bytes,
        };
        state
            .store
            .as_ref()
            .expect("store")
            .persist(|tx| tx.upsert_imported_document(&imported))
            .expect("wrong-act import persists");
        let mut wrong_import = absent_owner_dispatch_request(vec!["Fração B"]);
        wrong_import.reference = None;
        wrong_import.evidence_reference = None;
        wrong_import.imported_document_id = Some(imported.meta.id.clone());
        let err = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Path(communication.id.clone()),
            Json(wrong_import),
        )
        .await
        .expect_err("wrong-act import rejected");
        assert!(matches!(err, ApiError::Unprocessable(message) if message.contains("same act")));
        assert_eq!(state.ledger.read().await.len(), ledger_before);

        state
            .books
            .write()
            .await
            .get_mut(&book.id)
            .expect("book in memory")
            .state = chancela_core::BookState::Closed;
        let err = record_generated_document_dispatch_evidence(
            State(state.clone()),
            actor,
            CurrentAttestor::default(),
            Path(communication.id),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        )
        .await
        .expect_err("closed book rejected");
        assert!(matches!(err, ApiError::Conflict(message) if message.contains("read-only")));
        assert_eq!(state.ledger.read().await.len(), ledger_before);
    }

    #[tokio::test]
    async fn absent_owner_dispatch_evidence_denies_before_validation_details() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let (_owner, _entity, _book, _act, ata, _communication) =
            seed_absent_owner_dispatch_fixture(&state).await;
        let powerless = seed_powerless_actor(&state).await;
        let ledger_before = state.ledger.read().await.len();

        let get_err = match get_generated_document_dispatch_evidence(
            State(state.clone()),
            Path(ata.id.clone()),
            powerless.clone(),
        )
        .await
        {
            Ok(_) => panic!("GET should be denied before wrong-template validation"),
            Err(err) => err,
        };
        assert!(
            matches!(&get_err, ApiError::Forbidden(message) if message == crate::authz::FORBIDDEN),
            "GET should return generic permission denial, not validation details: {get_err:?}"
        );

        let post_err = match record_generated_document_dispatch_evidence(
            State(state.clone()),
            powerless,
            CurrentAttestor::default(),
            Path(ata.id),
            Json(absent_owner_dispatch_request(vec!["Fração B"])),
        )
        .await
        {
            Ok(_) => panic!("POST should be denied before wrong-template validation"),
            Err(err) => err,
        };
        assert!(
            matches!(&post_err, ApiError::Forbidden(message) if message == crate::authz::FORBIDDEN),
            "POST should return generic permission denial, not validation details: {post_err:?}"
        );
        assert_eq!(
            state.ledger.read().await.len(),
            ledger_before,
            "permission denial must not append ledger events"
        );
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
            recipients: vec![ConveningRecipient {
                name: "Bruno Cardoso".to_string(),
                contact: Some("bruno@example.test".to_string()),
                channel: Some(DispatchChannel::RegisteredLetterAR),
                reference: Some("RR123456789PT".to_string()),
                dispatched_at: Some(time::macros::date!(2026 - 06 - 10)),
            }],
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
        assert_eq!(ctx["convening"]["recipients"][0]["name"], "Bruno Cardoso");
        assert_eq!(
            ctx["convening"]["recipients"][0]["contact"],
            "bruno@example.test"
        );
        assert_eq!(
            ctx["convening"]["recipients"][0]["reference"],
            "RR123456789PT"
        );
        assert_eq!(
            ctx["convening"]["recipients"][0]["dispatched_at"],
            "2026-06-10"
        );
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
            required_signatory_records: Vec::new(),
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

    // -----------------------------------------------------------------------------------------
    // wp23 — user-authored template CRUD + export/import (documents::{create,replace,delete,
    // export,import}_template + merged list_templates).
    // -----------------------------------------------------------------------------------------

    /// A minimal, valid user-authored template (fictional entity, reserved `user-` id namespace).
    fn valid_user_template_json() -> String {
        r#"{
            "id": "user-encosto-ata/v1",
            "family": "CommercialCompany",
            "stage": "Ata",
            "channels": ["Physical"],
            "signature_policy": "QualifiedPreferred",
            "rule_pack_id": "csc-art63/v2",
            "locale": "pt-PT",
            "blocks": [
                { "kind": "Heading", "level": 1, "template": "Ata n.º {{ ata_number }}" },
                { "kind": "Paragraph", "template": "Reunida a assembleia em {{ meeting_date | long_date }}." }
            ]
        }"#
        .to_string()
    }

    #[tokio::test]
    async fn user_template_create_list_export_delete_reimport_round_trip() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        // create → 201, summary is an editable user template.
        let created = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("create handler ok");
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = response_json(created).await;
        assert_eq!(created_body["id"], "user-encosto-ata/v1");
        assert_eq!(created_body["editable"], true);
        assert_eq!(created_body["source"], "user");

        // list → merges built-ins (read-only) with our editable user template.
        let Json(listed) = list_templates(
            State(state.clone()),
            actor.clone(),
            Query(TemplatesQuery {
                family: None,
                stage: None,
            }),
        )
        .await
        .expect("list handler ok");
        let mine = listed
            .iter()
            .find(|s| s.id == "user-encosto-ata/v1")
            .expect("user template present in merged catalog");
        assert!(mine.editable);
        assert_eq!(mine.source, "user");
        assert!(
            listed.iter().any(|s| s.source == "builtin"),
            "merged catalog still carries the read-only built-ins"
        );

        // export → canonical JSON with an attachment disposition; re-validates cleanly.
        let exported = export_template(
            State(state.clone()),
            Path("user-encosto-ata/v1".to_owned()),
            actor.clone(),
        )
        .await
        .expect("export handler ok");
        assert_eq!(exported.status(), StatusCode::OK);
        assert_eq!(
            exported
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            exported
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"user-encosto-ata-v1.json\"")
        );
        let exported_bytes = axum::body::to_bytes(exported.into_body(), usize::MAX)
            .await
            .expect("export body");

        // delete → 204, then the user template is gone from the merged list.
        let deleted = delete_template(
            State(state.clone()),
            Path("user-encosto-ata/v1".to_owned()),
            actor.clone(),
            CurrentAttestor::default(),
        )
        .await
        .expect("delete handler ok");
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let Json(after_delete) = list_templates(
            State(state.clone()),
            actor.clone(),
            Query(TemplatesQuery {
                family: None,
                stage: None,
            }),
        )
        .await
        .expect("list ok");
        assert!(
            !after_delete.iter().any(|s| s.id == "user-encosto-ata/v1"),
            "deleted user template must not reappear"
        );

        // re-import the exported bytes → 201 (lossless round-trip under deny_unknown_fields).
        let reimported = import_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Query(TemplateImportQuery { dry_run: false }),
            exported_bytes,
        )
        .await
        .expect("import handler ok");
        assert_eq!(
            reimported.status(),
            StatusCode::CREATED,
            "exported canonical JSON re-imports losslessly"
        );

        let ledger = state.ledger.read().await;
        let template_events: Vec<_> = ledger
            .events()
            .iter()
            .filter(|event| event.kind.starts_with("template."))
            .collect();
        let kinds: Vec<&str> = template_events
            .iter()
            .map(|event| event.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec!["template.created", "template.deleted", "template.created"]
        );
        assert!(
            template_events
                .iter()
                .all(|event| event.scope == TEMPLATE_EVENT_SCOPE),
            "user-template mutations are application-scoped: {template_events:?}"
        );
    }

    #[tokio::test]
    async fn malformed_user_template_is_422_with_code_body() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        let bad = r#"{"id":"user-x/v1","family":"Association","stage":"Ata","channels":[],
            "signature_policy":"ManualAttested","rule_pack_id":"assoc-cc/v1","locale":"pt-PT",
            "surprise":true,"blocks":[{"kind":"Paragraph","template":"Olá."}]}"#;
        let resp = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(bad),
        )
        .await
        .expect("handler returns a response (not an Err)");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = response_json(resp).await;
        assert_eq!(body["code"], "malformed");
        assert!(body.get("message").is_some());
    }

    #[tokio::test]
    async fn duplicate_user_template_id_is_409() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        let first = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("first create ok");
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("second create returns a response");
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = response_json(second).await;
        assert_eq!(body["code"], "conflict");
        assert_eq!(body["field"], "id");
    }

    #[tokio::test]
    async fn replace_user_template_updates_store_and_ledgers_event() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        let created = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("create ok");
        assert_eq!(created.status(), StatusCode::CREATED);

        let replacement = valid_user_template_json().replace(
            "Ata n.º {{ ata_number }}",
            "Ata revista n.º {{ ata_number }}",
        );
        let replaced = replace_template(
            State(state.clone()),
            Path("user-encosto-ata/v1".to_owned()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(replacement.clone()),
        )
        .await
        .expect("replace handler ok");
        assert_eq!(replaced.status(), StatusCode::OK);
        let body = response_json(replaced).await;
        assert_eq!(body["id"], "user-encosto-ata/v1");
        assert_eq!(body["editable"], true);
        assert_eq!(body["source"], "user");

        let stored = state
            .store
            .as_ref()
            .expect("store")
            .user_template("user-encosto-ata/v1")
            .expect("store read")
            .expect("template row");
        assert!(
            stored.contains("Ata revista"),
            "replacement bytes persisted: {stored}"
        );
        let ledger = state.ledger.read().await;
        let last = ledger.events().last().expect("template.updated event");
        assert_eq!(last.kind, "template.updated");
        assert_eq!(last.scope, TEMPLATE_EVENT_SCOPE);
    }

    #[tokio::test]
    async fn replace_user_template_rejects_body_path_id_mismatch() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        let created = create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("create ok");
        assert_eq!(created.status(), StatusCode::CREATED);

        let mismatch = valid_user_template_json().replace(
            "\"id\": \"user-encosto-ata/v1\"",
            "\"id\": \"user-other-ata/v1\"",
        );
        let resp = replace_template(
            State(state.clone()),
            Path("user-encosto-ata/v1".to_owned()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(mismatch),
        )
        .await
        .expect("handler returns a response");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = response_json(resp).await;
        assert_eq!(body["code"], "id_mismatch");
        assert_eq!(body["field"], "id");

        let ledger = state.ledger.read().await;
        assert!(
            ledger
                .events()
                .iter()
                .all(|event| event.kind != "template.updated"),
            "id mismatch must not append update event"
        );
    }

    #[tokio::test]
    async fn delete_builtin_template_is_404() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let builtin_id = registry().specs()[0].id.clone();

        let err = delete_template(
            State(state.clone()),
            Path(builtin_id),
            actor.clone(),
            CurrentAttestor::default(),
        )
        .await
        .expect_err("built-ins are read-only");
        assert!(matches!(err, ApiError::NotFound));
    }

    #[tokio::test]
    async fn replace_builtin_template_is_404() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;
        let builtin_id = registry().specs()[0].id.clone();

        let err = replace_template(
            State(state.clone()),
            Path(builtin_id),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect_err("built-ins are read-only");
        assert!(matches!(err, ApiError::NotFound));
    }

    #[tokio::test]
    async fn import_dry_run_reports_verdict_without_persisting() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let actor = seed_owner(&state).await;

        // A valid unseen template → ok:true, and nothing is persisted.
        let ok = import_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Query(TemplateImportQuery { dry_run: true }),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("dry-run ok");
        assert_eq!(ok.status(), StatusCode::OK);
        let ok_body = response_json(ok).await;
        assert_eq!(ok_body["ok"], true);
        assert!(ok_body.get("error").is_none());

        // The dry-run persisted nothing.
        let Json(listed) = list_templates(
            State(state.clone()),
            actor.clone(),
            Query(TemplatesQuery {
                family: None,
                stage: None,
            }),
        )
        .await
        .expect("list ok");
        assert!(
            !listed.iter().any(|s| s.id == "user-encosto-ata/v1"),
            "dry-run must not persist"
        );

        // A duplicate (after a real create) → ok:false with a conflict verdict.
        create_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("create ok");
        let conflict = import_template(
            State(state.clone()),
            actor.clone(),
            CurrentAttestor::default(),
            Query(TemplateImportQuery { dry_run: true }),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect("dry-run conflict verdict");
        let conflict_body = response_json(conflict).await;
        assert_eq!(conflict_body["ok"], false);
        assert_eq!(conflict_body["error"]["code"], "conflict");
    }

    #[tokio::test]
    async fn create_template_requires_template_manage() {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.path());
        let powerless = seed_powerless_actor(&state).await;

        let err = create_template(
            State(state.clone()),
            powerless,
            CurrentAttestor::default(),
            Bytes::from(valid_user_template_json()),
        )
        .await
        .expect_err("no template.manage permission");
        assert!(matches!(err, ApiError::Forbidden(_)));
    }
}
