//! Validation and preservation for scanned historical paper-book import candidates.
//!
//! Historical paper-book packages are non-canonical evidence only. Preservation retains package
//! bytes and metadata, appends a metadata-only ledger event, and does not claim that scans are
//! canonical digital minutes or qualified signatures.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_core::{Act, BookId, MeetingChannel};
use chancela_store::{
    PaperBookOcrConversionDossierUpsert, StoreError, StoredPaperBookImport,
    StoredPaperBookImportMeta, StoredPaperBookOcrConversionDossier,
    StoredPaperBookOcrConversionExecutionArtifact, StoredPaperBookOcrDraft,
    StoredPaperBookOcrPageSpan, StoredPaperBookOcrReviewStatus, StoredPaperBookOcrStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStdout, Command};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_book};
use crate::dto::{ActView, format_date, parse_date};
use crate::error::ApiError;

const PAPER_BOOK_IMPORT_NOTICE: &str = "Historical paper-book scans are classified as non-canonical evidence only. This report does not preserve the package, replace canonical digital minutes, or claim PDF/A, legal, or qualified-signature validity.";
const PAPER_BOOK_PRESERVATION_NOTICE: &str = "Historical paper-book package preserved as non-canonical evidence only. It does not replace canonical digital minutes and no PDF/A, legal-validity, signature-validity, or qualified-signature claim is made.";
const PAPER_BOOK_OCR_STATUS_NOTICE: &str = "OCR status is operator-visible metadata only. Chancela has not extracted, verified, or stored authoritative OCR text for this preserved paper-book package.";
const PAPER_BOOK_OCR_DRAFT_NOTICE: &str = "OCR draft results are non-authoritative review aids linked to preserved paper-book imports. They are not canonical minutes, legal text, or a legal-validity claim.";
const PAPER_BOOK_OCR_DRAFT_TO_ACT_NOTICE: &str = "Accepted OCR draft text was copied into a new mutable draft act as a drafting aid only. No canonical document, PDF/A, signature, seal, or legal-validity acceptance was created.";
const PAPER_BOOK_OCR_CONVERSION_DOSSIER_NOTICE: &str = "This paper-book OCR conversion dossier is metadata-only, non-canonical, and non-legal-validity-conferring. It records accepted OCR draft review metadata only and does not create acts, documents, signed documents, archive packages, signatures, seals, PDF/A, or PDF/UA outputs.";
const PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACT_NOTICE: &str = "This reviewed OCR conversion execution artifact binds accepted OCR/dossier evidence to a mutable Draft act only. It is not a canonical or legal conversion and makes no PDF/A, PDF/UA, signature, archive-package, archive-certification, or legal-validity claim.";
const PAPER_BOOK_OCR_CANONICAL_REHEARSAL_NOTICE: &str = "This OCR/canonical rehearsal report is computed locally from preserved paper-book import metadata, OCR draft review metadata, and metadata-only dossier evidence. It does not perform OCR, mutate records, create canonical or sealed documents, call validators, certify PDF/A or PDF/UA, sign anything, or claim legal validity.";
const MAX_NOTES_CHARS: usize = 2_000;
const MAX_OCR_TEXT_CHARS: usize = 1_000_000;
const MAX_OCR_REVIEW_NOTE_CHARS: usize = 2_000;
const SQLITE_MAX_INTEGER_U64: u64 = i64::MAX as u64;
const DEFAULT_OCR_ARGS_TEMPLATE: &str = "{input}";
const DEFAULT_OCR_ENGINE_NAME: &str = "operator-configured-ocr";
const DEFAULT_OCR_TIMEOUT_SECS: u64 = 60;
const MAX_OCR_TIMEOUT_SECS: u64 = 300;
const DEFAULT_OCR_MAX_STDOUT_BYTES: usize = 256 * 1024;
pub const PAPER_BOOK_OCR_COMMAND_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_COMMAND";
pub const PAPER_BOOK_OCR_ARGS_TEMPLATE_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_ARGS_TEMPLATE";
pub const PAPER_BOOK_OCR_ENGINE_NAME_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_ENGINE_NAME";
pub const PAPER_BOOK_OCR_ENGINE_VERSION_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_ENGINE_VERSION";
pub const PAPER_BOOK_OCR_TIMEOUT_SECS_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_TIMEOUT_SECS";
pub const PAPER_BOOK_OCR_MAX_STDOUT_BYTES_ENV: &str = "CHANCELA_PAPER_BOOK_OCR_MAX_STDOUT_BYTES";
pub(crate) const PAPER_BOOK_IMPORT_MAX_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const PAPER_BOOK_IMPORT_ENVELOPE_BYTES: usize =
    PAPER_BOOK_IMPORT_MAX_BYTES * 4 / 3 + 64 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct PaperBookImportValidationRequest {
    #[serde(alias = "entity_id")]
    entity_ref: Option<String>,
    entity_name: Option<String>,
    entity_nipc: Option<String>,
    #[serde(alias = "book_id")]
    book_ref: Option<String>,
    #[serde(alias = "start_date")]
    date_from: Option<String>,
    #[serde(alias = "end_date")]
    date_to: Option<String>,
    page_count: Option<u32>,
    #[serde(alias = "source_page_from", alias = "start_page")]
    page_from: Option<u32>,
    #[serde(alias = "source_page_to", alias = "end_page")]
    page_to: Option<u32>,
    #[serde(
        alias = "ata_number_from",
        alias = "original_number_from",
        alias = "original_ata_from"
    )]
    original_ata_number_from: Option<u64>,
    #[serde(
        alias = "ata_number_to",
        alias = "original_number_to",
        alias = "original_ata_to"
    )]
    original_ata_number_to: Option<u64>,
    #[serde(alias = "filename")]
    source_filename: Option<String>,
    #[serde(alias = "sha256")]
    digest: Option<String>,
    notes: Option<String>,
    #[serde(
        default,
        alias = "ocr_canonical_preflight",
        alias = "canonical_preflight"
    )]
    canonical_conversion_preflight: Option<PaperBookCanonicalConversionPreflightRequest>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct PaperBookCanonicalConversionPreflightRequest {
    #[serde(default)]
    ocr_text_present: bool,
    #[serde(default, alias = "text_digest")]
    ocr_text_digest: Option<String>,
    #[serde(default)]
    operator_review_recorded: bool,
    #[serde(
        default,
        alias = "package_fixity_verified",
        alias = "fixity_verified",
        alias = "candidate_fixity_verified"
    )]
    package_fixity_recorded: bool,
    #[serde(
        default,
        alias = "page_range_confirmed",
        alias = "source_page_range_reviewed"
    )]
    page_range_reviewed: bool,
    #[serde(default)]
    legal_acceptance_recorded: bool,
}

#[derive(Debug, Deserialize)]
pub struct PaperBookImportPreserveRequest {
    #[serde(flatten)]
    metadata: PaperBookImportValidationRequest,
    #[serde(alias = "bytes_base64", alias = "data_base64", alias = "base64")]
    content_base64: String,
    content_type: String,
    #[serde(alias = "sha256", alias = "digest_sha256")]
    declared_sha256: String,
    #[serde(alias = "size")]
    size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookImportValidationReport {
    pub report_kind: &'static str,
    pub dry_run: bool,
    pub legal_notice: &'static str,
    pub identity: PaperBookIdentityReport,
    pub date_span: PaperBookDateSpanReport,
    pub package: PaperBookPackageReport,
    pub linking_evidence: PaperBookLinkingEvidenceReport,
    pub continuation: PaperBookContinuationRecommendation,
    pub canonical_conversion_preflight: PaperBookCanonicalConversionPreflightReport,
    pub candidate_classification: PaperBookCandidateClassification,
    pub can_accept_as_import_candidate: bool,
    pub required_operator_actions: Vec<&'static str>,
    pub findings: Vec<PaperBookImportFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookImportPreservationReport {
    pub report_kind: &'static str,
    pub dry_run: bool,
    pub legal_notice: &'static str,
    pub import_id: String,
    pub identity: PaperBookIdentityReport,
    pub date_span: PaperBookDateSpanReport,
    pub package: PaperBookPackageReport,
    pub linking_evidence: PaperBookLinkingEvidenceReport,
    pub continuation: PaperBookContinuationRecommendation,
    pub canonical_conversion_preflight: PaperBookCanonicalConversionPreflightReport,
    pub preservation: PaperBookPreservationReport,
    pub candidate_classification: PaperBookCandidateClassification,
    pub can_accept_as_import_candidate: bool,
    pub required_operator_actions: Vec<&'static str>,
    pub findings: Vec<PaperBookImportFinding>,
}

#[derive(Debug, Deserialize)]
pub struct PaperBookImportsQuery {
    pub book_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaperBookOcrCommandConfig {
    pub command_path: PathBuf,
    pub args_template: Vec<String>,
    pub engine_name: String,
    pub engine_version: Option<String>,
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
}

impl PaperBookOcrCommandConfig {
    pub fn new(command_path: impl Into<PathBuf>) -> Self {
        Self {
            command_path: command_path.into(),
            args_template: vec![DEFAULT_OCR_ARGS_TEMPLATE.to_owned()],
            engine_name: DEFAULT_OCR_ENGINE_NAME.to_owned(),
            engine_version: None,
            timeout: Duration::from_secs(DEFAULT_OCR_TIMEOUT_SECS),
            max_stdout_bytes: DEFAULT_OCR_MAX_STDOUT_BYTES,
        }
    }

    pub(crate) fn from_env() -> Option<Self> {
        let command_path = std::env::var(PAPER_BOOK_OCR_COMMAND_ENV).ok()?;
        let command_path = command_path.trim();
        if command_path.is_empty() {
            return None;
        }

        let args_template = std::env::var(PAPER_BOOK_OCR_ARGS_TEMPLATE_ENV)
            .ok()
            .map(|raw| parse_args_template_env(&raw))
            .unwrap_or_else(|| vec![DEFAULT_OCR_ARGS_TEMPLATE.to_owned()]);
        let engine_name = env_text(PAPER_BOOK_OCR_ENGINE_NAME_ENV)
            .unwrap_or_else(|| DEFAULT_OCR_ENGINE_NAME.to_owned());
        let engine_version = env_text(PAPER_BOOK_OCR_ENGINE_VERSION_ENV);
        let timeout = Duration::from_secs(env_u64(
            PAPER_BOOK_OCR_TIMEOUT_SECS_ENV,
            DEFAULT_OCR_TIMEOUT_SECS,
            1,
            MAX_OCR_TIMEOUT_SECS,
        ));
        let max_stdout_bytes = env_usize(
            PAPER_BOOK_OCR_MAX_STDOUT_BYTES_ENV,
            DEFAULT_OCR_MAX_STDOUT_BYTES,
            1,
            MAX_OCR_TEXT_CHARS,
        );

        Some(Self {
            command_path: PathBuf::from(command_path),
            args_template,
            engine_name,
            engine_version,
            timeout,
            max_stdout_bytes,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct PaperBookOcrStatusUpdateRequest {
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaperBookOcrDraftPageSpanRequest {
    pub start_page: u32,
    pub end_page: u32,
}

#[derive(Debug, Deserialize)]
pub struct PaperBookOcrDraftCreateRequest {
    pub extracted_text: Option<String>,
    pub text_digest: Option<String>,
    pub page_spans: Vec<PaperBookOcrDraftPageSpanRequest>,
    pub confidence: Option<f64>,
    pub engine_name: String,
    pub engine_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaperBookOcrDraftReviewRequest {
    pub review_status: String,
    pub review_note: Option<String>,
    pub superseded_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrStatusView {
    pub import_id: String,
    pub previous_ocr_status: &'static str,
    pub ocr_status: &'static str,
    pub status_notice: &'static str,
    pub ocr_text_stored: bool,
    pub authoritative_text_claimed: bool,
    pub legal_validity_claimed: bool,
    pub legal_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrDraftView {
    pub draft_id: String,
    pub import_id: String,
    pub extracted_text: Option<String>,
    pub text_digest: Option<String>,
    pub page_spans: Vec<PaperBookOcrDraftPageSpanView>,
    pub confidence: Option<f64>,
    pub engine: PaperBookOcrEngineView,
    pub created_at: String,
    pub created_by: String,
    pub review_status: &'static str,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
    pub review_note: Option<String>,
    pub superseded_by: Option<String>,
    pub draft_notice: &'static str,
    pub non_canonical: bool,
    pub authoritative_text_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signature_created: bool,
    pub legal_validity_claimed: bool,
    pub legal_notice: &'static str,
}

#[derive(Serialize)]
pub struct PaperBookOcrDraftCanonicalDraftResponse {
    pub import_id: String,
    pub draft_id: String,
    pub act: ActView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion_execution_artifact: Option<PaperBookOcrConversionExecutionArtifactView>,
    pub draft_act_created: bool,
    pub act_state: &'static str,
    pub notice: &'static str,
    pub ocr_text_copied_to_deliberations: bool,
    pub ocr_text_in_ledger_event: bool,
    pub non_canonical: bool,
    pub authoritative_text_claimed: bool,
    pub canonical_conversion_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signed_document_created: bool,
    pub archive_package_created: bool,
    pub archive_certification_claimed: bool,
    pub pdfa_created: bool,
    pub pdfua_created: bool,
    pub signature_created: bool,
    pub seal_created: bool,
    pub legal_validity_claimed: bool,
    pub legal_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrConversionExecutionArtifactView {
    pub artifact_id: String,
    pub import_id: String,
    pub draft_id: String,
    pub dossier_id: Option<String>,
    pub source_text_digest: Option<String>,
    pub source_page_spans: Vec<PaperBookOcrDraftPageSpanView>,
    pub source_review_status: &'static str,
    pub source_reviewed_at: Option<String>,
    pub source_reviewed_by: Option<String>,
    pub target_act_id: String,
    pub target_act_state: String,
    pub mutable_draft_act_created: bool,
    pub created_at: String,
    pub created_by: String,
    pub artifact_notice: &'static str,
    pub reviewed_conversion_execution_artifact: bool,
    pub non_canonical: bool,
    pub canonical_conversion_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signed_document_created: bool,
    pub archive_package_created: bool,
    pub archive_certification_claimed: bool,
    pub pdfa_created: bool,
    pub pdfua_created: bool,
    pub signature_created: bool,
    pub seal_created: bool,
    pub legal_validity_claimed: bool,
    pub source_extracted_text_in_artifact: bool,
    pub source_extracted_text_in_ledger_event: bool,
    pub legal_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrConversionDossierView {
    pub dossier_id: String,
    pub import_id: String,
    pub draft_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion_execution_artifacts: Option<Vec<PaperBookOcrConversionExecutionArtifactView>>,
    pub source_text_digest: Option<String>,
    pub source_page_spans: Vec<PaperBookOcrDraftPageSpanView>,
    pub source_review_status: &'static str,
    pub source_reviewed_at: Option<String>,
    pub source_reviewed_by: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub dossier_notice: &'static str,
    pub metadata_only: bool,
    pub non_canonical: bool,
    pub act_created: bool,
    pub canonical_act_created: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_document_created: bool,
    pub signed_document_created: bool,
    pub archive_package_created: bool,
    pub archive_certification_claimed: bool,
    pub pdfa_created: bool,
    pub pdfua_created: bool,
    pub signature_created: bool,
    pub seal_created: bool,
    pub legal_validity_claimed: bool,
    pub source_extracted_text_in_response: bool,
    pub source_extracted_text_in_ledger_event: bool,
    pub legal_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrRunResponse {
    pub import_id: String,
    pub previous_ocr_status: &'static str,
    pub ocr_status: &'static str,
    pub command_configured: bool,
    pub command_exit_success: bool,
    pub command_exit_code: Option<i32>,
    pub timed_out: bool,
    pub failure_reason: Option<&'static str>,
    pub stdout_bytes_captured: usize,
    pub stdout_truncated: bool,
    pub engine: PaperBookOcrEngineView,
    pub draft: Option<PaperBookOcrDraftView>,
    pub status_notice: &'static str,
    pub draft_notice: &'static str,
    pub non_canonical: bool,
    pub authoritative_text_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signature_created: bool,
    pub legal_validity_claimed: bool,
    pub legal_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrDraftPageSpanView {
    pub start_page: u32,
    pub end_page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrEngineView {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookImportView {
    pub import_id: String,
    pub entity_ref: String,
    pub entity_name: String,
    pub entity_nipc: String,
    pub book_ref: String,
    pub date_from: String,
    pub date_to: String,
    pub page_count: u32,
    pub page_from: u32,
    pub page_to: u32,
    pub original_ata_number_from: Option<u64>,
    pub original_ata_number_to: Option<u64>,
    pub linking_evidence: PaperBookLinkingEvidenceReport,
    pub continuation: PaperBookContinuationRecommendation,
    pub sha256: String,
    pub size_bytes: usize,
    pub content_type: String,
    pub source_filename: Option<String>,
    pub notes: Option<String>,
    pub imported_at: String,
    pub imported_by: String,
    pub ocr_status: &'static str,
    pub ocr_status_notice: &'static str,
    pub ocr_text_stored: bool,
    pub authoritative_text_claimed: bool,
    pub non_canonical: bool,
    pub legal_validity_claimed: bool,
    pub signature_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub legal_notice: &'static str,
    pub bytes_download: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalReport {
    pub report_kind: &'static str,
    pub dry_run: bool,
    pub rehearsal_scope: &'static str,
    pub legal_notice: &'static str,
    pub import_id: String,
    pub source_import: PaperBookOcrCanonicalRehearsalImportEvidence,
    pub ocr_evidence: PaperBookOcrCanonicalRehearsalOcrEvidence,
    pub dossier_evidence: PaperBookOcrCanonicalRehearsalDossierEvidence,
    pub readiness: PaperBookOcrCanonicalRehearsalReadiness,
    pub no_claims: PaperBookOcrCanonicalRehearsalNoClaims,
    pub required_operator_actions: Vec<&'static str>,
    pub findings: Vec<PaperBookImportFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalImportEvidence {
    pub import_present: bool,
    pub preserved_package_present: bool,
    pub book_ref: String,
    pub ocr_status: &'static str,
    pub page_count: u32,
    pub source_page_range: PaperBookPageRangeReport,
    pub original_ata_number_range: Option<PaperBookOriginalAtaNumberRangeReport>,
    pub package_digest_present: bool,
    pub package_size_bytes: usize,
    pub source_filename_present: bool,
    pub bytes_in_report: bool,
    pub non_canonical: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalOcrEvidence {
    pub draft_count: usize,
    pub accepted_draft_count: usize,
    pub unreviewed_draft_count: usize,
    pub rejected_draft_count: usize,
    pub superseded_draft_count: usize,
    pub selected_accepted_draft_id: Option<String>,
    pub selected_accepted_draft_text_digest_present: bool,
    pub selected_accepted_draft_extracted_text_present: bool,
    pub selected_accepted_draft_page_span_count: usize,
    pub selected_accepted_draft_page_span_pages: u32,
    pub operator_review_recorded: bool,
    pub raw_ocr_text_in_report: bool,
    pub confidence_buckets: PaperBookOcrCanonicalRehearsalConfidenceBuckets,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalConfidenceBuckets {
    pub known_count: usize,
    pub unknown_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalDossierEvidence {
    pub dossier_count: usize,
    pub metadata_only_dossier_present: bool,
    pub selected_dossier_id: Option<String>,
    pub selected_dossier_source_digest_present: bool,
    pub selected_dossier_page_span_count: usize,
    pub selected_dossier_page_span_pages: u32,
    pub bound_execution_artifact_count: usize,
    pub selected_bound_execution_artifact_count: usize,
    pub mutable_draft_act_artifact_present: bool,
    pub source_extracted_text_in_response: bool,
    pub source_extracted_text_in_ledger_event: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalReadiness {
    pub status: &'static str,
    pub scope: &'static str,
    pub evidence_source: &'static str,
    pub blockers: Vec<PaperBookCanonicalConversionBlocker>,
    pub next_local_action: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookOcrCanonicalRehearsalNoClaims {
    pub records_mutated: bool,
    pub external_ocr_called: bool,
    pub external_validator_called: bool,
    pub external_legal_service_called: bool,
    pub canonical_conversion_claimed: bool,
    pub ocr_accuracy_claimed: bool,
    pub legal_review_claimed: bool,
    pub legal_validity_claimed: bool,
    pub canonical_minutes_claimed: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub sealed_document_created: bool,
    pub signed_document_created: bool,
    pub archive_package_created: bool,
    pub archive_certification_claimed: bool,
    pub pdfa_created: bool,
    pub pdfa_certification_claimed: bool,
    pub pdfua_created: bool,
    pub pdfua_certification_claimed: bool,
    pub signature_created: bool,
    pub signing_requested: bool,
    pub signature_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub dglab_certification_claimed: bool,
    pub raw_ocr_text_in_report: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookIdentityReport {
    pub entity_ref: String,
    pub entity_name: String,
    pub entity_nipc: String,
    pub book_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookDateSpanReport {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookPackageReport {
    pub page_count: u32,
    pub source_page_range: PaperBookPageRangeReport,
    pub source_filename: Option<String>,
    pub digest: Option<String>,
    pub notes_present: bool,
    pub notes_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PaperBookPageRangeReport {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PaperBookOriginalAtaNumberRangeReport {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookLinkingEvidenceReport {
    pub source_page_range: PaperBookPageRangeReport,
    pub original_ata_number_range: Option<PaperBookOriginalAtaNumberRangeReport>,
    pub non_canonical: bool,
    pub planning_evidence_only: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signature_created: bool,
    pub legal_acceptance_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookContinuationRecommendation {
    pub recommendation: &'static str,
    pub recommended_action: &'static str,
    pub recommended_next_ata_number: Option<u64>,
    pub action_metadata: Vec<&'static str>,
    pub requires_operator_review: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signature_created: bool,
    pub legal_acceptance_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookCanonicalConversionPreflightReport {
    pub status: &'static str,
    pub preflight_requested: bool,
    pub scope: &'static str,
    pub evidence_source: &'static str,
    pub evidence: PaperBookCanonicalConversionEvidenceReport,
    pub blockers: Vec<PaperBookCanonicalConversionBlocker>,
    pub allowed_next_action: Option<&'static str>,
    pub raw_ocr_text_in_report: bool,
    pub canonical_act_created: bool,
    pub canonical_document_created: bool,
    pub signature_created: bool,
    pub signing_requested: bool,
    pub signature_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub legal_validity_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookCanonicalConversionEvidenceReport {
    pub ocr_text_present: bool,
    pub ocr_text_digest: Option<String>,
    pub operator_review_recorded: bool,
    pub candidate_digest_present: bool,
    pub package_fixity_recorded: bool,
    pub source_page_range_valid: bool,
    pub source_page_range: PaperBookPageRangeReport,
    pub page_range_reviewed: bool,
    pub legal_acceptance_recorded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookCanonicalConversionBlocker {
    pub code: &'static str,
    pub field: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookPreservationReport {
    pub status: &'static str,
    pub non_canonical: bool,
    pub sha256: String,
    pub size_bytes: usize,
    pub content_type: String,
    pub imported_at: String,
    pub imported_by: String,
    pub ocr_status: &'static str,
    pub bytes_in_ledger_event: bool,
    pub legal_validity_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookCandidateClassification {
    pub classification: &'static str,
    pub non_canonical: bool,
    pub historical_evidence: bool,
    pub preservation_status: &'static str,
    pub canonical_minutes_claimed: bool,
    pub legal_validity_claimed: bool,
    pub signature_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperBookImportFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl PaperBookImportFinding {
    fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "info",
            code,
            message: message.into(),
        }
    }
}

/// `POST /v1/books/paper-import/validate` - read-only validation/report for a scanned historical
/// paper-book package. It gates like book import, but never imports, preserves, or audits anything.
pub async fn validate_paper_book_import(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<PaperBookImportValidationRequest>,
) -> Result<Json<PaperBookImportValidationReport>, ApiError> {
    require_permission_for_report(&state, &actor).await?;
    Ok(Json(validate_candidate(req)?))
}

/// `POST /v1/books/paper-import` - preserve a scanned historical paper-book package as
/// non-canonical evidence. Re-runs metadata validation and fixity checks before writing bytes.
pub async fn preserve_paper_book_import(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PaperBookImportPreserveRequest>,
) -> Result<
    (
        axum::http::StatusCode,
        Json<PaperBookImportPreservationReport>,
    ),
    ApiError,
> {
    require_permission_for_report(&state, &actor).await?;
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "paper-book import preservation requires on-disk persistence".to_owned(),
        ));
    }

    let declared_sha256 = optional_digest(Some(req.declared_sha256))?
        .ok_or_else(|| ApiError::Unprocessable("sha256 is required".to_owned()))?;
    let content_type = required_content_type(req.content_type)?;
    let bytes = B64.decode(req.content_base64.trim()).map_err(|e| {
        ApiError::Unprocessable(format!("invalid base64 paper-book package content: {e}"))
    })?;
    verify_package_fixity(&bytes, req.size_bytes, &declared_sha256)?;

    let mut metadata_req = req.metadata.clone();
    metadata_req.digest = Some(declared_sha256.clone());
    let validation = validate_candidate(metadata_req)?;
    let notes = optional_text(req.metadata.notes, "notes")?;
    let import_id = Uuid::new_v4().to_string();
    let imported_at = OffsetDateTime::now_utc();
    let imported_by = actor.resolve("api");
    let stored = StoredPaperBookImport {
        meta: StoredPaperBookImportMeta {
            import_id: import_id.clone(),
            entity_ref: validation.identity.entity_ref.clone(),
            entity_name: validation.identity.entity_name.clone(),
            entity_nipc: validation.identity.entity_nipc.clone(),
            book_ref: validation.identity.book_ref.clone(),
            date_from: parse_date(&validation.date_span.from)?,
            date_to: parse_date(&validation.date_span.to)?,
            page_count: validation.package.page_count,
            page_from: validation.linking_evidence.source_page_range.from,
            page_to: validation.linking_evidence.source_page_range.to,
            original_number_from: validation
                .linking_evidence
                .original_ata_number_range
                .map(|range| range.from),
            original_number_to: validation
                .linking_evidence
                .original_ata_number_range
                .map(|range| range.to),
            sha256: declared_sha256.clone(),
            size_bytes: bytes.len(),
            content_type: content_type.clone(),
            source_filename: validation.package.source_filename.clone(),
            notes,
            imported_at,
            imported_by: imported_by.clone(),
            ocr_status: StoredPaperBookOcrStatus::NotRun,
        },
        bytes,
    };

    let payload = serde_json::to_vec(&paper_book_import_event_payload(&stored.meta))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &imported_by,
        &format!("paper-book-import:{import_id}"),
        "paper_book_import.preserved",
        None,
        &payload,
    )?;
    let stored_for_store = stored.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_paper_book_import(&stored_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok((
        StatusCode::CREATED,
        Json(preservation_report(validation, &stored.meta)),
    ))
}

/// `GET /v1/books/paper-import[?book_ref=...]` - list preserved paper-book import metadata.
/// The response is metadata-only; retained package bytes are fetched through the explicit bytes
/// route so they never ride in the list JSON body.
pub async fn list_paper_book_imports(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(q): Query<PaperBookImportsQuery>,
) -> Result<Json<Vec<PaperBookImportView>>, ApiError> {
    require_permission_for_report(&state, &actor).await?;
    let book_ref = optional_plain_ref(q.book_ref, "book_ref")?;
    let Some(store) = &state.store else {
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .paper_book_imports(book_ref.as_deref())
        .map_err(|e| ApiError::Internal(format!("paper-book import store read failed: {e}")))?;
    Ok(Json(rows.iter().map(paper_book_import_view).collect()))
}

/// `GET /v1/books/paper-import/{id}` - read preserved paper-book import metadata only.
pub async fn get_paper_book_import(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(id): Path<String>,
) -> Result<Json<PaperBookImportView>, ApiError> {
    let stored = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    Ok(Json(paper_book_import_view(&stored.meta)))
}

/// `POST /v1/books/paper-import/{id}/ocr/enqueue` - mark a preserved paper-book import as queued
/// for a later OCR worker. This does not run OCR and stores no extracted text.
pub async fn enqueue_paper_book_import_ocr(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(id): Path<String>,
) -> Result<Json<PaperBookOcrStatusView>, ApiError> {
    update_paper_book_import_ocr_status_internal(
        state,
        actor,
        attestor,
        &id,
        StoredPaperBookOcrStatus::Queued,
    )
    .await
    .map(Json)
}

/// `PATCH /v1/books/paper-import/{id}/ocr-status` - update only the OCR lifecycle marker for a
/// preserved paper-book import. This is metadata-only and does not store OCR output.
pub async fn update_paper_book_import_ocr_status(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(id): Path<String>,
    Json(req): Json<PaperBookOcrStatusUpdateRequest>,
) -> Result<Json<PaperBookOcrStatusView>, ApiError> {
    let status = parse_ocr_status(&req.status)?;
    update_paper_book_import_ocr_status_internal(state, actor, attestor, &id, status)
        .await
        .map(Json)
}

/// `POST /v1/books/paper-import/{id}/ocr/run` - run an operator-configured local OCR command
/// against the preserved package bytes and store bounded stdout as a non-authoritative draft.
/// The command is executed directly with `Command::new`, never through a shell.
pub async fn run_paper_book_import_ocr(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(id): Path<String>,
) -> Result<Json<PaperBookOcrRunResponse>, ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let config = state.paper_book_ocr_command.clone().ok_or_else(|| {
        ApiError::Unprocessable(
            "paper-book OCR run requires an operator-configured local OCR command".to_owned(),
        )
    })?;
    validate_ocr_command_config(&config)?;
    let output = execute_ocr_command(&config, &import).await?;
    let previous_ocr_status = import.meta.ocr_status;
    let updated_by = actor.resolve("api");

    if output.command_exit_success {
        let extracted_text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !extracted_text.is_empty() {
            let text_digest: [u8; 32] = Sha256::digest(extracted_text.as_bytes()).into();
            let draft = build_ocr_draft(
                PaperBookOcrDraftCreateRequest {
                    extracted_text: Some(extracted_text),
                    text_digest: Some(crate::hex::hex(&text_digest)),
                    page_spans: vec![PaperBookOcrDraftPageSpanRequest {
                        start_page: import.meta.page_from,
                        end_page: import.meta.page_to,
                    }],
                    confidence: None,
                    engine_name: config.engine_name.clone(),
                    engine_version: config.engine_version.clone(),
                },
                &import.meta,
                &actor,
            )?;

            let status_payload = serde_json::to_vec(&paper_book_ocr_status_event_payload(
                &import.meta,
                StoredPaperBookOcrStatus::Completed,
                &updated_by,
            ))?;
            let draft_payload =
                serde_json::to_vec(&paper_book_ocr_draft_event_payload(&draft, "created"))?;
            let mut ledger = state.ledger.write().await;
            crate::try_append_event(
                &mut ledger,
                &updated_by,
                &format!("paper-book-import:{}", import.meta.import_id),
                "paper_book_import.ocr_status_updated",
                None,
                &status_payload,
            )?;
            if let Err(err) = crate::try_append_event(
                &mut ledger,
                &draft.created_by,
                &format!("paper-book-import:{}", import.meta.import_id),
                "paper_book_import.ocr_draft_created",
                None,
                &draft_payload,
            ) {
                AppState::rollback_ledger_events(&mut ledger, 1);
                return Err(err);
            }
            let import_id_for_store = import.meta.import_id.clone();
            let draft_for_store = draft.clone();
            state
                .persist_write_through(&mut ledger, 2, move |tx| {
                    tx.update_paper_book_import_ocr_status(
                        &import_id_for_store,
                        StoredPaperBookOcrStatus::Completed,
                    )?;
                    tx.upsert_paper_book_ocr_draft(&draft_for_store)
                })
                .await?;
            state.attest_latest(&attestor, &ledger).await;
            drop(ledger);

            return Ok(Json(paper_book_ocr_run_response(
                &import.meta.import_id,
                previous_ocr_status,
                StoredPaperBookOcrStatus::Completed,
                &config,
                &output,
                None,
                Some(&draft),
            )));
        }
    }

    let failure_reason = output.failure_reason.or(Some("empty_stdout"));
    let status_payload = serde_json::to_vec(&paper_book_ocr_status_event_payload(
        &import.meta,
        StoredPaperBookOcrStatus::Failed,
        &updated_by,
    ))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &updated_by,
        &format!("paper-book-import:{}", import.meta.import_id),
        "paper_book_import.ocr_status_updated",
        None,
        &status_payload,
    )?;
    let import_id_for_store = import.meta.import_id.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.update_paper_book_import_ocr_status(
                &import_id_for_store,
                StoredPaperBookOcrStatus::Failed,
            )
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok(Json(paper_book_ocr_run_response(
        &import.meta.import_id,
        previous_ocr_status,
        StoredPaperBookOcrStatus::Failed,
        &config,
        &output,
        failure_reason,
        None,
    )))
}

/// `POST /v1/books/paper-import/{id}/ocr-drafts` - store a non-authoritative OCR draft result
/// linked to a preserved paper-book import. This does not run OCR and does not create canonical
/// text.
pub async fn create_paper_book_import_ocr_draft(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path(id): Path<String>,
    Json(req): Json<PaperBookOcrDraftCreateRequest>,
) -> Result<(StatusCode, Json<PaperBookOcrDraftView>), ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "paper-book OCR draft storage requires on-disk persistence".to_owned(),
        ));
    }
    let draft = build_ocr_draft(req, &import.meta, &actor)?;
    let payload = serde_json::to_vec(&paper_book_ocr_draft_event_payload(&draft, "created"))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &draft.created_by,
        &format!("paper-book-import:{}", import.meta.import_id),
        "paper_book_import.ocr_draft_created",
        None,
        &payload,
    )?;
    let draft_for_store = draft.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_paper_book_ocr_draft(&draft_for_store)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok((StatusCode::CREATED, Json(paper_book_ocr_draft_view(&draft))))
}

/// `GET /v1/books/paper-import/{id}/ocr-drafts` - list non-authoritative OCR draft results for a
/// preserved paper-book import.
pub async fn list_paper_book_import_ocr_drafts(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(id): Path<String>,
) -> Result<Json<Vec<PaperBookOcrDraftView>>, ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let Some(store) = &state.store else {
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .paper_book_ocr_drafts(&import.meta.import_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?;
    Ok(Json(rows.iter().map(paper_book_ocr_draft_view).collect()))
}

/// `PATCH /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/review` - update review metadata for
/// a non-authoritative OCR draft result.
pub async fn review_paper_book_import_ocr_draft(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path((id, draft_id)): Path<(String, String)>,
    Json(req): Json<PaperBookOcrDraftReviewRequest>,
) -> Result<Json<PaperBookOcrDraftView>, ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let draft_id = validate_import_id(&draft_id)?;
    let status = parse_ocr_review_status(&req.review_status)?;
    let review_note =
        optional_limited_text(req.review_note, "review_note", MAX_OCR_REVIEW_NOTE_CHARS)?;
    let superseded_by = optional_uuid_ref(req.superseded_by, "superseded_by")?;
    if status == StoredPaperBookOcrReviewStatus::Superseded && superseded_by.is_none() {
        return Err(ApiError::Unprocessable(
            "superseded OCR draft reviews require superseded_by".to_owned(),
        ));
    }
    if status != StoredPaperBookOcrReviewStatus::Superseded && superseded_by.is_some() {
        return Err(ApiError::Unprocessable(
            "superseded_by is only valid when review_status is superseded".to_owned(),
        ));
    }
    let Some(store) = &state.store else {
        return Err(ApiError::Unprocessable(
            "paper-book OCR draft review requires on-disk persistence".to_owned(),
        ));
    };
    let current = store
        .paper_book_ocr_draft(&draft_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    if current.import_id != import.meta.import_id {
        return Err(ApiError::NotFound);
    }

    let reviewed_by = actor.resolve("api");
    let reviewed_at = OffsetDateTime::now_utc();
    let payload = serde_json::to_vec(&paper_book_ocr_draft_review_event_payload(
        &current,
        status,
        &reviewed_by,
        superseded_by.as_deref(),
    ))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &reviewed_by,
        &format!("paper-book-import:{}", import.meta.import_id),
        "paper_book_import.ocr_draft_reviewed",
        None,
        &payload,
    )?;
    let draft_id_for_store = draft_id.clone();
    let reviewed_by_for_store = reviewed_by.clone();
    let review_note_for_store = review_note.clone();
    let superseded_by_for_store = superseded_by.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.review_paper_book_ocr_draft(
                &draft_id_for_store,
                status,
                Some(reviewed_at),
                Some(&reviewed_by_for_store),
                review_note_for_store.as_deref(),
                superseded_by_for_store.as_deref(),
            )
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    let reviewed = store
        .paper_book_ocr_draft(&draft_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(paper_book_ocr_draft_view(&reviewed)))
}

/// `POST /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft` - create one new
/// mutable draft act from an accepted OCR draft. The OCR text is copied only as working
/// deliberation text; no canonical document, PDF/A, signature, seal, or legal-validity acceptance
/// is created.
pub async fn create_act_draft_from_accepted_paper_book_ocr_draft(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path((id, draft_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<PaperBookOcrDraftCanonicalDraftResponse>), ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let draft_id = validate_import_id(&draft_id)?;
    let Some(store) = &state.store else {
        return Err(ApiError::Unprocessable(
            "paper-book OCR draft act creation requires on-disk persistence".to_owned(),
        ));
    };
    let draft = store
        .paper_book_ocr_draft(&draft_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    if draft.import_id != import.meta.import_id {
        return Err(ApiError::NotFound);
    }
    ensure_ocr_draft_can_create_act_draft(&draft)?;
    let existing_dossier = store
        .paper_book_ocr_conversion_dossier_for_draft(&import.meta.import_id, &draft.draft_id)
        .map_err(|e| {
            ApiError::Internal(format!(
                "paper-book OCR conversion dossier store read failed: {e}"
            ))
        })?;
    let ocr_text = draft
        .extracted_text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "accepted OCR draft must contain extracted_text; digest-only drafts cannot create act drafts"
                    .to_owned(),
            )
        })?;

    let book_id = BookId(Uuid::parse_str(import.meta.book_ref.trim()).map_err(|_| {
        ApiError::Unprocessable(
            "paper-book import book_ref must be the target open book id to create an act draft"
                .to_owned(),
        )
    })?);
    require_permission(&state, &actor, Permission::ActDraft, scope_of_book(book_id)).await?;
    let created_by = actor.resolve("api");

    // books → acts → ledger.
    let books = state.books.read().await;
    let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
    if !book.is_open() {
        return Err(ApiError::Conflict(format!(
            "book {book_id} is not open; OCR draft act creation is only available for open books"
        )));
    }
    let entity_id = book.entity_id;

    let mut acts = state.acts.write().await;
    let mut ledger = state.ledger.write().await;
    let mut act = Act::draft(
        book_id,
        paper_book_ocr_draft_act_title(&import.meta, &draft),
        MeetingChannel::Physical,
    );
    act.set_deliberations(ocr_text.to_owned())
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    let artifact = build_ocr_conversion_execution_artifact(
        &draft,
        existing_dossier.map(|dossier| dossier.dossier_id),
        act.id.to_string(),
        &created_by,
    );

    let scope = format!("entity:{}/book:{}/act:{}", entity_id, act.book_id, act.id);
    let payload = serde_json::to_vec(&paper_book_ocr_draft_to_act_event_payload(
        &import.meta,
        &draft,
        &act,
        &created_by,
        &artifact,
    ))?;
    crate::try_append_event(
        &mut ledger,
        &created_by,
        &scope,
        "paper_book_import.ocr_draft_act_drafted",
        None,
        &payload,
    )?;
    let act_for_store = act.clone();
    let artifact_for_store = artifact.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.upsert_act(&act_for_store)?;
            tx.upsert_paper_book_ocr_conversion_execution_artifact(&artifact_for_store)?;
            Ok(())
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;

    let response = paper_book_ocr_draft_canonical_draft_response(
        &import.meta,
        &draft,
        ActView::from(&act),
        Some(&artifact),
    );
    acts.insert(act.id, act);
    Ok((StatusCode::CREATED, Json(response)))
}

/// `POST /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier` - create a
/// metadata-only, non-canonical dossier for an accepted OCR draft. This never creates acts,
/// documents, signed documents, archive packages, signatures, seals, PDF/A, or PDF/UA outputs.
pub async fn create_paper_book_ocr_conversion_dossier(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Path((id, draft_id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<PaperBookOcrConversionDossierView>), ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let draft_id = validate_import_id(&draft_id)?;
    let Some(store) = &state.store else {
        return Err(ApiError::Unprocessable(
            "paper-book OCR conversion dossier storage requires on-disk persistence".to_owned(),
        ));
    };
    let draft = store
        .paper_book_ocr_draft(&draft_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    if draft.import_id != import.meta.import_id {
        return Err(ApiError::NotFound);
    }
    ensure_ocr_draft_can_create_conversion_dossier(&draft)?;

    let created_by = actor.resolve("api");
    let dossier = build_ocr_conversion_dossier(&draft, &created_by);
    let mut ledger = state.ledger.write().await;
    let scope = format!("paper-book-import:{}", import.meta.import_id);
    // wp27-e9: offload the durable transaction onto tokio's blocking pool. The closure clones the
    // in-memory ledger to build the projected chain INSIDE the tx (so the append commits atomically
    // with the dossier row); it therefore cannot borrow the `ledger` guard across the
    // `spawn_blocking` boundary — snapshot it first and move the owned snapshot in. `dossier`,
    // `created_by`, `scope` are used only inside the closure, so they are moved (not cloned).
    let ledger_snapshot = (*ledger).clone();
    let (upsert, bound_artifacts, projected_ledger) = store
        .persist_result_blocking_async(move |tx| {
            let upsert = tx.upsert_paper_book_ocr_conversion_dossier(&dossier)?;
            let (bound_artifacts, projected_ledger) = match &upsert {
                PaperBookOcrConversionDossierUpsert::Inserted(stored) => {
                    let bound_artifacts =
                        tx.bind_paper_book_ocr_conversion_execution_artifacts_to_dossier(
                            &stored.import_id,
                            &stored.draft_id,
                            &stored.dossier_id,
                        )?;
                    let payload =
                        serde_json::to_vec(&paper_book_ocr_conversion_dossier_event_payload(
                            stored,
                            &bound_artifacts,
                        ))?;
                    let mut projected = ledger_snapshot;
                    let event = projected.try_append(
                        &created_by,
                        &scope,
                        "paper_book_import.ocr_conversion_dossier_created",
                        None,
                        &payload,
                    )?;
                    tx.append_event(event)?;
                    (bound_artifacts, Some(projected))
                }
                PaperBookOcrConversionDossierUpsert::Existing(_) => (Vec::new(), None),
            };
            Ok((upsert, bound_artifacts, projected_ledger))
        })
        .await
        .map_err(|e| match e {
            StoreError::LedgerAppend(ledger_error) => ApiError::Conflict(format!(
                "appending paper_book_import.ocr_conversion_dossier_created would break a chain: {ledger_error}"
            )),
            StoreError::NotLeader => AppState::not_leader_error(),
            other => ApiError::Internal(format!(
                "failed to persist paper-book OCR conversion dossier to the durable store: {other}"
            )),
        })?;

    match upsert {
        PaperBookOcrConversionDossierUpsert::Inserted(stored) => {
            let Some(projected_ledger) = projected_ledger else {
                return Err(ApiError::Internal(
                    "paper-book OCR conversion dossier insert committed without a ledger projection"
                        .to_owned(),
                ));
            };
            *ledger = projected_ledger;
            state.attest_latest(&attestor, &ledger).await;
            let bound_artifacts = (!bound_artifacts.is_empty()).then_some(bound_artifacts);
            Ok((
                StatusCode::CREATED,
                Json(paper_book_ocr_conversion_dossier_view(
                    &stored,
                    bound_artifacts.as_deref(),
                )),
            ))
        }
        PaperBookOcrConversionDossierUpsert::Existing(stored) => {
            let bound_artifacts = store
                .paper_book_ocr_conversion_execution_artifacts_for_draft(
                    &stored.import_id,
                    &stored.draft_id,
                )
                .map_err(|e| {
                    ApiError::Internal(format!(
                        "paper-book OCR conversion execution artifact store read failed: {e}"
                    ))
                })?;
            let bound_artifacts = (!bound_artifacts.is_empty()).then_some(bound_artifacts);
            Ok((
                StatusCode::OK,
                Json(paper_book_ocr_conversion_dossier_view(
                    &stored,
                    bound_artifacts.as_deref(),
                )),
            ))
        }
    }
}

/// `GET /v1/books/paper-import/{id}/conversion-dossiers` - list metadata-only conversion
/// dossiers for a preserved paper-book import.
pub async fn list_paper_book_ocr_conversion_dossiers(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(id): Path<String>,
) -> Result<Json<Vec<PaperBookOcrConversionDossierView>>, ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let Some(store) = &state.store else {
        return Ok(Json(Vec::new()));
    };
    let rows = store
        .paper_book_ocr_conversion_dossiers(&import.meta.import_id)
        .map_err(|e| {
            ApiError::Internal(format!(
                "paper-book OCR conversion dossier store read failed: {e}"
            ))
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for dossier in &rows {
        let bound_artifacts = store
            .paper_book_ocr_conversion_execution_artifacts_for_draft(
                &dossier.import_id,
                &dossier.draft_id,
            )
            .map_err(|e| {
                ApiError::Internal(format!(
                    "paper-book OCR conversion execution artifact store read failed: {e}"
                ))
            })?;
        let bound_artifacts = (!bound_artifacts.is_empty()).then_some(bound_artifacts);
        out.push(paper_book_ocr_conversion_dossier_view(
            dossier,
            bound_artifacts.as_deref(),
        ));
    }
    Ok(Json(out))
}

/// `GET /v1/books/paper-import/{id}/ocr-canonical-rehearsal` - compute a local readiness report
/// from preserved import, OCR draft, dossier, and mutable-draft artifact metadata. This is
/// read-only and never calls OCR, validators, signing, archive, DGLAB, or legal services.
pub async fn get_paper_book_ocr_canonical_rehearsal(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(id): Path<String>,
) -> Result<Json<PaperBookOcrCanonicalRehearsalReport>, ApiError> {
    let import = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let Some(store) = &state.store else {
        return Err(ApiError::NotFound);
    };

    let drafts = store
        .paper_book_ocr_drafts(&import.meta.import_id)
        .map_err(|e| ApiError::Internal(format!("paper-book OCR draft store read failed: {e}")))?;
    let dossiers = store
        .paper_book_ocr_conversion_dossiers(&import.meta.import_id)
        .map_err(|e| {
            ApiError::Internal(format!(
                "paper-book OCR conversion dossier store read failed: {e}"
            ))
        })?;
    let mut artifacts = Vec::new();
    for draft in &drafts {
        let mut rows = store
            .paper_book_ocr_conversion_execution_artifacts_for_draft(
                &import.meta.import_id,
                &draft.draft_id,
            )
            .map_err(|e| {
                ApiError::Internal(format!(
                    "paper-book OCR conversion execution artifact store read failed: {e}"
                ))
            })?;
        artifacts.append(&mut rows);
    }

    Ok(Json(paper_book_ocr_canonical_rehearsal_report(
        &import.meta,
        &drafts,
        &dossiers,
        &artifacts,
    )))
}

/// `GET /v1/books/paper-import/{id}/bytes` - download the preserved non-canonical package bytes.
pub async fn get_paper_book_import_bytes(
    State(state): State<AppState>,
    actor: CurrentActor,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let stored = load_paper_book_import_for_actor(&state, &actor, &id).await?;
    let filename = paper_book_download_filename(&stored.meta);
    Response::builder()
        .header(header::CONTENT_TYPE, stored.meta.content_type.as_str())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(stored.bytes))
        .map_err(|e| {
            ApiError::Internal(format!("failed to build paper-book package response: {e}"))
        })
}

async fn require_permission_for_report(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<(), ApiError> {
    crate::authz::require_permission(state, actor, Permission::BookImport, Scope::Global).await
}

async fn load_paper_book_import_for_actor(
    state: &AppState,
    actor: &CurrentActor,
    raw_id: &str,
) -> Result<StoredPaperBookImport, ApiError> {
    let id = validate_import_id(raw_id)?;
    require_permission_for_report(state, actor).await?;
    let Some(store) = &state.store else {
        return Err(ApiError::NotFound);
    };
    store
        .paper_book_import(&id)
        .map_err(|e| ApiError::Internal(format!("paper-book import store read failed: {e}")))?
        .ok_or(ApiError::NotFound)
}

async fn update_paper_book_import_ocr_status_internal(
    state: AppState,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    raw_id: &str,
    status: StoredPaperBookOcrStatus,
) -> Result<PaperBookOcrStatusView, ApiError> {
    let id = validate_import_id(raw_id)?;
    require_permission_for_report(&state, &actor).await?;
    if state.store.is_none() {
        return Err(ApiError::Unprocessable(
            "paper-book OCR status updates require on-disk persistence".to_owned(),
        ));
    }
    let store = state.store.as_ref().expect("checked store");
    let current = store
        .paper_book_import(&id)
        .map_err(|e| ApiError::Internal(format!("paper-book import store read failed: {e}")))?
        .ok_or(ApiError::NotFound)?;
    if current.meta.ocr_status == StoredPaperBookOcrStatus::Disabled
        && status == StoredPaperBookOcrStatus::Queued
    {
        return Err(ApiError::Conflict(
            "paper-book OCR status is disabled; set a non-disabled status before enqueueing"
                .to_owned(),
        ));
    }
    let imported_by = actor.resolve("api");
    let payload = serde_json::to_vec(&paper_book_ocr_status_event_payload(
        &current.meta,
        status,
        &imported_by,
    ))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &imported_by,
        &format!("paper-book-import:{id}"),
        "paper_book_import.ocr_status_updated",
        None,
        &payload,
    )?;
    let id_for_store = id.clone();
    state
        .persist_write_through(&mut ledger, 1, move |tx| {
            tx.update_paper_book_import_ocr_status(&id_for_store, status)
        })
        .await?;
    state.attest_latest(&attestor, &ledger).await;
    drop(ledger);

    Ok(PaperBookOcrStatusView {
        import_id: id,
        previous_ocr_status: current.meta.ocr_status.as_str(),
        ocr_status: status.as_str(),
        status_notice: PAPER_BOOK_OCR_STATUS_NOTICE,
        ocr_text_stored: false,
        authoritative_text_claimed: false,
        legal_validity_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    })
}

struct OcrCommandOutput {
    command_exit_success: bool,
    command_exit_code: Option<i32>,
    timed_out: bool,
    failure_reason: Option<&'static str>,
    stdout: Vec<u8>,
    stdout_truncated: bool,
}

struct BoundedStdout {
    bytes: Vec<u8>,
    truncated: bool,
}

async fn execute_ocr_command(
    config: &PaperBookOcrCommandConfig,
    import: &StoredPaperBookImport,
) -> Result<OcrCommandOutput, ApiError> {
    let (temp_dir, input_path) = write_ocr_temp_input(import).await?;
    let output = run_local_ocr_command(config, &input_path).await;
    if let Err(e) = tokio::fs::remove_dir_all(&temp_dir).await {
        eprintln!(
            "paper-book OCR: failed to remove temporary input directory {} ({e})",
            temp_dir.display()
        );
    }
    output
}

async fn write_ocr_temp_input(
    import: &StoredPaperBookImport,
) -> Result<(PathBuf, PathBuf), ApiError> {
    let temp_dir = std::env::temp_dir().join(format!(
        "chancela-paper-ocr-{}-{}",
        import.meta.import_id,
        Uuid::new_v4()
    ));
    tokio::fs::create_dir_all(&temp_dir).await.map_err(|e| {
        ApiError::Internal(format!(
            "failed to create temporary paper-book OCR directory: {e}"
        ))
    })?;
    let input_path = temp_dir.join(format!(
        "paper-book-import-{}.{}",
        import.meta.import_id,
        paper_book_package_extension(&import.meta)
    ));
    if let Err(e) = tokio::fs::write(&input_path, &import.bytes).await {
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        return Err(ApiError::Internal(format!(
            "failed to write temporary paper-book OCR input: {e}"
        )));
    }
    Ok((temp_dir, input_path))
}

async fn run_local_ocr_command(
    config: &PaperBookOcrCommandConfig,
    input_path: &FsPath,
) -> Result<OcrCommandOutput, ApiError> {
    let args = expand_ocr_command_args(config, input_path)?;
    let mut command = Command::new(&config.command_path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return Ok(OcrCommandOutput {
                command_exit_success: false,
                command_exit_code: None,
                timed_out: false,
                failure_reason: Some("spawn_failed"),
                stdout: Vec::new(),
                stdout_truncated: false,
            });
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return Err(ApiError::Internal(
            "failed to capture paper-book OCR command stdout".to_owned(),
        ));
    };
    let read_task = tokio::spawn(read_bounded_stdout(stdout, config.max_stdout_bytes));

    let (command_exit_success, command_exit_code, timed_out, mut failure_reason) =
        match tokio::time::timeout(config.timeout, child.wait()).await {
            Ok(Ok(status)) => (
                status.success(),
                status.code(),
                false,
                (!status.success()).then_some("exit_status"),
            ),
            Ok(Err(_)) => (false, None, false, Some("wait_failed")),
            Err(_) => {
                let _ = child.kill().await;
                (false, None, true, Some("timeout"))
            }
        };

    let stdout = match read_task.await {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(_)) => {
            failure_reason = Some("stdout_read_failed");
            BoundedStdout {
                bytes: Vec::new(),
                truncated: false,
            }
        }
        Err(_) => {
            failure_reason = Some("stdout_read_failed");
            BoundedStdout {
                bytes: Vec::new(),
                truncated: false,
            }
        }
    };

    Ok(OcrCommandOutput {
        command_exit_success,
        command_exit_code,
        timed_out,
        failure_reason,
        stdout: stdout.bytes,
        stdout_truncated: stdout.truncated,
    })
}

async fn read_bounded_stdout(
    mut stdout: ChildStdout,
    max_stdout_bytes: usize,
) -> std::io::Result<BoundedStdout> {
    let mut captured = Vec::with_capacity(max_stdout_bytes.min(8 * 1024));
    let mut total = 0usize;
    let mut buf = [0u8; 8 * 1024];
    loop {
        let read = stdout.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = max_stdout_bytes.saturating_sub(captured.len());
        if remaining > 0 {
            captured.extend_from_slice(&buf[..read.min(remaining)]);
        }
    }
    Ok(BoundedStdout {
        bytes: captured,
        truncated: total > max_stdout_bytes,
    })
}

fn validate_ocr_command_config(config: &PaperBookOcrCommandConfig) -> Result<(), ApiError> {
    if config.command_path.as_os_str().is_empty() {
        return Err(ApiError::Unprocessable(
            "paper-book OCR command path is empty".to_owned(),
        ));
    }
    if config.timeout.is_zero() {
        return Err(ApiError::Unprocessable(
            "paper-book OCR timeout must be greater than zero".to_owned(),
        ));
    }
    if config.timeout > Duration::from_secs(MAX_OCR_TIMEOUT_SECS) {
        return Err(ApiError::Unprocessable(format!(
            "paper-book OCR timeout must be at most {MAX_OCR_TIMEOUT_SECS} seconds"
        )));
    }
    if config.max_stdout_bytes == 0 || config.max_stdout_bytes > MAX_OCR_TEXT_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "paper-book OCR max stdout bytes must be between 1 and {MAX_OCR_TEXT_CHARS}"
        )));
    }
    let template = normalized_ocr_args_template(config);
    if !template
        .iter()
        .any(|arg| arg.contains(DEFAULT_OCR_ARGS_TEMPLATE))
    {
        return Err(ApiError::Unprocessable(
            "paper-book OCR args template must include {input}".to_owned(),
        ));
    }
    let engine_name = required_text(Some(config.engine_name.clone()), "engine_name")?;
    reject_secret_markers("engine_name", &engine_name)?;
    if let Some(version) = optional_text(config.engine_version.clone(), "engine_version")? {
        reject_secret_markers("engine_version", &version)?;
    }
    Ok(())
}

fn normalized_ocr_args_template(config: &PaperBookOcrCommandConfig) -> Vec<String> {
    if config.args_template.is_empty() {
        vec![DEFAULT_OCR_ARGS_TEMPLATE.to_owned()]
    } else {
        config.args_template.clone()
    }
}

fn expand_ocr_command_args(
    config: &PaperBookOcrCommandConfig,
    input_path: &FsPath,
) -> Result<Vec<String>, ApiError> {
    let input = input_path.to_str().ok_or_else(|| {
        ApiError::Internal("temporary paper-book OCR input path is not UTF-8".to_owned())
    })?;
    Ok(normalized_ocr_args_template(config)
        .into_iter()
        .map(|arg| arg.replace(DEFAULT_OCR_ARGS_TEMPLATE, input))
        .collect())
}

fn paper_book_ocr_run_response(
    import_id: &str,
    previous_ocr_status: StoredPaperBookOcrStatus,
    ocr_status: StoredPaperBookOcrStatus,
    config: &PaperBookOcrCommandConfig,
    output: &OcrCommandOutput,
    failure_reason: Option<&'static str>,
    draft: Option<&StoredPaperBookOcrDraft>,
) -> PaperBookOcrRunResponse {
    PaperBookOcrRunResponse {
        import_id: import_id.to_owned(),
        previous_ocr_status: previous_ocr_status.as_str(),
        ocr_status: ocr_status.as_str(),
        command_configured: true,
        command_exit_success: output.command_exit_success,
        command_exit_code: output.command_exit_code,
        timed_out: output.timed_out,
        failure_reason,
        stdout_bytes_captured: output.stdout.len(),
        stdout_truncated: output.stdout_truncated,
        engine: PaperBookOcrEngineView {
            name: config.engine_name.clone(),
            version: config.engine_version.clone(),
        },
        draft: draft.map(paper_book_ocr_draft_view),
        status_notice: PAPER_BOOK_OCR_STATUS_NOTICE,
        draft_notice: PAPER_BOOK_OCR_DRAFT_NOTICE,
        non_canonical: true,
        authoritative_text_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signature_created: false,
        legal_validity_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    }
}

fn paper_book_ocr_canonical_rehearsal_report(
    import: &StoredPaperBookImportMeta,
    drafts: &[StoredPaperBookOcrDraft],
    dossiers: &[StoredPaperBookOcrConversionDossier],
    artifacts: &[StoredPaperBookOcrConversionExecutionArtifact],
) -> PaperBookOcrCanonicalRehearsalReport {
    let selected_draft = drafts.iter().find(|draft| {
        draft.review_status == StoredPaperBookOcrReviewStatus::Accepted
            && draft.superseded_by.is_none()
    });
    let selected_dossier = selected_draft.and_then(|draft| {
        dossiers
            .iter()
            .find(|dossier| dossier.draft_id == draft.draft_id)
    });
    let selected_artifact_count = match (selected_draft, selected_dossier) {
        (Some(draft), Some(dossier)) => artifacts
            .iter()
            .filter(|artifact| artifact_matches_selected_rehearsal_chain(artifact, draft, dossier))
            .count(),
        _ => 0,
    };
    let mutable_draft_act_artifact_present = match (selected_draft, selected_dossier) {
        (Some(draft), Some(dossier)) => artifacts.iter().any(|artifact| {
            artifact.mutable_draft_act_created
                && artifact_matches_selected_rehearsal_chain(artifact, draft, dossier)
        }),
        _ => false,
    };
    let selected_draft_digest_present = selected_draft
        .and_then(|draft| draft.text_digest.as_deref())
        .is_some_and(|digest| !digest.trim().is_empty());
    let selected_draft_page_span_count = selected_draft
        .map(|draft| draft.page_spans.len())
        .unwrap_or(0);
    let selected_draft_page_span_pages = selected_draft
        .map(|draft| paper_book_ocr_page_span_pages(&draft.page_spans))
        .unwrap_or(0);
    let selected_dossier_source_digest_present = selected_dossier
        .and_then(|dossier| dossier.source_text_digest.as_deref())
        .is_some();
    let selected_dossier_page_span_count = selected_dossier
        .map(|dossier| dossier.source_page_spans.len())
        .unwrap_or(0);
    let selected_dossier_page_span_pages = selected_dossier
        .map(|dossier| paper_book_ocr_page_span_pages(&dossier.source_page_spans))
        .unwrap_or(0);

    let mut blockers = Vec::new();
    if selected_draft.is_none() {
        blockers.push(preflight_blocker(
            "accepted_ocr_draft_required",
            "ocr_evidence.selected_accepted_draft_id",
            "local rehearsal requires an accepted OCR draft metadata record",
        ));
    }
    if selected_draft.is_some() && !selected_draft_digest_present {
        blockers.push(preflight_blocker(
            "ocr_text_digest_required",
            "ocr_evidence.selected_accepted_draft_text_digest_present",
            "local rehearsal requires OCR text digest evidence for the accepted draft",
        ));
    }
    if selected_draft.is_some() && selected_draft_page_span_count == 0 {
        blockers.push(preflight_blocker(
            "ocr_page_spans_required",
            "ocr_evidence.selected_accepted_draft_page_span_count",
            "local rehearsal requires page-span metadata for the accepted OCR draft",
        ));
    }
    if selected_draft.is_some() && selected_dossier.is_none() {
        blockers.push(preflight_blocker(
            "metadata_only_conversion_dossier_required",
            "dossier_evidence.selected_dossier_id",
            "local rehearsal requires a metadata-only conversion dossier for the accepted OCR draft",
        ));
    }
    if selected_dossier.is_some() && !selected_dossier_source_digest_present {
        blockers.push(preflight_blocker(
            "dossier_source_digest_required",
            "dossier_evidence.selected_dossier_source_digest_present",
            "local rehearsal requires source digest evidence in the metadata-only dossier",
        ));
    }
    if selected_dossier.is_some() && selected_dossier_page_span_count == 0 {
        blockers.push(preflight_blocker(
            "dossier_page_spans_required",
            "dossier_evidence.selected_dossier_page_span_count",
            "local rehearsal requires source page-span evidence in the metadata-only dossier",
        ));
    }

    let readiness_status = if blockers.is_empty() {
        "local_rehearsal_ready"
    } else {
        "blocked"
    };
    let next_local_action = if blockers.is_empty() {
        Some("retain_report_as_local_readiness_evidence")
    } else {
        Some("resolve_local_evidence_blockers_without_creating_canonical_records")
    };

    PaperBookOcrCanonicalRehearsalReport {
        report_kind: "paper_book_ocr_canonical_rehearsal",
        dry_run: true,
        rehearsal_scope: "local_ocr_canonical_conversion_rehearsal",
        legal_notice: PAPER_BOOK_OCR_CANONICAL_REHEARSAL_NOTICE,
        import_id: import.import_id.clone(),
        source_import: PaperBookOcrCanonicalRehearsalImportEvidence {
            import_present: true,
            preserved_package_present: true,
            book_ref: import.book_ref.clone(),
            ocr_status: import.ocr_status.as_str(),
            page_count: import.page_count,
            source_page_range: PaperBookPageRangeReport {
                from: import.page_from,
                to: import.page_to,
            },
            original_ata_number_range: original_ata_range_from_meta(import),
            package_digest_present: !import.sha256.trim().is_empty(),
            package_size_bytes: import.size_bytes,
            source_filename_present: import.source_filename.is_some(),
            bytes_in_report: false,
            non_canonical: true,
        },
        ocr_evidence: PaperBookOcrCanonicalRehearsalOcrEvidence {
            draft_count: drafts.len(),
            accepted_draft_count: drafts
                .iter()
                .filter(|draft| draft.review_status == StoredPaperBookOcrReviewStatus::Accepted)
                .count(),
            unreviewed_draft_count: drafts
                .iter()
                .filter(|draft| draft.review_status == StoredPaperBookOcrReviewStatus::Unreviewed)
                .count(),
            rejected_draft_count: drafts
                .iter()
                .filter(|draft| draft.review_status == StoredPaperBookOcrReviewStatus::Rejected)
                .count(),
            superseded_draft_count: drafts
                .iter()
                .filter(|draft| draft.review_status == StoredPaperBookOcrReviewStatus::Superseded)
                .count(),
            selected_accepted_draft_id: selected_draft.map(|draft| draft.draft_id.clone()),
            selected_accepted_draft_text_digest_present: selected_draft_digest_present,
            selected_accepted_draft_extracted_text_present: selected_draft
                .and_then(|draft| draft.extracted_text.as_deref())
                .is_some_and(|text| !text.trim().is_empty()),
            selected_accepted_draft_page_span_count: selected_draft_page_span_count,
            selected_accepted_draft_page_span_pages: selected_draft_page_span_pages,
            operator_review_recorded: selected_draft
                .is_some_and(|draft| draft.reviewed_at.is_some() && draft.reviewed_by.is_some()),
            raw_ocr_text_in_report: false,
            confidence_buckets: paper_book_ocr_confidence_buckets(drafts),
        },
        dossier_evidence: PaperBookOcrCanonicalRehearsalDossierEvidence {
            dossier_count: dossiers.len(),
            metadata_only_dossier_present: !dossiers.is_empty(),
            selected_dossier_id: selected_dossier.map(|dossier| dossier.dossier_id.clone()),
            selected_dossier_source_digest_present,
            selected_dossier_page_span_count,
            selected_dossier_page_span_pages,
            bound_execution_artifact_count: artifacts.len(),
            selected_bound_execution_artifact_count: selected_artifact_count,
            mutable_draft_act_artifact_present,
            source_extracted_text_in_response: false,
            source_extracted_text_in_ledger_event: false,
        },
        readiness: PaperBookOcrCanonicalRehearsalReadiness {
            status: readiness_status,
            scope: "local_rehearsal_only",
            evidence_source: "stored_paper_import_ocr_draft_dossier_metadata",
            blockers,
            next_local_action,
        },
        no_claims: paper_book_ocr_canonical_rehearsal_no_claims(),
        required_operator_actions: vec![
            "review_preserved_import_metadata",
            "review_accepted_ocr_draft_metadata",
            "review_metadata_only_conversion_dossier",
            "keep_any_future_canonical_conversion_in_a_separate_workflow",
        ],
        findings: vec![
            PaperBookImportFinding::info(
                "report_only",
                "rehearsal is read-only; no import, draft, dossier, act, document, signature, archive, or ledger record was created",
            ),
            PaperBookImportFinding::info(
                "local_evidence_only",
                "readiness is computed only from stored local metadata and does not claim OCR accuracy or legal acceptance",
            ),
            PaperBookImportFinding::info(
                "no_external_services",
                "report generation did not call OCR providers, validators, signing services, archive certification, DGLAB, or legal services",
            ),
        ],
    }
}

fn artifact_matches_selected_rehearsal_chain(
    artifact: &StoredPaperBookOcrConversionExecutionArtifact,
    draft: &StoredPaperBookOcrDraft,
    dossier: &StoredPaperBookOcrConversionDossier,
) -> bool {
    artifact.draft_id == draft.draft_id
        && artifact.dossier_id.as_deref() == Some(dossier.dossier_id.as_str())
}

fn paper_book_ocr_confidence_buckets(
    drafts: &[StoredPaperBookOcrDraft],
) -> PaperBookOcrCanonicalRehearsalConfidenceBuckets {
    let mut buckets = PaperBookOcrCanonicalRehearsalConfidenceBuckets {
        known_count: 0,
        unknown_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
    };
    for draft in drafts {
        let Some(confidence) = draft.confidence else {
            buckets.unknown_count += 1;
            continue;
        };
        buckets.known_count += 1;
        if confidence >= 0.90 {
            buckets.high_count += 1;
        } else if confidence >= 0.75 {
            buckets.medium_count += 1;
        } else {
            buckets.low_count += 1;
        }
    }
    buckets
}

fn paper_book_ocr_page_span_pages(spans: &[StoredPaperBookOcrPageSpan]) -> u32 {
    spans.iter().fold(0u32, |total, span| {
        total.saturating_add(
            span.end_page
                .saturating_sub(span.start_page)
                .saturating_add(1),
        )
    })
}

fn paper_book_ocr_canonical_rehearsal_no_claims() -> PaperBookOcrCanonicalRehearsalNoClaims {
    PaperBookOcrCanonicalRehearsalNoClaims {
        records_mutated: false,
        external_ocr_called: false,
        external_validator_called: false,
        external_legal_service_called: false,
        canonical_conversion_claimed: false,
        ocr_accuracy_claimed: false,
        legal_review_claimed: false,
        legal_validity_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        sealed_document_created: false,
        signed_document_created: false,
        archive_package_created: false,
        archive_certification_claimed: false,
        pdfa_created: false,
        pdfa_certification_claimed: false,
        pdfua_created: false,
        pdfua_certification_claimed: false,
        signature_created: false,
        signing_requested: false,
        signature_validity_claimed: false,
        qualified_signature_claimed: false,
        dglab_certification_claimed: false,
        raw_ocr_text_in_report: false,
    }
}

fn validate_candidate(
    req: PaperBookImportValidationRequest,
) -> Result<PaperBookImportValidationReport, ApiError> {
    let entity_ref = required_plain_ref(req.entity_ref, "entity_ref")?;
    let entity_name = required_text(req.entity_name, "entity_name")?;
    let entity_nipc = required_text(req.entity_nipc, "entity_nipc")?;
    let book_ref = required_plain_ref(req.book_ref, "book_ref")?;
    let date_from = required_text(req.date_from, "date_from")?;
    let date_to = required_text(req.date_to, "date_to")?;
    let page_count = req
        .page_count
        .ok_or_else(|| ApiError::Unprocessable("page_count is required".to_owned()))?;
    if page_count == 0 {
        return Err(ApiError::Unprocessable(
            "page_count must be greater than zero".to_owned(),
        ));
    }
    let source_page_range = validate_source_page_range(page_count, req.page_from, req.page_to)?;
    let original_ata_number_range = validate_original_ata_number_range(
        req.original_ata_number_from,
        req.original_ata_number_to,
    )?;
    let linking_evidence =
        paper_book_linking_evidence(source_page_range, original_ata_number_range);
    let continuation = paper_book_continuation_recommendation(original_ata_number_range);

    let from = parse_date(&date_from)?;
    let to = parse_date(&date_to)?;
    if from > to {
        return Err(ApiError::Unprocessable(
            "date range is invalid: date_from must be on or before date_to".to_owned(),
        ));
    }
    let today = OffsetDateTime::now_utc().date();
    if to > today {
        return Err(ApiError::Unprocessable(
            "historical paper-book import dates cannot be in the future".to_owned(),
        ));
    }

    let source_filename = optional_plain_ref(req.source_filename, "source_filename")?;
    let digest = optional_digest(req.digest)?;
    let notes = optional_text(req.notes, "notes")?;
    if let Some(notes) = notes.as_ref()
        && notes.chars().count() > MAX_NOTES_CHARS
    {
        return Err(ApiError::Unprocessable(format!(
            "notes must be at most {MAX_NOTES_CHARS} characters"
        )));
    }

    let fields = [
        ("entity_ref", entity_ref.as_str()),
        ("entity_name", entity_name.as_str()),
        ("entity_nipc", entity_nipc.as_str()),
        ("book_ref", book_ref.as_str()),
        ("date_from", date_from.as_str()),
        ("date_to", date_to.as_str()),
    ];
    for (field, value) in fields {
        reject_secret_markers(field, value)?;
    }
    if let Some(value) = source_filename.as_deref() {
        reject_secret_markers("source_filename", value)?;
    }
    if let Some(value) = notes.as_deref() {
        reject_secret_markers("notes", value)?;
    }
    let canonical_conversion_preflight = paper_book_canonical_conversion_preflight(
        req.canonical_conversion_preflight,
        digest.as_deref(),
        source_page_range,
        page_count,
    )?;

    Ok(PaperBookImportValidationReport {
        report_kind: "paper_book_import_validation",
        dry_run: true,
        legal_notice: PAPER_BOOK_IMPORT_NOTICE,
        identity: PaperBookIdentityReport {
            entity_ref,
            entity_name,
            entity_nipc,
            book_ref,
        },
        date_span: PaperBookDateSpanReport {
            from: format_date(from),
            to: format_date(to),
        },
        package: PaperBookPackageReport {
            page_count,
            source_page_range,
            source_filename,
            digest,
            notes_present: notes.is_some(),
            notes_truncated: false,
        },
        linking_evidence,
        continuation,
        canonical_conversion_preflight,
        candidate_classification: PaperBookCandidateClassification {
            classification: "historical_paper_book_non_canonical_evidence",
            non_canonical: true,
            historical_evidence: true,
            preservation_status: "not_preserved_by_validation",
            canonical_minutes_claimed: false,
            legal_validity_claimed: false,
            signature_validity_claimed: false,
            qualified_signature_claimed: false,
        },
        can_accept_as_import_candidate: true,
        required_operator_actions: vec![
            "review_report",
            "confirm_source_page_range",
            "record_original_ata_number_range_before_digital_continuation",
            "preserve_package_in_a_later_operator_action",
            "plan_digital_continuation_without_auto_creating_canonical_records",
        ],
        findings: vec![
            PaperBookImportFinding::info(
                "report_only",
                "validation is read-only; no package, book, act, document, or ledger event was created",
            ),
            PaperBookImportFinding::info(
                "linking_evidence_only",
                "page and original ata-number ranges are planning metadata only and do not create canonical records",
            ),
        ],
    })
}

fn preservation_report(
    validation: PaperBookImportValidationReport,
    meta: &StoredPaperBookImportMeta,
) -> PaperBookImportPreservationReport {
    PaperBookImportPreservationReport {
        report_kind: "paper_book_import_preservation",
        dry_run: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
        import_id: meta.import_id.clone(),
        identity: validation.identity,
        date_span: validation.date_span,
        package: PaperBookPackageReport {
            digest: Some(meta.sha256.clone()),
            ..validation.package
        },
        linking_evidence: paper_book_linking_evidence_from_meta(meta),
        continuation: paper_book_continuation_recommendation(original_ata_range_from_meta(meta)),
        canonical_conversion_preflight: validation.canonical_conversion_preflight,
        preservation: PaperBookPreservationReport {
            status: "preserved_non_canonical_package",
            non_canonical: true,
            sha256: meta.sha256.clone(),
            size_bytes: meta.size_bytes,
            content_type: meta.content_type.clone(),
            imported_at: meta.imported_at.format(&Rfc3339).unwrap_or_default(),
            imported_by: meta.imported_by.clone(),
            ocr_status: meta.ocr_status.as_str(),
            bytes_in_ledger_event: false,
            legal_validity_claimed: false,
        },
        candidate_classification: PaperBookCandidateClassification {
            classification: "historical_paper_book_non_canonical_evidence",
            non_canonical: true,
            historical_evidence: true,
            preservation_status: "preserved_non_canonical_package",
            canonical_minutes_claimed: false,
            legal_validity_claimed: false,
            signature_validity_claimed: false,
            qualified_signature_claimed: false,
        },
        can_accept_as_import_candidate: true,
        required_operator_actions: vec![
            "review_non_canonical_preservation_report",
            "review_linking_evidence_before_any_digital_continuation",
            "perform_ocr_in_a_later_operator_action_if_needed",
            "plan_next_digital_ata_without_auto_creating_canonical_records",
        ],
        findings: vec![
            PaperBookImportFinding::info(
                "preserved_non_canonical",
                "package bytes were preserved outside canonical books, acts, documents, and signatures; the ledger event contains metadata only",
            ),
            PaperBookImportFinding::info(
                "linking_evidence_preserved",
                "source page and original ata-number ranges were preserved as non-canonical planning metadata only",
            ),
        ],
    }
}

fn validate_source_page_range(
    page_count: u32,
    page_from: Option<u32>,
    page_to: Option<u32>,
) -> Result<PaperBookPageRangeReport, ApiError> {
    let from = page_from.unwrap_or(1);
    let to = page_to.unwrap_or(page_count);
    if from == 0 || to == 0 {
        return Err(ApiError::Unprocessable(
            "source page range is 1-based and must be greater than zero".to_owned(),
        ));
    }
    if from > to {
        return Err(ApiError::Unprocessable(
            "source page range is invalid: page_from must be on or before page_to".to_owned(),
        ));
    }
    if to > page_count {
        return Err(ApiError::Unprocessable(format!(
            "source page range page_to {to} exceeds page_count {page_count}"
        )));
    }
    Ok(PaperBookPageRangeReport { from, to })
}

fn validate_original_ata_number_range(
    from: Option<u64>,
    to: Option<u64>,
) -> Result<Option<PaperBookOriginalAtaNumberRangeReport>, ApiError> {
    let (Some(from), Some(to)) = (from, to) else {
        if from.is_some() || to.is_some() {
            return Err(ApiError::Unprocessable(
                "original_ata_number_from and original_ata_number_to must be supplied together"
                    .to_owned(),
            ));
        }
        return Ok(None);
    };
    if from == 0 || to == 0 {
        return Err(ApiError::Unprocessable(
            "original ata-number range values must be greater than zero".to_owned(),
        ));
    }
    if from > to {
        return Err(ApiError::Unprocessable(
            "original ata-number range is invalid: original_ata_number_from must be on or before original_ata_number_to"
                .to_owned(),
        ));
    }
    if from > SQLITE_MAX_INTEGER_U64 || to > SQLITE_MAX_INTEGER_U64 {
        return Err(ApiError::Unprocessable(
            "original ata-number range values are too large to persist".to_owned(),
        ));
    }
    Ok(Some(PaperBookOriginalAtaNumberRangeReport { from, to }))
}

fn paper_book_linking_evidence(
    source_page_range: PaperBookPageRangeReport,
    original_ata_number_range: Option<PaperBookOriginalAtaNumberRangeReport>,
) -> PaperBookLinkingEvidenceReport {
    PaperBookLinkingEvidenceReport {
        source_page_range,
        original_ata_number_range,
        non_canonical: true,
        planning_evidence_only: true,
        canonical_act_created: false,
        canonical_document_created: false,
        signature_created: false,
        legal_acceptance_claimed: false,
    }
}

fn paper_book_linking_evidence_from_meta(
    meta: &StoredPaperBookImportMeta,
) -> PaperBookLinkingEvidenceReport {
    paper_book_linking_evidence(
        PaperBookPageRangeReport {
            from: meta.page_from,
            to: meta.page_to,
        },
        original_ata_range_from_meta(meta),
    )
}

fn original_ata_range_from_meta(
    meta: &StoredPaperBookImportMeta,
) -> Option<PaperBookOriginalAtaNumberRangeReport> {
    match (meta.original_number_from, meta.original_number_to) {
        (Some(from), Some(to)) => Some(PaperBookOriginalAtaNumberRangeReport { from, to }),
        _ => None,
    }
}

fn paper_book_continuation_recommendation(
    original_ata_number_range: Option<PaperBookOriginalAtaNumberRangeReport>,
) -> PaperBookContinuationRecommendation {
    let recommended_next_ata_number =
        original_ata_number_range.and_then(|range| range.to.checked_add(1));
    let (recommendation, recommended_action, action_metadata) =
        if original_ata_number_range.is_some() {
            (
                "continue_after_operator_review_of_original_numbering",
                "prepare_next_digital_ata_using_recommended_next_ata_number",
                vec![
                    "source_page_range",
                    "original_ata_number_range",
                    "recommended_next_ata_number",
                ],
            )
        } else {
            (
                "capture_original_ata_number_range_before_continuation",
                "record_original_ata_number_range_then_plan_next_digital_ata",
                vec!["source_page_range", "original_ata_number_range"],
            )
        };
    PaperBookContinuationRecommendation {
        recommendation,
        recommended_action,
        recommended_next_ata_number,
        action_metadata,
        requires_operator_review: true,
        canonical_act_created: false,
        canonical_document_created: false,
        signature_created: false,
        legal_acceptance_claimed: false,
    }
}

fn paper_book_canonical_conversion_preflight(
    req: Option<PaperBookCanonicalConversionPreflightRequest>,
    candidate_digest: Option<&str>,
    source_page_range: PaperBookPageRangeReport,
    page_count: u32,
) -> Result<PaperBookCanonicalConversionPreflightReport, ApiError> {
    let preflight_requested = req.is_some();
    let req = req.unwrap_or_default();
    let ocr_text_digest = optional_digest(req.ocr_text_digest)?;
    let ocr_text_present = req.ocr_text_present || ocr_text_digest.is_some();
    let candidate_digest_present = candidate_digest.is_some();
    let source_page_range_valid = source_page_range.from > 0
        && source_page_range.to >= source_page_range.from
        && source_page_range.to <= page_count;

    let mut blockers = Vec::new();
    if preflight_requested {
        if !ocr_text_present {
            blockers.push(preflight_blocker(
                "missing_ocr_text",
                "canonical_conversion_preflight.ocr_text_digest",
                "canonical conversion preflight requires OCR text evidence or an OCR text digest",
            ));
        }
        if !req.operator_review_recorded {
            blockers.push(preflight_blocker(
                "missing_operator_review",
                "canonical_conversion_preflight.operator_review_recorded",
                "canonical conversion preflight requires an operator review record",
            ));
        }
        if !candidate_digest_present {
            blockers.push(preflight_blocker(
                "missing_candidate_digest",
                "package.digest",
                "canonical conversion preflight requires a candidate package sha256 digest",
            ));
        }
        if !req.package_fixity_recorded {
            blockers.push(preflight_blocker(
                "package_fixity_not_recorded",
                "canonical_conversion_preflight.package_fixity_recorded",
                "canonical conversion preflight requires recorded package fixity verification",
            ));
        }
        if !source_page_range_valid || !req.page_range_reviewed {
            blockers.push(preflight_blocker(
                "page_range_not_reviewed",
                "canonical_conversion_preflight.page_range_reviewed",
                "canonical conversion preflight requires operator-reviewed source page range evidence",
            ));
        }
        if !req.legal_acceptance_recorded {
            blockers.push(preflight_blocker(
                "legal_acceptance_not_recorded",
                "canonical_conversion_preflight.legal_acceptance_recorded",
                "canonical conversion preflight requires legal acceptance to be recorded separately",
            ));
        }
    }

    let status = if !preflight_requested {
        "not_attempted"
    } else if blockers.is_empty() {
        "allowed"
    } else {
        "blocked"
    };
    let allowed_next_action = if status == "allowed" {
        Some("prepare_canonical_conversion_draft_after_preservation")
    } else {
        None
    };

    Ok(PaperBookCanonicalConversionPreflightReport {
        status,
        preflight_requested,
        scope: "ocr_to_canonical_conversion_preflight",
        evidence_source: if preflight_requested {
            "operator_supplied_preflight_evidence"
        } else {
            "not_supplied"
        },
        evidence: PaperBookCanonicalConversionEvidenceReport {
            ocr_text_present,
            ocr_text_digest,
            operator_review_recorded: req.operator_review_recorded,
            candidate_digest_present,
            package_fixity_recorded: req.package_fixity_recorded,
            source_page_range_valid,
            source_page_range,
            page_range_reviewed: req.page_range_reviewed,
            legal_acceptance_recorded: req.legal_acceptance_recorded,
        },
        blockers,
        allowed_next_action,
        raw_ocr_text_in_report: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signature_created: false,
        signing_requested: false,
        signature_validity_claimed: false,
        qualified_signature_claimed: false,
        legal_validity_claimed: false,
    })
}

fn preflight_blocker(
    code: &'static str,
    field: &'static str,
    message: &'static str,
) -> PaperBookCanonicalConversionBlocker {
    PaperBookCanonicalConversionBlocker {
        code,
        field,
        message,
    }
}

fn parse_ocr_status(raw: &str) -> Result<StoredPaperBookOcrStatus, ApiError> {
    StoredPaperBookOcrStatus::parse(raw.trim()).map_err(|_| {
        ApiError::Unprocessable(
            "ocr status must be one of disabled, not_run, queued, running, completed, or failed"
                .to_owned(),
        )
    })
}

fn parse_ocr_review_status(raw: &str) -> Result<StoredPaperBookOcrReviewStatus, ApiError> {
    StoredPaperBookOcrReviewStatus::parse(raw.trim()).map_err(|_| {
        ApiError::Unprocessable(
            "review_status must be one of unreviewed, accepted, rejected, or superseded".to_owned(),
        )
    })
}

fn build_ocr_draft(
    req: PaperBookOcrDraftCreateRequest,
    import: &StoredPaperBookImportMeta,
    actor: &CurrentActor,
) -> Result<StoredPaperBookOcrDraft, ApiError> {
    let extracted_text =
        optional_limited_ocr_text(req.extracted_text, "extracted_text", MAX_OCR_TEXT_CHARS)?;
    let text_digest = optional_digest(req.text_digest)?;
    if extracted_text.is_none() && text_digest.is_none() {
        return Err(ApiError::Unprocessable(
            "OCR draft requires extracted_text or text_digest".to_owned(),
        ));
    }
    let page_spans = validate_ocr_page_spans(req.page_spans, import.page_count)?;
    let confidence = validate_confidence(req.confidence)?;
    let engine_name = required_text(Some(req.engine_name), "engine_name")?;
    reject_secret_markers("engine_name", &engine_name)?;
    let engine_version = optional_text(req.engine_version, "engine_version")?;
    if let Some(version) = engine_version.as_deref() {
        reject_secret_markers("engine_version", version)?;
    }
    Ok(StoredPaperBookOcrDraft {
        draft_id: Uuid::new_v4().to_string(),
        import_id: import.import_id.clone(),
        extracted_text,
        text_digest,
        page_spans,
        confidence,
        engine_name,
        engine_version,
        created_at: OffsetDateTime::now_utc(),
        created_by: actor.resolve("api"),
        review_status: StoredPaperBookOcrReviewStatus::Unreviewed,
        reviewed_at: None,
        reviewed_by: None,
        review_note: None,
        superseded_by: None,
    })
}

fn ensure_ocr_draft_can_create_act_draft(draft: &StoredPaperBookOcrDraft) -> Result<(), ApiError> {
    match draft.review_status {
        StoredPaperBookOcrReviewStatus::Accepted => {}
        StoredPaperBookOcrReviewStatus::Unreviewed => {
            return Err(ApiError::Conflict(
                "OCR draft must be accepted before creating an act draft".to_owned(),
            ));
        }
        StoredPaperBookOcrReviewStatus::Rejected => {
            return Err(ApiError::Conflict(
                "rejected OCR drafts cannot create act drafts".to_owned(),
            ));
        }
        StoredPaperBookOcrReviewStatus::Superseded => {
            return Err(ApiError::Conflict(
                "superseded OCR drafts cannot create act drafts".to_owned(),
            ));
        }
    }
    if draft.superseded_by.is_some() {
        return Err(ApiError::Conflict(
            "superseded OCR drafts cannot create act drafts".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_ocr_draft_can_create_conversion_dossier(
    draft: &StoredPaperBookOcrDraft,
) -> Result<(), ApiError> {
    match draft.review_status {
        StoredPaperBookOcrReviewStatus::Accepted => {}
        StoredPaperBookOcrReviewStatus::Unreviewed => {
            return Err(ApiError::Conflict(
                "OCR draft must be accepted before creating a conversion dossier".to_owned(),
            ));
        }
        StoredPaperBookOcrReviewStatus::Rejected => {
            return Err(ApiError::Conflict(
                "rejected OCR drafts cannot create conversion dossiers".to_owned(),
            ));
        }
        StoredPaperBookOcrReviewStatus::Superseded => {
            return Err(ApiError::Conflict(
                "superseded OCR drafts cannot create conversion dossiers".to_owned(),
            ));
        }
    }
    if draft.superseded_by.is_some() {
        return Err(ApiError::Conflict(
            "superseded OCR drafts cannot create conversion dossiers".to_owned(),
        ));
    }
    Ok(())
}

fn build_ocr_conversion_dossier(
    draft: &StoredPaperBookOcrDraft,
    created_by: &str,
) -> StoredPaperBookOcrConversionDossier {
    StoredPaperBookOcrConversionDossier {
        dossier_id: Uuid::new_v4().to_string(),
        import_id: draft.import_id.clone(),
        draft_id: draft.draft_id.clone(),
        source_text_digest: ocr_draft_source_text_digest(draft),
        source_page_spans: draft.page_spans.clone(),
        source_review_status: draft.review_status,
        source_reviewed_at: draft.reviewed_at,
        source_reviewed_by: draft.reviewed_by.clone(),
        created_at: OffsetDateTime::now_utc(),
        created_by: created_by.to_owned(),
    }
}

fn build_ocr_conversion_execution_artifact(
    draft: &StoredPaperBookOcrDraft,
    dossier_id: Option<String>,
    target_act_id: String,
    created_by: &str,
) -> StoredPaperBookOcrConversionExecutionArtifact {
    StoredPaperBookOcrConversionExecutionArtifact {
        artifact_id: Uuid::new_v4().to_string(),
        import_id: draft.import_id.clone(),
        draft_id: draft.draft_id.clone(),
        dossier_id,
        source_text_digest: ocr_draft_source_text_digest(draft),
        source_page_spans: draft.page_spans.clone(),
        source_review_status: draft.review_status,
        source_reviewed_at: draft.reviewed_at,
        source_reviewed_by: draft.reviewed_by.clone(),
        target_act_id,
        target_act_state: "Draft".to_owned(),
        mutable_draft_act_created: true,
        created_at: OffsetDateTime::now_utc(),
        created_by: created_by.to_owned(),
        canonical_conversion_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signed_document_created: false,
        archive_package_created: false,
        pdfa_created: false,
        pdfua_created: false,
        signature_created: false,
        seal_created: false,
        archive_certification_claimed: false,
        legal_validity_claimed: false,
        source_extracted_text_in_artifact: false,
        source_extracted_text_in_ledger_event: false,
    }
}

fn ocr_draft_source_text_digest(draft: &StoredPaperBookOcrDraft) -> Option<String> {
    draft.text_digest.clone()
}

fn paper_book_ocr_draft_act_title(
    import: &StoredPaperBookImportMeta,
    draft: &StoredPaperBookOcrDraft,
) -> String {
    let start_page = draft
        .page_spans
        .first()
        .map(|span| span.start_page)
        .unwrap_or(import.page_from);
    let end_page = draft
        .page_spans
        .last()
        .map(|span| span.end_page)
        .unwrap_or(import.page_to);
    format!("Rascunho de ata a partir de OCR do livro em papel (paginas {start_page}-{end_page})")
}

fn validate_ocr_page_spans(
    raw: Vec<PaperBookOcrDraftPageSpanRequest>,
    page_count: u32,
) -> Result<Vec<StoredPaperBookOcrPageSpan>, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::Unprocessable(
            "OCR draft page_spans must not be empty".to_owned(),
        ));
    }
    let mut spans = Vec::with_capacity(raw.len());
    for span in raw {
        if span.start_page == 0 || span.end_page == 0 {
            return Err(ApiError::Unprocessable(
                "OCR draft page spans are 1-based and must be greater than zero".to_owned(),
            ));
        }
        if span.start_page > span.end_page {
            return Err(ApiError::Unprocessable(
                "OCR draft page span start_page must be on or before end_page".to_owned(),
            ));
        }
        if span.end_page > page_count {
            return Err(ApiError::Unprocessable(format!(
                "OCR draft page span end_page {} exceeds preserved package page_count {}",
                span.end_page, page_count
            )));
        }
        spans.push(StoredPaperBookOcrPageSpan {
            start_page: span.start_page,
            end_page: span.end_page,
        });
    }
    Ok(spans)
}

fn validate_confidence(confidence: Option<f64>) -> Result<Option<f64>, ApiError> {
    if let Some(value) = confidence
        && (!value.is_finite() || !(0.0..=1.0).contains(&value))
    {
        return Err(ApiError::Unprocessable(
            "OCR draft confidence must be between 0 and 1".to_owned(),
        ));
    }
    Ok(confidence)
}

fn paper_book_import_event_payload(meta: &StoredPaperBookImportMeta) -> serde_json::Value {
    json!({
        "import_id": meta.import_id,
        "entity_ref": meta.entity_ref,
        "entity_name": meta.entity_name,
        "entity_nipc": meta.entity_nipc,
        "book_ref": meta.book_ref,
        "date_from": format_date(meta.date_from),
        "date_to": format_date(meta.date_to),
        "page_count": meta.page_count,
        "page_from": meta.page_from,
        "page_to": meta.page_to,
        "original_ata_number_from": meta.original_number_from,
        "original_ata_number_to": meta.original_number_to,
        "linking_evidence": paper_book_linking_evidence_from_meta(meta),
        "continuation": paper_book_continuation_recommendation(original_ata_range_from_meta(meta)),
        "sha256": meta.sha256,
        "size_bytes": meta.size_bytes,
        "content_type": meta.content_type,
        "source_filename": meta.source_filename,
        "notes_present": meta.notes.is_some(),
        "imported_at": meta.imported_at.format(&Rfc3339).unwrap_or_default(),
        "imported_by": meta.imported_by,
        "ocr_status": meta.ocr_status.as_str(),
        "bytes_in_payload": false,
        "non_canonical": true,
        "historical_evidence": true,
        "canonical_minutes_claimed": false,
        "legal_validity_claimed": false,
        "signature_validity_claimed": false,
        "qualified_signature_claimed": false,
    })
}

fn paper_book_ocr_draft_event_payload(
    draft: &StoredPaperBookOcrDraft,
    action: &'static str,
) -> serde_json::Value {
    json!({
        "action": action,
        "draft_id": draft.draft_id,
        "import_id": draft.import_id,
        "text_digest": draft.text_digest,
        "extracted_text_stored": draft.extracted_text.is_some(),
        "extracted_text_in_payload": false,
        "page_spans": draft.page_spans.iter().map(|span| json!({
            "start_page": span.start_page,
            "end_page": span.end_page,
        })).collect::<Vec<_>>(),
        "confidence": draft.confidence,
        "engine_name": draft.engine_name,
        "engine_version": draft.engine_version,
        "created_at": draft.created_at.format(&Rfc3339).unwrap_or_default(),
        "created_by": draft.created_by,
        "review_status": draft.review_status.as_str(),
        "draft_notice": PAPER_BOOK_OCR_DRAFT_NOTICE,
        "non_canonical": true,
        "authoritative_text_claimed": false,
        "canonical_minutes_claimed": false,
        "canonical_act_created": false,
        "canonical_document_created": false,
        "signature_created": false,
        "legal_validity_claimed": false,
    })
}

fn paper_book_ocr_draft_review_event_payload(
    draft: &StoredPaperBookOcrDraft,
    status: StoredPaperBookOcrReviewStatus,
    reviewed_by: &str,
    superseded_by: Option<&str>,
) -> serde_json::Value {
    json!({
        "draft_id": draft.draft_id,
        "import_id": draft.import_id,
        "previous_review_status": draft.review_status.as_str(),
        "review_status": status.as_str(),
        "reviewed_by": reviewed_by,
        "superseded_by": superseded_by,
        "extracted_text_in_payload": false,
        "review_note_in_payload": false,
        "draft_notice": PAPER_BOOK_OCR_DRAFT_NOTICE,
        "non_canonical": true,
        "authoritative_text_claimed": false,
        "canonical_minutes_claimed": false,
        "canonical_act_created": false,
        "canonical_document_created": false,
        "signature_created": false,
        "legal_validity_claimed": false,
    })
}

fn paper_book_ocr_draft_to_act_event_payload(
    import: &StoredPaperBookImportMeta,
    draft: &StoredPaperBookOcrDraft,
    act: &Act,
    created_by: &str,
    artifact: &StoredPaperBookOcrConversionExecutionArtifact,
) -> serde_json::Value {
    json!({
        "import_id": import.import_id,
        "draft_id": draft.draft_id,
        "book_id": act.book_id.to_string(),
        "act_id": act.id.to_string(),
        "created_by": created_by,
        "source_review_status": draft.review_status.as_str(),
        "source_reviewed_at": draft.reviewed_at.map(|t| t.format(&Rfc3339).unwrap_or_default()),
        "source_reviewed_by": draft.reviewed_by.clone(),
        "source_text_digest": ocr_draft_source_text_digest(draft),
        "source_extracted_text_present": draft.extracted_text.is_some(),
        "source_extracted_text_in_payload": false,
        "ocr_text_copied_to_deliberations": true,
        "act_state": "Draft",
        "draft_act_created": true,
        "conversion_execution_artifact": paper_book_ocr_conversion_execution_artifact_event_payload(artifact),
        "notice": PAPER_BOOK_OCR_DRAFT_TO_ACT_NOTICE,
        "non_canonical": true,
        "authoritative_text_claimed": false,
        "canonical_conversion_claimed": false,
        "canonical_minutes_claimed": false,
        "canonical_act_created": false,
        "canonical_document_created": false,
        "signed_document_created": false,
        "archive_package_created": false,
        "archive_certification_claimed": false,
        "pdfa_created": false,
        "pdfua_created": false,
        "signature_created": false,
        "seal_created": false,
        "legal_validity_claimed": false,
    })
}

fn paper_book_ocr_conversion_execution_artifact_event_payload(
    artifact: &StoredPaperBookOcrConversionExecutionArtifact,
) -> serde_json::Value {
    json!({
        "artifact_id": artifact.artifact_id,
        "import_id": artifact.import_id,
        "draft_id": artifact.draft_id,
        "dossier_id": artifact.dossier_id,
        "source_text_digest": artifact.source_text_digest,
        "source_page_spans": artifact.source_page_spans.iter().map(|span| json!({
            "start_page": span.start_page,
            "end_page": span.end_page,
        })).collect::<Vec<_>>(),
        "source_review_status": artifact.source_review_status.as_str(),
        "source_reviewed_at": artifact.source_reviewed_at.map(|t| t.format(&Rfc3339).unwrap_or_default()),
        "source_reviewed_by": artifact.source_reviewed_by,
        "target_act_id": artifact.target_act_id,
        "target_act_state": artifact.target_act_state,
        "mutable_draft_act_created": artifact.mutable_draft_act_created,
        "created_at": artifact.created_at.format(&Rfc3339).unwrap_or_default(),
        "created_by": artifact.created_by,
        "artifact_notice": PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACT_NOTICE,
        "reviewed_conversion_execution_artifact": true,
        "non_canonical": true,
        "canonical_conversion_claimed": artifact.canonical_conversion_claimed,
        "canonical_minutes_claimed": artifact.canonical_minutes_claimed,
        "canonical_act_created": artifact.canonical_act_created,
        "canonical_document_created": artifact.canonical_document_created,
        "signed_document_created": artifact.signed_document_created,
        "archive_package_created": artifact.archive_package_created,
        "archive_certification_claimed": artifact.archive_certification_claimed,
        "pdfa_created": artifact.pdfa_created,
        "pdfua_created": artifact.pdfua_created,
        "signature_created": artifact.signature_created,
        "seal_created": artifact.seal_created,
        "legal_validity_claimed": artifact.legal_validity_claimed,
        "source_extracted_text_in_artifact": artifact.source_extracted_text_in_artifact,
        "source_extracted_text_in_ledger_event": artifact.source_extracted_text_in_ledger_event,
    })
}

fn paper_book_ocr_conversion_dossier_event_payload(
    dossier: &StoredPaperBookOcrConversionDossier,
    bound_artifacts: &[StoredPaperBookOcrConversionExecutionArtifact],
) -> serde_json::Value {
    json!({
        "dossier_id": dossier.dossier_id,
        "import_id": dossier.import_id,
        "draft_id": dossier.draft_id,
        "bound_conversion_execution_artifacts": bound_artifacts.iter().map(
            paper_book_ocr_conversion_execution_artifact_event_payload
        ).collect::<Vec<_>>(),
        "source_text_digest": dossier.source_text_digest,
        "source_page_spans": dossier.source_page_spans.iter().map(|span| json!({
            "start_page": span.start_page,
            "end_page": span.end_page,
        })).collect::<Vec<_>>(),
        "source_review_status": dossier.source_review_status.as_str(),
        "source_reviewed_at": dossier.source_reviewed_at.map(|t| t.format(&Rfc3339).unwrap_or_default()),
        "source_reviewed_by": dossier.source_reviewed_by,
        "created_at": dossier.created_at.format(&Rfc3339).unwrap_or_default(),
        "created_by": dossier.created_by,
        "dossier_notice": PAPER_BOOK_OCR_CONVERSION_DOSSIER_NOTICE,
        "metadata_only": true,
        "non_canonical": true,
        "act_created": false,
        "canonical_act_created": false,
        "canonical_minutes_claimed": false,
        "canonical_document_created": false,
        "signed_document_created": false,
        "archive_package_created": false,
        "archive_certification_claimed": false,
        "pdfa_created": false,
        "pdfua_created": false,
        "signature_created": false,
        "seal_created": false,
        "legal_validity_claimed": false,
        "source_extracted_text_in_response": false,
        "source_extracted_text_in_ledger_event": false,
    })
}

fn paper_book_ocr_status_event_payload(
    meta: &StoredPaperBookImportMeta,
    status: StoredPaperBookOcrStatus,
    updated_by: &str,
) -> serde_json::Value {
    json!({
        "import_id": meta.import_id,
        "previous_ocr_status": meta.ocr_status.as_str(),
        "ocr_status": status.as_str(),
        "updated_by": updated_by,
        "status_notice": PAPER_BOOK_OCR_STATUS_NOTICE,
        "ocr_text_stored": false,
        "authoritative_text_claimed": false,
        "bytes_in_payload": false,
        "non_canonical": true,
        "legal_validity_claimed": false,
        "signature_validity_claimed": false,
        "qualified_signature_claimed": false,
    })
}

fn paper_book_import_view(meta: &StoredPaperBookImportMeta) -> PaperBookImportView {
    PaperBookImportView {
        import_id: meta.import_id.clone(),
        entity_ref: meta.entity_ref.clone(),
        entity_name: meta.entity_name.clone(),
        entity_nipc: meta.entity_nipc.clone(),
        book_ref: meta.book_ref.clone(),
        date_from: format_date(meta.date_from),
        date_to: format_date(meta.date_to),
        page_count: meta.page_count,
        page_from: meta.page_from,
        page_to: meta.page_to,
        original_ata_number_from: meta.original_number_from,
        original_ata_number_to: meta.original_number_to,
        linking_evidence: paper_book_linking_evidence_from_meta(meta),
        continuation: paper_book_continuation_recommendation(original_ata_range_from_meta(meta)),
        sha256: meta.sha256.clone(),
        size_bytes: meta.size_bytes,
        content_type: meta.content_type.clone(),
        source_filename: meta.source_filename.clone(),
        notes: meta.notes.clone(),
        imported_at: meta.imported_at.format(&Rfc3339).unwrap_or_default(),
        imported_by: meta.imported_by.clone(),
        ocr_status: meta.ocr_status.as_str(),
        ocr_status_notice: PAPER_BOOK_OCR_STATUS_NOTICE,
        ocr_text_stored: false,
        authoritative_text_claimed: false,
        non_canonical: true,
        legal_validity_claimed: false,
        signature_validity_claimed: false,
        qualified_signature_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
        bytes_download: format!("/v1/books/paper-import/{}/bytes", meta.import_id),
    }
}

fn paper_book_ocr_draft_canonical_draft_response(
    import: &StoredPaperBookImportMeta,
    draft: &StoredPaperBookOcrDraft,
    act: ActView,
    artifact: Option<&StoredPaperBookOcrConversionExecutionArtifact>,
) -> PaperBookOcrDraftCanonicalDraftResponse {
    PaperBookOcrDraftCanonicalDraftResponse {
        import_id: import.import_id.clone(),
        draft_id: draft.draft_id.clone(),
        act,
        conversion_execution_artifact: artifact
            .map(paper_book_ocr_conversion_execution_artifact_view),
        draft_act_created: true,
        act_state: "Draft",
        notice: PAPER_BOOK_OCR_DRAFT_TO_ACT_NOTICE,
        ocr_text_copied_to_deliberations: true,
        ocr_text_in_ledger_event: false,
        non_canonical: true,
        authoritative_text_claimed: false,
        canonical_conversion_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signed_document_created: false,
        archive_package_created: false,
        archive_certification_claimed: false,
        pdfa_created: false,
        pdfua_created: false,
        signature_created: false,
        seal_created: false,
        legal_validity_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    }
}

fn paper_book_ocr_conversion_execution_artifact_view(
    artifact: &StoredPaperBookOcrConversionExecutionArtifact,
) -> PaperBookOcrConversionExecutionArtifactView {
    PaperBookOcrConversionExecutionArtifactView {
        artifact_id: artifact.artifact_id.clone(),
        import_id: artifact.import_id.clone(),
        draft_id: artifact.draft_id.clone(),
        dossier_id: artifact.dossier_id.clone(),
        source_text_digest: artifact.source_text_digest.clone(),
        source_page_spans: artifact
            .source_page_spans
            .iter()
            .map(|span| PaperBookOcrDraftPageSpanView {
                start_page: span.start_page,
                end_page: span.end_page,
            })
            .collect(),
        source_review_status: artifact.source_review_status.as_str(),
        source_reviewed_at: artifact
            .source_reviewed_at
            .map(|t| t.format(&Rfc3339).unwrap_or_default()),
        source_reviewed_by: artifact.source_reviewed_by.clone(),
        target_act_id: artifact.target_act_id.clone(),
        target_act_state: artifact.target_act_state.clone(),
        mutable_draft_act_created: artifact.mutable_draft_act_created,
        created_at: artifact.created_at.format(&Rfc3339).unwrap_or_default(),
        created_by: artifact.created_by.clone(),
        artifact_notice: PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACT_NOTICE,
        reviewed_conversion_execution_artifact: true,
        non_canonical: true,
        canonical_conversion_claimed: artifact.canonical_conversion_claimed,
        canonical_minutes_claimed: artifact.canonical_minutes_claimed,
        canonical_act_created: artifact.canonical_act_created,
        canonical_document_created: artifact.canonical_document_created,
        signed_document_created: artifact.signed_document_created,
        archive_package_created: artifact.archive_package_created,
        archive_certification_claimed: artifact.archive_certification_claimed,
        pdfa_created: artifact.pdfa_created,
        pdfua_created: artifact.pdfua_created,
        signature_created: artifact.signature_created,
        seal_created: artifact.seal_created,
        legal_validity_claimed: artifact.legal_validity_claimed,
        source_extracted_text_in_artifact: artifact.source_extracted_text_in_artifact,
        source_extracted_text_in_ledger_event: artifact.source_extracted_text_in_ledger_event,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    }
}

fn paper_book_ocr_conversion_dossier_view(
    dossier: &StoredPaperBookOcrConversionDossier,
    bound_artifacts: Option<&[StoredPaperBookOcrConversionExecutionArtifact]>,
) -> PaperBookOcrConversionDossierView {
    PaperBookOcrConversionDossierView {
        dossier_id: dossier.dossier_id.clone(),
        import_id: dossier.import_id.clone(),
        draft_id: dossier.draft_id.clone(),
        conversion_execution_artifacts: bound_artifacts.map(|artifacts| {
            artifacts
                .iter()
                .map(paper_book_ocr_conversion_execution_artifact_view)
                .collect()
        }),
        source_text_digest: dossier.source_text_digest.clone(),
        source_page_spans: dossier
            .source_page_spans
            .iter()
            .map(|span| PaperBookOcrDraftPageSpanView {
                start_page: span.start_page,
                end_page: span.end_page,
            })
            .collect(),
        source_review_status: dossier.source_review_status.as_str(),
        source_reviewed_at: dossier
            .source_reviewed_at
            .map(|t| t.format(&Rfc3339).unwrap_or_default()),
        source_reviewed_by: dossier.source_reviewed_by.clone(),
        created_at: dossier.created_at.format(&Rfc3339).unwrap_or_default(),
        created_by: dossier.created_by.clone(),
        dossier_notice: PAPER_BOOK_OCR_CONVERSION_DOSSIER_NOTICE,
        metadata_only: true,
        non_canonical: true,
        act_created: false,
        canonical_act_created: false,
        canonical_minutes_claimed: false,
        canonical_document_created: false,
        signed_document_created: false,
        archive_package_created: false,
        archive_certification_claimed: false,
        pdfa_created: false,
        pdfua_created: false,
        signature_created: false,
        seal_created: false,
        legal_validity_claimed: false,
        source_extracted_text_in_response: false,
        source_extracted_text_in_ledger_event: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    }
}

fn paper_book_ocr_draft_view(draft: &StoredPaperBookOcrDraft) -> PaperBookOcrDraftView {
    PaperBookOcrDraftView {
        draft_id: draft.draft_id.clone(),
        import_id: draft.import_id.clone(),
        extracted_text: draft.extracted_text.clone(),
        text_digest: draft.text_digest.clone(),
        page_spans: draft
            .page_spans
            .iter()
            .map(|span| PaperBookOcrDraftPageSpanView {
                start_page: span.start_page,
                end_page: span.end_page,
            })
            .collect(),
        confidence: draft.confidence,
        engine: PaperBookOcrEngineView {
            name: draft.engine_name.clone(),
            version: draft.engine_version.clone(),
        },
        created_at: draft.created_at.format(&Rfc3339).unwrap_or_default(),
        created_by: draft.created_by.clone(),
        review_status: draft.review_status.as_str(),
        reviewed_at: draft
            .reviewed_at
            .map(|t| t.format(&Rfc3339).unwrap_or_default()),
        reviewed_by: draft.reviewed_by.clone(),
        review_note: draft.review_note.clone(),
        superseded_by: draft.superseded_by.clone(),
        draft_notice: PAPER_BOOK_OCR_DRAFT_NOTICE,
        non_canonical: true,
        authoritative_text_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signature_created: false,
        legal_validity_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
    }
}

fn validate_import_id(raw: &str) -> Result<String, ApiError> {
    let id = raw.trim();
    if id.is_empty() || looks_path_like(id) {
        return Err(ApiError::Unprocessable(
            "invalid paper-book import id".to_owned(),
        ));
    }
    Uuid::parse_str(id)
        .map_err(|_| ApiError::Unprocessable("invalid paper-book import id".to_owned()))?;
    Ok(id.to_owned())
}

fn paper_book_download_filename(meta: &StoredPaperBookImportMeta) -> String {
    if let Some(filename) = meta.source_filename.as_deref() {
        return filename.to_owned();
    }
    format!(
        "paper-book-import-{}.{}",
        meta.import_id,
        paper_book_package_extension(meta)
    )
}

fn paper_book_package_extension(meta: &StoredPaperBookImportMeta) -> &'static str {
    match meta
        .content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        _ => "bin",
    }
}

fn verify_package_fixity(
    bytes: &[u8],
    declared_size: usize,
    declared_sha256: &str,
) -> Result<(), ApiError> {
    if bytes.is_empty() {
        return Err(ApiError::Unprocessable(
            "paper-book package body is empty".to_owned(),
        ));
    }
    if bytes.len() > PAPER_BOOK_IMPORT_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "paper-book package is {} bytes; preservation accepts at most {} bytes",
            bytes.len(),
            PAPER_BOOK_IMPORT_MAX_BYTES
        )));
    }
    if bytes.len() != declared_size {
        return Err(ApiError::Unprocessable(format!(
            "declared size_bytes {declared_size} does not match decoded package size {}",
            bytes.len()
        )));
    }
    let actual_digest: [u8; 32] = Sha256::digest(bytes).into();
    let actual = crate::hex::hex(&actual_digest);
    if actual != declared_sha256 {
        return Err(ApiError::Unprocessable(
            "declared sha256 does not match decoded paper-book package bytes".to_owned(),
        ));
    }
    Ok(())
}

fn required_text(value: Option<String>, field: &'static str) -> Result<String, ApiError> {
    let Some(value) = optional_text(value, field)? else {
        return Err(ApiError::Unprocessable(format!("{field} is required")));
    };
    Ok(value)
}

fn required_plain_ref(value: Option<String>, field: &'static str) -> Result<String, ApiError> {
    let Some(value) = optional_plain_ref(value, field)? else {
        return Err(ApiError::Unprocessable(format!("{field} is required")));
    };
    Ok(value)
}

fn optional_text(value: Option<String>, field: &'static str) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().any(char::is_control) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn optional_limited_text(
    value: Option<String>,
    field: &'static str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = optional_text(value, field)? else {
        return Ok(None);
    };
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    Ok(Some(value))
}

fn optional_limited_ocr_text(
    value: Option<String>,
    field: &'static str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::Unprocessable(format!(
            "{field} must not contain control characters other than tabs or line breaks"
        )));
    }
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn optional_uuid_ref(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, ApiError> {
    let Some(value) = optional_plain_ref(value, field)? else {
        return Ok(None);
    };
    Uuid::parse_str(&value)
        .map_err(|_| ApiError::Unprocessable(format!("{field} must be a UUID")))?;
    Ok(Some(value))
}

fn optional_plain_ref(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, ApiError> {
    let Some(value) = optional_text(value, field)? else {
        return Ok(None);
    };
    if looks_path_like(&value) {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be a plain identifier or file name, not a path"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn optional_digest(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = optional_text(value, "digest")? else {
        return Ok(None);
    };
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::Unprocessable(
            "digest must be a 64-character sha256 hex value".to_owned(),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn required_content_type(value: String) -> Result<String, ApiError> {
    let Some(value) = optional_text(Some(value), "content_type")? else {
        return Err(ApiError::Unprocessable(
            "content_type is required".to_owned(),
        ));
    };
    if value.len() > 255 {
        return Err(ApiError::Unprocessable(
            "content_type must be at most 255 characters".to_owned(),
        ));
    }
    reject_secret_markers("content_type", &value)?;
    let base = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let allowed = matches!(
        base.as_str(),
        "application/pdf" | "application/zip" | "application/octet-stream"
    );
    if !allowed {
        return Err(ApiError::Unprocessable(
            "content_type must be application/pdf, application/zip, or application/octet-stream"
                .to_owned(),
        ));
    }
    Ok(value)
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

fn reject_secret_markers(field: &'static str, value: &str) -> Result<(), ApiError> {
    let marker = secret_marker(value);
    if let Some(marker) = marker {
        return Err(ApiError::Unprocessable(format!(
            "{field} contains a prohibited secret/access-code marker ({marker})"
        )));
    }
    Ok(())
}

fn secret_marker(value: &str) -> Option<&'static str> {
    let lower = value.to_lowercase();
    let compact = lower.replace([' ', '_'], "-");
    let markers = [
        ("access-code", "access-code"),
        ("codigo-de-acesso", "codigo-de-acesso"),
        ("código-de-acesso", "código-de-acesso"),
        ("password", "password"),
        ("senha", "senha"),
        ("api-key", "api-key"),
        ("bearer-token", "bearer-token"),
        ("secret=", "secret"),
        ("secret:", "secret"),
    ];
    markers
        .iter()
        .find(|(needle, _)| compact.contains(*needle))
        .map(|(_, label)| *label)
}

fn env_text(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

fn parse_args_template_env(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return vec![DEFAULT_OCR_ARGS_TEMPLATE.to_owned()];
    }
    if raw.starts_with('[')
        && let Ok(args) = serde_json::from_str::<Vec<String>>(raw)
    {
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.trim().to_owned())
            .filter(|arg| !arg.is_empty())
            .collect();
        if !args.is_empty() {
            return args;
        }
    }
    raw.split_whitespace().map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> PaperBookImportValidationRequest {
        PaperBookImportValidationRequest {
            entity_ref: Some("entity-legacy-001".to_owned()),
            entity_name: Some("Encosto Estrategico, S.A.".to_owned()),
            entity_nipc: Some("503004642".to_owned()),
            book_ref: Some("ag-book-1968-1971".to_owned()),
            date_from: Some("1968-01-01".to_owned()),
            date_to: Some("1971-12-31".to_owned()),
            page_count: Some(240),
            page_from: Some(1),
            page_to: Some(48),
            original_ata_number_from: Some(101),
            original_ata_number_to: Some(119),
            source_filename: Some("ag-1968-1971.pdf".to_owned()),
            digest: Some("AB".repeat(32)),
            notes: Some("Scanned from bound paper minute book.".to_owned()),
            canonical_conversion_preflight: None,
        }
    }

    fn sample_ocr_draft() -> StoredPaperBookOcrDraft {
        StoredPaperBookOcrDraft {
            draft_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            import_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            extracted_text: Some(
                "Actual OCR text that must stay out of audit payloads.".to_owned(),
            ),
            text_digest: Some("ab".repeat(32)),
            page_spans: vec![StoredPaperBookOcrPageSpan {
                start_page: 1,
                end_page: 2,
            }],
            confidence: Some(0.87),
            engine_name: "fixture-ocr".to_owned(),
            engine_version: Some("0.1.0".to_owned()),
            created_at: OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap(),
            created_by: "rui.secretario".to_owned(),
            review_status: StoredPaperBookOcrReviewStatus::Unreviewed,
            reviewed_at: None,
            reviewed_by: None,
            review_note: None,
            superseded_by: None,
        }
    }

    #[test]
    fn validation_normalizes_digest_and_stays_non_canonical() {
        let report = validate_candidate(base_request()).expect("valid report");
        let expected = "ab".repeat(32);
        assert_eq!(report.package.digest.as_deref(), Some(expected.as_str()));
        assert_eq!(report.package.source_page_range.from, 1);
        assert_eq!(report.package.source_page_range.to, 48);
        assert_eq!(
            report.linking_evidence.original_ata_number_range,
            Some(PaperBookOriginalAtaNumberRangeReport { from: 101, to: 119 })
        );
        assert_eq!(report.continuation.recommended_next_ata_number, Some(120));
        assert!(report.candidate_classification.non_canonical);
        assert!(!report.candidate_classification.qualified_signature_claimed);
        assert!(!report.candidate_classification.canonical_minutes_claimed);
        assert_eq!(
            report.canonical_conversion_preflight.status,
            "not_attempted"
        );
        assert!(report.canonical_conversion_preflight.blockers.is_empty());
        assert!(
            report
                .canonical_conversion_preflight
                .evidence
                .candidate_digest_present
        );
        assert!(!report.canonical_conversion_preflight.canonical_act_created);
        assert!(
            !report
                .canonical_conversion_preflight
                .canonical_document_created
        );
        assert!(!report.canonical_conversion_preflight.signature_created);
        assert!(!report.canonical_conversion_preflight.signing_requested);
    }

    #[test]
    fn canonical_conversion_preflight_is_bounded_and_conservative() {
        let mut blocked = base_request();
        blocked.digest = None;
        blocked.canonical_conversion_preflight =
            Some(PaperBookCanonicalConversionPreflightRequest::default());
        let report = validate_candidate(blocked).expect("blocked preflight report");

        assert_eq!(report.canonical_conversion_preflight.status, "blocked");
        assert!(
            report
                .canonical_conversion_preflight
                .blockers
                .iter()
                .any(|blocker| blocker.code == "missing_ocr_text")
        );
        assert!(
            report
                .canonical_conversion_preflight
                .blockers
                .iter()
                .any(|blocker| blocker.code == "missing_candidate_digest")
        );
        assert!(
            report
                .canonical_conversion_preflight
                .blockers
                .iter()
                .any(|blocker| blocker.code == "legal_acceptance_not_recorded")
        );
        assert!(!report.canonical_conversion_preflight.canonical_act_created);
        assert!(
            !report
                .canonical_conversion_preflight
                .canonical_document_created
        );
        assert!(!report.canonical_conversion_preflight.signature_created);
        assert!(
            !report
                .canonical_conversion_preflight
                .qualified_signature_claimed
        );

        let mut allowed = base_request();
        allowed.canonical_conversion_preflight =
            Some(PaperBookCanonicalConversionPreflightRequest {
                ocr_text_present: false,
                ocr_text_digest: Some("CD".repeat(32)),
                operator_review_recorded: true,
                package_fixity_recorded: true,
                page_range_reviewed: true,
                legal_acceptance_recorded: true,
            });
        let report = validate_candidate(allowed).expect("allowed preflight report");

        assert_eq!(report.canonical_conversion_preflight.status, "allowed");
        assert!(report.canonical_conversion_preflight.blockers.is_empty());
        assert_eq!(
            report
                .canonical_conversion_preflight
                .evidence
                .ocr_text_digest
                .as_deref(),
            Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
        assert!(!report.canonical_conversion_preflight.canonical_act_created);
        assert!(
            !report
                .canonical_conversion_preflight
                .canonical_document_created
        );
        assert!(!report.canonical_conversion_preflight.signature_created);
        assert!(
            !report
                .canonical_conversion_preflight
                .signature_validity_claimed
        );
        assert!(
            !report
                .canonical_conversion_preflight
                .qualified_signature_claimed
        );
    }

    #[test]
    fn validation_defaults_source_page_range_and_requests_numbering_before_continuation() {
        let mut req = base_request();
        req.page_from = None;
        req.page_to = None;
        req.original_ata_number_from = None;
        req.original_ata_number_to = None;

        let report = validate_candidate(req).expect("valid report");

        assert_eq!(report.package.source_page_range.from, 1);
        assert_eq!(report.package.source_page_range.to, 240);
        assert_eq!(report.linking_evidence.original_ata_number_range, None);
        assert_eq!(
            report.continuation.recommendation,
            "capture_original_ata_number_range_before_continuation"
        );
        assert_eq!(report.continuation.recommended_next_ata_number, None);
        assert!(!report.continuation.canonical_act_created);
        assert!(!report.continuation.legal_acceptance_claimed);
    }

    #[test]
    fn secret_markers_are_rejected_without_blocking_secretario_words() {
        let mut ok = base_request();
        ok.notes = Some("Livro rubricado pelo secretario da mesa.".to_owned());
        validate_candidate(ok).expect("plain secretary wording is allowed");

        let mut bad = base_request();
        bad.notes = Some("access code 1234-5678-9012".to_owned());
        assert!(validate_candidate(bad).is_err());
    }

    #[test]
    fn ocr_draft_audit_payloads_are_non_canonical_and_metadata_only() {
        let draft = sample_ocr_draft();
        let created = paper_book_ocr_draft_event_payload(&draft, "created");
        assert_eq!(created["extracted_text_stored"], true);
        assert_eq!(created["extracted_text_in_payload"], false);
        assert_eq!(created["authoritative_text_claimed"], false);
        assert_eq!(created["canonical_minutes_claimed"], false);
        assert_eq!(created["canonical_act_created"], false);
        assert_eq!(created["canonical_document_created"], false);
        assert_eq!(created["signature_created"], false);
        assert_eq!(created["legal_validity_claimed"], false);
        let created_text = serde_json::to_string(&created).expect("payload serializes");
        assert!(!created_text.contains("Actual OCR text"));

        let reviewed = paper_book_ocr_draft_review_event_payload(
            &draft,
            StoredPaperBookOcrReviewStatus::Superseded,
            "rui.secretario",
            Some("33333333-3333-4333-8333-333333333333"),
        );
        assert_eq!(reviewed["review_note_in_payload"], false);
        assert_eq!(reviewed["extracted_text_in_payload"], false);
        assert_eq!(reviewed["canonical_act_created"], false);
        assert_eq!(reviewed["canonical_document_created"], false);
        assert_eq!(reviewed["signature_created"], false);
        assert_eq!(reviewed["authoritative_text_claimed"], false);

        let mut accepted = draft.clone();
        accepted.review_status = StoredPaperBookOcrReviewStatus::Accepted;
        accepted.reviewed_at = Some(OffsetDateTime::from_unix_timestamp(1_790_000_100).unwrap());
        accepted.reviewed_by = Some("rui.secretario".to_owned());
        let import = StoredPaperBookImportMeta {
            import_id: accepted.import_id.clone(),
            entity_ref: "entity-legacy-001".to_owned(),
            entity_name: "Encosto Estrategico, S.A.".to_owned(),
            entity_nipc: "503004642".to_owned(),
            book_ref: "33333333-3333-4333-8333-333333333333".to_owned(),
            date_from: time::macros::date!(1968 - 01 - 01),
            date_to: time::macros::date!(1971 - 12 - 31),
            page_count: 2,
            page_from: 1,
            page_to: 2,
            original_number_from: Some(1),
            original_number_to: Some(1),
            sha256: "cd".repeat(32),
            size_bytes: 512,
            content_type: "application/pdf".to_owned(),
            source_filename: Some("ag-1968-1971.pdf".to_owned()),
            notes: None,
            imported_at: OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap(),
            imported_by: "rui.secretario".to_owned(),
            ocr_status: StoredPaperBookOcrStatus::Completed,
        };
        let act = Act::draft(
            BookId(Uuid::parse_str(&import.book_ref).unwrap()),
            "Rascunho OCR",
            MeetingChannel::Physical,
        );
        let artifact = build_ocr_conversion_execution_artifact(
            &accepted,
            Some("44444444-4444-4444-8444-444444444444".to_owned()),
            act.id.to_string(),
            "rui.secretario",
        );
        let act_payload = paper_book_ocr_draft_to_act_event_payload(
            &import,
            &accepted,
            &act,
            "rui.secretario",
            &artifact,
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["reviewed_conversion_execution_artifact"],
            true
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["canonical_conversion_claimed"],
            false
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["canonical_minutes_claimed"],
            false
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["archive_certification_claimed"],
            false
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["pdfa_created"],
            false
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["pdfua_created"],
            false
        );
        assert_eq!(
            act_payload["conversion_execution_artifact"]["source_extracted_text_in_ledger_event"],
            false
        );
        let act_payload_text = serde_json::to_string(&act_payload).expect("payload serializes");
        assert!(!act_payload_text.contains("Actual OCR text"));

        let dossier = build_ocr_conversion_dossier(&accepted, "rui.secretario");
        let dossier_payload = paper_book_ocr_conversion_dossier_event_payload(
            &dossier,
            std::slice::from_ref(&artifact),
        );
        assert_eq!(
            dossier_payload["bound_conversion_execution_artifacts"][0]["target_act_id"],
            artifact.target_act_id
        );
        assert_eq!(
            dossier_payload["bound_conversion_execution_artifacts"][0]["legal_validity_claimed"],
            false
        );
        assert_eq!(
            dossier_payload["bound_conversion_execution_artifacts"][0]["archive_package_created"],
            false
        );
        let dossier_payload_text =
            serde_json::to_string(&dossier_payload).expect("payload serializes");
        assert!(!dossier_payload_text.contains("Actual OCR text"));
    }
}
