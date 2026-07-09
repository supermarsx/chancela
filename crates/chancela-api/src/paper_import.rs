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
use chancela_store::{StoredPaperBookImport, StoredPaperBookImportMeta, StoredPaperBookOcrStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::dto::{format_date, parse_date};
use crate::error::ApiError;

const PAPER_BOOK_IMPORT_NOTICE: &str = "Historical paper-book scans are classified as non-canonical evidence only. This report does not preserve the package, replace canonical digital minutes, or claim PDF/A, legal, or qualified-signature validity.";
const PAPER_BOOK_PRESERVATION_NOTICE: &str = "Historical paper-book package preserved as non-canonical evidence only. It does not replace canonical digital minutes and no PDF/A, legal-validity, signature-validity, or qualified-signature claim is made.";
const MAX_NOTES_CHARS: usize = 2_000;
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
    #[serde(alias = "filename")]
    source_filename: Option<String>,
    #[serde(alias = "sha256")]
    digest: Option<String>,
    notes: Option<String>,
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
    pub sha256: String,
    pub size_bytes: usize,
    pub content_type: String,
    pub source_filename: Option<String>,
    pub notes: Option<String>,
    pub imported_at: String,
    pub imported_by: String,
    pub ocr_status: &'static str,
    pub non_canonical: bool,
    pub legal_validity_claimed: bool,
    pub signature_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub legal_notice: &'static str,
    pub bytes_download: String,
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
    pub source_filename: Option<String>,
    pub digest: Option<String>,
    pub notes_present: bool,
    pub notes_truncated: bool,
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
            sha256: declared_sha256.clone(),
            size_bytes: bytes.len(),
            content_type: content_type.clone(),
            source_filename: validation.package.source_filename.clone(),
            notes,
            imported_at,
            imported_by: imported_by.clone(),
            ocr_status: StoredPaperBookOcrStatus::NotStarted,
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
    state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_paper_book_import(&stored))?;
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
    if let Some(notes) = notes.as_ref() {
        if notes.chars().count() > MAX_NOTES_CHARS {
            return Err(ApiError::Unprocessable(format!(
                "notes must be at most {MAX_NOTES_CHARS} characters"
            )));
        }
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
            source_filename,
            digest,
            notes_present: notes.is_some(),
            notes_truncated: false,
        },
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
            "preserve_package_in_a_later_operator_action",
            "link_to_canonical_records_without_replacing_them",
        ],
        findings: vec![PaperBookImportFinding::info(
            "report_only",
            "validation is read-only; no package, book, act, document, or ledger event was created",
        )],
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
            "perform_ocr_in_a_later_operator_action_if_needed",
            "link_to_canonical_records_without_replacing_them",
        ],
        findings: vec![PaperBookImportFinding::info(
            "preserved_non_canonical",
            "package bytes were preserved outside canonical books, acts, documents, and signatures; the ledger event contains metadata only",
        )],
    }
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
        sha256: meta.sha256.clone(),
        size_bytes: meta.size_bytes,
        content_type: meta.content_type.clone(),
        source_filename: meta.source_filename.clone(),
        notes: meta.notes.clone(),
        imported_at: meta.imported_at.format(&Rfc3339).unwrap_or_default(),
        imported_by: meta.imported_by.clone(),
        ocr_status: meta.ocr_status.as_str(),
        non_canonical: true,
        legal_validity_claimed: false,
        signature_validity_claimed: false,
        qualified_signature_claimed: false,
        legal_notice: PAPER_BOOK_PRESERVATION_NOTICE,
        bytes_download: format!("/v1/books/paper-import/{}/bytes", meta.import_id),
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
    let ext = match meta
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
    };
    format!("paper-book-import-{}.{}", meta.import_id, ext)
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
            source_filename: Some("ag-1968-1971.pdf".to_owned()),
            digest: Some("AB".repeat(32)),
            notes: Some("Scanned from bound paper minute book.".to_owned()),
        }
    }

    #[test]
    fn validation_normalizes_digest_and_stays_non_canonical() {
        let report = validate_candidate(base_request()).expect("valid report");
        let expected = "ab".repeat(32);
        assert_eq!(report.package.digest.as_deref(), Some(expected.as_str()));
        assert!(report.candidate_classification.non_canonical);
        assert!(!report.candidate_classification.qualified_signature_claimed);
        assert!(!report.candidate_classification.canonical_minutes_claimed);
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
}
