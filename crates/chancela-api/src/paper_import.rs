//! Read-only validation for scanned historical paper-book import candidates.
//!
//! This first slice deliberately stops at a validation/report plan: it does not persist scanned
//! material, does not append ledger events, and does not claim that scans are canonical digital
//! minutes or qualified signatures.

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::dto::{format_date, parse_date};
use crate::error::ApiError;

const PAPER_BOOK_IMPORT_NOTICE: &str = "Historical paper-book scans are classified as non-canonical evidence only. This report does not preserve the package, replace canonical digital minutes, or claim PDF/A, legal, or qualified-signature validity.";
const MAX_NOTES_CHARS: usize = 2_000;

#[derive(Debug, Deserialize)]
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

async fn require_permission_for_report(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<(), ApiError> {
    crate::authz::require_permission(state, actor, Permission::BookImport, Scope::Global).await
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
