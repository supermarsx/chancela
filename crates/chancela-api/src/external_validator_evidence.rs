use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chancela_authz::{Permission, Scope};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ApiError, AppState, CurrentActor, require_permission};

pub const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND: &str = "external_validator_report_metadata";
pub const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA: &str =
    "chancela-external-validator-report-evidence/v1";
pub const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX: &str = "evidence/external-validators/";
pub const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN: &str =
    "evidence/external-validators/{case_id}-{validator_family}.json";
pub const TECHNICAL_METADATA_ONLY: &str = "technical_metadata_only";
pub const EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct ExternalValidatorEvidenceAttachment {
    pub case_id: String,
    pub validator_family: String,
    pub archive_path: String,
    pub content_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExternalValidatorEvidenceAttachmentIndex {
    pub case_id: String,
    pub validator_family: String,
    pub path: String,
    pub content_type: String,
    pub sha256: String,
}

impl From<&ExternalValidatorEvidenceAttachment> for ExternalValidatorEvidenceAttachmentIndex {
    fn from(value: &ExternalValidatorEvidenceAttachment) -> Self {
        Self {
            case_id: value.case_id.clone(),
            validator_family: value.validator_family.clone(),
            path: value.archive_path.clone(),
            content_type: value.content_type.clone(),
            sha256: value.sha256.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExternalValidatorReportMetadataList {
    pub storage: &'static str,
    pub status: &'static str,
    pub count: usize,
    pub malformed_count: usize,
    pub duplicate_suggested_path_count: usize,
    pub reports: Vec<ExternalValidatorEvidenceAttachmentIndex>,
}

#[derive(Debug, Serialize)]
pub struct ExternalValidatorReportMetadataCreateResponse {
    pub storage: &'static str,
    pub status: &'static str,
    pub report: ExternalValidatorEvidenceAttachmentIndex,
}

/// `GET /v1/external-validator-reports` - list technical metadata summaries only.
pub async fn list_external_validator_report_metadata(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<ExternalValidatorReportMetadataList>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    let raw_entries = state.external_validator_report_metadata.read().await;
    Ok(Json(metadata_list_response(&raw_entries)))
}

/// `POST /v1/external-validator-reports` - accept operator-supplied technical metadata only.
pub async fn create_external_validator_report_metadata(
    State(state): State<AppState>,
    actor: CurrentActor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<
    (
        StatusCode,
        Json<ExternalValidatorReportMetadataCreateResponse>,
    ),
    ApiError,
> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;
    require_json_content_type(&headers)?;
    let attachment = validate_external_validator_report_metadata(&body).map_err(|e| {
        ApiError::Unprocessable(format!("invalid external-validator metadata: {e}"))
    })?;

    let mut raw_entries = state.external_validator_report_metadata.write().await;
    for raw in raw_entries.iter() {
        let Ok(existing) = validate_external_validator_report_metadata(raw) else {
            continue;
        };
        if existing.archive_path == attachment.archive_path {
            return Err(ApiError::Conflict(format!(
                "duplicate external-validator suggested_path would be ambiguous: {}",
                attachment.archive_path
            )));
        }
    }
    raw_entries.push(body.to_vec());

    Ok((
        StatusCode::CREATED,
        Json(ExternalValidatorReportMetadataCreateResponse {
            storage: "in_memory",
            status: "external_validator_report_metadata_attached",
            report: ExternalValidatorEvidenceAttachmentIndex::from(&attachment),
        }),
    ))
}

pub fn matching_attachments(
    raw_entries: &[Vec<u8>],
    observed_pdf_sha256: impl IntoIterator<Item = String>,
) -> Vec<ExternalValidatorEvidenceAttachment> {
    let observed = observed_pdf_sha256
        .into_iter()
        .filter(|hash| is_sha256_hex(hash))
        .collect::<BTreeSet<_>>();
    if observed.is_empty() {
        return Vec::new();
    }

    let mut parsed = Vec::new();
    let mut path_counts = BTreeMap::<String, usize>::new();
    for raw in raw_entries {
        if let Some(attachment) = parse_attachment(raw) {
            *path_counts
                .entry(attachment.archive_path.clone())
                .or_default() += 1;
            parsed.push(attachment);
        }
    }

    let mut attachments = parsed
        .into_iter()
        .filter(|attachment| path_counts.get(&attachment.archive_path) == Some(&1))
        .filter(|attachment| observed.contains(document_sha256(&attachment.bytes).as_str()))
        .collect::<Vec<_>>();
    attachments.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    attachments
}

pub fn attachment_indexes(
    attachments: &[ExternalValidatorEvidenceAttachment],
) -> Vec<ExternalValidatorEvidenceAttachmentIndex> {
    attachments.iter().map(Into::into).collect()
}

pub fn validate_external_validator_report_metadata(
    raw: &[u8],
) -> Result<ExternalValidatorEvidenceAttachment, String> {
    parse_attachment(raw).ok_or_else(|| {
        "expected external_validator_report_metadata JSON with technical-only scope, legal_validity_claimed=false, safe suggested_path, and lowercase SHA-256 values".to_owned()
    })
}

fn parse_attachment(raw: &[u8]) -> Option<ExternalValidatorEvidenceAttachment> {
    let value: Value = serde_json::from_slice(raw).ok()?;
    let object = value.as_object()?;

    if object.get("schema")?.as_str()? != EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA {
        return None;
    }
    if object.get("evidence_kind")?.as_str()? != EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND {
        return None;
    }
    if object.get("legal_validity_claimed")?.as_bool()? {
        return None;
    }
    validate_scope(object.get("evidence_scope")?)?;

    let case_id = object.get("case_id")?.as_str()?.to_owned();
    if !is_safe_slug(&case_id) {
        return None;
    }
    let validator = object.get("validator")?.as_object()?;
    let validator_family = validator.get("family")?.as_str()?.to_owned();
    if !is_safe_slug(&validator_family) {
        return None;
    }
    if validator.get("run_status")?.as_str()? != "recorded" {
        return None;
    }

    let document = object.get("document")?.as_object()?;
    let document_sha256 = document.get("sha256")?.as_str()?;
    if !is_sha256_hex(document_sha256) {
        return None;
    }

    let archive_attachment = object.get("archive_attachment")?.as_object()?;
    if archive_attachment.get("role")?.as_str()? != "technical_external_validator_report_metadata" {
        return None;
    }
    let content_type = archive_attachment.get("content_type")?.as_str()?.to_owned();
    if content_type != "application/json" {
        return None;
    }
    let archive_path = archive_attachment
        .get("suggested_path")?
        .as_str()?
        .to_owned();
    if !valid_archive_path(&archive_path, &case_id, &validator_family) {
        return None;
    }

    validate_indexing(object.get("evidence_indexing")?)?;

    Some(ExternalValidatorEvidenceAttachment {
        case_id,
        validator_family,
        archive_path,
        content_type,
        sha256: sha256_hex(raw),
        bytes: raw.to_vec(),
    })
}

fn validate_scope(scope: &Value) -> Option<()> {
    let scope = scope.as_object()?;
    (scope.get("kind")?.as_str()? == "external_validator_report").then_some(())?;
    scope.get("technical_only")?.as_bool()?.then_some(())?;
    (scope.get("legal_validity_assessment")?.as_str()? == "not_assessed").then_some(())?;
    (scope.get("claim")?.as_str()? == "technical_validator_evidence_only").then_some(())
}

fn validate_indexing(indexing: &Value) -> Option<()> {
    let indexing = indexing.as_object()?;
    (indexing.get("status_scope")?.as_str()? == TECHNICAL_METADATA_ONLY).then_some(())?;
    let archive = indexing.get("archive_package")?.as_object()?;
    (archive.get("index_path")?.as_str()? == "evidence/index.json").then_some(())?;
    (archive.get("indexed_path_prefix")?.as_str()?
        == EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX)
        .then_some(())?;
    (archive.get("indexed_path_pattern")?.as_str()?
        == EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN)
        .then_some(())?;
    let bundle = indexing.get("document_bundle")?.as_object()?;
    (bundle.get("index_json_pointer")?.as_str()?
        == "/validation_report/evidence_index/external_validator_reports")
        .then_some(())?;
    (bundle.get("archive_path_prefix")?.as_str()? == EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX)
        .then_some(())?;
    (bundle.get("archive_path_pattern")?.as_str()?
        == EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN)
        .then_some(())
}

fn valid_archive_path(path: &str, case_id: &str, validator_family: &str) -> bool {
    path == format!(
        "{EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX}{case_id}-{validator_family}.json"
    ) && !path.contains('\\')
        && !path
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
}

fn is_safe_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn document_sha256(bytes: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return String::new();
    };
    value
        .get("document")
        .and_then(|document| document.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    crate::hex::hex(&digest)
}

fn metadata_list_response(raw_entries: &[Vec<u8>]) -> ExternalValidatorReportMetadataList {
    let mut reports = Vec::new();
    let mut malformed_count = 0;
    let mut path_counts = BTreeMap::<String, usize>::new();
    for raw in raw_entries {
        match validate_external_validator_report_metadata(raw) {
            Ok(attachment) => {
                *path_counts
                    .entry(attachment.archive_path.clone())
                    .or_default() += 1;
                reports.push(attachment);
            }
            Err(_) => malformed_count += 1,
        }
    }

    let duplicate_suggested_path_count = path_counts.values().filter(|count| **count > 1).count();
    reports.retain(|report| path_counts.get(&report.archive_path) == Some(&1));
    reports.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    let reports = attachment_indexes(&reports);
    let status = if reports.is_empty() {
        "no_external_validator_report_metadata_attached"
    } else {
        "external_validator_report_metadata_attached"
    };

    ExternalValidatorReportMetadataList {
        storage: "in_memory",
        status,
        count: reports.len(),
        malformed_count,
        duplicate_suggested_path_count,
        reports,
    }
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(value) = headers.get(axum::http::header::CONTENT_TYPE) else {
        return Err(ApiError::Unprocessable(
            "external-validator metadata must be submitted as application/json".to_owned(),
        ));
    };
    let Ok(value) = value.to_str() else {
        return Err(ApiError::Unprocessable(
            "external-validator metadata content-type is invalid".to_owned(),
        ));
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(
            "external-validator metadata must be submitted as application/json".to_owned(),
        ))
    }
}
