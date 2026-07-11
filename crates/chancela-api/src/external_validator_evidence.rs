use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{ApiError, AppState, CurrentActor, require_permission};

pub const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND: &str = "external_validator_report_metadata";
pub const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA: &str =
    "chancela-external-validator-report-evidence/v1";
pub const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX: &str = "evidence/external-validators/";
pub const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN: &str =
    "evidence/external-validators/{case_id}-{validator_family}.json";
pub const EXTERNAL_VALIDATOR_RAW_REPORT_ARCHIVE_PATH_PATTERN: &str =
    "evidence/external-validators/{case_id}-{validator_family}-raw-report.{extension}";
pub const TECHNICAL_METADATA_ONLY: &str = "technical_metadata_only";
pub const EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES: usize = 256 * 1024;
pub const EXTERNAL_VALIDATOR_RAW_REPORT_MAX_BYTES: usize = 2 * 1024 * 1024;
pub const EXTERNAL_VALIDATOR_REPORT_UPLOAD_MAX_BYTES: usize =
    EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES
        + (EXTERNAL_VALIDATOR_RAW_REPORT_MAX_BYTES * 4 / 3)
        + 64 * 1024;
pub(crate) const EXTERNAL_VALIDATOR_REPORT_METADATA_DIR: &str = "external-validator-reports";

#[derive(Clone, Debug)]
pub struct ExternalValidatorEvidenceAttachment {
    pub case_id: String,
    pub validator_family: String,
    pub archive_path: String,
    pub content_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
    pub raw_report: Option<ExternalValidatorRawReportAttachment>,
}

#[derive(Clone, Debug)]
pub struct ExternalValidatorRawReportAttachment {
    pub archive_path: Option<String>,
    pub suggested_path: Option<String>,
    pub content_type: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub source_filename: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

impl ExternalValidatorRawReportAttachment {
    pub fn preservation_status(&self) -> &'static str {
        if self.bytes.is_some() {
            "raw_report_attached"
        } else {
            "raw_report_manifest_only"
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExternalValidatorEvidenceAttachmentIndex {
    pub case_id: String,
    pub validator_family: String,
    pub path: String,
    pub content_type: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_report: Option<ExternalValidatorRawReportAttachmentIndex>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExternalValidatorRawReportAttachmentIndex {
    pub preservation_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_path: Option<String>,
    pub content_type: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_filename: Option<String>,
}

impl From<&ExternalValidatorRawReportAttachment> for ExternalValidatorRawReportAttachmentIndex {
    fn from(value: &ExternalValidatorRawReportAttachment) -> Self {
        Self {
            preservation_status: value.preservation_status(),
            path: value.archive_path.clone(),
            suggested_path: value.suggested_path.clone(),
            content_type: value.content_type.clone(),
            sha256: value.sha256.clone(),
            size_bytes: value.size_bytes,
            source_filename: value.source_filename.clone(),
        }
    }
}

impl From<&ExternalValidatorEvidenceAttachment> for ExternalValidatorEvidenceAttachmentIndex {
    fn from(value: &ExternalValidatorEvidenceAttachment) -> Self {
        Self {
            case_id: value.case_id.clone(),
            validator_family: value.validator_family.clone(),
            path: value.archive_path.clone(),
            content_type: value.content_type.clone(),
            sha256: value.sha256.clone(),
            raw_report: value.raw_report.as_ref().map(Into::into),
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
    Ok(Json(metadata_list_response(
        &raw_entries,
        storage_mode(state.external_validator_report_metadata_dir.is_some()),
    )))
}

/// `GET /v1/external-validator-reports/{case_id}/{validator_family}` - download one validated
/// technical metadata JSON report by its stable redacted-summary identity.
pub async fn download_external_validator_report_metadata(
    State(state): State<AppState>,
    AxumPath((case_id, validator_family)): AxumPath<(String, String)>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    require_safe_report_identity(&case_id, &validator_family)?;

    let raw_entries = state.external_validator_report_metadata.read().await;
    let attachment = attachment_for_identity(&raw_entries, &case_id, &validator_family)?;
    drop(raw_entries);

    if let Some(attachment) = attachment {
        return Ok((
            [(header::CONTENT_TYPE, "application/json")],
            attachment.bytes,
        )
            .into_response());
    }

    if state
        .external_validator_report_metadata_dir
        .as_ref()
        .is_some_and(|dir| {
            malformed_persisted_sidecar_for_identity(dir, &case_id, &validator_family)
        })
    {
        return Err(ApiError::Unprocessable(
            "invalid external-validator technical metadata sidecar for requested identity"
                .to_owned(),
        ));
    }

    Err(ApiError::NotFound)
}

/// `GET /v1/external-validator-reports/{case_id}/{validator_family}/raw-report` - download
/// retained raw external-validator report bytes only, when the metadata sidecar carried them.
pub async fn download_external_validator_raw_report_bytes(
    State(state): State<AppState>,
    AxumPath((case_id, validator_family)): AxumPath<(String, String)>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;
    require_safe_report_identity(&case_id, &validator_family)?;

    let raw_entries = state.external_validator_report_metadata.read().await;
    let attachment = attachment_for_identity(&raw_entries, &case_id, &validator_family)?;
    drop(raw_entries);

    let Some(attachment) = attachment else {
        if state
            .external_validator_report_metadata_dir
            .as_ref()
            .is_some_and(|dir| {
                malformed_persisted_sidecar_for_identity(dir, &case_id, &validator_family)
            })
        {
            return Err(ApiError::Unprocessable(
                "invalid external-validator technical metadata sidecar for requested identity"
                    .to_owned(),
            ));
        }

        return Err(ApiError::NotFound);
    };

    let Some(raw_report) = attachment.raw_report else {
        return Err(ApiError::NotFound);
    };
    let Some(bytes) = raw_report.bytes else {
        return Err(ApiError::NotFound);
    };
    let filename = raw_report_download_filename(
        &attachment.case_id,
        &attachment.validator_family,
        &raw_report.content_type,
    )?;

    Ok((
        [
            (header::CONTENT_TYPE, raw_report.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        bytes,
    )
        .into_response())
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
    if let Some(dir) = &state.external_validator_report_metadata_dir {
        persist_external_validator_report_metadata(dir, &attachment, &body).map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist external-validator metadata sidecar: {e}"
            ))
        })?;
    }
    raw_entries.push(body.to_vec());

    Ok((
        StatusCode::CREATED,
        Json(ExternalValidatorReportMetadataCreateResponse {
            storage: storage_mode(state.external_validator_report_metadata_dir.is_some()),
            status: "external_validator_report_metadata_attached",
            report: ExternalValidatorEvidenceAttachmentIndex::from(&attachment),
        }),
    ))
}

pub(crate) fn load_external_validator_report_metadata(dir: &Path) -> Vec<Vec<u8>> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            eprintln!(
                "warning: failed to read external-validator metadata sidecar directory {} ({e}); using no durable external-validator metadata",
                dir.display()
            );
            return Vec::new();
        }
    };

    let mut paths = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!(
                    "warning: failed to inspect an external-validator metadata sidecar entry in {} ({e}); ignoring it",
                    dir.display()
                );
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                eprintln!(
                    "warning: failed to inspect external-validator metadata sidecar {} ({e}); counting it as malformed",
                    path.display()
                );
                paths.push(path);
                continue;
            }
        };
        if file_type.is_file() {
            paths.push(path);
        }
    }
    paths.sort();

    paths
        .into_iter()
        .map(|path| match read_external_validator_metadata_sidecar(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "warning: failed to load external-validator metadata sidecar {} ({e}); counting it as malformed",
                    path.display()
                );
                Vec::new()
            }
        })
        .collect()
}

pub(crate) fn persist_external_validator_report_metadata(
    dir: &Path,
    attachment: &ExternalValidatorEvidenceAttachment,
    raw: &[u8],
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = external_validator_report_metadata_path(dir, attachment)?;
    write_external_validator_report_metadata_atomic(&path, raw)?;
    Ok(path)
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
        "expected external_validator_report_metadata JSON with technical-only scope, legal_validity_claimed=false, safe suggested_path, lowercase SHA-256 values, and optional raw_report fixity only".to_owned()
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
    let raw_report = parse_raw_report_for_attachment(
        object.get("raw_report"),
        object.get("report"),
        &case_id,
        &validator_family,
    )?;

    Some(ExternalValidatorEvidenceAttachment {
        case_id,
        validator_family,
        archive_path,
        content_type,
        sha256: sha256_hex(raw),
        bytes: raw.to_vec(),
        raw_report,
    })
}

fn parse_raw_report_for_attachment(
    raw_report: Option<&Value>,
    report: Option<&Value>,
    case_id: &str,
    validator_family: &str,
) -> Option<Option<ExternalValidatorRawReportAttachment>> {
    if let Some(raw_report) = raw_report {
        return parse_declared_raw_report(raw_report, case_id, validator_family).map(Some);
    }
    Some(report.and_then(report_manifest_from_report_object))
}

fn parse_declared_raw_report(
    value: &Value,
    case_id: &str,
    validator_family: &str,
) -> Option<ExternalValidatorRawReportAttachment> {
    let object = value.as_object()?;
    let content_type = normalized_raw_report_content_type(object.get("content_type")?.as_str()?)?;
    let sha256 = object.get("sha256")?.as_str()?.to_owned();
    if !is_sha256_hex(&sha256) {
        return None;
    }
    let size_bytes = raw_report_size_bytes(object)?;
    let source_filename = optional_safe_filename(object.get("source_filename"))?;
    let expected_path =
        external_validator_raw_report_archive_path(case_id, validator_family, &content_type)?;
    let suggested_path = optional_text(object.get("suggested_path"))
        .or_else(|| optional_text(object.get("archive_path")));
    if let Some(path) = suggested_path.as_deref() {
        if !valid_raw_report_archive_path(path, case_id, validator_family, &content_type) {
            return None;
        }
    }
    let bytes = match optional_text(object.get("content_base64")) {
        Some(encoded) => {
            let decoded = B64.decode(encoded).ok()?;
            if decoded.len() > EXTERNAL_VALIDATOR_RAW_REPORT_MAX_BYTES {
                return None;
            }
            if decoded.len() as u64 != size_bytes || sha256_hex(&decoded) != sha256 {
                return None;
            }
            Some(decoded)
        }
        None => None,
    };
    let archive_path = bytes.as_ref().map(|_| expected_path.clone());
    if bytes.is_some()
        && suggested_path
            .as_deref()
            .is_some_and(|path| path != expected_path)
    {
        return None;
    }

    Some(ExternalValidatorRawReportAttachment {
        archive_path,
        suggested_path,
        content_type,
        sha256,
        size_bytes,
        source_filename,
        bytes,
    })
}

fn report_manifest_from_report_object(
    value: &Value,
) -> Option<ExternalValidatorRawReportAttachment> {
    let object = value.as_object()?;
    let content_type = normalized_raw_report_content_type(object.get("content_type")?.as_str()?)?;
    let sha256 = object.get("sha256")?.as_str()?.to_owned();
    if !is_sha256_hex(&sha256) {
        return None;
    }
    let size_bytes = raw_report_size_bytes(object)?;
    let source_filename = optional_safe_filename(object.get("source_filename"))?;
    Some(ExternalValidatorRawReportAttachment {
        archive_path: None,
        suggested_path: None,
        content_type,
        sha256,
        size_bytes,
        source_filename,
        bytes: None,
    })
}

fn raw_report_size_bytes(object: &serde_json::Map<String, Value>) -> Option<u64> {
    let bytes = object
        .get("bytes")
        .or_else(|| object.get("size_bytes"))?
        .as_u64()?;
    (bytes > 0).then_some(bytes)
}

fn optional_text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn optional_safe_filename(value: Option<&Value>) -> Option<Option<String>> {
    let Some(filename) = optional_text(value) else {
        return Some(None);
    };
    (is_safe_source_filename(&filename)).then_some(Some(filename))
}

fn is_safe_source_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('\\')
        && !value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn normalized_raw_report_content_type(value: &str) -> Option<String> {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/json"
            | "application/pdf"
            | "application/xml"
            | "text/xml"
            | "text/plain"
            | "application/octet-stream"
    )
    .then_some(media_type)
}

fn raw_report_extension(content_type: &str) -> Option<&'static str> {
    match content_type {
        "application/json" => Some("json"),
        "application/pdf" => Some("pdf"),
        "application/xml" | "text/xml" => Some("xml"),
        "text/plain" => Some("txt"),
        "application/octet-stream" => Some("bin"),
        _ => None,
    }
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
    path == external_validator_report_archive_path(case_id, validator_family)
        && is_safe_archive_path(path)
}

fn external_validator_report_archive_path(case_id: &str, validator_family: &str) -> String {
    format!("{EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX}{case_id}-{validator_family}.json")
}

fn valid_raw_report_archive_path(
    path: &str,
    case_id: &str,
    validator_family: &str,
    content_type: &str,
) -> bool {
    external_validator_raw_report_archive_path(case_id, validator_family, content_type)
        .is_some_and(|expected| path == expected)
        && is_safe_archive_path(path)
}

fn external_validator_raw_report_archive_path(
    case_id: &str,
    validator_family: &str,
    content_type: &str,
) -> Option<String> {
    let extension = raw_report_extension(content_type)?;
    Some(format!(
        "{EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX}{case_id}-{validator_family}-raw-report.{extension}"
    ))
}

fn is_safe_archive_path(path: &str) -> bool {
    !path.contains('\\')
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

fn metadata_list_response(
    raw_entries: &[Vec<u8>],
    storage: &'static str,
) -> ExternalValidatorReportMetadataList {
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
        storage,
        status,
        count: reports.len(),
        malformed_count,
        duplicate_suggested_path_count,
        reports,
    }
}

fn require_safe_report_identity(case_id: &str, validator_family: &str) -> Result<(), ApiError> {
    if is_safe_slug(case_id) && is_safe_slug(validator_family) {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(
            "external-validator report identity must use safe case_id and validator_family slugs"
                .to_owned(),
        ))
    }
}

fn attachment_for_identity(
    raw_entries: &[Vec<u8>],
    case_id: &str,
    validator_family: &str,
) -> Result<Option<ExternalValidatorEvidenceAttachment>, ApiError> {
    let mut parsed = Vec::new();
    let mut identity_counts = BTreeMap::<(String, String), usize>::new();
    let mut path_counts = BTreeMap::<String, usize>::new();

    for raw in raw_entries {
        let Ok(attachment) = validate_external_validator_report_metadata(raw) else {
            continue;
        };
        *identity_counts
            .entry((
                attachment.case_id.clone(),
                attachment.validator_family.clone(),
            ))
            .or_default() += 1;
        *path_counts
            .entry(attachment.archive_path.clone())
            .or_default() += 1;
        parsed.push(attachment);
    }

    let mut matches = parsed
        .into_iter()
        .filter(|attachment| {
            attachment.case_id == case_id && attachment.validator_family == validator_family
        })
        .collect::<Vec<_>>();

    if matches.is_empty() {
        return Ok(None);
    }

    let identity_count = identity_counts
        .get(&(case_id.to_owned(), validator_family.to_owned()))
        .copied()
        .unwrap_or_default();
    let duplicate_path = matches.iter().any(|attachment| {
        path_counts
            .get(&attachment.archive_path)
            .copied()
            .unwrap_or_default()
            > 1
    });
    if identity_count != 1 || duplicate_path || matches.len() != 1 {
        return Err(ApiError::Conflict(
            "duplicate external-validator report identity or suggested_path is ambiguous; refusing technical metadata download"
                .to_owned(),
        ));
    }

    Ok(Some(matches.pop().expect("one matching attachment")))
}

fn raw_report_download_filename(
    case_id: &str,
    validator_family: &str,
    content_type: &str,
) -> Result<String, ApiError> {
    let extension = raw_report_extension(content_type).ok_or_else(|| {
        ApiError::Unprocessable(
            "invalid external-validator raw report content type for requested identity".to_owned(),
        )
    })?;
    if is_safe_slug(case_id) && is_safe_slug(validator_family) {
        Ok(format!(
            "{case_id}-{validator_family}-raw-report.{extension}"
        ))
    } else {
        Err(ApiError::Unprocessable(
            "external-validator report identity must use safe case_id and validator_family slugs"
                .to_owned(),
        ))
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

fn read_external_validator_metadata_sidecar(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > EXTERNAL_VALIDATOR_REPORT_UPLOAD_MAX_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "sidecar exceeds {} bytes",
                EXTERNAL_VALIDATOR_REPORT_UPLOAD_MAX_BYTES
            ),
        ));
    }
    std::fs::read(path)
}

fn external_validator_report_metadata_path(
    dir: &Path,
    attachment: &ExternalValidatorEvidenceAttachment,
) -> std::io::Result<PathBuf> {
    let Some(file_name) = external_validator_report_metadata_file_name(
        &attachment.case_id,
        &attachment.validator_family,
    ) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "external-validator sidecar file name is not safe",
        ));
    };
    Ok(dir.join(file_name))
}

fn external_validator_report_metadata_file_name(
    case_id: &str,
    validator_family: &str,
) -> Option<String> {
    (is_safe_slug(case_id) && is_safe_slug(validator_family))
        .then(|| format!("{case_id}-{validator_family}.json"))
}

fn malformed_persisted_sidecar_for_identity(
    dir: &Path,
    case_id: &str,
    validator_family: &str,
) -> bool {
    let Some(file_name) = external_validator_report_metadata_file_name(case_id, validator_family)
    else {
        return false;
    };
    let path = dir.join(file_name);
    match read_external_validator_metadata_sidecar(&path) {
        Ok(bytes) => validate_external_validator_report_metadata(&bytes)
            .map(|attachment| {
                attachment.case_id != case_id || attachment.validator_family != validator_family
            })
            .unwrap_or(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn write_external_validator_report_metadata_atomic(
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = tmp_path(path);
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "external-validator-report.json".into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

fn storage_mode(durable: bool) -> &'static str {
    if durable { "data_dir" } else { "in_memory" }
}
