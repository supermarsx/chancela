use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
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
pub const TECHNICAL_METADATA_ONLY: &str = "technical_metadata_only";
pub const EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES: usize = 256 * 1024;
pub(crate) const EXTERNAL_VALIDATOR_REPORT_METADATA_DIR: &str = "external-validator-reports";

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
    let bytes = raw_metadata_for_identity(&raw_entries, &case_id, &validator_family)?;
    drop(raw_entries);

    if let Some(bytes) = bytes {
        return Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response());
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
    path == external_validator_report_archive_path(case_id, validator_family)
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
}

fn external_validator_report_archive_path(case_id: &str, validator_family: &str) -> String {
    format!("{EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX}{case_id}-{validator_family}.json")
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

fn raw_metadata_for_identity(
    raw_entries: &[Vec<u8>],
    case_id: &str,
    validator_family: &str,
) -> Result<Option<Vec<u8>>, ApiError> {
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

    Ok(Some(matches.pop().expect("one matching attachment").bytes))
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
    if metadata.len() > EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "sidecar exceeds {} bytes",
                EXTERNAL_VALIDATOR_REPORT_METADATA_MAX_BYTES
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
