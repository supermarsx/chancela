//! Data-directory/storage telemetry for the Data Management tab.
//!
//! This endpoint is deliberately read-only: it never appends ledger events, never records platform
//! logs, and never opens or migrates a second store connection. Filesystem checks run on a blocking
//! worker so directory traversal and permission probes do not occupy the async runtime.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use chancela_store::{
    Store, StoreDatabaseFormat, StoreError, StoreKeyOpsPlan, StoreKeyOpsStatus,
    StoreKeyRotationExecution, StoreKeyRotationPreflight, StoreOpenOptions,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use tokio::task;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::{authorizer, require_permission};
use crate::database::DatabaseEncryptionKeySource;
use crate::error::ApiError;

#[derive(Debug, Clone, Serialize)]
pub struct DataStatusResponse {
    pub generated_at: String,
    pub persistence: PersistenceStatus,
    pub data_dir: DataDirStatus,
    pub permissions: PermissionStatus,
    pub usage: UsageStatus,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMode {
    Durable,
    InMemory,
    FallbackInMemory,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersistenceStatus {
    pub mode: PersistenceMode,
    pub data_dir_configured: bool,
    pub durable_store_open: bool,
    pub active_backend_family: Option<DurableBackendFamily>,
    pub sidecar_storage_mode: SidecarStorageMode,
    pub database_encryption_configured: bool,
    pub database_encryption: DatabaseEncryptionStatus,
    pub store_schema_version: Option<i64>,
    pub ledger_length: u64,
    pub ledger_verified: Option<bool>,
    pub degraded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableBackendFamily {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarStorageMode {
    File,
    Database,
    InMemory,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseEncryptionStatus {
    /// Whether this running store opened with a configured database encryption key.
    pub configured: bool,
    /// Whether this binary was compiled with SQLCipher support.
    pub sqlcipher_available: bool,
    /// True only when the running durable store is configured and SQLCipher-capable.
    pub sqlcipher_backed: bool,
    /// Non-secret classification of the source that supplied the configured key.
    pub key_source: DatabaseEncryptionKeySourceStatus,
    /// Status of the future hardware-derived default/fallback key source.
    pub hardware_derived_fallback: HardwareDerivedFallbackStatus,
    /// Header-level database format from the store key-ops preflight, when a data dir exists.
    pub database_format: Option<StoreDatabaseFormat>,
    /// Store key-ops plan from the same preflight, when available.
    pub key_ops_plan: Option<StoreKeyOpsPlan>,
    /// True when a plaintext SQLite database is present and the running store is not SQLCipher-backed.
    pub plaintext_migration_pending: bool,
    /// True when direct keyed open would be refused because a plaintext store must be migrated by
    /// backup/export/restore instead of in-place rewrite.
    pub plaintext_migration_blocked: bool,
    /// Full secret-free store key-ops report for audit/operator surfaces.
    pub key_ops: Option<StoreKeyOpsStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseEncryptionKeySourceStatus {
    None,
    OperatorEnv,
    OperatorKeyFile,
    Programmatic,
    HardwareDerivedFallback,
}

impl From<Option<DatabaseEncryptionKeySource>> for DatabaseEncryptionKeySourceStatus {
    fn from(source: Option<DatabaseEncryptionKeySource>) -> Self {
        match source {
            None => Self::None,
            Some(DatabaseEncryptionKeySource::Env) => Self::OperatorEnv,
            Some(DatabaseEncryptionKeySource::File) => Self::OperatorKeyFile,
            Some(DatabaseEncryptionKeySource::Programmatic) => Self::Programmatic,
            Some(DatabaseEncryptionKeySource::HardwareDerivedFallback) => {
                Self::HardwareDerivedFallback
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareDerivedFallbackStatus {
    pub available: bool,
    pub selected: bool,
    pub fail_closed_if_requested: bool,
    pub status: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataDirStatus {
    pub path: Option<String>,
    pub exists: Option<bool>,
    pub is_directory: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionStatus {
    pub read_dir: PermissionCheck,
    pub create_file: PermissionCheck,
    pub write_file: PermissionCheck,
    pub delete_probe_file: PermissionCheck,
    pub durable_store_open: PermissionCheck,
    pub sqlite_store_open: PermissionCheck,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionCheck {
    pub ok: bool,
    pub checked: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageStatus {
    pub total_bytes: u64,
    pub filesystem: Vec<ConcernUsage>,
    pub logical_payload: Vec<ConcernUsage>,
    pub sidecars: Vec<ConcernUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub largest_payload_table: Option<DataPayloadStats>,
    /// Backwards-compatible alias for older web/contract clients.
    pub sqlite_logical: Vec<ConcernUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlite_largest_payload_table: Option<DataPayloadStats>,
    pub scan_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConcernUsage {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<UsageConcernKind>,
    pub label: String,
    pub bytes: u64,
    pub basis: UsageBasis,
    pub exact: bool,
    pub file_count: u64,
    pub directory_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_stats: Option<DataPayloadStats>,
    pub relative_roots: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageConcernKind {
    SqliteLogicalTable,
    SidecarLogicalStore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataPayloadStats {
    pub table_name: String,
    pub estimated_payload_bytes: u64,
    pub row_count: u64,
    pub average_bytes_per_row: Option<u64>,
    pub estimate_method: PayloadEstimateMethod,
    pub estimate_basis: UsageBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEstimateMethod {
    LocalLoadedPayloadEstimate,
}

#[derive(Debug, Deserialize)]
pub struct DataCleanupRequest {
    pub target: String,
    pub dry_run: Option<bool>,
    pub minimum_age_days: Option<u64>,
    pub keep_latest: Option<usize>,
    pub preview_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataCleanupResponse {
    pub target: String,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_token: Option<String>,
    pub deleted_bytes: u64,
    pub deleted_files: u64,
    pub deleted_directories: u64,
    pub would_delete_bytes: u64,
    pub would_delete_files: u64,
    pub would_delete_directories: u64,
    pub skipped: Vec<String>,
    pub data_dir: Option<String>,
}

#[derive(Deserialize)]
pub struct DataKeyRotationPreflightRequest {
    #[serde(default)]
    current_key: Option<String>,
    #[serde(default, alias = "replacement_key")]
    new_key: Option<String>,
}

impl fmt::Debug for DataKeyRotationPreflightRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataKeyRotationPreflightRequest")
            .field("current_key", &key_log_status(self.current_key.as_deref()))
            .field("new_key", &key_log_status(self.new_key.as_deref()))
            .finish()
    }
}

#[derive(Deserialize)]
pub struct DataKeyRotationExecuteRequest {
    #[serde(default, alias = "replacement_key")]
    new_key: Option<String>,
}

impl fmt::Debug for DataKeyRotationExecuteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataKeyRotationExecuteRequest")
            .field("new_key", &key_log_status(self.new_key.as_deref()))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageBasis {
    Filesystem,
    LogicalPayload,
    SidecarLogicalPayload,
    #[allow(dead_code)]
    SqliteLogicalPayload,
    SqliteFile,
}

struct FsInspection {
    data_dir: DataDirStatus,
    permissions: PermissionStatus,
    usage: UsageStatus,
}

#[derive(Clone, Copy)]
struct ConcernDef {
    id: &'static str,
    label: &'static str,
    basis: UsageBasis,
}

#[derive(Default)]
struct ConcernAccumulator {
    bytes: u64,
    file_count: u64,
    directory_count: u64,
    relative_roots: BTreeMap<String, ()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupTarget {
    Crash,
    Exports,
}

impl CleanupTarget {
    fn id(self) -> &'static str {
        match self {
            CleanupTarget::Crash => "crash",
            CleanupTarget::Exports => "exports",
        }
    }
}

#[derive(Debug, Clone)]
struct CleanupPolicy {
    dry_run: bool,
    request_policy: CleanupRequestPolicy,
    minimum_age: Option<Duration>,
    keep_latest: usize,
    retained_files: BTreeSet<PathBuf>,
    now: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CleanupRequestPolicy {
    minimum_age_days: Option<u64>,
    keep_latest: usize,
}

impl CleanupRequestPolicy {
    fn from_request(req: &DataCleanupRequest) -> Self {
        Self {
            minimum_age_days: req.minimum_age_days,
            keep_latest: req.keep_latest.unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone)]
struct CleanupFileCandidate {
    path: PathBuf,
    bytes: u64,
    modified: Option<SystemTime>,
    sha256: [u8; 32],
}

#[derive(Debug, Clone)]
struct CleanupDirectoryCandidate {
    path: PathBuf,
    modified: Option<SystemTime>,
}

#[derive(Debug, Clone, Default)]
struct CleanupSelectionManifest {
    files: Vec<CleanupFileCandidate>,
    directories: Vec<CleanupDirectoryCandidate>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExportCleanupPreviewRecord {
    data_dir: PathBuf,
    policy: CleanupRequestPolicy,
    manifest: CleanupSelectionManifest,
    expires_at: SystemTime,
}

struct ExportCleanupPreview {
    response: DataCleanupResponse,
    record: ExportCleanupPreviewRecord,
}

const EXPORT_CLEANUP_PREVIEW_TTL: Duration = Duration::from_secs(10 * 60);

impl CleanupPolicy {
    fn from_request(target: CleanupTarget, req: &DataCleanupRequest) -> Result<Self, ApiError> {
        let has_export_policy = req.dry_run.is_some()
            || req.minimum_age_days.is_some()
            || req.keep_latest.is_some()
            || req.preview_token.is_some();
        if target != CleanupTarget::Exports && has_export_policy {
            return Err(ApiError::Unprocessable(
                "cleanup retention policy options are supported only for exports".to_owned(),
            ));
        }

        let minimum_age = req
            .minimum_age_days
            .map(|days| {
                days.checked_mul(24 * 60 * 60)
                    .map(Duration::from_secs)
                    .ok_or_else(|| {
                        ApiError::Unprocessable(
                            "minimum_age_days is too large to evaluate".to_owned(),
                        )
                    })
            })
            .transpose()?;

        Ok(Self {
            dry_run: req.dry_run.unwrap_or(false),
            request_policy: CleanupRequestPolicy::from_request(req),
            minimum_age,
            keep_latest: req.keep_latest.unwrap_or(0),
            retained_files: BTreeSet::new(),
            now: SystemTime::now(),
        })
    }

    fn should_delete_file(&self, path: &Path, meta: &fs::Metadata) -> bool {
        if self.retained_files.contains(path) {
            return false;
        }
        let Some(minimum_age) = self.minimum_age else {
            return true;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        self.now
            .duration_since(modified)
            .is_ok_and(|age| age >= minimum_age)
    }
}

/// `GET /v1/data/status` - read-only storage and data-directory telemetry.
pub async fn get_data_status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DataStatusResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;

    let data_dir = state.data_dir();
    let data_dir_configured = data_dir.is_some();
    let store = state.store.clone();
    let durable_store_open = store.is_some();
    let active_backend_family = durable_store_open.then_some(if state.sidecars_db_backed {
        DurableBackendFamily::Postgres
    } else {
        DurableBackendFamily::Sqlite
    });
    let sidecar_storage_mode = if state.sidecars_db_backed {
        SidecarStorageMode::Database
    } else if data_dir_configured {
        SidecarStorageMode::File
    } else {
        SidecarStorageMode::InMemory
    };
    let mode = match (data_dir_configured, durable_store_open) {
        (_, true) => PersistenceMode::Durable,
        (true, false) => PersistenceMode::FallbackInMemory,
        (false, false) => PersistenceMode::InMemory,
    };
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let degraded = *state.degraded.read().await;
    let database_encryption_configured = state.database_encryption_configured;
    let database_encryption_key_source = state.database_encryption_key_source;
    let mut sidecar_scan_errors = Vec::new();
    let sidecars = if state.sidecars_db_backed {
        db_backed_sidecar_usage(&state, &mut sidecar_scan_errors).await
    } else {
        Vec::new()
    };

    let (mut fs, database_encryption) = match data_dir {
        Some(dir) => task::spawn_blocking(move || {
            let database_encryption = inspect_database_encryption(
                Some(&dir),
                database_encryption_configured,
                database_encryption_key_source,
            );
            (inspect_data_dir(dir, store), database_encryption)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("data status worker failed: {e}")))?,
        None => (
            inspect_unconfigured_data_dir(durable_store_open),
            inspect_database_encryption(
                None,
                database_encryption_configured,
                database_encryption_key_source,
            ),
        ),
    };
    fs.usage.sidecars = sidecars;
    fs.usage.scan_errors.append(&mut sidecar_scan_errors);

    Ok(Json(DataStatusResponse {
        generated_at: now_rfc3339(),
        persistence: PersistenceStatus {
            mode,
            data_dir_configured,
            durable_store_open,
            active_backend_family,
            sidecar_storage_mode,
            database_encryption_configured,
            database_encryption,
            store_schema_version: durable_store_open
                .then_some(chancela_store::schema::SCHEMA_VERSION),
            ledger_length,
            ledger_verified,
            degraded,
        },
        data_dir: fs.data_dir,
        permissions: fs.permissions,
        usage: fs.usage,
    }))
}

/// `POST /v1/data/cleanup` - bounded storage cleanup for crash reports or retained exports.
pub async fn cleanup_data(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<DataCleanupRequest>,
) -> Result<Json<DataCleanupResponse>, ApiError> {
    // Storage maintenance is a settings/data-management operation: not public, and stronger than
    // the read-only status view, but intentionally below the full data.wipe destructive reset rail.
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let target = parse_cleanup_target(&req.target)?;
    let policy = CleanupPolicy::from_request(target, &req)?;
    let Some(data_dir) = state.data_dir() else {
        return Err(ApiError::Unprocessable(
            "storage cleanup requires on-disk persistence; set CHANCELA_DATA_DIR".to_owned(),
        ));
    };
    let data_dir_display = data_dir.to_string_lossy().into_owned();

    if target == CleanupTarget::Exports && policy.dry_run {
        let mut preview =
            task::spawn_blocking(move || preview_export_cleanup_data_dir(data_dir, policy))
                .await
                .map_err(|e| ApiError::Internal(format!("data cleanup worker failed: {e}")))??;
        let token = uuid::Uuid::new_v4().to_string();
        preview.response.preview_token = Some(token.clone());
        preview.response.data_dir = Some(data_dir_display);
        let now = SystemTime::now();
        {
            let mut previews = state.export_cleanup_previews.write().await;
            prune_expired_export_cleanup_previews(&mut previews.records, now);
            previews.records.insert(token, preview.record);
        }
        return Ok(Json(preview.response));
    }

    if target == CleanupTarget::Exports {
        let token = req
            .preview_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ApiError::Unprocessable(
                    "export cleanup execution requires a valid preview_token from a dry-run preview"
                        .to_owned(),
                )
            })?
            .to_owned();
        let data_dir_for_canonical = data_dir.clone();
        let base = task::spawn_blocking(move || canonical_data_dir(&data_dir_for_canonical))
            .await
            .map_err(|e| ApiError::Internal(format!("data cleanup worker failed: {e}")))??;
        let record = consume_export_cleanup_preview(&state, &token, &base, &policy).await?;
        let mut response =
            task::spawn_blocking(move || execute_export_cleanup_manifest(base, record))
                .await
                .map_err(|e| ApiError::Internal(format!("data cleanup worker failed: {e}")))??;
        response.data_dir = Some(data_dir_display);
        return Ok(Json(response));
    }

    let mut response = task::spawn_blocking(move || cleanup_data_dir(data_dir, target, policy))
        .await
        .map_err(|e| ApiError::Internal(format!("data cleanup worker failed: {e}")))??;
    response.data_dir = Some(data_dir_display);
    Ok(Json(response))
}

/// `POST /v1/data/key-rotation/preflight` - read-only SQLCipher rekey readiness check.
pub async fn preflight_data_key_rotation(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<DataKeyRotationPreflightRequest>,
) -> Result<Json<StoreKeyRotationPreflight>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsManage, Scope::Global).await?;

    let Some(data_dir) = state.data_dir() else {
        return Err(ApiError::Unprocessable(
            "data key-rotation preflight requires on-disk persistence; set CHANCELA_DATA_DIR"
                .to_owned(),
        ));
    };

    let DataKeyRotationPreflightRequest {
        current_key,
        new_key,
    } = req;
    let current_options = match current_key {
        Some(key) => StoreOpenOptions::new().with_encryption_key(key),
        None => StoreOpenOptions::default(),
    };
    let new_key = new_key.unwrap_or_default();

    let preflight = task::spawn_blocking(move || {
        Store::key_rotation_preflight(&data_dir, &current_options, &new_key)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("data key-rotation preflight worker failed: {e}")))?
    .map_err(map_key_rotation_preflight_error)?;

    Ok(Json(preflight))
}

/// `POST /v1/data/key-rotation` - guarded SQLCipher rekey execution for an already-open keyed store.
pub async fn execute_data_key_rotation(
    State(state): State<AppState>,
    actor: CurrentActor,
    Json(req): Json<DataKeyRotationExecuteRequest>,
) -> Result<Json<StoreKeyRotationExecution>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    // Execution is intentionally interactive-session-only. API-key principals may run the
    // read-only preflight if granted settings.manage, but not mutate the data-store key.
    authz.principal()?;
    authz.require(Permission::SettingsManage, Scope::Global)?;

    let Some(data_dir) = state.data_dir() else {
        return Err(ApiError::Unprocessable(
            "data key-rotation requires on-disk persistence; set CHANCELA_DATA_DIR".to_owned(),
        ));
    };
    if !state.database_encryption_configured {
        return Err(ApiError::Unprocessable(
            "data key-rotation execution requires an already-open SQLCipher store; plaintext stores must use the supported backup/export-restore migration plan".to_owned(),
        ));
    }
    let Some(store) = state.store.clone() else {
        return Err(ApiError::Unprocessable(
            "data key-rotation execution requires a durable store that is already open".to_owned(),
        ));
    };

    let new_key = req.new_key.unwrap_or_default();
    let current_options = StoreOpenOptions::new().with_encryption_key("<configured>");
    let preflight = Store::key_rotation_preflight(&data_dir, &current_options, &new_key)
        .map_err(map_key_rotation_preflight_error)?;
    if !preflight.ready() {
        return Err(ApiError::Unprocessable(format!(
            "data key-rotation execution refused by preflight status {:?}; no rekey was attempted",
            preflight.status
        )));
    }

    let execution =
        task::spawn_blocking(move || store.rotate_encryption_key_with_evidence(&new_key))
            .await
            .map_err(|e| ApiError::Internal(format!("data key-rotation worker failed: {e}")))?
            .map_err(map_key_rotation_execution_error)?;

    Ok(Json(execution))
}

fn map_key_rotation_preflight_error(_e: StoreError) -> ApiError {
    ApiError::Unprocessable(
        "data key-rotation preflight could not inspect the durable database".to_owned(),
    )
}

fn map_key_rotation_execution_error(e: StoreError) -> ApiError {
    match e {
        StoreError::EmptyEncryptionKey => ApiError::Unprocessable(
            "data key-rotation replacement key must not be empty".to_owned(),
        ),
        StoreError::EncryptionUnavailable => ApiError::Unprocessable(
            "data key-rotation execution requires a SQLCipher-enabled build".to_owned(),
        ),
        StoreError::EncryptionKeyRejected { .. } => ApiError::Unprocessable(
            "data key-rotation execution was rejected by SQLCipher or the store could not be verified after rekey".to_owned(),
        ),
        _ => ApiError::Internal("data key-rotation execution failed".to_owned()),
    }
}

fn parse_cleanup_target(raw: &str) -> Result<CleanupTarget, ApiError> {
    match raw.trim() {
        "crash" => Ok(CleanupTarget::Crash),
        "exports" => Ok(CleanupTarget::Exports),
        other => Err(ApiError::Unprocessable(format!(
            "unsupported cleanup target {other:?} (use crash | exports)"
        ))),
    }
}

fn cleanup_data_dir(
    data_dir: PathBuf,
    target: CleanupTarget,
    mut policy: CleanupPolicy,
) -> Result<DataCleanupResponse, ApiError> {
    Ok(cleanup_data_dir_inner(data_dir, target, &mut policy)?.response)
}

fn preview_export_cleanup_data_dir(
    data_dir: PathBuf,
    mut policy: CleanupPolicy,
) -> Result<ExportCleanupPreview, ApiError> {
    let run = cleanup_data_dir_inner(data_dir, CleanupTarget::Exports, &mut policy)?;
    let expires_at = SystemTime::now()
        .checked_add(EXPORT_CLEANUP_PREVIEW_TTL)
        .unwrap_or(UNIX_EPOCH + EXPORT_CLEANUP_PREVIEW_TTL);
    Ok(ExportCleanupPreview {
        response: run.response,
        record: ExportCleanupPreviewRecord {
            data_dir: run.base,
            policy: policy.request_policy,
            manifest: run.manifest,
            expires_at,
        },
    })
}

struct CleanupDataRun {
    base: PathBuf,
    response: DataCleanupResponse,
    manifest: CleanupSelectionManifest,
}

fn cleanup_data_dir_inner(
    data_dir: PathBuf,
    target: CleanupTarget,
    policy: &mut CleanupPolicy,
) -> Result<CleanupDataRun, ApiError> {
    let base = canonical_data_dir(&data_dir)?;
    let mut response = DataCleanupResponse {
        target: target.id().to_owned(),
        dry_run: policy.dry_run,
        preview_token: None,
        deleted_bytes: 0,
        deleted_files: 0,
        deleted_directories: 0,
        would_delete_bytes: 0,
        would_delete_files: 0,
        would_delete_directories: 0,
        skipped: Vec::new(),
        data_dir: None,
    };
    let mut manifest = CleanupSelectionManifest::default();

    let entries = fs::read_dir(&base).map_err(|e| {
        ApiError::Unprocessable(format!(
            "data directory cannot be read for cleanup ({}): {e}",
            base.display()
        ))
    })?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                response
                    .skipped
                    .push(format!("failed to read a data-directory entry: {e}"));
                continue;
            }
        };
        let root = entry.file_name().to_string_lossy().into_owned();
        if concern_for_root(&root).id == target.id() {
            if target == CleanupTarget::Exports && policy.keep_latest > 0 {
                let keep_latest = policy.keep_latest;
                retain_latest_files(&base, &entry.path(), keep_latest, policy, &mut response);
            }
            cleanup_concern_root(&base, &entry.path(), policy, &mut response, &mut manifest);
        }
    }

    Ok(CleanupDataRun {
        base,
        response,
        manifest,
    })
}

fn canonical_data_dir(dir: &Path) -> Result<PathBuf, ApiError> {
    let base = fs::canonicalize(dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ApiError::Unprocessable(format!("data directory does not exist: {}", dir.display()))
        }
        _ => ApiError::Unprocessable(format!(
            "data directory cannot be resolved for cleanup ({}): {e}",
            dir.display()
        )),
    })?;
    let meta = fs::symlink_metadata(&base).map_err(|e| {
        ApiError::Unprocessable(format!(
            "data directory cannot be inspected for cleanup ({}): {e}",
            base.display()
        ))
    })?;
    if !meta.is_dir() {
        return Err(ApiError::Unprocessable(format!(
            "data directory is not a directory: {}",
            base.display()
        )));
    }
    Ok(base)
}

fn cleanup_concern_root(
    base: &Path,
    root: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
    manifest: &mut CleanupSelectionManifest,
) {
    let rel = relative_display(base, root);
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup root: {e}"));
            return;
        }
    };
    if meta.file_type().is_symlink() {
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup root"));
        return;
    }
    if let Err(reason) = validate_cleanup_target(base, root) {
        response.skipped.push(format!("{rel}: {reason}"));
        return;
    }

    if meta.is_dir() {
        let _ = cleanup_directory_contents(base, root, policy, response, manifest);
    } else if meta.is_file() {
        let _ = cleanup_file(root, &meta, base, policy, response, manifest);
    } else {
        response
            .skipped
            .push(format!("{rel}: unsupported filesystem entry type"));
    }
}

fn cleanup_directory_contents(
    base: &Path,
    dir: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
    manifest: &mut CleanupSelectionManifest,
) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            response.skipped.push(format!(
                "{}: failed to read cleanup directory: {e}",
                relative_display(base, dir)
            ));
            return false;
        }
    };

    let mut all_entries_removed = true;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                response.skipped.push(format!(
                    "{}: failed to read cleanup directory entry: {e}",
                    relative_display(base, dir)
                ));
                all_entries_removed = false;
                continue;
            }
        };
        if !cleanup_path(base, &entry.path(), policy, response, manifest) {
            all_entries_removed = false;
        }
    }
    all_entries_removed
}

fn cleanup_path(
    base: &Path,
    path: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
    manifest: &mut CleanupSelectionManifest,
) -> bool {
    let rel = relative_display(base, path);
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup target: {e}"));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup target"));
        return false;
    }
    if let Err(reason) = validate_cleanup_target(base, path) {
        response.skipped.push(format!("{rel}: {reason}"));
        return false;
    }

    if meta.is_dir() {
        let contents_removed = cleanup_directory_contents(base, path, policy, response, manifest);
        if policy.dry_run {
            if contents_removed {
                response.would_delete_directories =
                    response.would_delete_directories.saturating_add(1);
                manifest.directories.push(CleanupDirectoryCandidate {
                    path: path.to_path_buf(),
                    modified: meta.modified().ok(),
                });
                return true;
            }
            return false;
        }
        match fs::remove_dir(path) {
            Ok(()) => {
                response.deleted_directories = response.deleted_directories.saturating_add(1);
                true
            }
            Err(e) => {
                response
                    .skipped
                    .push(format!("{rel}: failed to delete directory: {e}"));
                false
            }
        }
    } else if meta.is_file() {
        cleanup_file(path, &meta, base, policy, response, manifest)
    } else {
        response
            .skipped
            .push(format!("{rel}: unsupported filesystem entry type"));
        false
    }
}

fn cleanup_file(
    path: &Path,
    meta: &fs::Metadata,
    base: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
    manifest: &mut CleanupSelectionManifest,
) -> bool {
    if !policy.should_delete_file(path, meta) {
        return false;
    }
    if policy.dry_run {
        let rel = relative_display(base, path);
        let sha256 = match sha256_file(path) {
            Ok(sha256) => sha256,
            Err(e) => {
                response.skipped.push(format!(
                    "{rel}: failed to hash cleanup target during preview: {e}"
                ));
                return false;
            }
        };
        manifest.files.push(CleanupFileCandidate {
            path: path.to_path_buf(),
            bytes: meta.len(),
            modified: meta.modified().ok(),
            sha256,
        });
        response.would_delete_files = response.would_delete_files.saturating_add(1);
        response.would_delete_bytes = response.would_delete_bytes.saturating_add(meta.len());
        return true;
    }
    delete_file(path, meta.len(), base, response)
}

fn delete_file(path: &Path, bytes: u64, base: &Path, response: &mut DataCleanupResponse) -> bool {
    let rel = relative_display(base, path);
    match fs::remove_file(path) {
        Ok(()) => {
            response.deleted_files = response.deleted_files.saturating_add(1);
            response.deleted_bytes = response.deleted_bytes.saturating_add(bytes);
            true
        }
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to delete file: {e}"));
            false
        }
    }
}

fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

async fn consume_export_cleanup_preview(
    state: &AppState,
    token: &str,
    data_dir: &Path,
    policy: &CleanupPolicy,
) -> Result<ExportCleanupPreviewRecord, ApiError> {
    let now = SystemTime::now();
    let mut previews = state.export_cleanup_previews.write().await;
    prune_expired_export_cleanup_previews(&mut previews.records, now);
    let Some(record) = previews.records.remove(token) else {
        return Err(ApiError::Unprocessable(
            "export cleanup preview_token is invalid or expired; run preview again".to_owned(),
        ));
    };
    if record.expires_at <= now {
        return Err(ApiError::Unprocessable(
            "export cleanup preview_token expired; run preview again".to_owned(),
        ));
    }
    if record.data_dir != data_dir {
        return Err(ApiError::Unprocessable(
            "export cleanup preview_token does not match the current data directory; run preview again"
                .to_owned(),
        ));
    }
    if record.policy != policy.request_policy {
        return Err(ApiError::Unprocessable(
            "export cleanup preview_token does not match the requested cleanup policy; run preview again"
                .to_owned(),
        ));
    }
    Ok(record)
}

fn prune_expired_export_cleanup_previews(
    previews: &mut HashMap<String, ExportCleanupPreviewRecord>,
    now: SystemTime,
) {
    previews.retain(|_, preview| preview.expires_at > now);
}

fn execute_export_cleanup_manifest(
    base: PathBuf,
    record: ExportCleanupPreviewRecord,
) -> Result<DataCleanupResponse, ApiError> {
    if record.data_dir != base {
        return Err(ApiError::Unprocessable(
            "export cleanup preview_token does not match the current data directory; run preview again"
                .to_owned(),
        ));
    }
    let mut response = DataCleanupResponse {
        target: CleanupTarget::Exports.id().to_owned(),
        dry_run: false,
        preview_token: None,
        deleted_bytes: 0,
        deleted_files: 0,
        deleted_directories: 0,
        would_delete_bytes: 0,
        would_delete_files: 0,
        would_delete_directories: 0,
        skipped: Vec::new(),
        data_dir: None,
    };

    let skipped_directories =
        prevalidate_manifest_directories(&base, &record.manifest.directories, &mut response);
    let directories_with_selected_descendants =
        directories_with_selected_descendants(&record.manifest);

    for candidate in &record.manifest.files {
        delete_manifest_file(&base, candidate, &skipped_directories, &mut response);
    }

    let mut directories = record.manifest.directories;
    directories.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| left.path.as_os_str().cmp(right.path.as_os_str()))
    });
    for candidate in directories {
        let selected_descendant_was_removed =
            directories_with_selected_descendants.contains(&candidate.path);
        delete_manifest_directory(
            &base,
            &candidate,
            &skipped_directories,
            selected_descendant_was_removed,
            &mut response,
        );
    }

    Ok(response)
}

fn directories_with_selected_descendants(manifest: &CleanupSelectionManifest) -> BTreeSet<PathBuf> {
    let mut directories = BTreeSet::new();
    for directory in &manifest.directories {
        if manifest
            .files
            .iter()
            .any(|file| file.path.starts_with(&directory.path))
            || manifest.directories.iter().any(|child| {
                child.path != directory.path && child.path.starts_with(&directory.path)
            })
        {
            directories.insert(directory.path.clone());
        }
    }
    directories
}

fn prevalidate_manifest_directories(
    base: &Path,
    candidates: &[CleanupDirectoryCandidate],
    response: &mut DataCleanupResponse,
) -> BTreeSet<PathBuf> {
    let mut skipped = BTreeSet::new();
    for candidate in candidates {
        if !manifest_directory_metadata_matches_preview(base, candidate, response) {
            skipped.insert(candidate.path.clone());
        }
    }
    skipped
}

fn manifest_directory_metadata_matches_preview(
    base: &Path,
    candidate: &CleanupDirectoryCandidate,
    response: &mut DataCleanupResponse,
) -> bool {
    let path = &candidate.path;
    let rel = relative_display(base, path);
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup directory: {e}"));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup directory"));
        return false;
    }
    if let Err(reason) = validate_cleanup_target(base, path) {
        response.skipped.push(format!("{rel}: {reason}"));
        return false;
    }
    if !meta.is_dir() {
        response
            .skipped
            .push(format!("{rel}: cleanup target is no longer a directory"));
        return false;
    }
    let Some(preview_modified) = candidate.modified else {
        response.skipped.push(format!(
            "{rel}: cleanup directory metadata unavailable since preview"
        ));
        return false;
    };
    match meta.modified() {
        Ok(current_modified) if current_modified == preview_modified => true,
        Ok(_) => {
            response.skipped.push(format!(
                "{rel}: cleanup directory metadata changed since preview"
            ));
            false
        }
        Err(e) => {
            response.skipped.push(format!(
                "{rel}: cleanup directory metadata unavailable during execution: {e}"
            ));
            false
        }
    }
}

fn path_is_within_skipped_directory(path: &Path, skipped_directories: &BTreeSet<PathBuf>) -> bool {
    skipped_directories
        .iter()
        .any(|directory| path.starts_with(directory))
}

fn delete_manifest_file(
    base: &Path,
    candidate: &CleanupFileCandidate,
    skipped_directories: &BTreeSet<PathBuf>,
    response: &mut DataCleanupResponse,
) -> bool {
    let path = &candidate.path;
    let rel = relative_display(base, path);
    if path_is_within_skipped_directory(path, skipped_directories) {
        response.skipped.push(format!(
            "{rel}: skipped because containing directory changed since preview"
        ));
        return false;
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup target: {e}"));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup target"));
        return false;
    }
    if let Err(reason) = validate_cleanup_target(base, path) {
        response.skipped.push(format!("{rel}: {reason}"));
        return false;
    }
    if !meta.is_file() {
        response
            .skipped
            .push(format!("{rel}: cleanup target is no longer a file"));
        return false;
    }
    if meta.len() != candidate.bytes {
        response.skipped.push(format!(
            "{rel}: cleanup target metadata changed since preview"
        ));
        return false;
    }
    if let Some(preview_modified) = candidate.modified {
        match meta.modified() {
            Ok(current_modified) if current_modified == preview_modified => {}
            _ => {
                response.skipped.push(format!(
                    "{rel}: cleanup target metadata changed since preview"
                ));
                return false;
            }
        }
    }
    let current_sha256 = match sha256_file(path) {
        Ok(hash) => hash,
        Err(e) => {
            response.skipped.push(format!(
                "{rel}: failed to hash cleanup target during execution: {e}"
            ));
            return false;
        }
    };
    if current_sha256 != candidate.sha256 {
        response.skipped.push(format!(
            "{rel}: cleanup target content changed since preview"
        ));
        return false;
    }
    delete_file(path, candidate.bytes, base, response)
}

fn delete_manifest_directory(
    base: &Path,
    candidate: &CleanupDirectoryCandidate,
    skipped_directories: &BTreeSet<PathBuf>,
    selected_descendant_was_removed: bool,
    response: &mut DataCleanupResponse,
) -> bool {
    let path = &candidate.path;
    let rel = relative_display(base, path);
    if skipped_directories.contains(path) {
        return false;
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup target: {e}"));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup target"));
        return false;
    }
    if let Err(reason) = validate_cleanup_target(base, path) {
        response.skipped.push(format!("{rel}: {reason}"));
        return false;
    }
    if !meta.is_dir() {
        response
            .skipped
            .push(format!("{rel}: cleanup target is no longer a directory"));
        return false;
    }
    let current_modified = match meta.modified() {
        Ok(modified) => modified,
        Err(e) => {
            response.skipped.push(format!(
                "{rel}: cleanup directory metadata unavailable during execution: {e}"
            ));
            return false;
        }
    };
    if !selected_descendant_was_removed {
        match candidate.modified {
            Some(preview_modified) if current_modified == preview_modified => {}
            Some(_) => {
                response.skipped.push(format!(
                    "{rel}: cleanup directory metadata changed since preview"
                ));
                return false;
            }
            None => {
                response.skipped.push(format!(
                    "{rel}: cleanup directory metadata unavailable since preview"
                ));
                return false;
            }
        }
    }
    match fs::remove_dir(path) {
        Ok(()) => {
            response.deleted_directories = response.deleted_directories.saturating_add(1);
            true
        }
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to delete directory: {e}"));
            false
        }
    }
}

fn validate_cleanup_target(base: &Path, target: &Path) -> Result<(), String> {
    let resolved = fs::canonicalize(target)
        .map_err(|e| format!("cleanup target could not be resolved: {e}"))?;
    if resolved == base {
        return Err("refusing to clean the data-directory root".to_owned());
    }
    if !resolved.starts_with(base) {
        return Err(format!(
            "protected target resolved outside the data directory ({})",
            resolved.display()
        ));
    }
    Ok(())
}

fn retain_latest_files(
    base: &Path,
    root: &Path,
    keep_latest: usize,
    policy: &mut CleanupPolicy,
    response: &mut DataCleanupResponse,
) {
    let mut files = Vec::new();
    collect_cleanup_files(base, root, response, &mut files);
    files.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.as_os_str().cmp(right.1.as_os_str()))
    });
    policy
        .retained_files
        .extend(files.into_iter().take(keep_latest).map(|(_, path)| path));
}

fn collect_cleanup_files(
    base: &Path,
    path: &Path,
    response: &mut DataCleanupResponse,
    files: &mut Vec<(SystemTime, PathBuf)>,
) {
    let rel = relative_display(base, path);
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            response
                .skipped
                .push(format!("{rel}: failed to inspect cleanup target: {e}"));
            return;
        }
    };
    if meta.file_type().is_symlink() {
        return;
    }
    if validate_cleanup_target(base, path).is_err() {
        return;
    }

    if meta.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) => {
                response.skipped.push(format!(
                    "{}: failed to read cleanup directory: {e}",
                    relative_display(base, path)
                ));
                return;
            }
        };
        for entry in entries {
            match entry {
                Ok(entry) => collect_cleanup_files(base, &entry.path(), response, files),
                Err(e) => response.skipped.push(format!(
                    "{}: failed to read cleanup directory entry: {e}",
                    relative_display(base, path)
                )),
            }
        }
    } else if meta.is_file() {
        files.push((meta.modified().unwrap_or(UNIX_EPOCH), path.to_path_buf()));
    }
}

fn inspect_unconfigured_data_dir(durable_store_open: bool) -> FsInspection {
    FsInspection {
        data_dir: DataDirStatus {
            path: None,
            exists: None,
            is_directory: None,
        },
        permissions: PermissionStatus {
            read_dir: unchecked("no data directory configured"),
            create_file: unchecked("no data directory configured"),
            write_file: unchecked("no data directory configured"),
            delete_probe_file: unchecked("no data directory configured"),
            durable_store_open: PermissionCheck {
                ok: durable_store_open,
                checked: true,
                message: if durable_store_open {
                    "durable store is open".to_owned()
                } else {
                    "durable store is not open because no data directory is configured".to_owned()
                },
            },
            sqlite_store_open: PermissionCheck {
                ok: durable_store_open,
                checked: true,
                message: if durable_store_open {
                    "durable SQLite store is open".to_owned()
                } else {
                    "durable SQLite store is not open because no data directory is configured"
                        .to_owned()
                },
            },
        },
        usage: UsageStatus {
            total_bytes: 0,
            filesystem: Vec::new(),
            logical_payload: Vec::new(),
            sidecars: Vec::new(),
            largest_payload_table: None,
            sqlite_logical: Vec::new(),
            sqlite_largest_payload_table: None,
            scan_errors: Vec::new(),
        },
    }
}

fn inspect_data_dir(dir: PathBuf, store: Option<chancela_store::Store>) -> FsInspection {
    let durable_store_open = store.is_some();
    let mut scan_errors = Vec::new();
    let (exists, is_directory) = match fs::symlink_metadata(&dir) {
        Ok(meta) => (Some(true), Some(meta.is_dir())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Some(false), Some(false)),
        Err(e) => {
            scan_errors.push(format!(
                "failed to inspect data directory {}: {e}",
                dir.display()
            ));
            (None, None)
        }
    };

    let permissions = probe_permissions(&dir, durable_store_open);
    let mut usage = scan_filesystem_usage(&dir);
    if let Some(store) = store.as_ref() {
        usage.sqlite_logical = scan_sqlite_logical_usage(store, &mut usage.scan_errors);
        usage.sqlite_largest_payload_table = largest_sqlite_payload_table(&usage.sqlite_logical);
        usage.logical_payload = neutral_logical_usage(&usage.sqlite_logical);
        usage.largest_payload_table = usage
            .sqlite_largest_payload_table
            .as_ref()
            .map(neutral_payload_stats);
    }
    scan_errors.append(&mut usage.scan_errors);
    usage.scan_errors = scan_errors;

    FsInspection {
        data_dir: DataDirStatus {
            path: Some(dir.to_string_lossy().into_owned()),
            exists,
            is_directory,
        },
        permissions,
        usage,
    }
}

fn inspect_database_encryption(
    data_dir: Option<&Path>,
    configured: bool,
    key_source: Option<DatabaseEncryptionKeySource>,
) -> DatabaseEncryptionStatus {
    let sqlcipher_available = cfg!(feature = "sqlcipher");
    let key_ops_result = data_dir.map(|dir| {
        let options = if configured || key_source.is_some() {
            StoreOpenOptions::new().with_encryption_key("<configured>")
        } else {
            StoreOpenOptions::default()
        };
        Store::key_ops_status(dir, &options)
    });
    let (key_ops, key_ops_error) = match key_ops_result {
        Some(Ok(status)) => (Some(status), None),
        Some(Err(err)) => (
            None,
            Some(format!(
                "database encryption status could not inspect store key-ops: {err}"
            )),
        ),
        None => (None, None),
    };
    let database_format = key_ops.as_ref().map(|status| status.database_format);
    let key_ops_plan = key_ops.as_ref().map(|status| status.plan);
    let sqlcipher_backed = configured && sqlcipher_available;
    let plaintext_migration_pending =
        database_format == Some(StoreDatabaseFormat::PlaintextSqlite) && !sqlcipher_backed;
    let plaintext_migration_blocked =
        key_ops_plan == Some(StoreKeyOpsPlan::RefusePlaintextToEncryptedMigration);
    let selected_hardware_fallback =
        key_source == Some(DatabaseEncryptionKeySource::HardwareDerivedFallback);

    DatabaseEncryptionStatus {
        configured,
        sqlcipher_available,
        sqlcipher_backed,
        key_source: key_source.into(),
        hardware_derived_fallback: HardwareDerivedFallbackStatus {
            available: false,
            selected: selected_hardware_fallback,
            fail_closed_if_requested: true,
            status: "unavailable",
            message: "No hardware-bound database key derivation provider is wired; requests for it fail closed instead of using a static fallback key.",
        },
        database_format,
        key_ops_plan,
        plaintext_migration_pending,
        plaintext_migration_blocked,
        key_ops,
        key_ops_error,
    }
}

fn probe_permissions(dir: &Path, durable_store_open: bool) -> PermissionStatus {
    let read_dir = match fs::read_dir(dir) {
        Ok(_) => ok("directory can be read"),
        Err(e) => failed(format!("directory cannot be read: {e}")),
    };

    let probe = dir.join(probe_file_name());
    let (create_file, write_file, delete_probe_file) =
        match OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(mut file) => {
                let create = ok("probe file can be created");
                let write = match file
                    .write_all(b"chancela data status probe\n")
                    .and_then(|_| file.flush())
                {
                    Ok(()) => ok("probe file can be written"),
                    Err(e) => failed(format!("probe file cannot be written: {e}")),
                };
                drop(file);
                let delete = match fs::remove_file(&probe) {
                    Ok(()) => ok("probe file can be deleted"),
                    Err(e) => failed(format!("probe file could not be deleted: {e}")),
                };
                (create, write, delete)
            }
            Err(e) => (
                failed(format!("probe file cannot be created: {e}")),
                unchecked("write probe skipped because the probe file could not be created"),
                unchecked("delete probe skipped because the probe file could not be created"),
            ),
        };

    PermissionStatus {
        read_dir,
        create_file,
        write_file,
        delete_probe_file,
        durable_store_open: PermissionCheck {
            ok: durable_store_open,
            checked: true,
            message: if durable_store_open {
                "durable store is open".to_owned()
            } else {
                "durable store is not open".to_owned()
            },
        },
        sqlite_store_open: PermissionCheck {
            ok: durable_store_open,
            checked: true,
            message: if durable_store_open {
                "durable SQLite store is open".to_owned()
            } else {
                "durable SQLite store is not open".to_owned()
            },
        },
    }
}

fn scan_filesystem_usage(dir: &Path) -> UsageStatus {
    let mut accumulators: BTreeMap<&'static str, (ConcernDef, ConcernAccumulator)> =
        BTreeMap::new();
    let mut scan_errors = Vec::new();

    if !dir.is_dir() {
        return UsageStatus {
            total_bytes: 0,
            filesystem: Vec::new(),
            logical_payload: Vec::new(),
            sidecars: Vec::new(),
            largest_payload_table: None,
            sqlite_logical: Vec::new(),
            sqlite_largest_payload_table: None,
            scan_errors,
        };
    }

    scan_dir(dir, dir, &mut accumulators, &mut scan_errors);
    let mut filesystem = Vec::new();
    let mut total_bytes = 0_u64;
    for (_id, (def, acc)) in accumulators {
        total_bytes = total_bytes.saturating_add(acc.bytes);
        filesystem.push(ConcernUsage {
            id: def.id.to_owned(),
            kind: None,
            label: def.label.to_owned(),
            bytes: acc.bytes,
            basis: def.basis,
            exact: true,
            file_count: acc.file_count,
            directory_count: acc.directory_count,
            row_count: None,
            payload_stats: None,
            relative_roots: acc.relative_roots.into_keys().collect(),
        });
    }

    UsageStatus {
        total_bytes,
        filesystem,
        logical_payload: Vec::new(),
        sidecars: Vec::new(),
        largest_payload_table: None,
        sqlite_logical: Vec::new(),
        sqlite_largest_payload_table: None,
        scan_errors,
    }
}

fn scan_sqlite_logical_usage(
    store: &chancela_store::Store,
    scan_errors: &mut Vec<String>,
) -> Vec<ConcernUsage> {
    let loaded = match store.load() {
        Ok(loaded) => loaded,
        Err(e) => {
            scan_errors.push(format!("failed to read SQLite logical usage: {e}"));
            return Vec::new();
        }
    };

    let mut usage = Vec::new();
    let mut table_usage = Vec::new();

    let ledger_bytes = loaded
        .ledger
        .events()
        .iter()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
    table_usage.push(sqlite_logical_table(
        "events",
        loaded.ledger.len() as u64,
        ledger_bytes,
    ));
    usage.push(sqlite_logical_concern(
        "ledger",
        "Ledger events",
        loaded.ledger.len() as u64,
        ledger_bytes,
        vec!["events"],
    ));

    let entity_bytes = loaded
        .entities
        .values()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
    let book_bytes = loaded
        .books
        .values()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
    let act_bytes = loaded
        .acts
        .values()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
    table_usage.push(sqlite_logical_table(
        "entities",
        loaded.entities.len() as u64,
        entity_bytes,
    ));
    table_usage.push(sqlite_logical_table(
        "books",
        loaded.books.len() as u64,
        book_bytes,
    ));
    table_usage.push(sqlite_logical_table(
        "acts",
        loaded.acts.len() as u64,
        act_bytes,
    ));
    usage.push(sqlite_logical_concern(
        "domain",
        "Domain records",
        (loaded.entities.len() + loaded.books.len() + loaded.acts.len()) as u64,
        entity_bytes
            .saturating_add(book_bytes)
            .saturating_add(act_bytes),
        vec!["entities", "books", "acts"],
    ));

    let registry_bytes = loaded
        .registry_extracts
        .values()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
    table_usage.push(sqlite_logical_table(
        "registry_extracts",
        loaded.registry_extracts.len() as u64,
        registry_bytes,
    ));
    usage.push(sqlite_logical_concern(
        "registry",
        "Registry extracts",
        loaded.registry_extracts.len() as u64,
        registry_bytes,
        vec!["registry_extracts"],
    ));

    let follow_up_bytes = loaded
        .follow_ups
        .values()
        .map(follow_up_len_estimate)
        .fold(0_u64, u64::saturating_add);
    table_usage.push(sqlite_logical_table(
        "follow_ups",
        loaded.follow_ups.len() as u64,
        follow_up_bytes,
    ));
    usage.push(sqlite_logical_concern(
        "follow_ups",
        "Follow-ups",
        loaded.follow_ups.len() as u64,
        follow_up_bytes,
        vec!["follow_ups"],
    ));

    let mut document_rows = 0_u64;
    let mut document_bytes = 0_u64;
    for act_id in loaded.acts.keys().copied() {
        match store.documents_for_act(act_id) {
            Ok(docs) => {
                document_rows = document_rows.saturating_add(docs.len() as u64);
                document_bytes = document_bytes.saturating_add(
                    docs.iter()
                        .map(stored_document_len_estimate)
                        .fold(0_u64, u64::saturating_add),
                );
            }
            Err(e) => scan_errors.push(format!(
                "failed to read SQLite logical usage for documents: {e}"
            )),
        }
    }
    table_usage.push(sqlite_logical_table(
        "documents",
        document_rows,
        document_bytes,
    ));
    usage.push(sqlite_logical_concern(
        "documents",
        "Generated documents",
        document_rows,
        document_bytes,
        vec!["documents"],
    ));

    match store.all_signed_documents() {
        Ok(signed) => {
            let bytes = signed
                .values()
                .map(signed_document_len_estimate)
                .fold(0_u64, u64::saturating_add);
            table_usage.push(sqlite_logical_table(
                "signed_documents",
                signed.len() as u64,
                bytes,
            ));
            usage.push(sqlite_logical_concern(
                "signed_documents",
                "Signed documents",
                signed.len() as u64,
                bytes,
                vec!["signed_documents"],
            ));
        }
        Err(e) => scan_errors.push(format!(
            "failed to read SQLite logical usage for signed_documents: {e}"
        )),
    }

    match store.all_pending_cmd_sessions() {
        Ok(pending) => {
            let bytes = pending
                .values()
                .map(pending_session_len_estimate)
                .fold(0_u64, u64::saturating_add);
            table_usage.push(sqlite_logical_table(
                "pending_cmd_sessions",
                pending.len() as u64,
                bytes,
            ));
            usage.push(sqlite_logical_concern(
                "pending_signatures",
                "Pending signing sessions",
                pending.len() as u64,
                bytes,
                vec!["pending_cmd_sessions"],
            ));
        }
        Err(e) => scan_errors.push(format!(
            "failed to read SQLite logical usage for pending_cmd_sessions: {e}"
        )),
    }

    match store.imported_documents(None) {
        Ok(imports) => {
            let bytes = imports
                .iter()
                .map(imported_document_meta_len_estimate)
                .fold(0_u64, u64::saturating_add);
            table_usage.push(sqlite_logical_table(
                "imported_documents",
                imports.len() as u64,
                bytes,
            ));
            usage.push(sqlite_logical_concern(
                "imported_documents",
                "Imported document evidence",
                imports.len() as u64,
                bytes,
                vec!["imported_documents"],
            ));
        }
        Err(e) => scan_errors.push(format!(
            "failed to read SQLite logical usage for imported_documents: {e}"
        )),
    }

    match store.imported_books() {
        Ok(imports) => {
            let mut bytes = 0_u64;
            for import in &imports {
                bytes = bytes.saturating_add(imported_book_len_estimate(import));
                match store.imported_bundle(&import.import_id) {
                    Ok(Some(bundle)) => {
                        bytes = bytes.saturating_add(bundle.len() as u64);
                    }
                    Ok(None) => scan_errors.push(format!(
                        "imported_books row {} has no retained bundle bytes",
                        import.import_id
                    )),
                    Err(e) => scan_errors.push(format!(
                        "failed to read retained bundle bytes for import {}: {e}",
                        import.import_id
                    )),
                }
            }
            table_usage.push(sqlite_logical_table(
                "imported_books",
                imports.len() as u64,
                bytes,
            ));
            usage.push(sqlite_logical_concern(
                "imported_books",
                "Imported book bundles",
                imports.len() as u64,
                bytes,
                vec!["imported_books"],
            ));
        }
        Err(e) => scan_errors.push(format!(
            "failed to read SQLite logical usage for imported_books: {e}"
        )),
    }

    match store.paper_book_imports(None) {
        Ok(imports) => {
            let bytes = imports
                .iter()
                .map(paper_book_import_meta_len_estimate)
                .fold(0_u64, u64::saturating_add);
            table_usage.push(sqlite_logical_table(
                "paper_book_imports",
                imports.len() as u64,
                bytes,
            ));
            usage.push(sqlite_logical_concern(
                "paper_book_imports",
                "Paper book imports",
                imports.len() as u64,
                bytes,
                vec!["paper_book_imports"],
            ));

            let mut draft_rows = 0_u64;
            let mut draft_bytes = 0_u64;
            for import in imports {
                match store.paper_book_ocr_drafts(&import.import_id) {
                    Ok(drafts) => {
                        draft_rows = draft_rows.saturating_add(drafts.len() as u64);
                        draft_bytes = draft_bytes.saturating_add(
                            drafts
                                .iter()
                                .map(paper_book_ocr_draft_len_estimate)
                                .fold(0_u64, u64::saturating_add),
                        );
                    }
                    Err(e) => scan_errors.push(format!(
                        "failed to read SQLite logical usage for paper_book_ocr_drafts: {e}"
                    )),
                }
            }
            table_usage.push(sqlite_logical_table(
                "paper_book_ocr_drafts",
                draft_rows,
                draft_bytes,
            ));
            usage.push(sqlite_logical_concern(
                "paper_book_ocr_drafts",
                "Paper book OCR drafts",
                draft_rows,
                draft_bytes,
                vec!["paper_book_ocr_drafts"],
            ));
        }
        Err(e) => scan_errors.push(format!(
            "failed to read SQLite logical usage for paper_book_imports: {e}"
        )),
    }

    usage.extend(table_usage);
    usage
}

fn sqlite_logical_concern(
    id: &str,
    label: &str,
    row_count: u64,
    bytes: u64,
    tables: Vec<&str>,
) -> ConcernUsage {
    ConcernUsage {
        id: id.to_owned(),
        kind: None,
        label: label.to_owned(),
        bytes,
        basis: UsageBasis::SqliteLogicalPayload,
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: Some(row_count),
        payload_stats: None,
        relative_roots: tables.into_iter().map(str::to_owned).collect(),
    }
}

fn sqlite_logical_table(table: &str, row_count: u64, bytes: u64) -> ConcernUsage {
    let payload_stats = DataPayloadStats {
        table_name: table.to_owned(),
        estimated_payload_bytes: bytes,
        row_count,
        average_bytes_per_row: (row_count > 0).then(|| bytes / row_count),
        estimate_method: PayloadEstimateMethod::LocalLoadedPayloadEstimate,
        estimate_basis: UsageBasis::SqliteLogicalPayload,
    };
    ConcernUsage {
        id: format!("sqlite_table_{table}"),
        kind: Some(UsageConcernKind::SqliteLogicalTable),
        label: format!("SQLite table: {table}"),
        bytes,
        basis: UsageBasis::SqliteLogicalPayload,
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: Some(row_count),
        payload_stats: Some(payload_stats),
        relative_roots: vec![table.to_owned()],
    }
}

fn largest_sqlite_payload_table(usage: &[ConcernUsage]) -> Option<DataPayloadStats> {
    usage
        .iter()
        .filter_map(|entry| entry.payload_stats.as_ref())
        .max_by_key(|stats| {
            (
                stats.estimated_payload_bytes,
                stats.row_count,
                stats.table_name.len(),
            )
        })
        .cloned()
}

fn neutral_logical_usage(sqlite_usage: &[ConcernUsage]) -> Vec<ConcernUsage> {
    sqlite_usage
        .iter()
        .cloned()
        .map(|mut concern| {
            concern.basis = UsageBasis::LogicalPayload;
            if let Some(stats) = concern.payload_stats.as_mut() {
                stats.estimate_basis = UsageBasis::LogicalPayload;
            }
            if concern.kind == Some(UsageConcernKind::SqliteLogicalTable) {
                if let Some(table) = concern.relative_roots.first() {
                    concern.label = format!("Database table: {table}");
                }
            }
            concern
        })
        .collect()
}

fn neutral_payload_stats(stats: &DataPayloadStats) -> DataPayloadStats {
    let mut stats = stats.clone();
    stats.estimate_basis = UsageBasis::LogicalPayload;
    stats
}

async fn db_backed_sidecar_usage(
    state: &AppState,
    scan_errors: &mut Vec<String>,
) -> Vec<ConcernUsage> {
    let users = {
        let users = state.users.read().await;
        sidecar_logical_concern(
            "users",
            "DB-backed sidecar: users",
            users.len() as u64,
            users
                .values()
                .map(json_len_estimate)
                .fold(0_u64, u64::saturating_add),
            vec![crate::users::USERS_FILE],
            true,
        )
    };
    let roles = {
        let roles = state.roles.read().await;
        sidecar_logical_concern(
            "roles",
            "DB-backed sidecar: roles",
            roles.len() as u64,
            roles
                .iter()
                .map(json_len_estimate)
                .fold(0_u64, u64::saturating_add),
            vec![crate::roles::ROLES_FILE],
            true,
        )
    };
    let delegations = {
        let delegations = state.delegations.read().await;
        sidecar_logical_concern(
            "delegations",
            "DB-backed sidecar: delegations",
            delegations.len() as u64,
            delegations
                .values()
                .map(json_len_estimate)
                .fold(0_u64, u64::saturating_add),
            vec![crate::delegations::DELEGATIONS_FILE],
            true,
        )
    };
    let settings = {
        let settings = state.settings.read().await;
        sidecar_logical_concern(
            "settings",
            "DB-backed sidecar: settings",
            1,
            json_len_estimate(&*settings),
            vec![crate::settings::SETTINGS_FILE],
            true,
        )
    };
    let provider_credentials = match state.store.clone() {
        Some(store) => match task::spawn_blocking(move || store.read_credential_records()).await {
            Ok(Ok(records)) => {
                let bytes = records
                    .iter()
                    .map(|record| {
                        record.mode.len() as u64
                            + record.provider_id.len() as u64
                            + record.updated_at.len() as u64
                            + std::mem::size_of_val(&record.key_version) as u64
                            + record.record_blob.len() as u64
                    })
                    .fold(0_u64, u64::saturating_add);
                sidecar_logical_concern(
                    "provider_credentials",
                    "DB-backed sidecar: provider credentials",
                    records.len() as u64,
                    bytes,
                    vec![crate::secretstore_persist::CREDENTIAL_SIDECAR_FILE],
                    true,
                )
            }
            Ok(Err(e)) => {
                scan_errors.push(format!(
                    "failed to read DB-backed provider credential sidecar telemetry: {e}"
                ));
                sidecar_logical_concern(
                    "provider_credentials",
                    "DB-backed sidecar: provider credentials",
                    0,
                    0,
                    vec![crate::secretstore_persist::CREDENTIAL_SIDECAR_FILE],
                    false,
                )
            }
            Err(e) => {
                scan_errors.push(format!(
                    "provider credential sidecar telemetry worker failed: {e}"
                ));
                sidecar_logical_concern(
                    "provider_credentials",
                    "DB-backed sidecar: provider credentials",
                    0,
                    0,
                    vec![crate::secretstore_persist::CREDENTIAL_SIDECAR_FILE],
                    false,
                )
            }
        },
        None => {
            scan_errors.push(
                "DB-backed provider credential sidecar telemetry unavailable: durable store is not open"
                    .to_owned(),
            );
            sidecar_logical_concern(
                "provider_credentials",
                "DB-backed sidecar: provider credentials",
                0,
                0,
                vec![crate::secretstore_persist::CREDENTIAL_SIDECAR_FILE],
                false,
            )
        }
    };

    vec![users, roles, delegations, settings, provider_credentials]
}

fn sidecar_logical_concern(
    id: &str,
    label: &str,
    row_count: u64,
    bytes: u64,
    roots: Vec<&str>,
    exact: bool,
) -> ConcernUsage {
    ConcernUsage {
        id: id.to_owned(),
        kind: Some(UsageConcernKind::SidecarLogicalStore),
        label: label.to_owned(),
        bytes,
        basis: UsageBasis::SidecarLogicalPayload,
        exact,
        file_count: 0,
        directory_count: 0,
        row_count: Some(row_count),
        payload_stats: Some(DataPayloadStats {
            table_name: id.to_owned(),
            estimated_payload_bytes: bytes,
            row_count,
            average_bytes_per_row: (row_count > 0).then(|| bytes / row_count),
            estimate_method: PayloadEstimateMethod::LocalLoadedPayloadEstimate,
            estimate_basis: UsageBasis::SidecarLogicalPayload,
        }),
        relative_roots: roots.into_iter().map(str::to_owned).collect(),
    }
}

fn json_len_estimate(value: &impl Serialize) -> u64 {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len() as u64)
}

fn opt_len(value: Option<&str>) -> u64 {
    value.map_or(0, |s| s.len() as u64)
}

fn follow_up_len_estimate(follow_up: &chancela_store::StoredFollowUp) -> u64 {
    follow_up.id.len() as u64
        + follow_up.act_id.to_string().len() as u64
        + follow_up.title.len() as u64
        + opt_len(follow_up.detail.as_deref())
        + opt_len(follow_up.assignee.as_deref())
        + opt_len(follow_up.assignee_display.as_deref())
        + follow_up.created_by.len() as u64
        + opt_len(follow_up.completed_by.as_deref())
        + 32
}

fn stored_document_len_estimate(doc: &chancela_store::StoredDocument) -> u64 {
    doc.id.len() as u64
        + doc.act_id.to_string().len() as u64
        + doc.template_id.len() as u64
        + doc.pdf_digest.len() as u64
        + doc.profile.len() as u64
        + doc.pdf_bytes.len() as u64
}

fn signed_document_len_estimate(doc: &chancela_store::StoredSignedDocument) -> u64 {
    doc.act_id.to_string().len() as u64
        + doc.document_id.len() as u64
        + doc.signed_pdf_digest.len() as u64
        + doc.signature_family.len() as u64
        + doc.evidentiary_level.len() as u64
        + opt_len(doc.trusted_list_status.as_deref())
        + opt_len(doc.signer_cert_subject.as_deref())
        + doc.signer_cert_der.len() as u64
        + doc
            .timestamp_token_der
            .as_ref()
            .map_or(0, |bytes| bytes.len() as u64)
        + opt_len(doc.timestamp_trust_report_json.as_deref())
        + doc.signed_pdf_bytes.len() as u64
}

fn pending_session_len_estimate(session: &chancela_store::PendingCmdSession) -> u64 {
    session.session_id.len() as u64
        + session.act_id.to_string().len() as u64
        + session.actor.len() as u64
        + session.status.len() as u64
        + session.masked_phone.len() as u64
        + session.doc_name.len() as u64
        + session.session_json.len() as u64
        + session.prepared_json.len() as u64
}

fn imported_document_meta_len_estimate(meta: &chancela_store::StoredImportedDocumentMeta) -> u64 {
    meta.id.len() as u64
        + meta.act_id.map_or(0, |id| id.to_string().len() as u64)
        + opt_len(meta.filename.as_deref())
        + opt_len(meta.declared_content_type.as_deref())
        + meta.detected_content_type.len() as u64
        + meta.sha256.len() as u64
        + meta.imported_by.len() as u64
        + meta.size_bytes as u64
}

fn imported_book_len_estimate(import: &chancela_store::recovery::ImportRecord) -> u64 {
    import.import_id.len() as u64
        + import.entity_id.len() as u64
        + import.book_id.len() as u64
        + import.source_instance_id.len() as u64
        + import.bundle_digest.len() as u64
        + format!("{:?}", import.verdict).len() as u64
        + 8
}

fn paper_book_import_meta_len_estimate(meta: &chancela_store::StoredPaperBookImportMeta) -> u64 {
    meta.import_id.len() as u64
        + meta.entity_ref.len() as u64
        + meta.entity_name.len() as u64
        + meta.entity_nipc.len() as u64
        + meta.book_ref.len() as u64
        + meta.sha256.len() as u64
        + meta.content_type.len() as u64
        + opt_len(meta.source_filename.as_deref())
        + opt_len(meta.notes.as_deref())
        + meta.imported_by.len() as u64
        + meta.size_bytes as u64
}

fn paper_book_ocr_draft_len_estimate(draft: &chancela_store::StoredPaperBookOcrDraft) -> u64 {
    draft.draft_id.len() as u64
        + draft.import_id.len() as u64
        + opt_len(draft.extracted_text.as_deref())
        + opt_len(draft.text_digest.as_deref())
        + json_len_estimate(&draft.page_spans)
        + draft.engine_name.len() as u64
        + opt_len(draft.engine_version.as_deref())
        + draft.created_by.len() as u64
        + opt_len(draft.reviewed_by.as_deref())
        + opt_len(draft.review_note.as_deref())
        + opt_len(draft.superseded_by.as_deref())
}

fn scan_dir(
    base: &Path,
    current: &Path,
    accumulators: &mut BTreeMap<&'static str, (ConcernDef, ConcernAccumulator)>,
    scan_errors: &mut Vec<String>,
) {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(e) => {
            scan_errors.push(format!(
                "failed to read {}: {e}",
                relative_display(base, current)
            ));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                scan_errors.push(format!(
                    "failed to read an entry under {}: {e}",
                    relative_display(base, current)
                ));
                continue;
            }
        };
        let path = entry.path();
        let rel = path.strip_prefix(base).unwrap_or(path.as_path());
        let root = relative_root(rel);
        let def = concern_for_root(&root);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                scan_errors.push(format!(
                    "failed to inspect {}: {e}",
                    relative_display(base, &path)
                ));
                continue;
            }
        };
        let is_dir = meta.is_dir();
        let entry = accumulators
            .entry(def.id)
            .or_insert_with(|| (def, ConcernAccumulator::default()));
        entry.1.relative_roots.insert(root, ());
        if is_dir {
            entry.1.directory_count = entry.1.directory_count.saturating_add(1);
            scan_dir(base, &path, accumulators, scan_errors);
        } else {
            entry.1.file_count = entry.1.file_count.saturating_add(1);
            entry.1.bytes = entry.1.bytes.saturating_add(meta.len());
        }
    }
}

fn concern_for_root(root: &str) -> ConcernDef {
    let lower = root.to_ascii_lowercase();
    if lower.starts_with(chancela_store::DB_FILE) {
        return ConcernDef {
            id: "database",
            label: "Database",
            basis: UsageBasis::SqliteFile,
        };
    }
    match lower.as_str() {
        crate::settings::SETTINGS_FILE => ConcernDef {
            id: "settings",
            label: "Settings",
            basis: UsageBasis::Filesystem,
        },
        crate::users::USERS_FILE
        | crate::roles::ROLES_FILE
        | crate::delegations::DELEGATIONS_FILE => ConcernDef {
            id: "users_roles_delegations",
            label: "Users, roles, and delegations",
            basis: UsageBasis::Filesystem,
        },
        crate::apikeys::API_KEYS_FILE => ConcernDef {
            id: "api_keys",
            label: "API keys",
            basis: UsageBasis::Filesystem,
        },
        crate::privacy::DSR_REQUESTS_FILE
        | crate::privacy::PROCESSORS_FILE
        | crate::privacy::DPIAS_FILE
        | crate::privacy::BREACH_PLAYBOOKS_FILE
        | crate::privacy::TRANSFER_CONTROLS_FILE
        | crate::privacy::RETENTION_POLICIES_FILE
        | crate::privacy::RETENTION_EXECUTIONS_FILE
        | crate::privacy::RETENTION_CANDIDATE_RESOLUTIONS_FILE => ConcernDef {
            id: "privacy",
            label: "Privacy sidecars",
            basis: UsageBasis::Filesystem,
        },
        crate::notifications::NOTIFICATION_TRIAGE_FILE => ConcernDef {
            id: "notifications",
            label: "Notifications",
            basis: UsageBasis::Filesystem,
        },
        crate::platform_logs::PLATFORM_LOGS_FILE => ConcernDef {
            id: "platform_logs",
            label: "Platform logs",
            basis: UsageBasis::Filesystem,
        },
        crate::backup_recovery::BACKUP_RECOVERY_DRILLS_FILE => ConcernDef {
            id: "backup_recovery_drills",
            label: "Backup recovery drill receipts",
            basis: UsageBasis::Filesystem,
        },
        crate::external_signing::EXTERNAL_SIGNING_ENVELOPES_FILE => ConcernDef {
            id: "external_signing",
            label: "External signing",
            basis: UsageBasis::Filesystem,
        },
        chancela_cae::CACHE_FILE => ConcernDef {
            id: "cae_catalog",
            label: "CAE catalog",
            basis: UsageBasis::Filesystem,
        },
        crate::law::LAWS_DIR => ConcernDef {
            id: "laws",
            label: "Laws",
            basis: UsageBasis::Filesystem,
        },
        "backups" => ConcernDef {
            id: "backups",
            label: "Backups",
            basis: UsageBasis::Filesystem,
        },
        "exports" => ConcernDef {
            id: "exports",
            label: "Exports",
            basis: UsageBasis::Filesystem,
        },
        _ if lower == "tsl.xml"
            || lower == "tsl-refresh-status.json"
            || lower.contains("trusted-list")
            || lower.contains("trust") =>
        {
            ConcernDef {
                id: "trust",
                label: "TSL/trust files",
                basis: UsageBasis::Filesystem,
            }
        }
        _ if lower.starts_with("crash") => ConcernDef {
            id: "crash",
            label: "Crash reports",
            basis: UsageBasis::Filesystem,
        },
        _ => ConcernDef {
            id: "other",
            label: "Other",
            basis: UsageBasis::Filesystem,
        },
    }
}

fn relative_root(path: &Path) -> String {
    path.components()
        .find_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .unwrap_or_else(|| ".".to_owned())
}

fn relative_display(base: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(base).unwrap_or(path);
    if rel.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        rel.to_string_lossy().into_owned()
    }
}

fn probe_file_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        ".chancela-data-status-probe-{}-{nanos}.tmp",
        std::process::id()
    )
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn ok(message: impl Into<String>) -> PermissionCheck {
    PermissionCheck {
        ok: true,
        checked: true,
        message: message.into(),
    }
}

fn failed(message: impl Into<String>) -> PermissionCheck {
    PermissionCheck {
        ok: false,
        checked: true,
        message: message.into(),
    }
}

fn unchecked(message: impl Into<String>) -> PermissionCheck {
    PermissionCheck {
        ok: false,
        checked: false,
        message: message.into(),
    }
}

fn key_log_status(key: Option<&str>) -> &'static str {
    match key {
        None => "missing",
        Some(raw) if raw.trim().is_empty() => "empty",
        Some(_) => "configured",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_core::{Entity, EntityKind, Nipc};
    use chancela_ledger::Ledger;

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "chancela-data-status-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn sqlite_usage_entry<'a>(usage: &'a [ConcernUsage], id: &str) -> &'a ConcernUsage {
        usage
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("missing SQLite logical usage entry {id}"))
    }

    fn write_file_with_modified(path: &Path, contents: &[u8], modified: SystemTime) {
        std::fs::write(path, contents).expect("write test file");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open test file for timestamp update");
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .expect("set test file modified timestamp");
    }

    #[test]
    fn data_status_concern_classification_covers_known_roots() {
        assert_eq!(concern_for_root("chancela.db").id, "database");
        assert_eq!(concern_for_root("chancela.db-wal").id, "database");
        assert_eq!(concern_for_root("settings.json").id, "settings");
        assert_eq!(concern_for_root("users.json").id, "users_roles_delegations");
        assert_eq!(concern_for_root("roles.json").id, "users_roles_delegations");
        assert_eq!(
            concern_for_root("delegations.json").id,
            "users_roles_delegations"
        );
        assert_eq!(concern_for_root("apikeys.json").id, "api_keys");
        assert_eq!(concern_for_root("privacy-dpias.json").id, "privacy");
        assert_eq!(
            concern_for_root("privacy-retention-executions.json").id,
            "privacy"
        );
        assert_eq!(
            concern_for_root("privacy-retention-candidate-resolutions.json").id,
            "privacy"
        );
        assert_eq!(
            concern_for_root("notification-triage.json").id,
            "notifications"
        );
        assert_eq!(concern_for_root("platform-logs.json").id, "platform_logs");
        assert_eq!(
            concern_for_root("backup-recovery-drills.json").id,
            "backup_recovery_drills"
        );
        assert_eq!(
            concern_for_root("external-signing-envelopes.json").id,
            "external_signing"
        );
        assert_eq!(concern_for_root("cae-catalog.json").id, "cae_catalog");
        assert_eq!(concern_for_root("tsl.xml").id, "trust");
        assert_eq!(concern_for_root("laws").id, "laws");
        assert_eq!(concern_for_root("backups").id, "backups");
        assert_eq!(concern_for_root("exports").id, "exports");
        assert_eq!(concern_for_root("crash").id, "crash");
        assert_eq!(concern_for_root("misc.bin").id, "other");
    }

    #[test]
    fn sqlite_logical_usage_includes_per_table_payload_stats() {
        let tmp = TempDir::new("sqlite-table-stats");
        let store = chancela_store::Store::open(&tmp.dir).expect("store opens");
        let entity = Entity::new(
            "Table Stats, Lda.",
            Nipc::unvalidated("500002020"),
            "Rua de Teste, Lisboa",
            EntityKind::SociedadePorQuotas,
        );
        let mut ledger = Ledger::new();
        let event = ledger
            .append(
                "tester",
                "entity:table-stats",
                "entity.created",
                None,
                b"entity payload",
            )
            .clone();
        store
            .persist(|tx| {
                tx.append_event(&event)?;
                tx.upsert_entity(&entity)?;
                Ok(())
            })
            .expect("persist event and entity");

        let mut scan_errors = Vec::new();
        let usage = scan_sqlite_logical_usage(&store, &mut scan_errors);

        assert!(scan_errors.is_empty(), "scan errors: {scan_errors:?}");
        let ledger_group = sqlite_usage_entry(&usage, "ledger");
        assert_eq!(ledger_group.row_count, Some(1));
        assert!(ledger_group.bytes > 0);

        let events = sqlite_usage_entry(&usage, "sqlite_table_events");
        assert_eq!(events.label, "SQLite table: events");
        assert_eq!(events.kind, Some(UsageConcernKind::SqliteLogicalTable));
        assert!(matches!(events.basis, UsageBasis::SqliteLogicalPayload));
        assert!(!events.exact);
        assert_eq!(events.row_count, Some(1));
        assert!(events.bytes > 0);
        assert_eq!(events.relative_roots, vec!["events".to_owned()]);
        let event_stats = events.payload_stats.as_ref().expect("events payload stats");
        assert_eq!(event_stats.table_name, "events");
        assert_eq!(event_stats.row_count, 1);
        assert_eq!(event_stats.estimated_payload_bytes, events.bytes);
        assert_eq!(event_stats.average_bytes_per_row, Some(events.bytes));
        assert_eq!(
            event_stats.estimate_method,
            PayloadEstimateMethod::LocalLoadedPayloadEstimate
        );
        assert_eq!(event_stats.estimate_basis, UsageBasis::SqliteLogicalPayload);

        let entities = sqlite_usage_entry(&usage, "sqlite_table_entities");
        assert_eq!(entities.row_count, Some(1));
        assert!(entities.bytes > 0);
        assert_eq!(entities.relative_roots, vec!["entities".to_owned()]);

        let books = sqlite_usage_entry(&usage, "sqlite_table_books");
        assert_eq!(books.row_count, Some(0));
        assert_eq!(books.bytes, 0);
        assert_eq!(
            books
                .payload_stats
                .as_ref()
                .expect("books payload stats")
                .average_bytes_per_row,
            None
        );

        let largest = largest_sqlite_payload_table(&usage).expect("largest payload table");
        assert!(largest.estimated_payload_bytes >= event_stats.estimated_payload_bytes);
        assert_eq!(
            largest.estimate_method,
            PayloadEstimateMethod::LocalLoadedPayloadEstimate
        );
    }

    #[test]
    fn sqlite_logical_usage_is_empty_without_durable_store() {
        let no_data_dir = inspect_unconfigured_data_dir(false);
        assert_eq!(no_data_dir.usage.total_bytes, 0);
        assert!(no_data_dir.usage.filesystem.is_empty());
        assert!(no_data_dir.usage.sqlite_logical.is_empty());
        assert!(no_data_dir.usage.scan_errors.is_empty());
        assert!(!no_data_dir.permissions.sqlite_store_open.ok);
        assert!(no_data_dir.permissions.sqlite_store_open.checked);

        let tmp = TempDir::new("fallback-in-memory");
        let fallback = inspect_data_dir(tmp.dir.clone(), None);
        assert!(fallback.usage.sqlite_logical.is_empty());
        assert!(!fallback.permissions.sqlite_store_open.ok);
        assert!(fallback.permissions.sqlite_store_open.checked);
    }

    #[test]
    fn exports_dry_run_reports_cleanup_plan_without_removing_files() {
        let tmp = TempDir::new("exports-dry-run-plan");
        let exports = tmp.dir.join("exports");
        let nested = exports.join("old-bundles");
        std::fs::create_dir_all(&nested).expect("exports dirs");

        let now = SystemTime::now();
        let old = now
            .checked_sub(Duration::from_secs(3 * 24 * 60 * 60))
            .expect("old timestamp");
        let newer_old = old
            .checked_add(Duration::from_secs(60))
            .expect("newer old timestamp");
        let recent = now
            .checked_sub(Duration::from_secs(60))
            .expect("recent timestamp");

        let old_export = exports.join("old.zip");
        let nested_old_export = nested.join("nested-old.zip");
        let recent_export = exports.join("recent.zip");
        let crash = tmp.dir.join("crash.log");
        write_file_with_modified(&old_export, b"old-export", old);
        write_file_with_modified(&nested_old_export, b"nested-old-export", newer_old);
        write_file_with_modified(&recent_export, b"recent-export", recent);
        std::fs::write(&crash, b"crash").expect("crash file");

        let req = DataCleanupRequest {
            target: "exports".to_owned(),
            dry_run: Some(true),
            minimum_age_days: Some(1),
            keep_latest: Some(1),
            preview_token: None,
        };
        let policy =
            CleanupPolicy::from_request(CleanupTarget::Exports, &req).expect("exports policy");

        let response =
            cleanup_data_dir(tmp.dir.clone(), CleanupTarget::Exports, policy).expect("dry run");

        assert_eq!(response.target, "exports");
        assert!(response.dry_run);
        assert_eq!(response.deleted_files, 0);
        assert_eq!(response.deleted_directories, 0);
        assert_eq!(response.deleted_bytes, 0);
        assert_eq!(response.would_delete_files, 2);
        assert_eq!(response.would_delete_directories, 1);
        assert_eq!(
            response.would_delete_bytes,
            (b"old-export".len() + b"nested-old-export".len()) as u64
        );
        assert!(
            response.skipped.is_empty(),
            "unexpected skipped entries: {:?}",
            response.skipped
        );

        assert!(old_export.is_file(), "old export preserved");
        assert!(nested_old_export.is_file(), "nested old export preserved");
        assert!(recent_export.is_file(), "recent export preserved");
        assert!(nested.is_dir(), "would-delete directory preserved");
        assert!(crash.is_file(), "crash file untouched");
    }

    #[test]
    fn cleanup_policy_rejects_retained_export_fields_for_crash_target() {
        let req = DataCleanupRequest {
            target: "crash".to_owned(),
            dry_run: Some(true),
            minimum_age_days: Some(30),
            keep_latest: Some(5),
            preview_token: None,
        };

        let err = CleanupPolicy::from_request(CleanupTarget::Crash, &req)
            .expect_err("crash policy fields should be rejected");

        match err {
            ApiError::Unprocessable(message) => {
                assert!(message.contains("supported only for exports"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cleanup_target_validation_refuses_root_and_outside_paths() {
        let base = TempDir::new("base");
        let outside = TempDir::new("outside");
        let base = std::fs::canonicalize(&base.dir).expect("canonical base");
        let outside_file = outside.dir.join("crash.log");
        std::fs::write(&outside_file, b"outside").expect("outside file");

        let root_error = validate_cleanup_target(&base, &base).expect_err("root refused");
        assert!(root_error.contains("data-directory root"));

        let outside_error =
            validate_cleanup_target(&base, &outside_file).expect_err("outside refused");
        assert!(outside_error.contains("outside the data directory"));
    }

    #[test]
    fn key_rotation_preflight_request_debug_redacts_key_material() {
        let req = DataKeyRotationPreflightRequest {
            current_key: Some("current-secret".to_owned()),
            new_key: Some("new-secret".to_owned()),
        };

        let debug = format!("{req:?}");

        assert!(debug.contains("configured"));
        assert!(!debug.contains("current-secret"));
        assert!(!debug.contains("new-secret"));
    }

    #[test]
    fn key_rotation_execute_request_debug_redacts_key_material() {
        let req = DataKeyRotationExecuteRequest {
            new_key: Some("new-secret".to_owned()),
        };

        let debug = format!("{req:?}");

        assert!(debug.contains("configured"));
        assert!(!debug.contains("new-secret"));
    }
}
