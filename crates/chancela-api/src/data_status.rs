//! Data-directory/storage telemetry for the Data Management tab.
//!
//! This endpoint is deliberately read-only: it never appends ledger events, never records platform
//! logs, and never opens or migrates a second store connection. Filesystem checks run on a blocking
//! worker so directory traversal and permission probes do not occupy the async runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use tokio::task;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
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
    pub database_encryption_configured: bool,
    pub store_schema_version: Option<i64>,
    pub ledger_length: u64,
    pub ledger_verified: Option<bool>,
    pub degraded: bool,
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
    pub sqlite_logical: Vec<ConcernUsage>,
    pub scan_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConcernUsage {
    pub id: String,
    pub label: String,
    pub bytes: u64,
    pub basis: UsageBasis,
    pub exact: bool,
    pub file_count: u64,
    pub directory_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    pub relative_roots: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DataCleanupRequest {
    pub target: String,
    pub dry_run: Option<bool>,
    pub minimum_age_days: Option<u64>,
    pub keep_latest: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataCleanupResponse {
    pub target: String,
    pub dry_run: bool,
    pub deleted_bytes: u64,
    pub deleted_files: u64,
    pub deleted_directories: u64,
    pub skipped: Vec<String>,
    pub data_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageBasis {
    Filesystem,
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
    minimum_age: Option<Duration>,
    keep_latest: usize,
    retained_files: BTreeSet<PathBuf>,
    now: SystemTime,
}

impl CleanupPolicy {
    fn from_request(target: CleanupTarget, req: &DataCleanupRequest) -> Result<Self, ApiError> {
        let has_export_policy =
            req.dry_run.is_some() || req.minimum_age_days.is_some() || req.keep_latest.is_some();
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
    let mode = match (data_dir_configured, durable_store_open) {
        (_, true) => PersistenceMode::Durable,
        (true, false) => PersistenceMode::FallbackInMemory,
        (false, false) => PersistenceMode::InMemory,
    };
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let degraded = *state.degraded.read().await;

    let fs = match data_dir {
        Some(dir) => task::spawn_blocking(move || inspect_data_dir(dir, store))
            .await
            .map_err(|e| ApiError::Internal(format!("data status worker failed: {e}")))?,
        None => inspect_unconfigured_data_dir(durable_store_open),
    };

    Ok(Json(DataStatusResponse {
        generated_at: now_rfc3339(),
        persistence: PersistenceStatus {
            mode,
            data_dir_configured,
            durable_store_open,
            database_encryption_configured: state.database_encryption_configured,
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

    let mut response = task::spawn_blocking(move || cleanup_data_dir(data_dir, target, policy))
        .await
        .map_err(|e| ApiError::Internal(format!("data cleanup worker failed: {e}")))??;
    response.data_dir = Some(data_dir_display);
    Ok(Json(response))
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
    let base = canonical_data_dir(&data_dir)?;
    let mut response = DataCleanupResponse {
        target: target.id().to_owned(),
        dry_run: policy.dry_run,
        deleted_bytes: 0,
        deleted_files: 0,
        deleted_directories: 0,
        skipped: Vec::new(),
        data_dir: None,
    };

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
                retain_latest_files(
                    &base,
                    &entry.path(),
                    policy.keep_latest,
                    &mut policy,
                    &mut response,
                );
            }
            cleanup_concern_root(&base, &entry.path(), &policy, &mut response);
        }
    }

    Ok(response)
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
        cleanup_directory_contents(base, root, policy, response);
    } else if meta.is_file() {
        cleanup_file(root, &meta, base, policy, response);
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
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            response.skipped.push(format!(
                "{}: failed to read cleanup directory: {e}",
                relative_display(base, dir)
            ));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                response.skipped.push(format!(
                    "{}: failed to read cleanup directory entry: {e}",
                    relative_display(base, dir)
                ));
                continue;
            }
        };
        cleanup_path(base, &entry.path(), policy, response);
    }
}

fn cleanup_path(
    base: &Path,
    path: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
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
        response
            .skipped
            .push(format!("{rel}: protected symlink cleanup target"));
        return;
    }
    if let Err(reason) = validate_cleanup_target(base, path) {
        response.skipped.push(format!("{rel}: {reason}"));
        return;
    }

    if meta.is_dir() {
        cleanup_directory_contents(base, path, policy, response);
        if policy.dry_run {
            return;
        }
        match fs::remove_dir(path) {
            Ok(()) => {
                response.deleted_directories = response.deleted_directories.saturating_add(1);
            }
            Err(e) => response
                .skipped
                .push(format!("{rel}: failed to delete directory: {e}")),
        }
    } else if meta.is_file() {
        cleanup_file(path, &meta, base, policy, response);
    } else {
        response
            .skipped
            .push(format!("{rel}: unsupported filesystem entry type"));
    }
}

fn cleanup_file(
    path: &Path,
    meta: &fs::Metadata,
    base: &Path,
    policy: &CleanupPolicy,
    response: &mut DataCleanupResponse,
) {
    if !policy.should_delete_file(path, meta) {
        return;
    }
    if policy.dry_run {
        return;
    }
    delete_file(path, meta.len(), base, response);
}

fn delete_file(path: &Path, bytes: u64, base: &Path, response: &mut DataCleanupResponse) {
    let rel = relative_display(base, path);
    match fs::remove_file(path) {
        Ok(()) => {
            response.deleted_files = response.deleted_files.saturating_add(1);
            response.deleted_bytes = response.deleted_bytes.saturating_add(bytes);
        }
        Err(e) => response
            .skipped
            .push(format!("{rel}: failed to delete file: {e}")),
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
            sqlite_logical: Vec::new(),
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
            sqlite_logical: Vec::new(),
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
            label: def.label.to_owned(),
            bytes: acc.bytes,
            basis: def.basis,
            exact: true,
            file_count: acc.file_count,
            directory_count: acc.directory_count,
            row_count: None,
            relative_roots: acc.relative_roots.into_keys().collect(),
        });
    }

    UsageStatus {
        total_bytes,
        filesystem,
        sqlite_logical: Vec::new(),
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

    let ledger_bytes = loaded
        .ledger
        .events()
        .iter()
        .map(json_len_estimate)
        .fold(0_u64, u64::saturating_add);
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
        label: label.to_owned(),
        bytes,
        basis: UsageBasis::SqliteLogicalPayload,
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: Some(row_count),
        relative_roots: tables.into_iter().map(str::to_owned).collect(),
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
        | crate::privacy::RETENTION_EXECUTIONS_FILE => ConcernDef {
            id: "privacy",
            label: "Privacy sidecars",
            basis: UsageBasis::Filesystem,
        },
        crate::notifications::NOTIFICATION_TRIAGE_FILE => ConcernDef {
            id: "notifications",
            label: "Notifications",
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

#[cfg(test)]
mod tests {
    use super::*;

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
            concern_for_root("notification-triage.json").id,
            "notifications"
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
}
