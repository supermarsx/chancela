//! Data-directory/storage telemetry for the Data Management tab.
//!
//! This endpoint is deliberately read-only: it never appends ledger events, never records platform
//! logs, and never opens or migrates a second store connection. Filesystem checks run on a blocking
//! worker so directory traversal and permission probes do not occupy the async runtime.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use chancela_authz::{Permission, Scope};
use serde::Serialize;
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

/// `GET /v1/data/status` - read-only storage and data-directory telemetry.
pub async fn get_data_status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DataStatusResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;

    let data_dir = state.data_dir();
    let data_dir_configured = data_dir.is_some();
    let durable_store_open = state.store.is_some();
    let mode = match (data_dir_configured, durable_store_open) {
        (_, true) => PersistenceMode::Durable,
        (true, false) => PersistenceMode::FallbackInMemory,
        (false, false) => PersistenceMode::InMemory,
    };
    let ledger_length = state.ledger.read().await.len() as u64;
    let ledger_verified = state.chain_status.as_ref().map(|status| status.is_ok());
    let degraded = *state.degraded.read().await;

    let mut fs = match data_dir {
        Some(dir) => task::spawn_blocking(move || inspect_data_dir(dir, durable_store_open))
            .await
            .map_err(|e| ApiError::Internal(format!("data status worker failed: {e}")))?,
        None => inspect_unconfigured_data_dir(durable_store_open),
    };

    if durable_store_open {
        fs.usage.scan_errors.push(
            "sqlite logical usage not reported: chancela-store does not expose read-only table payload statistics"
                .to_owned(),
        );
    }

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

fn inspect_data_dir(dir: PathBuf, durable_store_open: bool) -> FsInspection {
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
        | crate::privacy::RETENTION_POLICIES_FILE => ConcernDef {
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
}
