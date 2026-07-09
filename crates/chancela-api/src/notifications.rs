//! Persisted notification triage for dashboard-derived notification ids.
//!
//! The dashboard still owns alert/reminder generation. This module stores only the operator's
//! triage decision for a generated notification id, bounded per actor and file-backed when the API
//! has a data directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

pub const NOTIFICATION_TRIAGE_FILE: &str = "notification-triage.json";

const MAX_TRIAGE_ENTRIES_PER_OWNER: usize = 500;
const MAX_NOTIFICATION_ID_BYTES: usize = 256;
const MAX_OWNER_BYTES: usize = 128;

pub type NotificationTriageKey = (String, String);
pub type NotificationTriageTable = HashMap<NotificationTriageKey, NotificationTriageEntry>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTriageStatus {
    Unread,
    Read,
    Dismissed,
    Acknowledged,
}

impl NotificationTriageStatus {
    fn is_stored(self) -> bool {
        !matches!(self, NotificationTriageStatus::Unread)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationTriageEntry {
    pub owner: String,
    pub notification_id: String,
    pub status: NotificationTriageStatus,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct NotificationTriageResponse {
    pub entries: Vec<NotificationTriageEntry>,
    pub durable: bool,
    pub max_entries_per_owner: usize,
}

#[derive(Deserialize)]
pub struct NotificationTriageUpdate {
    pub status: NotificationTriageStatus,
}

#[derive(Serialize)]
pub struct NotificationTriageUpdateResponse {
    pub status: NotificationTriageStatus,
    pub entry: Option<NotificationTriageEntry>,
    pub durable: bool,
}

pub(crate) fn load_notification_triage(path: &Path) -> Option<NotificationTriageTable> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<NotificationTriageEntry>>(&bytes) {
        Ok(list) => {
            let mut table = NotificationTriageTable::new();
            for entry in list {
                if !entry.status.is_stored()
                    || !valid_loaded_owner(&entry.owner)
                    || !valid_loaded_notification_id(&entry.notification_id)
                {
                    continue;
                }
                table.insert((entry.owner.clone(), entry.notification_id.clone()), entry);
            }
            prune_all_owners(&mut table);
            Some(table)
        }
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid notification triage document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_notification_triage_atomic(
    path: &Path,
    table: &NotificationTriageTable,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut list: Vec<&NotificationTriageEntry> = table
        .values()
        .filter(|entry| entry.status.is_stored())
        .collect();
    list.sort_by(|a, b| {
        a.owner
            .cmp(&b.owner)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
            .then_with(|| a.notification_id.cmp(&b.notification_id))
    });
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) async fn persist_notification_triage(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.notification_triage_path {
        let table = state.notification_triage.read().await;
        write_notification_triage_atomic(path, &table).map_err(|e| {
            ApiError::Internal(format!("failed to persist notification triage: {e}"))
        })?;
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| NOTIFICATION_TRIAGE_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

fn valid_loaded_owner(owner: &str) -> bool {
    !owner.trim().is_empty()
        && owner.len() <= MAX_OWNER_BYTES
        && !owner.chars().any(char::is_control)
}

fn valid_loaded_notification_id(id: &str) -> bool {
    !id.trim().is_empty()
        && id.len() <= MAX_NOTIFICATION_ID_BYTES
        && !id.chars().any(char::is_control)
}

fn validate_notification_id(raw: &str) -> Result<String, ApiError> {
    let id = raw.trim();
    if id.is_empty() {
        return Err(ApiError::Unprocessable(
            "notification id must not be empty".to_owned(),
        ));
    }
    if id.len() > MAX_NOTIFICATION_ID_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "notification id must be at most {MAX_NOTIFICATION_ID_BYTES} bytes"
        )));
    }
    if id.chars().any(char::is_control) {
        return Err(ApiError::Unprocessable(
            "notification id must not contain control characters".to_owned(),
        ));
    }
    Ok(id.to_owned())
}

fn owner_key(actor: &CurrentActor) -> Result<String, ApiError> {
    let owner = actor.resolve("api");
    if !valid_loaded_owner(&owner) {
        return Err(ApiError::Unprocessable(
            "notification owner could not be resolved".to_owned(),
        ));
    }
    Ok(owner)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn entries_for_owner(table: &NotificationTriageTable, owner: &str) -> Vec<NotificationTriageEntry> {
    let mut entries = table
        .values()
        .filter(|entry| entry.owner == owner && entry.status.is_stored())
        .cloned()
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.notification_id.cmp(&b.notification_id))
    });
    entries
}

fn prune_all_owners(table: &mut NotificationTriageTable) {
    let owners = table
        .values()
        .map(|entry| entry.owner.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for owner in owners {
        prune_owner(table, &owner);
    }
}

fn prune_owner(table: &mut NotificationTriageTable, owner: &str) {
    let entries = entries_for_owner(table, owner);
    if entries.len() <= MAX_TRIAGE_ENTRIES_PER_OWNER {
        return;
    }
    for entry in entries.into_iter().skip(MAX_TRIAGE_ENTRIES_PER_OWNER) {
        table.remove(&(entry.owner, entry.notification_id));
    }
}

/// `GET /v1/notifications/triage` — list the signed-in actor's notification triage state.
pub async fn list_notification_triage(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<NotificationTriageResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    let owner = owner_key(&actor)?;
    let table = state.notification_triage.read().await;
    let entries = entries_for_owner(&table, &owner);
    Ok(Json(NotificationTriageResponse {
        entries,
        durable: state.notification_triage_path.is_some(),
        max_entries_per_owner: MAX_TRIAGE_ENTRIES_PER_OWNER,
    }))
}

/// `PATCH /v1/notifications/triage/{id}` — set one id to read/dismissed/acknowledged, or unread to clear.
pub async fn patch_notification_triage(
    State(state): State<AppState>,
    actor: CurrentActor,
    AxumPath(notification_id): AxumPath<String>,
    Json(req): Json<NotificationTriageUpdate>,
) -> Result<Json<NotificationTriageUpdateResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    let owner = owner_key(&actor)?;
    let notification_id = validate_notification_id(&notification_id)?;
    let entry = {
        let mut table = state.notification_triage.write().await;
        let key = (owner.clone(), notification_id.clone());
        if req.status.is_stored() {
            let entry = NotificationTriageEntry {
                owner: owner.clone(),
                notification_id: notification_id.clone(),
                status: req.status,
                updated_at: now_rfc3339(),
            };
            table.insert(key, entry.clone());
            prune_owner(&mut table, &owner);
            Some(entry)
        } else {
            table.remove(&key);
            None
        }
    };
    persist_notification_triage(&state).await?;
    Ok(Json(NotificationTriageUpdateResponse {
        status: req.status,
        entry,
        durable: state.notification_triage_path.is_some(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_load_round_trip_prunes_per_owner() {
        let dir = std::env::temp_dir().join(format!("chancela-notify-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(NOTIFICATION_TRIAGE_FILE);
        let mut table = NotificationTriageTable::new();
        for i in 0..(MAX_TRIAGE_ENTRIES_PER_OWNER + 2) {
            let entry = NotificationTriageEntry {
                owner: "ana".to_owned(),
                notification_id: format!("alert:{i:03}"),
                status: NotificationTriageStatus::Read,
                updated_at: format!("2026-07-09T00:{i:02}:00Z"),
            };
            table.insert((entry.owner.clone(), entry.notification_id.clone()), entry);
        }
        let other = NotificationTriageEntry {
            owner: "bruno".to_owned(),
            notification_id: "alert:other".to_owned(),
            status: NotificationTriageStatus::Acknowledged,
            updated_at: "2026-07-09T01:00:00Z".to_owned(),
        };
        table.insert(
            (other.owner.clone(), other.notification_id.clone()),
            other.clone(),
        );

        write_notification_triage_atomic(&path, &table).expect("write");
        let loaded = load_notification_triage(&path).expect("load");

        assert_eq!(
            entries_for_owner(&loaded, "ana").len(),
            MAX_TRIAGE_ENTRIES_PER_OWNER
        );
        assert_eq!(entries_for_owner(&loaded, "bruno"), vec![other]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_file_is_ignored() {
        let dir = std::env::temp_dir().join(format!("chancela-notify-bad-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(NOTIFICATION_TRIAGE_FILE);
        std::fs::write(&path, b"{ not json").expect("write bad json");

        assert!(load_notification_triage(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
