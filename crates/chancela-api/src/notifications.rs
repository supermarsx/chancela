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
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

pub const NOTIFICATION_TRIAGE_FILE: &str = "notification-triage.json";

const MAX_TRIAGE_ENTRIES_PER_OWNER: usize = 500;
const MAX_NOTIFICATION_ID_BYTES: usize = 256;
const MAX_OWNER_BYTES: usize = 128;

/// Server env var (Tier A, non-secret, restart-to-apply): how many days a *dismissed* triage entry
/// is retained before it is pruned. `0` disables time-based retention (the count cap still applies).
/// An unset or unparseable value falls back to [`DEFAULT_DISMISS_RETENTION_DAYS`]. Surfaced in the
/// t14 env-override admin panel (t17-e3), but read here directly from the environment so the server
/// feature is decoupled from that panel.
pub const DISMISS_RETENTION_DAYS_ENV: &str = "CHANCELA_NOTIFICATION_DISMISS_RETENTION_DAYS";
const DEFAULT_DISMISS_RETENTION_DAYS: u64 = 120;

/// Client-authored display snapshot caps (bytes). A dismissed notification's snapshot is opaque,
/// disposable UI text — length-capped and control-char-free so the stored archive stays bounded.
const MAX_SNAPSHOT_KIND_BYTES: usize = 64;
const MAX_SNAPSHOT_TONE_BYTES: usize = 64;
const MAX_SNAPSHOT_BADGE_BYTES: usize = 128;
const MAX_SNAPSHOT_TITLE_BYTES: usize = 256;
const MAX_SNAPSHOT_DETAIL_BYTES: usize = 1024;
const MAX_SNAPSHOT_TIMESTAMP_BYTES: usize = 64;
const MAX_SNAPSHOT_ACTION_LABEL_BYTES: usize = 128;
const MAX_SNAPSHOT_ACTION_HREF_BYTES: usize = 512;

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
    /// For a dismissed entry this equals the dismissal instant; the retention clock reads it when no
    /// explicit `dismissed_at` is present (graceful degradation for entries written before this field
    /// existed). RFC3339 UTC.
    pub updated_at: String,
    /// The dismissal instant, set only when `status` is [`NotificationTriageStatus::Dismissed`]. The
    /// retention clock prefers it over `updated_at`. Optional so old files deserialize unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissed_at: Option<String>,
    /// Client-authored display copy captured at dismiss time so the Dismissed tab can show the
    /// notification even after its underlying dashboard condition resolves. Optional; a dismissed
    /// entry without one falls back to live reconstruction on the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<NotificationSnapshot>,
}

/// A frozen display copy of a dismissed notification. Opaque, length-capped, control-char-free text
/// authored by the client in whatever locale the notification was dismissed in — an archive of what
/// was dismissed, never re-localized by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSnapshot {
    pub kind: String,
    pub tone: String,
    pub badge: String,
    pub title: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<NotificationSnapshotAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSnapshotAction {
    pub href: String,
    pub label: String,
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
    /// Display snapshot to freeze onto the entry when `status` is dismissed. Ignored for any other
    /// status. Rejected (422) if any field exceeds its cap or carries a control character.
    #[serde(default)]
    pub snapshot: Option<NotificationSnapshot>,
}

#[derive(Serialize)]
pub struct NotificationTriageUpdateResponse {
    pub status: NotificationTriageStatus,
    pub entry: Option<NotificationTriageEntry>,
    pub durable: bool,
}

pub(crate) fn load_notification_triage(path: &Path) -> Option<NotificationTriageTable> {
    load_notification_triage_at(path, retention_cutoff(notification_dismiss_retention()))
}

/// Load with an explicit retention `cutoff` (`None` = retention disabled). Split out so the prune is
/// unit-testable without touching the process environment or the wall clock.
fn load_notification_triage_at(
    path: &Path,
    cutoff: Option<OffsetDateTime>,
) -> Option<NotificationTriageTable> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<NotificationTriageEntry>>(&bytes) {
        Ok(list) => {
            let mut table = NotificationTriageTable::new();
            for mut entry in list {
                if !entry.status.is_stored()
                    || !valid_loaded_owner(&entry.owner)
                    || !valid_loaded_notification_id(&entry.notification_id)
                {
                    continue;
                }
                sanitize_loaded_snapshot(&mut entry);
                table.insert((entry.owner.clone(), entry.notification_id.clone()), entry);
            }
            prune_all_owners(&mut table);
            prune_dismissed_by_retention(&mut table, cutoff);
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

/// Drop a snapshot that is malformed or attached to a non-dismissed status — the entry itself is
/// always kept (a bad display copy is never allowed to lose the operator's triage decision).
fn sanitize_loaded_snapshot(entry: &mut NotificationTriageEntry) {
    if entry.status != NotificationTriageStatus::Dismissed {
        entry.snapshot = None;
        entry.dismissed_at = None;
        return;
    }
    if let Some(snapshot) = &entry.snapshot
        && validate_snapshot(snapshot).is_err()
    {
        entry.snapshot = None;
    }
}

pub(crate) fn write_notification_triage_atomic(
    path: &Path,
    table: &NotificationTriageTable,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
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

/// Resolve the dismissed-entry retention window from the process environment. `None` means
/// retention is disabled (`0`); otherwise a positive [`Duration`]. Unset/unparseable ⇒ the 120-day
/// default. Reads [`DISMISS_RETENTION_DAYS_ENV`], which the t14 override layer stamps onto the env
/// before startup, so the override is already visible here.
pub fn notification_dismiss_retention() -> Option<Duration> {
    parse_retention_days(std::env::var(DISMISS_RETENTION_DAYS_ENV).ok().as_deref())
}

/// Pure interval resolution, split from the env read so it is testable without touching env.
fn parse_retention_days(raw: Option<&str>) -> Option<Duration> {
    let days = match raw {
        Some(value) => value
            .trim()
            .parse::<u64>()
            .unwrap_or(DEFAULT_DISMISS_RETENTION_DAYS),
        None => DEFAULT_DISMISS_RETENTION_DAYS,
    };
    if days == 0 {
        None
    } else {
        Some(Duration::days(days as i64))
    }
}

/// The instant before which dismissed entries have aged out, or `None` when retention is disabled.
fn retention_cutoff(interval: Option<Duration>) -> Option<OffsetDateTime> {
    interval.map(|interval| OffsetDateTime::now_utc() - interval)
}

/// The instant a dismissed entry's retention clock started: explicit `dismissed_at` if present,
/// else `updated_at`. Parsed as an instant — never compared lexicographically.
fn dismissed_clock(entry: &NotificationTriageEntry) -> Option<OffsetDateTime> {
    let raw = entry.dismissed_at.as_deref().unwrap_or(&entry.updated_at);
    OffsetDateTime::parse(raw, &Rfc3339).ok()
}

/// Remove dismissed entries whose retention clock is at or before `cutoff`. `read`/`acknowledged`
/// entries are never time-pruned (only the count cap applies to them). An entry whose timestamp
/// cannot be parsed is kept — data is never dropped on an unreadable clock.
fn prune_dismissed_by_retention(
    table: &mut NotificationTriageTable,
    cutoff: Option<OffsetDateTime>,
) {
    let Some(cutoff) = cutoff else {
        return;
    };
    table.retain(|_, entry| {
        if entry.status != NotificationTriageStatus::Dismissed {
            return true;
        }
        match dismissed_clock(entry) {
            Some(clock) => clock > cutoff,
            None => true,
        }
    });
}

fn check_snapshot_field(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        return Err(format!("snapshot {field} must be at most {max} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "snapshot {field} must not contain control characters"
        ));
    }
    Ok(())
}

/// Validate a client-authored snapshot against the per-field caps. Loud rejection on the write path
/// (mapped to 422); on load a failing snapshot is dropped, keeping the entry.
fn validate_snapshot(snapshot: &NotificationSnapshot) -> Result<(), String> {
    check_snapshot_field("kind", &snapshot.kind, MAX_SNAPSHOT_KIND_BYTES)?;
    check_snapshot_field("tone", &snapshot.tone, MAX_SNAPSHOT_TONE_BYTES)?;
    check_snapshot_field("badge", &snapshot.badge, MAX_SNAPSHOT_BADGE_BYTES)?;
    check_snapshot_field("title", &snapshot.title, MAX_SNAPSHOT_TITLE_BYTES)?;
    check_snapshot_field("detail", &snapshot.detail, MAX_SNAPSHOT_DETAIL_BYTES)?;
    if let Some(timestamp) = &snapshot.timestamp {
        check_snapshot_field("timestamp", timestamp, MAX_SNAPSHOT_TIMESTAMP_BYTES)?;
    }
    if let Some(action) = &snapshot.action {
        check_snapshot_field(
            "action label",
            &action.label,
            MAX_SNAPSHOT_ACTION_LABEL_BYTES,
        )?;
        check_snapshot_field("action href", &action.href, MAX_SNAPSHOT_ACTION_HREF_BYTES)?;
    }
    Ok(())
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
    let cutoff = retention_cutoff(state.notification_dismiss_retention);
    let table = state.notification_triage.read().await;
    let mut entries = entries_for_owner(&table, &owner);
    // Belt-and-suspenders: omit dismissed entries past the retention cutoff so an aged item never
    // displays in the window between the on-load / on-write prunes.
    if let Some(cutoff) = cutoff {
        entries.retain(|entry| {
            entry.status != NotificationTriageStatus::Dismissed
                || dismissed_clock(entry).is_none_or(|clock| clock > cutoff)
        });
    }
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
    let dismissing = req.status == NotificationTriageStatus::Dismissed;
    // A snapshot is only meaningful on a dismiss; validate loudly (422) when it will be stored.
    let snapshot = if dismissing {
        if let Some(snapshot) = &req.snapshot {
            validate_snapshot(snapshot).map_err(ApiError::Unprocessable)?;
        }
        req.snapshot.clone()
    } else {
        None
    };
    let cutoff = retention_cutoff(state.notification_dismiss_retention);
    let entry = {
        let mut table = state.notification_triage.write().await;
        let key = (owner.clone(), notification_id.clone());
        if req.status.is_stored() {
            let now = now_rfc3339();
            let entry = NotificationTriageEntry {
                owner: owner.clone(),
                notification_id: notification_id.clone(),
                status: req.status,
                updated_at: now.clone(),
                dismissed_at: dismissing.then_some(now),
                snapshot,
            };
            table.insert(key, entry.clone());
            prune_owner(&mut table, &owner);
            prune_dismissed_by_retention(&mut table, cutoff);
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
                dismissed_at: None,
                snapshot: None,
            };
            table.insert((entry.owner.clone(), entry.notification_id.clone()), entry);
        }
        let other = NotificationTriageEntry {
            owner: "bruno".to_owned(),
            notification_id: "alert:other".to_owned(),
            status: NotificationTriageStatus::Acknowledged,
            updated_at: "2026-07-09T01:00:00Z".to_owned(),
            dismissed_at: None,
            snapshot: None,
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

    fn dismissed(id: &str, at: &str) -> NotificationTriageEntry {
        NotificationTriageEntry {
            owner: "ana".to_owned(),
            notification_id: id.to_owned(),
            status: NotificationTriageStatus::Dismissed,
            updated_at: at.to_owned(),
            dismissed_at: Some(at.to_owned()),
            snapshot: None,
        }
    }

    fn insert(table: &mut NotificationTriageTable, entry: NotificationTriageEntry) {
        table.insert((entry.owner.clone(), entry.notification_id.clone()), entry);
    }

    fn sample_snapshot() -> NotificationSnapshot {
        NotificationSnapshot {
            kind: "alert".to_owned(),
            tone: "error".to_owned(),
            badge: "Provenance".to_owned(),
            title: "Provenance expired".to_owned(),
            detail: "Encosto Estratégico Lda registry provenance lapsed.".to_owned(),
            timestamp: Some("2026-07-01T00:00:00Z".to_owned()),
            action: Some(NotificationSnapshotAction {
                href: "/entities/entity-1".to_owned(),
                label: "Rever entidade".to_owned(),
            }),
        }
    }

    #[test]
    fn parse_retention_days_default_and_disabled() {
        assert_eq!(parse_retention_days(None), Some(Duration::days(120)));
        assert_eq!(parse_retention_days(Some("30")), Some(Duration::days(30)));
        assert_eq!(parse_retention_days(Some("  7 ")), Some(Duration::days(7)));
        // 0 disables retention.
        assert_eq!(parse_retention_days(Some("0")), None);
        // Garbage falls back to the default rather than disabling silently.
        assert_eq!(
            parse_retention_days(Some("nope")),
            Some(Duration::days(120))
        );
        assert_eq!(parse_retention_days(Some("-5")), Some(Duration::days(120)));
    }

    #[test]
    fn retention_prunes_only_aged_dismissed_entries() {
        let now = OffsetDateTime::now_utc();
        let mut table = NotificationTriageTable::new();
        // Aged dismissed → pruned.
        insert(
            &mut table,
            dismissed(
                "alert:aged",
                &(now - Duration::days(200)).format(&Rfc3339).unwrap(),
            ),
        );
        // Recent dismissed → kept.
        insert(
            &mut table,
            dismissed(
                "alert:recent",
                &(now - Duration::days(10)).format(&Rfc3339).unwrap(),
            ),
        );
        // Aged acknowledged → kept (D4: only dismissed ages out).
        insert(
            &mut table,
            NotificationTriageEntry {
                status: NotificationTriageStatus::Acknowledged,
                dismissed_at: None,
                ..dismissed(
                    "alert:ack",
                    &(now - Duration::days(300)).format(&Rfc3339).unwrap(),
                )
            },
        );

        let cutoff = retention_cutoff(Some(Duration::days(120)));
        prune_dismissed_by_retention(&mut table, cutoff);

        assert!(!table.contains_key(&("ana".to_owned(), "alert:aged".to_owned())));
        assert!(table.contains_key(&("ana".to_owned(), "alert:recent".to_owned())));
        assert!(table.contains_key(&("ana".to_owned(), "alert:ack".to_owned())));
    }

    #[test]
    fn retention_disabled_keeps_everything() {
        let mut table = NotificationTriageTable::new();
        insert(&mut table, dismissed("alert:old", "2000-01-01T00:00:00Z"));
        prune_dismissed_by_retention(&mut table, retention_cutoff(None));
        assert!(table.contains_key(&("ana".to_owned(), "alert:old".to_owned())));
    }

    #[test]
    fn retention_falls_back_to_updated_at_and_keeps_unparseable() {
        let now = OffsetDateTime::now_utc();
        let mut table = NotificationTriageTable::new();
        // No dismissed_at → clock reads updated_at (aged) → pruned.
        insert(
            &mut table,
            NotificationTriageEntry {
                dismissed_at: None,
                ..dismissed(
                    "alert:fallback",
                    &(now - Duration::days(200)).format(&Rfc3339).unwrap(),
                )
            },
        );
        // Unparseable clock → kept (never dropped on an unreadable timestamp).
        insert(&mut table, dismissed("alert:garbage", "not-a-timestamp"));

        prune_dismissed_by_retention(&mut table, retention_cutoff(Some(Duration::days(120))));

        assert!(!table.contains_key(&("ana".to_owned(), "alert:fallback".to_owned())));
        assert!(table.contains_key(&("ana".to_owned(), "alert:garbage".to_owned())));
    }

    #[test]
    fn cutoff_is_instant_parsed_across_offset_forms() {
        // Same instant, different RFC3339 spellings: fractional seconds and a non-UTC offset.
        let mut table = NotificationTriageTable::new();
        insert(
            &mut table,
            dismissed("alert:frac", "2026-07-22T00:00:00.500Z"),
        );
        insert(
            &mut table,
            dismissed("alert:offset", "2026-07-22T01:00:00+01:00"),
        );
        // Cutoff one second earlier than both instants (2026-07-21T23:59:59Z) → both kept.
        let cutoff = OffsetDateTime::parse("2026-07-21T23:59:59Z", &Rfc3339).unwrap();
        prune_dismissed_by_retention(&mut table, Some(cutoff));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn snapshot_round_trips_through_load() {
        let dir = std::env::temp_dir().join(format!("chancela-notify-snap-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(NOTIFICATION_TRIAGE_FILE);
        let mut table = NotificationTriageTable::new();
        let mut entry = dismissed(
            "alert:snap",
            &OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
        );
        entry.snapshot = Some(sample_snapshot());
        insert(&mut table, entry.clone());

        write_notification_triage_atomic(&path, &table).expect("write");
        let loaded = load_notification_triage(&path).expect("load");
        let round = loaded
            .get(&("ana".to_owned(), "alert:snap".to_owned()))
            .expect("entry survives");
        assert_eq!(round.snapshot, Some(sample_snapshot()));
        assert!(round.dismissed_at.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_drops_malformed_snapshot_keeps_entry() {
        let dir = std::env::temp_dir().join(format!("chancela-notify-bad-snap-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(NOTIFICATION_TRIAGE_FILE);
        // Title over the 256-byte cap → snapshot dropped, entry retained.
        let json = format!(
            r#"[{{"owner":"ana","notification_id":"alert:bad","status":"dismissed","updated_at":"{now}","dismissed_at":"{now}","snapshot":{{"kind":"alert","tone":"error","badge":"b","title":"{long}","detail":"d"}}}}]"#,
            now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            long = "x".repeat(MAX_SNAPSHOT_TITLE_BYTES + 1),
        );
        std::fs::write(&path, json).expect("write");

        let loaded = load_notification_triage(&path).expect("load");
        let entry = loaded
            .get(&("ana".to_owned(), "alert:bad".to_owned()))
            .expect("entry kept");
        assert!(entry.snapshot.is_none(), "malformed snapshot dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_drops_snapshot_on_non_dismissed_status() {
        let dir = std::env::temp_dir().join(format!("chancela-notify-nd-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(NOTIFICATION_TRIAGE_FILE);
        let json = r#"[{"owner":"ana","notification_id":"alert:read","status":"read","updated_at":"2026-07-20T00:00:00Z","snapshot":{"kind":"alert","tone":"error","badge":"b","title":"t","detail":"d"}}]"#;
        std::fs::write(&path, json).expect("write");

        let loaded = load_notification_triage(&path).expect("load");
        let entry = loaded
            .get(&("ana".to_owned(), "alert:read".to_owned()))
            .expect("entry kept");
        assert!(entry.snapshot.is_none());
        assert!(entry.dismissed_at.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_snapshot_rejects_oversize_and_control_chars() {
        let mut over = sample_snapshot();
        over.detail = "x".repeat(MAX_SNAPSHOT_DETAIL_BYTES + 1);
        assert!(validate_snapshot(&over).is_err());

        let mut ctrl = sample_snapshot();
        ctrl.title = "line\u{0007}bell".to_owned();
        assert!(validate_snapshot(&ctrl).is_err());

        assert!(validate_snapshot(&sample_snapshot()).is_ok());
    }
}
