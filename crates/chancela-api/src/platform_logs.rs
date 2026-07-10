//! API-owned platform log tail.
//!
//! This is deliberately only an API-owned structured sink. It does not tail historical
//! stdout/stderr, and it does not contain MCP process logs unless a future supervisor forwards
//! structured events into the API.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::{Query, State};
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::{
    PLATFORM_API_SERVICE_ID, PLATFORM_APP_SERVICE_ID, PLATFORM_MCP_STDIO_SERVICE_ID,
    PlatformLogLevel, PlatformLoggingSettings, validate_platform_service_id,
};

pub(crate) const PLATFORM_LOG_DEFAULT_TAIL: usize = 100;
pub(crate) const PLATFORM_LOG_MAX_TAIL: usize = 200;
pub(crate) const PLATFORM_LOG_RETENTION_LIMIT: usize = 512;
pub(crate) const PLATFORM_LOGS_FILE: &str = "platform-logs.json";
const PLATFORM_LOG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformLogEntry {
    pub id: String,
    pub seq: u64,
    pub timestamp: String,
    pub service_id: String,
    pub level: PlatformLogLevel,
    pub target: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct PlatformLogRing {
    capacity: usize,
    next_seq: u64,
    entries: VecDeque<PlatformLogEntry>,
}

impl Default for PlatformLogRing {
    fn default() -> Self {
        Self {
            capacity: PLATFORM_LOG_RETENTION_LIMIT,
            next_seq: 1,
            entries: VecDeque::with_capacity(PLATFORM_LOG_RETENTION_LIMIT),
        }
    }
}

impl PlatformLogRing {
    fn from_persisted(next_seq: u64, entries: Vec<PlatformLogEntry>) -> Self {
        let mut entries = entries
            .into_iter()
            .filter(valid_persisted_entry)
            .collect::<Vec<_>>();
        let overflow = entries.len().saturating_sub(PLATFORM_LOG_RETENTION_LIMIT);
        if overflow > 0 {
            entries.drain(0..overflow);
        }
        let max_seq = entries.iter().map(|entry| entry.seq).max().unwrap_or(0);
        Self {
            capacity: PLATFORM_LOG_RETENTION_LIMIT,
            next_seq: next_seq.max(max_seq.saturating_add(1)).max(1),
            entries: VecDeque::from(entries),
        }
    }

    pub fn push(
        &mut self,
        service_id: &str,
        level: PlatformLogLevel,
        target: &str,
        message: impl Into<String>,
        context: Option<Value>,
    ) -> Result<PlatformLogEntry, ApiError> {
        validate_platform_service_id(service_id)?;
        validate_emitted_level(level)?;
        let target = target.trim();
        if target.is_empty() {
            return Err(ApiError::Unprocessable(
                "platform log target must not be blank".to_owned(),
            ));
        }
        let message = message.into();
        if message.trim().is_empty() {
            return Err(ApiError::Unprocessable(
                "platform log message must not be blank".to_owned(),
            ));
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = PlatformLogEntry {
            id: format!("platform-log-{seq}"),
            seq,
            timestamp: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
            service_id: service_id.to_owned(),
            level,
            target: target.to_owned(),
            message,
            context,
        };
        self.entries.push_back(entry.clone());
        let overflow = self.entries.len().saturating_sub(self.capacity);
        for _ in 0..overflow {
            self.entries.pop_front();
        }
        Ok(entry)
    }

    fn persisted_entries(&self) -> Vec<PlatformLogEntry> {
        self.entries.iter().cloned().collect()
    }

    pub fn tail(&self, filter: PlatformLogFilter, tail: usize) -> Vec<PlatformLogEntry> {
        let mut logs = self
            .entries
            .iter()
            .rev()
            .filter(|entry| filter.matches(entry))
            .take(tail)
            .cloned()
            .collect::<Vec<_>>();
        logs.reverse();
        logs
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_seq = 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlatformLogFile {
    schema_version: u32,
    next_seq: u64,
    entries: Vec<PlatformLogEntry>,
}

pub(crate) fn load_platform_logs(path: &Path) -> Option<PlatformLogRing> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<PlatformLogFile>(&bytes) {
        Ok(file) if file.schema_version == PLATFORM_LOG_SCHEMA_VERSION => {
            Some(PlatformLogRing::from_persisted(file.next_seq, file.entries))
        }
        Ok(file) => {
            eprintln!(
                "warning: {} has unsupported platform log schema version {}; using empty log tail",
                path.display(),
                file.schema_version
            );
            None
        }
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid platform log document ({e}); using empty log tail",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_platform_logs_atomic(
    path: &Path,
    logs: &PlatformLogRing,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file = PlatformLogFile {
        schema_version: PLATFORM_LOG_SCHEMA_VERSION,
        next_seq: logs.next_seq,
        entries: logs.persisted_entries(),
    };
    let json = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
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

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| PLATFORM_LOGS_FILE.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

fn valid_persisted_entry(entry: &PlatformLogEntry) -> bool {
    entry.seq > 0
        && entry.id == format!("platform-log-{}", entry.seq)
        && time::OffsetDateTime::parse(&entry.timestamp, &Rfc3339).is_ok()
        && validate_platform_service_id(&entry.service_id).is_ok()
        && validate_emitted_level(entry.level).is_ok()
        && !entry.target.trim().is_empty()
        && !entry.message.trim().is_empty()
}

#[derive(Debug, Clone)]
pub(crate) struct PlatformLogInput<'a> {
    pub service_id: &'a str,
    pub level: PlatformLogLevel,
    pub target: &'a str,
    pub message: &'a str,
    pub context: Option<Value>,
}

pub(crate) async fn record_platform_log(
    state: &AppState,
    input: PlatformLogInput<'_>,
) -> Result<(), ApiError> {
    validate_platform_service_id(input.service_id)?;
    validate_emitted_level(input.level)?;
    let threshold = {
        let settings = state.settings.read().await;
        platform_log_threshold(&settings.platform.logging, input.service_id)
    };
    if !platform_log_level_enabled(input.level, threshold) {
        return Ok(());
    }

    let mut logs = state.platform_logs.write().await;
    let before = logs.clone();
    logs.push(
        input.service_id,
        input.level,
        input.target,
        input.message,
        input.context,
    )?;
    if let Some(path) = &state.platform_logs_path {
        if let Err(e) = write_platform_logs_atomic(path, &logs) {
            *logs = before;
            return Err(ApiError::Internal(format!(
                "failed to persist platform logs: {e}"
            )));
        }
    }
    Ok(())
}

fn platform_log_threshold(logging: &PlatformLoggingSettings, service_id: &str) -> PlatformLogLevel {
    if let Some(level) = logging.service_overrides.get(service_id) {
        return *level;
    }
    let area = match service_id {
        PLATFORM_APP_SERVICE_ID => logging.app,
        PLATFORM_API_SERVICE_ID => logging.api,
        PLATFORM_MCP_STDIO_SERVICE_ID => logging.mcp,
        _ => logging.global,
    };
    stricter_log_threshold(logging.global, area)
}

fn platform_log_level_enabled(level: PlatformLogLevel, threshold: PlatformLogLevel) -> bool {
    threshold != PlatformLogLevel::Off && log_level_rank(level) >= log_level_rank(threshold)
}

fn stricter_log_threshold(left: PlatformLogLevel, right: PlatformLogLevel) -> PlatformLogLevel {
    if log_level_rank(left) >= log_level_rank(right) {
        left
    } else {
        right
    }
}

fn log_level_rank(level: PlatformLogLevel) -> u8 {
    match level {
        PlatformLogLevel::Trace => 0,
        PlatformLogLevel::Debug => 1,
        PlatformLogLevel::Info => 2,
        PlatformLogLevel::Warn => 3,
        PlatformLogLevel::Error => 4,
        PlatformLogLevel::Off => 5,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PlatformLogFilter<'a> {
    service_id: Option<&'a str>,
    level: Option<PlatformLogLevel>,
}

impl PlatformLogFilter<'_> {
    fn matches(&self, entry: &PlatformLogEntry) -> bool {
        self.service_id
            .is_none_or(|service_id| service_id == entry.service_id)
            && self.level.is_none_or(|level| level == entry.level)
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct PlatformLogsQuery {
    service_id: Option<String>,
    level: Option<String>,
    tail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformLogsResponse {
    pub logs: Vec<PlatformLogEntry>,
    pub tail: usize,
    pub order: &'static str,
    pub limitations: Vec<String>,
}

/// `GET /v1/platform/logs` — read the newest API-owned platform log tail in chronological order.
pub async fn list_logs(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<PlatformLogsQuery>,
) -> Result<Json<PlatformLogsResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SettingsRead, Scope::Global).await?;

    let service_id = match query.service_id.as_deref() {
        Some(service_id) => {
            validate_platform_service_id(service_id)?;
            Some(service_id)
        }
        None => None,
    };
    let level = query.level.as_deref().map(parse_log_level).transpose()?;
    let tail = validate_tail(query.tail.as_deref())?;
    let filter = PlatformLogFilter { service_id, level };
    let logs = state.platform_logs.read().await.tail(filter, tail);

    Ok(Json(PlatformLogsResponse {
        logs,
        tail,
        order: "chronological",
        limitations: limitations(state.platform_logs_path.is_some()),
    }))
}

fn limitations(durable: bool) -> Vec<String> {
    let mut limitations = if durable {
        vec![
            "This is a data-dir-backed, bounded API-owned structured platform log tail.".to_owned(),
            format!(
                "Retention is deterministic: only the newest {PLATFORM_LOG_RETENTION_LIMIT} API-owned platform log entries are kept."
            ),
        ]
    } else {
        vec![
            "This is an in-memory API-owned structured log ring; entries reset when the API process restarts."
                .to_owned(),
        ]
    };
    limitations.push(
        "It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards structured events into the API."
            .to_owned(),
    );
    limitations
}

fn validate_tail(tail: Option<&str>) -> Result<usize, ApiError> {
    let tail = match tail {
        Some(raw) => raw.parse::<usize>().map_err(|_| {
            ApiError::Unprocessable(format!(
                "platform log tail must be an integer between 1 and {PLATFORM_LOG_MAX_TAIL}, got {raw:?}"
            ))
        })?,
        None => PLATFORM_LOG_DEFAULT_TAIL,
    };
    if !(1..=PLATFORM_LOG_MAX_TAIL).contains(&tail) {
        return Err(ApiError::Unprocessable(format!(
            "platform log tail must be between 1 and {PLATFORM_LOG_MAX_TAIL}, got {tail}"
        )));
    }
    Ok(tail)
}

fn parse_log_level(raw: &str) -> Result<PlatformLogLevel, ApiError> {
    match raw {
        "trace" => Ok(PlatformLogLevel::Trace),
        "debug" => Ok(PlatformLogLevel::Debug),
        "info" => Ok(PlatformLogLevel::Info),
        "warn" => Ok(PlatformLogLevel::Warn),
        "error" => Ok(PlatformLogLevel::Error),
        "off" => Err(ApiError::Unprocessable(
            "platform log level \"off\" is a settings value, not an emitted log level".to_owned(),
        )),
        _ => Err(ApiError::Unprocessable(format!(
            "unknown platform log level {raw:?}; expected trace, debug, info, warn, or error"
        ))),
    }
}

fn validate_emitted_level(level: PlatformLogLevel) -> Result<(), ApiError> {
    if level == PlatformLogLevel::Off {
        return Err(ApiError::Unprocessable(
            "platform log entries cannot use level off".to_owned(),
        ));
    }
    Ok(())
}
