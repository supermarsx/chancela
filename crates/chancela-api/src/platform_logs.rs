//! In-memory platform log tail.
//!
//! This is deliberately only an API-owned ring buffer. It does not tail historical stdout/stderr,
//! and it does not contain MCP process logs unless a future supervisor forwards structured events
//! into the API.

use std::collections::VecDeque;

use axum::Json;
use axum::extract::{Query, State};
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;
use crate::settings::{PlatformLogLevel, validate_platform_service_id};

pub(crate) const PLATFORM_LOG_DEFAULT_TAIL: usize = 100;
pub(crate) const PLATFORM_LOG_MAX_TAIL: usize = 200;
const PLATFORM_LOG_RING_CAPACITY: usize = 512;

#[derive(Debug, Clone, Serialize)]
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
            capacity: PLATFORM_LOG_RING_CAPACITY,
            next_seq: 1,
            entries: VecDeque::with_capacity(PLATFORM_LOG_RING_CAPACITY),
        }
    }
}

impl PlatformLogRing {
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
) -> Result<PlatformLogEntry, ApiError> {
    state.platform_logs.write().await.push(
        input.service_id,
        input.level,
        input.target,
        input.message,
        input.context,
    )
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

/// `GET /v1/platform/logs` — read the newest in-memory platform log tail in chronological order.
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
        limitations: vec![
            "This is an in-memory API log ring; entries reset when the API process restarts."
                .to_owned(),
            "It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards them."
                .to_owned(),
        ],
    }))
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
