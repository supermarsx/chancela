//! API-owned platform log tail.
//!
//! This is deliberately only an API-owned structured sink. It does not tail historical
//! stdout/stderr, and it does not contain MCP process logs unless a future supervisor forwards
//! structured events into the API.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, require_permission};
use crate::error::ApiError;
use crate::settings::{
    PlatformLogLevel, is_known_platform_service_id, validate_platform_service_id,
};

pub(crate) const PLATFORM_LOG_DEFAULT_TAIL: usize = 100;
pub(crate) const PLATFORM_LOG_MAX_TAIL: usize = 200;
pub(crate) const PLATFORM_LOG_RETENTION_LIMIT: usize = 512;
pub(crate) const PLATFORM_LOGS_FILE: &str = "platform-logs.json";
const PLATFORM_LOG_SCHEMA_VERSION: u32 = 1;
const FORWARDED_LOG_SERVICE_ID_MAX_BYTES: usize = 64;
const FORWARDED_LOG_TARGET_MAX_BYTES: usize = 256;
const FORWARDED_LOG_MESSAGE_MAX_BYTES: usize = 2048;
const FORWARDED_LOG_CONTEXT_MAX_BYTES: usize = 8 * 1024;
const FORWARDED_LOG_CONTEXT_MAX_DEPTH: usize = 4;
const FORWARDED_LOG_CONTEXT_MAX_KEYS: usize = 64;
const FORWARDED_LOG_CONTEXT_KEY_MAX_BYTES: usize = 64;
const FORWARDED_LOG_CONTEXT_STRING_MAX_BYTES: usize = 1024;
const FORWARDED_LOG_CONTEXT_ARRAY_MAX_ITEMS: usize = 32;
const FORWARDED_LOG_ROUTE: &str = "/v1/platform/logs/forwarded";

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

    fn retention_metadata(&self, durable: bool) -> PlatformLogRetentionMetadata {
        let oldest_seq = self.entries.front().map(|entry| entry.seq);
        let newest_seq = self.entries.back().map(|entry| entry.seq);
        PlatformLogRetentionMetadata {
            retention_limit: self.capacity,
            retained_count: self.entries.len(),
            oldest_seq,
            newest_seq,
            dropped_before_seq: oldest_seq
                .and_then(|seq| seq.checked_sub(1))
                .filter(|seq| *seq > 0),
            durable,
            basis: if durable { "data_dir" } else { "memory" },
            source: if durable {
                PLATFORM_LOGS_FILE
            } else {
                "process_memory"
            },
        }
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

#[derive(Debug)]
struct ForwardedPlatformLogRequest {
    service_id: String,
    level: PlatformLogLevel,
    target: String,
    message: String,
    context: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ForwardedPlatformLogAcceptedAuditPayload {
    log_id: String,
    log_seq: u64,
    log_timestamp: String,
    service_id: String,
    level: PlatformLogLevel,
    target: String,
    message_len_bytes: usize,
    message_sha256: String,
    context_key_count: usize,
    context_serialized_size_bytes: usize,
}

#[derive(Debug, Serialize)]
struct ForwardedPlatformLogRouteOutcomeAuditPayload {
    route: &'static str,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct ForwardedPlatformLogRejectedAuditPayload {
    route: &'static str,
    outcome: &'static str,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct ForwardedPlatformLogSuppressedAuditPayload {
    route: &'static str,
    outcome: &'static str,
    reason_code: &'static str,
    service_id: String,
    level: PlatformLogLevel,
    target: String,
    message_len_bytes: usize,
    message_sha256: String,
    context_key_count: usize,
    context_serialized_size_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
enum ForwardedLogRejectionReason {
    MalformedJson,
    NonObject,
    UnsupportedField,
    MissingRequiredValue,
    InvalidType,
    BlankValue,
    OversizedValue,
    InvalidValue,
    InvalidContext,
    UnsupportedContextKey,
}

impl ForwardedLogRejectionReason {
    fn code(self) -> &'static str {
        match self {
            ForwardedLogRejectionReason::MalformedJson => "malformed_json",
            ForwardedLogRejectionReason::NonObject => "non_object",
            ForwardedLogRejectionReason::UnsupportedField => "unsupported_field",
            ForwardedLogRejectionReason::MissingRequiredValue => "missing_required_value",
            ForwardedLogRejectionReason::InvalidType => "invalid_type",
            ForwardedLogRejectionReason::BlankValue => "blank_value",
            ForwardedLogRejectionReason::OversizedValue => "oversized_value",
            ForwardedLogRejectionReason::InvalidValue => "invalid_value",
            ForwardedLogRejectionReason::InvalidContext => "invalid_context",
            ForwardedLogRejectionReason::UnsupportedContextKey => "unsupported_context_key",
        }
    }

    fn message(self) -> &'static str {
        match self {
            ForwardedLogRejectionReason::MalformedJson => {
                "forwarded platform log request body is malformed JSON"
            }
            ForwardedLogRejectionReason::NonObject => {
                "forwarded platform log request must be a JSON object"
            }
            ForwardedLogRejectionReason::UnsupportedField => {
                "forwarded platform log request contains unsupported fields"
            }
            ForwardedLogRejectionReason::MissingRequiredValue => {
                "forwarded platform log request is missing required values"
            }
            ForwardedLogRejectionReason::InvalidType => {
                "forwarded platform log request contains invalid value types"
            }
            ForwardedLogRejectionReason::BlankValue => {
                "forwarded platform log request contains blank values"
            }
            ForwardedLogRejectionReason::OversizedValue => {
                "forwarded platform log request contains oversized values"
            }
            ForwardedLogRejectionReason::InvalidValue => {
                "forwarded platform log request contains invalid values"
            }
            ForwardedLogRejectionReason::InvalidContext => {
                "forwarded platform log context is invalid"
            }
            ForwardedLogRejectionReason::UnsupportedContextKey => {
                "forwarded platform log context contains unsupported keys"
            }
        }
    }
}

#[derive(Debug)]
struct ForwardedLogRejection {
    reason: ForwardedLogRejectionReason,
}

impl ForwardedLogRejection {
    fn new(reason: ForwardedLogRejectionReason) -> Self {
        Self { reason }
    }

    fn into_api_error(self) -> ApiError {
        ApiError::Unprocessable(self.reason.message().to_owned())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ForwardedPlatformLogResponse {
    pub accepted: bool,
}

pub(crate) async fn record_platform_log(
    state: &AppState,
    input: PlatformLogInput<'_>,
) -> Result<Option<PlatformLogEntry>, ApiError> {
    validate_platform_service_id(input.service_id)?;
    validate_emitted_level(input.level)?;
    let threshold = {
        let settings = state.settings.read().await;
        settings.platform.logging.effective_for(input.service_id)
    };
    if !threshold.allows(input.level) {
        return Ok(None);
    }

    let mut logs = state.platform_logs.write().await;
    let before = logs.clone();
    let entry = logs.push(
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
    Ok(Some(entry))
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
    pub retention: PlatformLogRetentionMetadata,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformLogRetentionMetadata {
    pub retention_limit: usize,
    pub retained_count: usize,
    pub oldest_seq: Option<u64>,
    pub newest_seq: Option<u64>,
    pub dropped_before_seq: Option<u64>,
    pub durable: bool,
    pub basis: &'static str,
    pub source: &'static str,
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
    let durable = state.platform_logs_path.is_some();
    let platform_logs = state.platform_logs.read().await;
    let logs = platform_logs.tail(filter, tail);
    let retention = platform_logs.retention_metadata(durable);

    Ok(Json(PlatformLogsResponse {
        logs,
        tail,
        order: "chronological",
        retention,
        limitations: limitations(durable),
    }))
}

/// `POST /v1/platform/logs/forwarded` — ingest one supervisor-forwarded structured platform log.
pub async fn ingest_forwarded_log(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<(StatusCode, Json<ForwardedPlatformLogResponse>), ApiError> {
    let authz = authorizer(&state, &actor).await?;
    if !authz.permits(Permission::PlatformLogsWrite, Scope::Global) {
        append_forwarded_log_denied_event(&state, &actor, &attestor).await?;
        return Err(forbidden());
    }

    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            let rejection = ForwardedLogRejection::new(ForwardedLogRejectionReason::MalformedJson);
            append_forwarded_log_rejected_event(&state, &actor, &attestor, rejection.reason)
                .await?;
            return Err(rejection.into_api_error());
        }
    };

    let request = match parse_forwarded_log_request(payload) {
        Ok(request) => request,
        Err(rejection) => {
            append_forwarded_log_rejected_event(&state, &actor, &attestor, rejection.reason)
                .await?;
            return Err(rejection.into_api_error());
        }
    };

    let retained = record_platform_log(
        &state,
        PlatformLogInput {
            service_id: &request.service_id,
            level: request.level,
            target: &request.target,
            message: &request.message,
            context: request.context.clone(),
        },
    )
    .await?;
    if let Some(entry) = retained {
        append_forwarded_log_accepted_event(&state, &actor, &attestor, &entry).await?;
    } else {
        append_forwarded_log_suppressed_event(&state, &actor, &attestor, &request).await?;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ForwardedPlatformLogResponse { accepted: true }),
    ))
}

async fn append_forwarded_log_accepted_event(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    entry: &PlatformLogEntry,
) -> Result<(), ApiError> {
    let payload = forwarded_log_accepted_payload(entry)?;
    append_forwarded_log_audit_event(
        state,
        actor,
        attestor,
        "platform.log.forwarded.accepted",
        "forwarded platform log accepted",
        &payload,
    )
    .await
}

async fn append_forwarded_log_denied_event(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let payload = ForwardedPlatformLogRouteOutcomeAuditPayload {
        route: FORWARDED_LOG_ROUTE,
        outcome: "rbac_denied",
    };
    append_forwarded_log_audit_event(
        state,
        actor,
        attestor,
        "platform.log.forwarded.denied",
        "forwarded platform log denied",
        &payload,
    )
    .await
}

async fn append_forwarded_log_rejected_event(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    reason: ForwardedLogRejectionReason,
) -> Result<(), ApiError> {
    let payload = ForwardedPlatformLogRejectedAuditPayload {
        route: FORWARDED_LOG_ROUTE,
        outcome: "rejected",
        reason_code: reason.code(),
    };
    append_forwarded_log_audit_event(
        state,
        actor,
        attestor,
        "platform.log.forwarded.rejected",
        "forwarded platform log rejected",
        &payload,
    )
    .await
}

async fn append_forwarded_log_suppressed_event(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    request: &ForwardedPlatformLogRequest,
) -> Result<(), ApiError> {
    let payload = forwarded_log_suppressed_payload(request)?;
    append_forwarded_log_audit_event(
        state,
        actor,
        attestor,
        "platform.log.forwarded.suppressed",
        "forwarded platform log suppressed",
        &payload,
    )
    .await
}

async fn append_forwarded_log_audit_event<T: Serialize>(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    kind: &str,
    justification: &str,
    payload: &T,
) -> Result<(), ApiError> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let actor = actor.resolve("api");
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor,
        "platform",
        kind,
        Some(justification),
        &payload_bytes,
    )?;
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

fn forwarded_log_accepted_payload(
    entry: &PlatformLogEntry,
) -> Result<ForwardedPlatformLogAcceptedAuditPayload, ApiError> {
    let (context_key_count, context_serialized_size_bytes) =
        forwarded_context_audit_summary(entry.context.as_ref())?;
    Ok(ForwardedPlatformLogAcceptedAuditPayload {
        log_id: entry.id.clone(),
        log_seq: entry.seq,
        log_timestamp: entry.timestamp.clone(),
        service_id: entry.service_id.clone(),
        level: entry.level,
        target: entry.target.clone(),
        message_len_bytes: entry.message.len(),
        message_sha256: crate::hex::hex(&chancela_ledger::digest(entry.message.as_bytes())),
        context_key_count,
        context_serialized_size_bytes,
    })
}

fn forwarded_log_suppressed_payload(
    request: &ForwardedPlatformLogRequest,
) -> Result<ForwardedPlatformLogSuppressedAuditPayload, ApiError> {
    let (context_key_count, context_serialized_size_bytes) =
        forwarded_context_audit_summary(request.context.as_ref())?;
    Ok(ForwardedPlatformLogSuppressedAuditPayload {
        route: FORWARDED_LOG_ROUTE,
        outcome: "suppressed",
        reason_code: "threshold_suppressed",
        service_id: request.service_id.clone(),
        level: request.level,
        target: request.target.clone(),
        message_len_bytes: request.message.len(),
        message_sha256: crate::hex::hex(&chancela_ledger::digest(request.message.as_bytes())),
        context_key_count,
        context_serialized_size_bytes,
    })
}

fn forwarded_context_audit_summary(context: Option<&Value>) -> Result<(usize, usize), ApiError> {
    let Some(context) = context else {
        return Ok((0, 0));
    };
    let serialized_size = serde_json::to_vec(context)
        .map_err(|e| ApiError::Internal(format!("failed to summarize platform log context: {e}")))?
        .len();
    Ok((context_key_count(context), serialized_size))
}

fn context_key_count(value: &Value) -> usize {
    match value {
        Value::Object(map) => map.len() + map.values().map(context_key_count).sum::<usize>(),
        Value::Array(items) => items.iter().map(context_key_count).sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
    }
}

fn parse_forwarded_log_request(
    payload: Value,
) -> Result<ForwardedPlatformLogRequest, ForwardedLogRejection> {
    let fields = payload
        .as_object()
        .ok_or_else(|| ForwardedLogRejection::new(ForwardedLogRejectionReason::NonObject))?;

    for key in fields.keys() {
        match key.as_str() {
            "service_id" | "level" | "target" | "message" | "context" => {}
            _ => {
                return Err(ForwardedLogRejection::new(
                    ForwardedLogRejectionReason::UnsupportedField,
                ));
            }
        }
    }

    let service_id =
        required_bounded_string(fields, "service_id", FORWARDED_LOG_SERVICE_ID_MAX_BYTES)?;
    if !is_known_platform_service_id(&service_id) {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::InvalidValue,
        ));
    }

    let level = parse_forwarded_log_level(&required_bounded_string(fields, "level", 16)?)?;
    let target = required_bounded_string(fields, "target", FORWARDED_LOG_TARGET_MAX_BYTES)?;
    let message = required_bounded_string(fields, "message", FORWARDED_LOG_MESSAGE_MAX_BYTES)?;
    let context = match fields.get("context") {
        None | Some(Value::Null) => None,
        Some(value) => {
            validate_forwarded_context(value)?;
            Some(value.clone())
        }
    };

    Ok(ForwardedPlatformLogRequest {
        service_id,
        level,
        target,
        message,
        context,
    })
}

fn required_bounded_string(
    fields: &serde_json::Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<String, ForwardedLogRejection> {
    let raw = fields.get(field).ok_or_else(|| {
        ForwardedLogRejection::new(ForwardedLogRejectionReason::MissingRequiredValue)
    })?;
    let value = raw
        .as_str()
        .ok_or_else(|| ForwardedLogRejection::new(ForwardedLogRejectionReason::InvalidType))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::BlankValue,
        ));
    }
    if trimmed.len() > max_bytes {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::OversizedValue,
        ));
    }
    Ok(trimmed.to_owned())
}

fn parse_forwarded_log_level(raw: &str) -> Result<PlatformLogLevel, ForwardedLogRejection> {
    match raw {
        "trace" => Ok(PlatformLogLevel::Trace),
        "debug" => Ok(PlatformLogLevel::Debug),
        "info" => Ok(PlatformLogLevel::Info),
        "warn" => Ok(PlatformLogLevel::Warn),
        "error" => Ok(PlatformLogLevel::Error),
        _ => Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::InvalidValue,
        )),
    }
}

fn validate_forwarded_context(context: &Value) -> Result<(), ForwardedLogRejection> {
    let Some(object) = context.as_object() else {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::InvalidContext,
        ));
    };
    if object.is_empty() {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::BlankValue,
        ));
    }
    let size = serde_json::to_vec(context)
        .map_err(|_| ForwardedLogRejection::new(ForwardedLogRejectionReason::InvalidContext))?
        .len();
    if size > FORWARDED_LOG_CONTEXT_MAX_BYTES {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::OversizedValue,
        ));
    }

    let mut key_count = 0;
    validate_forwarded_context_value(context, 0, &mut key_count)
}

fn validate_forwarded_context_value(
    value: &Value,
    depth: usize,
    key_count: &mut usize,
) -> Result<(), ForwardedLogRejection> {
    if depth > FORWARDED_LOG_CONTEXT_MAX_DEPTH {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::InvalidContext,
        ));
    }

    match value {
        Value::Object(map) => {
            for (key, child) in map {
                validate_forwarded_context_key(key)?;
                *key_count += 1;
                if *key_count > FORWARDED_LOG_CONTEXT_MAX_KEYS {
                    return Err(ForwardedLogRejection::new(
                        ForwardedLogRejectionReason::OversizedValue,
                    ));
                }
                validate_forwarded_context_value(child, depth + 1, key_count)?;
            }
        }
        Value::Array(items) => {
            if items.len() > FORWARDED_LOG_CONTEXT_ARRAY_MAX_ITEMS {
                return Err(ForwardedLogRejection::new(
                    ForwardedLogRejectionReason::OversizedValue,
                ));
            }
            for item in items {
                validate_forwarded_context_value(item, depth + 1, key_count)?;
            }
        }
        Value::String(value) => {
            if value.trim().is_empty() {
                return Err(ForwardedLogRejection::new(
                    ForwardedLogRejectionReason::BlankValue,
                ));
            }
            if value.len() > FORWARDED_LOG_CONTEXT_STRING_MAX_BYTES {
                return Err(ForwardedLogRejection::new(
                    ForwardedLogRejectionReason::OversizedValue,
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }

    Ok(())
}

fn validate_forwarded_context_key(key: &str) -> Result<(), ForwardedLogRejection> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::BlankValue,
        ));
    }
    if trimmed.len() > FORWARDED_LOG_CONTEXT_KEY_MAX_BYTES {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::OversizedValue,
        ));
    }
    if is_stream_context_key(trimmed) || is_secret_like_context_key(trimmed) {
        return Err(ForwardedLogRejection::new(
            ForwardedLogRejectionReason::UnsupportedContextKey,
        ));
    }
    Ok(())
}

fn is_stream_context_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("stdout") || key.eq_ignore_ascii_case("stderr")
}

fn is_secret_like_context_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "authorization",
        "credential",
        "privatekey",
        "accesskey",
        "clientsecret",
        "bearer",
        "cookie",
        "session",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
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
