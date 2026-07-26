//! Cross-process search projector runtime and heartbeat contract.
//!
//! The HTTP process can run with `CHANCELA_SEARCH_RUNTIME=query-only`; this service independently
//! refreshes authoritative application state, builds the search corpus, and publishes one complete
//! durable generation through the store's lease/checkpoint CAS boundary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chancela_search::{
    ExternalSearchProjectorConfig, IndexOperation, SearchDocument, SearchIndexPhase,
    SearchIndexState, SearchProjectionCommand, SearchProjectionControl,
    SearchProjectionPublishOutcome, SearchProjectionPublishRejection, SearchProjectorLease,
    SearchSettings,
};
use chancela_store::Store;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

pub const RUNTIME_DIR_ENV: &str = "CHANCELA_SEARCH_RUNTIME_DIR";
pub const HEARTBEAT_SECONDS_ENV: &str = "CHANCELA_SEARCH_HEARTBEAT_SECONDS";
pub const HEALTH_MAX_AGE_SECONDS_ENV: &str = "CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS";
pub const INSTANCE_ID_ENV: &str = "CHANCELA_SEARCH_INSTANCE_ID";
pub const HEARTBEAT_DIRECTORY: &str = "search-projector-heartbeats";
pub const NODE_ROLE_ENV: &str = "CHANCELA_NODE_ROLE";

const HEARTBEAT_SCHEMA_VERSION: u32 = 2;
const SERVICE_NAME: &str = "chancela-search-projector";
const SEARCH_PROJECTION_UTC_BUCKET_CHANGED: &str =
    "search projection crossed its captured UTC date; retrying from a fresh as-of instant";
const DEFAULT_HEARTBEAT_SECONDS: u64 = 10;
pub const DEFAULT_HEALTH_MAX_AGE_SECONDS: u64 = 600;
const MIN_HEARTBEAT_SECONDS: u64 = 1;
const MAX_HEARTBEAT_SECONDS: u64 = 300;
const MIN_LEASE_SECONDS: u64 = 15;
const HEARTBEAT_PRUNE_MAX_INSPECTED: usize = 256;
const HEARTBEAT_PRUNE_MAX_REMOVED: usize = 32;
const HEARTBEAT_RETENTION_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const CHILD_SHUTDOWN_GRACE: Duration = Duration::from_secs(4);
const OWNED_SHUTDOWN_RELEASE_GRACE: Duration = Duration::from_millis(500);
/// Process-level grace after a shutdown signal before the projector supervisor is aborted.
pub const PROCESS_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectorRunMode {
    Run,
    Once,
}

/// Narrow process bootstrap: one query-only store plus the three settings needed before Tokio and
/// the first corpus snapshot exist.
pub struct ProjectorBootstrap {
    store: Store,
    pub config: ExternalSearchProjectorConfig,
}

#[derive(Debug, Clone)]
pub struct ProjectorOptions {
    pub runtime_dir: PathBuf,
    pub heartbeat_interval: Duration,
    pub health_max_age: Duration,
    pub owner: String,
}

impl ProjectorOptions {
    pub fn from_env(runtime_dir: Option<PathBuf>) -> Result<Self, ProjectorError> {
        let runtime_dir = runtime_dir
            .or_else(|| std::env::var_os(RUNTIME_DIR_ENV).map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("chancela-runtime"));
        let heartbeat_seconds = match std::env::var(HEARTBEAT_SECONDS_ENV) {
            Ok(raw) => raw.trim().parse::<u64>().map_err(|_| {
                ProjectorError::Configuration(format!(
                    "{HEARTBEAT_SECONDS_ENV}={raw:?} is invalid; expected an integer from \
                     {MIN_HEARTBEAT_SECONDS} to {MAX_HEARTBEAT_SECONDS}"
                ))
            })?,
            Err(std::env::VarError::NotPresent) => DEFAULT_HEARTBEAT_SECONDS,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ProjectorError::Configuration(format!(
                    "{HEARTBEAT_SECONDS_ENV} contains non-Unicode data"
                )));
            }
        };
        if !(MIN_HEARTBEAT_SECONDS..=MAX_HEARTBEAT_SECONDS).contains(&heartbeat_seconds) {
            return Err(ProjectorError::Configuration(format!(
                "{HEARTBEAT_SECONDS_ENV} must be from {MIN_HEARTBEAT_SECONDS} to \
                {MAX_HEARTBEAT_SECONDS}, got {heartbeat_seconds}"
            )));
        }
        let health_max_age = resolve_health_max_age(Some(heartbeat_seconds), None)?;
        let host = match std::env::var(INSTANCE_ID_ENV) {
            Ok(raw) => normalize_instance_id(&raw)?,
            Err(std::env::VarError::NotPresent) => std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown-host".to_owned()),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ProjectorError::Configuration(format!(
                    "{INSTANCE_ID_ENV} contains non-Unicode data"
                )));
            }
        };
        Ok(Self {
            runtime_dir,
            heartbeat_interval: Duration::from_secs(heartbeat_seconds),
            health_max_age,
            owner: format!("{host}:{}:{}", std::process::id(), Uuid::new_v4()),
        })
    }

    fn lease_ttl(&self) -> Duration {
        Duration::from_secs(
            self.heartbeat_interval
                .as_secs()
                .saturating_mul(4)
                .max(MIN_LEASE_SECONDS),
        )
    }
}

/// Resolve the heartbeat freshness window from the explicit CLI override or
/// [`HEALTH_MAX_AGE_SECONDS_ENV`] (default 600 seconds). The window must be at least twice the
/// heartbeat interval so routine scheduling jitter cannot flap service health.
pub fn resolve_health_max_age(
    heartbeat_seconds: Option<u64>,
    explicit_max_age_seconds: Option<u64>,
) -> Result<Duration, ProjectorError> {
    let heartbeat_seconds = match heartbeat_seconds {
        Some(value) => value,
        None => configured_u64(
            HEARTBEAT_SECONDS_ENV,
            DEFAULT_HEARTBEAT_SECONDS,
            MIN_HEARTBEAT_SECONDS,
            MAX_HEARTBEAT_SECONDS,
        )?,
    };
    let max_age_seconds = match explicit_max_age_seconds {
        Some(value) => value,
        None => configured_u64(
            HEALTH_MAX_AGE_SECONDS_ENV,
            DEFAULT_HEALTH_MAX_AGE_SECONDS,
            1,
            u64::MAX,
        )?,
    };
    let minimum = heartbeat_seconds.saturating_mul(2);
    if max_age_seconds < minimum {
        return Err(ProjectorError::Configuration(format!(
            "{HEALTH_MAX_AGE_SECONDS_ENV} (or --max-age-seconds) must be at least twice \
             {HEARTBEAT_SECONDS_ENV}: expected >= {minimum}, got {max_age_seconds}"
        )));
    }
    Ok(Duration::from_secs(max_age_seconds))
}

fn configured_u64(name: &str, default: u64, min: u64, max: u64) -> Result<u64, ProjectorError> {
    let value = match std::env::var(name) {
        Ok(raw) => raw.trim().parse::<u64>().map_err(|_| {
            ProjectorError::Configuration(format!(
                "{name}={raw:?} is invalid; expected an integer from {min} to {max}"
            ))
        })?,
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ProjectorError::Configuration(format!(
                "{name} contains non-Unicode data"
            )));
        }
    };
    if !(min..=max).contains(&value) {
        return Err(ProjectorError::Configuration(format!(
            "{name} must be from {min} to {max}, got {value}"
        )));
    }
    Ok(value)
}

fn normalize_instance_id(raw: &str) -> Result<String, ProjectorError> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        return Err(ProjectorError::Configuration(format!(
            "{INSTANCE_ID_ENV} must contain from 1 to 128 printable characters"
        )));
    }
    Ok(value.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectorPhase {
    Starting,
    Standby,
    Building,
    Idle,
    Paused,
    Disabled,
    Error,
    ShuttingDown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectorHeartbeat {
    pub schema_version: u32,
    pub service: String,
    pub lease_id: String,
    pub owner: String,
    pub pid: u32,
    pub phase: ProjectorPhase,
    pub updated_at: String,
    pub updated_at_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_unix_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence_token: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ProjectorHeartbeat {
    fn new(owner: String) -> Self {
        let mut heartbeat = Self {
            schema_version: HEARTBEAT_SCHEMA_VERSION,
            service: SERVICE_NAME.to_owned(),
            lease_id: String::new(),
            owner,
            pid: std::process::id(),
            phase: ProjectorPhase::Starting,
            updated_at: String::new(),
            updated_at_unix_ms: 0,
            lease_expires_at_unix_ms: None,
            source_revision: None,
            fence_token: None,
            command_generation: None,
            generation: None,
            document_count: None,
            last_error: None,
        };
        heartbeat.touch();
        heartbeat
    }

    fn touch(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.updated_at = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        self.updated_at_unix_ms =
            i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    }

    fn observe_control(&mut self, control: &SearchProjectionControl) {
        self.source_revision = Some(control.checkpoint.source_revision);
        self.fence_token = Some(control.checkpoint.fence_token);
        self.command_generation = Some(control.checkpoint.command_generation);
        self.lease_expires_at_unix_ms = control
            .lease
            .as_ref()
            .filter(|lease| lease.owner == self.owner)
            .map(|lease| lease.expires_at_unix_ms);
    }

    fn observe_lease(&mut self, lease: &SearchProjectorLease) {
        self.lease_id.clone_from(&lease.lease_id);
        self.lease_expires_at_unix_ms = Some(lease.expires_at_unix_ms);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectorError {
    #[error("{0}")]
    Configuration(String),
    #[error("failed to initialize projector state: {0}")]
    State(String),
    #[error("external search projector requires a durable store")]
    DurableStoreRequired,
    #[error("projector store operation failed: {0}")]
    Store(String),
    #[error("search projection failed: {0}")]
    Projection(String),
    #[error("another search projector holds the durable lease")]
    LeaseUnavailable,
    #[error("search projection is durably paused")]
    Paused,
    #[error("search projection is disabled in instance settings")]
    Disabled,
    #[error("heartbeat at {path} is unhealthy: {reason}")]
    UnhealthyHeartbeat { path: PathBuf, reason: String },
    #[error("heartbeat I/O failed for {path}: {source}")]
    HeartbeatIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("heartbeat JSON at {path} is invalid: {source}")]
    HeartbeatJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Fail closed before opening a Postgres store unless the projector is pinned as a follower.
///
/// Its dedicated projector lease is independent from the API ledger-writer advisory lock. This
/// guard prevents a standalone projector that starts first from ever competing for the latter.
pub fn validate_projector_environment() -> Result<(), ProjectorError> {
    let backend = std::env::var(chancela_runtime_config::DB_BACKEND_ENV)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(backend.as_str(), "postgres" | "postgresql" | "pg") {
        let role = std::env::var(NODE_ROLE_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if role != "follower" {
            return Err(ProjectorError::Configuration(format!(
                "{}={backend} requires {NODE_ROLE_ENV}=follower for {SERVICE_NAME}; the projector \
                 must never contend for the authoritative ledger-writer lock",
                chancela_runtime_config::DB_BACKEND_ENV
            )));
        }
    }
    Ok(())
}

pub fn bootstrap_state() -> Result<ProjectorBootstrap, ProjectorError> {
    validate_projector_environment()?;
    let (store, settings) = chancela_runtime_config::search_projector_store_and_settings_from_env()
        .map_err(|error| ProjectorError::State(error.to_string()))?;
    let config = ExternalSearchProjectorConfig::from(&settings.search);
    Ok(ProjectorBootstrap { store, config })
}

fn configured_reconciliation_interval(config: &ExternalSearchProjectorConfig) -> Duration {
    Duration::from_secs(u64::from(config.interval_seconds.clamp(5, 86_400)))
}

struct ReconciliationState {
    interval: Duration,
    startup_pending: bool,
}

/// Run continuously, or perform at most one required generation for `Once`.
pub async fn run_projector(
    bootstrap: ProjectorBootstrap,
    options: ProjectorOptions,
    mode: ProjectorRunMode,
    shutdown: Arc<AtomicBool>,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    let provider = StoreProvider::new(bootstrap.store);
    // The durable source checkpoint cannot identify a new binary's embedded law/template catalog
    // or projection-algorithm changes. Keep this process-level flag across lease retries and clear
    // it only after the first successful publication.
    let mut reconciliation = ReconciliationState {
        interval: configured_reconciliation_interval(&bootstrap.config),
        startup_pending: true,
    };
    let heartbeat = Arc::new(Mutex::new(ProjectorHeartbeat::new(options.owner.clone())));

    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(finish_shutdown_local(&heartbeat));
        }
        let store = provider.current().await?;
        let lease = acquire_lease(&store, &options).await?;
        let Some(lease) = lease else {
            update_local_heartbeat(&heartbeat, |value| {
                value.phase = ProjectorPhase::Standby;
                value.lease_expires_at_unix_ms = None;
                value.last_error = None;
            });
            if mode == ProjectorRunMode::Once {
                return Err(ProjectorError::LeaseUnavailable);
            }
            wait_or_shutdown(options.heartbeat_interval, &shutdown).await;
            continue;
        };
        update_local_heartbeat(&heartbeat, |value| {
            value.observe_lease(&lease);
            value.phase = ProjectorPhase::Starting;
            value.last_error = None;
        });

        match run_with_lease(
            &provider,
            &options,
            mode,
            &shutdown,
            &heartbeat,
            lease.clone(),
            &mut reconciliation,
        )
        .await
        {
            Ok(done) => {
                if done && shutdown.load(Ordering::Acquire) {
                    return finish_owned_shutdown_and_release(
                        &provider,
                        &options.runtime_dir,
                        &heartbeat,
                        &lease,
                    )
                    .await;
                }
                if done || mode == ProjectorRunMode::Once {
                    let finished =
                        finish_owned_shutdown(&provider, &options.runtime_dir, &heartbeat, &lease)
                            .await;
                    let _ = release_lease_current(&provider, lease).await;
                    return finished;
                }
                let _ = release_lease_current(&provider, lease).await;
            }
            Err(ProjectorError::Store(message)) if message.contains("lease lost") => {
                let _ = release_lease_current(&provider, lease).await;
                if mode == ProjectorRunMode::Once {
                    return Err(ProjectorError::Store(message));
                }
            }
            Err(error) => {
                let heartbeat_result = update_heartbeat_if_still_owned(
                    &provider,
                    &options.runtime_dir,
                    &heartbeat,
                    &lease,
                    |value| {
                        value.phase = ProjectorPhase::Error;
                        value.last_error = Some(error.to_string());
                    },
                )
                .await;
                let _ = release_lease_current(&provider, lease).await;
                heartbeat_result?;
                if mode == ProjectorRunMode::Once {
                    return Err(error);
                }
                wait_or_shutdown(options.heartbeat_interval, &shutdown).await;
            }
        }
    }
}

/// Apply the definitive process-level shutdown bound around the entire projector run.
///
/// This covers awaits outside candidate construction too (store reopen, lease acquisition,
/// control/status reads, and release). `Ok(None)` means the grace elapsed and the async supervisor
/// was aborted after the shutdown flag had been published.
pub async fn supervise_projector_task<F>(
    mut task: tokio::task::JoinHandle<Result<ProjectorHeartbeat, ProjectorError>>,
    shutdown: Arc<AtomicBool>,
    shutdown_signal: F,
    grace: Duration,
) -> Result<Option<ProjectorHeartbeat>, ProjectorError>
where
    F: std::future::Future<Output = ()>,
{
    tokio::select! {
        result = &mut task => flatten_projector_join(result).map(Some),
        () = shutdown_signal => {
            shutdown.store(true, Ordering::Release);
            match tokio::time::timeout(grace, &mut task).await {
                Ok(result) => flatten_projector_join(result).map(Some),
                Err(_) => {
                    task.abort();
                    let _ = tokio::time::timeout(Duration::from_millis(100), &mut task).await;
                    Ok(None)
                }
            }
        }
    }
}

fn flatten_projector_join(
    result: Result<Result<ProjectorHeartbeat, ProjectorError>, tokio::task::JoinError>,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    result.map_err(|error| {
        ProjectorError::State(format!(
            "projector supervisor terminated unexpectedly: {error}"
        ))
    })?
}

async fn run_with_lease(
    provider: &StoreProvider,
    options: &ProjectorOptions,
    mode: ProjectorRunMode,
    shutdown: &Arc<AtomicBool>,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    lease: SearchProjectorLease,
    reconciliation: &mut ReconciliationState,
) -> Result<bool, ProjectorError> {
    let lease_lost = Arc::new(AtomicBool::new(false));
    let stop_heartbeat = Arc::new(AtomicBool::new(false));
    let heartbeat_task = tokio::spawn(heartbeat_lease(
        provider.clone(),
        options.clone(),
        heartbeat.clone(),
        lease.clone(),
        shutdown.clone(),
        lease_lost.clone(),
        stop_heartbeat.clone(),
    ));

    let result = async {
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Ok(true);
            }
            if lease_lost.load(Ordering::Acquire) {
                return Err(ProjectorError::Store("projector lease lost".to_owned()));
            }

            let control_store = provider.current().await?;
            let before = read_control(&control_store).await?;
            ensure_current_lease(&before, &lease)?;
            update_owned_heartbeat(&options.runtime_dir, heartbeat, &before, &lease, |value| {
                value.observe_control(&before);
                value.last_error = None;
            })?;
            if before.command == SearchProjectionCommand::Pause {
                update_owned_heartbeat(
                    &options.runtime_dir,
                    heartbeat,
                    &before,
                    &lease,
                    |value| {
                        value.phase = ProjectorPhase::Paused;
                    },
                )?;
                if mode == ProjectorRunMode::Once {
                    return Err(ProjectorError::Paused);
                }
                wait_or_shutdown(reconciliation.interval, shutdown).await;
                continue;
            }

            let current_config = load_projector_config(&control_store).await?;
            reconciliation.interval = configured_reconciliation_interval(&current_config);
            if !current_config.enabled {
                update_heartbeat_if_still_owned(
                    provider,
                    &options.runtime_dir,
                    heartbeat,
                    &lease,
                    |value| {
                        value.phase = ProjectorPhase::Disabled;
                    },
                )
                .await?;
                if mode == ProjectorRunMode::Once {
                    return Err(ProjectorError::Disabled);
                }
                wait_or_shutdown(reconciliation.interval, shutdown).await;
                continue;
            }

            let completed_status = load_completed_status(&control_store).await?;
            let projection_required = projection_required(
                &before,
                completed_status.as_ref(),
                OffsetDateTime::now_utc(),
                reconciliation.startup_pending,
            );
            if !projection_required {
                update_heartbeat_if_still_owned(
                    provider,
                    &options.runtime_dir,
                    heartbeat,
                    &lease,
                    |value| {
                        value.phase = ProjectorPhase::Idle;
                        if let Some(status) = completed_status.as_ref() {
                            value.generation = Some(status.generation);
                            value.document_count = Some(status.document_count);
                        }
                    },
                )
                .await?;
                if mode == ProjectorRunMode::Once {
                    return Ok(true);
                }
                wait_or_shutdown(reconciliation.interval, shutdown).await;
                continue;
            }

            // Capture-before-refresh + capture-after-refresh closes the gap between independent
            // source-table/sidecar reads. A commit during snapshot hydration changes the revision
            // and discards this candidate before any corpus work begins.
            //
            // Re-resolve at this boundary: Postgres returns the stable process handle (avoiding a
            // second pool per generation), while SQLite reopens after `before` so an atomic
            // recovery inode swap cannot strand hydration on the prior file.
            let candidate_store = provider.current().await?;
            // Wrap spawn_blocking in an async task. On shutdown the wrapper can be aborted after
            // the grace even though Tokio cannot stop an already-running blocking read. That
            // detached read-only call cannot publish; publication remains guarded separately by
            // the durable lease/checkpoint CAS.
            let mut refresh_task = tokio::spawn(async move {
                tokio::task::spawn_blocking(move || -> Result<_, ProjectorError> {
                    let data_dir =
                        chancela_runtime_config::resolve_data_dir().ok_or_else(|| {
                            ProjectorError::State(format!(
                                "the external search projector requires a durable store; set {}",
                                chancela_runtime_config::DATA_DIR_ENV
                            ))
                        })?;
                    let settings = chancela_runtime_config::search_projector_settings_with_store(
                        &candidate_store,
                        &data_dir,
                    )
                    .map_err(|error| ProjectorError::State(error.to_string()))?;
                    let projection_as_of = OffsetDateTime::now_utc();
                    let inputs = chancela_search_projection::load_projection_inputs(
                        &candidate_store,
                        &data_dir,
                        &settings,
                        projection_as_of,
                    )
                    .map_err(ProjectorError::State)?;
                    Ok((settings, inputs, candidate_store, projection_as_of))
                })
                .await
                .map_err(|error| {
                    ProjectorError::State(format!("state refresh task panicked: {error}"))
                })?
            });
            let refreshed = tokio::select! {
                result = &mut refresh_task => {
                    result.map_err(|error| {
                        ProjectorError::State(format!("state refresh wrapper panicked: {error}"))
                    })??
                }
                () = wait_for_shutdown_requested(shutdown) => {
                    return finish_task_after_supervisor(
                        &mut refresh_task,
                        None,
                        Ok(true),
                        CHILD_SHUTDOWN_GRACE,
                    ).await;
                }
            };
            let (refreshed_settings, projection_inputs, refreshed_store, projection_as_of) =
                refreshed;
            let refreshed_search_settings = refreshed_settings.search;
            reconciliation.interval = Duration::from_secs(u64::from(
                refreshed_search_settings.interval_seconds.clamp(5, 86_400),
            ));
            if !refreshed_search_settings.enabled {
                update_heartbeat_if_still_owned(
                    provider,
                    &options.runtime_dir,
                    heartbeat,
                    &lease,
                    |value| {
                        value.phase = ProjectorPhase::Disabled;
                    },
                )
                .await?;
                if mode == ProjectorRunMode::Once {
                    return Err(ProjectorError::Disabled);
                }
                wait_or_shutdown(reconciliation.interval, shutdown).await;
                continue;
            }
            let after = read_control(&refreshed_store).await?;
            ensure_current_lease(&after, &lease)?;
            if before.checkpoint != after.checkpoint || before.command != after.command {
                continue;
            }

            update_owned_heartbeat(&options.runtime_dir, heartbeat, &after, &lease, |value| {
                value.phase = ProjectorPhase::Building;
                value.observe_control(&after);
            })?;
            let candidate_cancel = Arc::new(AtomicBool::new(false));
            // Independent of the supervisor's current await: if it is stuck in provider/control
            // I/O and the process-level grace later aborts it, the candidate still observes global
            // shutdown and cannot continue toward publication unaware.
            let watcher_shutdown = shutdown.clone();
            let watcher_cancel = candidate_cancel.clone();
            let candidate_shutdown_watcher = tokio::spawn(async move {
                wait_for_shutdown_requested(&watcher_shutdown).await;
                watcher_cancel.store(true, Ordering::Release);
            });
            let build_provider = provider.clone();
            let build_lease = lease.clone();
            let build_cancel = candidate_cancel.clone();
            let checkpoint = after.checkpoint;
            let force_rebuild = after.command == SearchProjectionCommand::Rebuild;
            let mut build_task = tokio::spawn(async move {
                build_and_publish_projection(
                    &build_provider,
                    projection_inputs,
                    refreshed_search_settings,
                    projection_as_of,
                    build_lease,
                    checkpoint,
                    force_rebuild,
                    build_cancel,
                )
                .await
            });
            let mut superseded = false;
            let mut supervisor_exit = None;
            let build_result = loop {
                tokio::select! {
                    result = &mut build_task => {
                        break Some(result);
                    }
                    () = wait_for_shutdown_requested(shutdown) => {
                        supervisor_exit = Some(Ok(true));
                        break None;
                    }
                    () = tokio::time::sleep(Duration::from_millis(500)) => {
                        if lease_lost.load(Ordering::Acquire) {
                            supervisor_exit = Some(Err(ProjectorError::Store(
                                "projector lease lost".to_owned(),
                            )));
                            break None;
                        }
                        if !candidate_cancel.load(Ordering::Acquire) {
                            let current = match provider.current().await {
                                Ok(store) => read_control(&store).await,
                                Err(error) => Err(error),
                            };
                            match current {
                                Ok(control)
                                    if candidate_control_is_current(
                                        &control,
                                        checkpoint,
                                        &lease,
                                    ) => {}
                                Ok(_) => {
                                    superseded = true;
                                    candidate_cancel.store(true, Ordering::Release);
                                }
                                Err(error) => {
                                    supervisor_exit = Some(Err(error));
                                    break None;
                                }
                            }
                        }
                    }
                }
            };
            candidate_shutdown_watcher.abort();
            let _ = candidate_shutdown_watcher.await;
            if let Some(supervisor_exit) = supervisor_exit {
                return match supervisor_exit {
                    Ok(done) => {
                        finish_task_after_supervisor(
                            &mut build_task,
                            Some(candidate_cancel.as_ref()),
                            Ok(done),
                            CHILD_SHUTDOWN_GRACE,
                        )
                        .await
                    }
                    Err(error) => {
                        finish_candidate_after_error(
                            &mut build_task,
                            candidate_cancel.as_ref(),
                            error,
                        )
                        .await
                    }
                };
            }
            let build_result =
                build_result.expect("candidate result exists without supervisor exit");
            let build_result = build_result.map_err(|error| {
                ProjectorError::Projection(format!("candidate task panicked: {error}"))
            })?;
            if shutdown.load(Ordering::Acquire) {
                return Ok(true);
            }
            if lease_lost.load(Ordering::Acquire) {
                return Err(ProjectorError::Store("projector lease lost".to_owned()));
            }
            if superseded {
                // Pause, rebuild, source revision, destructive fence, or lease replacement changed
                // while the corpus was being assembled. The build observes cancellation and its
                // result is deliberately discarded; the next loop consumes the durable command.
                continue;
            }
            let outcome = match build_result {
                Err(error) if error == SEARCH_PROJECTION_UTC_BUCKET_CHANGED => {
                    // Every time-derived row in one candidate shares a captured UTC as-of
                    // instant. Crossing midnight invalidates that candidate before CAS; retry
                    // immediately under the still-current lease with a fresh bucket.
                    continue;
                }
                result => result.map_err(ProjectorError::Projection)?,
            };
            match outcome {
                SearchProjectionPublishOutcome::Published {
                    generation,
                    document_count,
                    ..
                } => {
                    reconciliation.startup_pending = false;
                    update_heartbeat_if_still_owned(
                        provider,
                        &options.runtime_dir,
                        heartbeat,
                        &lease,
                        |value| {
                            value.phase = ProjectorPhase::Idle;
                            value.generation = Some(generation);
                            value.document_count = Some(document_count);
                            value.last_error = None;
                        },
                    )
                    .await?;
                    if mode == ProjectorRunMode::Once {
                        return Ok(true);
                    }
                }
                SearchProjectionPublishOutcome::Rejected { reason, control } => {
                    update_heartbeat_if_still_owned(
                        provider,
                        &options.runtime_dir,
                        heartbeat,
                        &lease,
                        |value| {
                            value.observe_control(&control);
                        },
                    )
                    .await?;
                    match reason {
                        SearchProjectionPublishRejection::LeaseLost => {
                            return Err(ProjectorError::Store("projector lease lost".to_owned()));
                        }
                        SearchProjectionPublishRejection::Paused => {
                            if mode == ProjectorRunMode::Once {
                                return Err(ProjectorError::Paused);
                            }
                        }
                        SearchProjectionPublishRejection::SourceChanged
                        | SearchProjectionPublishRejection::FenceChanged
                        | SearchProjectionPublishRejection::CommandChanged => {}
                    }
                }
            }
        }
    }
    .await;

    stop_heartbeat.store(true, Ordering::Release);
    let mut heartbeat_task = heartbeat_task;
    if tokio::time::timeout(Duration::from_secs(5), &mut heartbeat_task)
        .await
        .is_err()
    {
        heartbeat_task.abort();
        let _ = heartbeat_task.await;
    }
    result
}

async fn acquire_lease(
    store: &Store,
    options: &ProjectorOptions,
) -> Result<Option<SearchProjectorLease>, ProjectorError> {
    let store = store.clone();
    let owner = options.owner.clone();
    let ttl = options.lease_ttl();
    store
        .read_blocking_async(move |store| store.try_acquire_search_projector_lease(&owner, ttl))
        .await
        .map_err(|error| ProjectorError::Store(error.to_string()))
}

async fn release_lease(store: &Store, lease: SearchProjectorLease) -> Result<(), ProjectorError> {
    let store = store.clone();
    store
        .read_blocking_async(move |store| store.release_search_projector_lease(&lease))
        .await
        .map(|_| ())
        .map_err(|error| ProjectorError::Store(error.to_string()))
}

async fn release_lease_current(
    provider: &StoreProvider,
    lease: SearchProjectorLease,
) -> Result<(), ProjectorError> {
    let store = provider.current().await?;
    release_lease(&store, lease).await
}

async fn read_control(store: &Store) -> Result<SearchProjectionControl, ProjectorError> {
    let store = store.clone();
    store
        .read_blocking_async(|store| store.search_projection_control())
        .await
        .map_err(|error| ProjectorError::Store(error.to_string()))
}

async fn load_completed_status(
    store: &Store,
) -> Result<Option<chancela_search::SearchIndexState>, ProjectorError> {
    let store = store.clone();
    store
        .read_blocking_async(|store| store.search_index_state())
        .await
        .map_err(|error| ProjectorError::Store(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
async fn build_and_publish_projection(
    provider: &StoreProvider,
    inputs: chancela_search_projection::ProjectionInputs,
    settings: SearchSettings,
    projection_as_of: OffsetDateTime,
    lease: SearchProjectorLease,
    checkpoint: chancela_search::SearchProjectionCheckpoint,
    force_rebuild: bool,
    shutdown: Arc<AtomicBool>,
) -> Result<SearchProjectionPublishOutcome, String> {
    if !settings.enabled {
        return Err("search projection is disabled in instance settings".to_owned());
    }
    if shutdown.load(Ordering::Acquire) {
        return Err("search projection cancelled for shutdown".to_owned());
    }
    let build_shutdown = shutdown.clone();
    let build = tokio::task::spawn_blocking(move || {
        chancela_search_projection::build_corpus(
            inputs,
            &settings,
            build_shutdown.as_ref(),
            projection_as_of,
        )
    })
    .await
    .map_err(|error| format!("search projection build task panicked: {error}"))??;
    ensure_projection_date_current(build.projection_utc_date)?;

    // Reopen at the publication boundary so a SQLite recovery inode replacement cannot receive a
    // valid CAS result through a handle retained from the captured source snapshot.
    let store = provider
        .current()
        .await
        .map_err(|error| error.to_string())?;
    let existing = store
        .read_blocking_async(|store| {
            Ok::<_, chancela_store::StoreError>((
                store.search_documents()?,
                store.search_index_state()?,
            ))
        })
        .await
        .map_err(|error| format!("search projection baseline load failed: {error}"))?;
    let (existing_documents, existing_status) = existing;
    let existing_by_id: HashMap<String, SearchDocument> = existing_documents
        .into_iter()
        .map(|document| (document.id.clone(), document))
        .collect();
    let target_by_id: HashMap<String, SearchDocument> = build
        .documents
        .into_iter()
        .map(|document| (document.id.clone(), document))
        .collect();
    let mut operations = Vec::with_capacity(
        target_by_id
            .len()
            .saturating_add(existing_by_id.len().saturating_sub(target_by_id.len())),
    );
    for (id, document) in &target_by_id {
        if force_rebuild || existing_by_id.get(id) != Some(document) {
            operations.push(IndexOperation::Upsert(Box::new(document.clone())));
        }
    }
    for id in existing_by_id.keys() {
        if !target_by_id.contains_key(id) {
            operations.push(IndexOperation::Delete(id.clone()));
        }
    }
    operations.sort_by(|left, right| operation_id(left).cmp(operation_id(right)));

    let target_count = target_by_id.len() as u64;
    let truncated_document_count = target_by_id
        .values()
        .filter(|document| document.content_truncated)
        .count() as u64;
    let now = format_projection_time(projection_as_of);
    let mut completed = existing_status.unwrap_or_default();
    completed.phase = SearchIndexPhase::Idle;
    completed.generation = completed.generation.saturating_add(1);
    completed.document_count = target_count;
    completed.truncated_document_count = truncated_document_count;
    completed.indexed_content_chars = build.indexed_content_chars;
    completed.content_budget_exhausted = build.content_budget_exhausted;
    completed.processed = operations.len() as u64;
    completed.total = operations.len() as u64;
    completed.last_event_seq = build.last_event_seq;
    completed.last_started_at = Some(now.clone());
    completed.last_completed_at = Some(now.clone());
    completed.last_error = None;
    completed.error_at = None;
    completed.projection_fenced = false;
    completed.updated_at = now;
    if shutdown.load(Ordering::Acquire) {
        return Err("search projection cancelled for shutdown".to_owned());
    }
    ensure_projection_date_current(build.projection_utc_date)?;
    store
        .read_blocking_async(move |store| {
            store.publish_search_projection(&lease, checkpoint, &operations, &completed)
        })
        .await
        .map_err(|error| format!("search projection CAS publication failed: {error}"))
}

fn ensure_projection_date_current(projection_utc_date: time::Date) -> Result<(), String> {
    if OffsetDateTime::now_utc().date() != projection_utc_date {
        return Err(SEARCH_PROJECTION_UTC_BUCKET_CHANGED.to_owned());
    }
    Ok(())
}

fn operation_id(operation: &IndexOperation) -> &str {
    match operation {
        IndexOperation::Upsert(document) => &document.id,
        IndexOperation::Delete(id) => id,
    }
}

fn format_projection_time(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

async fn load_projector_config(
    store: &Store,
) -> Result<ExternalSearchProjectorConfig, ProjectorError> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || {
        let data_dir = chancela_runtime_config::resolve_data_dir().ok_or_else(|| {
            ProjectorError::State(format!(
                "the external search projector requires a durable store; set {}",
                chancela_runtime_config::DATA_DIR_ENV
            ))
        })?;
        let settings =
            chancela_runtime_config::search_projector_settings_with_store(&store, &data_dir)
                .map_err(|error| ProjectorError::State(error.to_string()))?;
        Ok::<_, ProjectorError>(ExternalSearchProjectorConfig::from(&settings.search))
    })
    .await
    .map_err(|error| {
        ProjectorError::State(format!("search settings preflight task panicked: {error}"))
    })?
}

fn ensure_current_lease(
    control: &SearchProjectionControl,
    lease: &SearchProjectorLease,
) -> Result<(), ProjectorError> {
    if control
        .lease
        .as_ref()
        .is_some_and(|current| current.lease_id == lease.lease_id && current.owner == lease.owner)
    {
        Ok(())
    } else {
        Err(ProjectorError::Store("projector lease lost".to_owned()))
    }
}

fn candidate_control_is_current(
    control: &SearchProjectionControl,
    checkpoint: chancela_search::SearchProjectionCheckpoint,
    lease: &SearchProjectorLease,
) -> bool {
    control.checkpoint == checkpoint
        && control.command != SearchProjectionCommand::Pause
        && control.lease.as_ref().is_some_and(|current| {
            current.lease_id == lease.lease_id && current.owner == lease.owner
        })
}

/// Decide whether this lease must construct a candidate rather than stay on the cheap idle path.
///
/// The source checkpoint covers application-routed writes, but it does not identify a newly
/// deployed binary's embedded law/template catalog or the UTC date used by retention and Action
/// Center rules. Reconcile once per process startup and once after the successful generation's UTC
/// date bucket changes. `Pause` is also guarded here even though the supervisor handles it first.
fn projection_required(
    control: &SearchProjectionControl,
    completed_status: Option<&SearchIndexState>,
    now: OffsetDateTime,
    startup_reconcile_pending: bool,
) -> bool {
    if control.command == SearchProjectionCommand::Pause {
        return false;
    }
    startup_reconcile_pending
        || control.published_checkpoint != Some(control.checkpoint)
        || control.command == SearchProjectionCommand::Rebuild
        || !completed_in_utc_date(completed_status, now)
}

fn completed_in_utc_date(completed_status: Option<&SearchIndexState>, now: OffsetDateTime) -> bool {
    completed_status.is_some_and(|status| {
        !status.projection_fenced
            && status.generation > 0
            && status
                .last_completed_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                .is_some_and(|completed| {
                    completed.to_offset(time::UtcOffset::UTC).date()
                        == now.to_offset(time::UtcOffset::UTC).date()
                })
    })
}

async fn heartbeat_lease(
    provider: StoreProvider,
    options: ProjectorOptions,
    heartbeat: Arc<Mutex<ProjectorHeartbeat>>,
    lease: SearchProjectorLease,
    shutdown: Arc<AtomicBool>,
    lease_lost: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(options.heartbeat_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = wait_for_heartbeat_stop(&shutdown, &stop) => return,
        }
        if stop.load(Ordering::Acquire) || shutdown.load(Ordering::Acquire) {
            return;
        }
        let owned_lease = lease.clone();
        let ttl = options.lease_ttl();
        let renewed = match provider.current().await {
            Ok(store) => store
                .read_blocking_async(move |store| {
                    store.heartbeat_search_projector_lease(&owned_lease, ttl)
                })
                .await
                .map(|renewed| (store, renewed)),
            Err(error) => {
                lease_lost.store(true, Ordering::Release);
                update_local_heartbeat(&heartbeat, |value| {
                    value.phase = ProjectorPhase::Error;
                    value.last_error = Some(error.to_string());
                });
                return;
            }
        };
        match renewed {
            Ok((store, true)) => {
                if let Ok(control) = read_control(&store).await {
                    let _ = update_owned_heartbeat(
                        &options.runtime_dir,
                        &heartbeat,
                        &control,
                        &lease,
                        |value| {
                            value.observe_control(&control);
                        },
                    );
                }
            }
            Ok((_, false)) | Err(_) => {
                lease_lost.store(true, Ordering::Release);
                update_local_heartbeat(&heartbeat, |value| {
                    value.phase = ProjectorPhase::Error;
                    value.last_error = Some("durable projector lease was lost".to_owned());
                });
                return;
            }
        }
    }
}

#[derive(Clone)]
struct StoreProvider {
    /// Postgres pools reconnect to one logical database and are safe to retain. SQLite handles are
    /// reopened at poll boundaries because recovery can atomically replace the database inode.
    stable_postgres: Option<Store>,
}

impl StoreProvider {
    fn new(store: Store) -> Self {
        Self {
            stable_postgres: store.cluster_election_enabled().then_some(store),
        }
    }

    async fn current(&self) -> Result<Store, ProjectorError> {
        match &self.stable_postgres {
            Some(store) => Ok(store.clone()),
            None => reopen_store().await,
        }
    }
}

async fn reopen_store() -> Result<Store, ProjectorError> {
    tokio::task::spawn_blocking(chancela_runtime_config::search_projector_store_from_env)
        .await
        .map_err(|error| ProjectorError::State(format!("store reopen task panicked: {error}")))?
        .map_err(|error| ProjectorError::State(error.to_string()))
}

/// Cancel an async supervisor child, give it a bounded cooperative join window, then abort and
/// acknowledge cancellation before returning the supervisor's already-selected outcome.
///
/// The child may itself be awaiting `spawn_blocking`; Tokio cannot stop that blocking closure once
/// started, so aborting detaches the read/DB call from the async wrapper. A detached refresh is
/// read-only. A detached publication attempt still has to pass the durable lease/checkpoint CAS,
/// which is invalidated by release/takeover/expiry as the supervisor unwinds.
async fn finish_task_after_supervisor<T>(
    task: &mut tokio::task::JoinHandle<T>,
    cancellation: Option<&AtomicBool>,
    supervisor_outcome: Result<bool, ProjectorError>,
    grace: Duration,
) -> Result<bool, ProjectorError> {
    if let Some(cancellation) = cancellation {
        cancellation.store(true, Ordering::Release);
    }
    if tokio::time::timeout(grace, &mut *task).await.is_err() {
        task.abort();
        // Async wrappers acknowledge abort promptly. Keep even this acknowledgement bounded so a
        // runtime regression cannot make the shutdown grace self-defeating.
        let _ = tokio::time::timeout(Duration::from_millis(100), &mut *task).await;
    }
    supervisor_outcome
}

/// A non-shutdown supervisor error must not detach a still-publishing candidate. Signal
/// cooperative cancellation and truly join the async wrapper before propagating the stored error.
async fn finish_candidate_after_error<T>(
    task: &mut tokio::task::JoinHandle<T>,
    cancellation: &AtomicBool,
    error: ProjectorError,
) -> Result<bool, ProjectorError> {
    cancellation.store(true, Ordering::Release);
    let _ = task.await;
    Err(error)
}

async fn wait_for_shutdown_requested(shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_heartbeat_stop(shutdown: &AtomicBool, stop: &AtomicBool) {
    while !shutdown.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_or_shutdown(duration: Duration, shutdown: &AtomicBool) {
    let deadline = tokio::time::Instant::now() + duration;
    while !shutdown.load(Ordering::Acquire) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100).min(duration)).await;
    }
}

fn finish_shutdown_local(heartbeat: &Arc<Mutex<ProjectorHeartbeat>>) -> ProjectorHeartbeat {
    update_local_heartbeat(heartbeat, |value| {
        value.phase = ProjectorPhase::ShuttingDown;
        value.lease_expires_at_unix_ms = None;
    });
    lock_heartbeat(heartbeat).clone()
}

async fn finish_owned_shutdown(
    provider: &StoreProvider,
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    lease: &SearchProjectorLease,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    update_heartbeat_if_still_owned(provider, runtime_dir, heartbeat, lease, |value| {
        value.phase = ProjectorPhase::ShuttingDown;
        value.lease_expires_at_unix_ms = None;
    })
    .await?;
    Ok(lock_heartbeat(heartbeat).clone())
}

/// Publish the final owned heartbeat and surrender the durable lease without defeating the
/// process-level five-second shutdown bound. Lease expiry remains the fallback if the store is
/// unavailable or the bounded best-effort release cannot complete promptly.
async fn finish_owned_shutdown_and_release(
    provider: &StoreProvider,
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    lease: &SearchProjectorLease,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    let finished = finish_owned_shutdown(provider, runtime_dir, heartbeat, lease).await;
    let _ = tokio::time::timeout(
        OWNED_SHUTDOWN_RELEASE_GRACE,
        release_lease_current(provider, lease.clone()),
    )
    .await;
    finished
}

fn update_local_heartbeat(
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    update: impl FnOnce(&mut ProjectorHeartbeat),
) {
    let mut value = lock_heartbeat(heartbeat);
    update(&mut value);
    value.last_error = value.last_error.as_deref().and_then(bounded_diagnostic);
    value.touch();
}

fn update_owned_heartbeat(
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    control: &SearchProjectionControl,
    lease: &SearchProjectorLease,
    update: impl FnOnce(&mut ProjectorHeartbeat),
) -> Result<bool, ProjectorError> {
    update_local_heartbeat(heartbeat, |value| {
        value.observe_lease(lease);
        update(value);
    });
    write_shared_heartbeat_if_current_lease(runtime_dir, heartbeat, control, lease)
}

async fn update_heartbeat_if_still_owned(
    provider: &StoreProvider,
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    lease: &SearchProjectorLease,
    update: impl FnOnce(&mut ProjectorHeartbeat),
) -> Result<bool, ProjectorError> {
    update_local_heartbeat(heartbeat, |value| {
        value.observe_lease(lease);
        update(value);
    });
    let store = match provider.current().await {
        Ok(store) => store,
        Err(_) => return Ok(false),
    };
    let control = match read_control(&store).await {
        Ok(control) => control,
        Err(_) => return Ok(false),
    };
    write_shared_heartbeat_if_current_lease(runtime_dir, heartbeat, &control, lease)
}

fn write_shared_heartbeat_if_current_lease(
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    control: &SearchProjectionControl,
    lease: &SearchProjectorLease,
) -> Result<bool, ProjectorError> {
    let now_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    let heartbeat_matches = {
        let value = lock_heartbeat(heartbeat);
        value.owner == lease.owner && value.lease_id == lease.lease_id
    };
    if !heartbeat_matches
        || !control.lease.as_ref().is_some_and(|current| {
            current.lease_id == lease.lease_id
                && current.owner == lease.owner
                && current.expires_at_unix_ms > now_ms
        })
    {
        return Ok(false);
    }
    write_shared_heartbeat(runtime_dir, heartbeat, lease)?;
    // Cleanup is deliberately best-effort: a directory permission race must not turn an otherwise
    // valid current heartbeat into a lease-health failure.
    let _ = prune_retired_heartbeat_files(runtime_dir, &lease.lease_id, now_ms);
    Ok(true)
}

fn bounded_diagnostic(raw: &str) -> Option<String> {
    let mut value = String::with_capacity(raw.len().min(512));
    for character in raw.trim().chars().take(512) {
        value.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    (!value.is_empty()).then_some(value)
}

fn lock_heartbeat(
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
) -> std::sync::MutexGuard<'_, ProjectorHeartbeat> {
    heartbeat
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_shared_heartbeat(
    runtime_dir: &Path,
    heartbeat: &Arc<Mutex<ProjectorHeartbeat>>,
    lease: &SearchProjectorLease,
) -> Result<(), ProjectorError> {
    write_heartbeat_atomic(runtime_dir, &lease.lease_id, &lock_heartbeat(heartbeat))
}

pub fn heartbeat_directory(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(HEARTBEAT_DIRECTORY)
}

pub fn heartbeat_path(runtime_dir: &Path, lease_id: &str) -> Result<PathBuf, ProjectorError> {
    let lease_id = Uuid::parse_str(lease_id).map_err(|_| {
        ProjectorError::Configuration(
            "durable search projector lease_id must be a canonical UUID".to_owned(),
        )
    })?;
    Ok(heartbeat_directory(runtime_dir).join(format!("{lease_id}.json")))
}

pub fn write_heartbeat_atomic(
    runtime_dir: &Path,
    lease_id: &str,
    heartbeat: &ProjectorHeartbeat,
) -> Result<(), ProjectorError> {
    if heartbeat.lease_id != lease_id {
        return Err(ProjectorError::Configuration(
            "heartbeat lease_id does not match its lease-scoped path".to_owned(),
        ));
    }
    let directory = heartbeat_directory(runtime_dir);
    std::fs::create_dir_all(&directory).map_err(|source| ProjectorError::HeartbeatIo {
        path: directory.clone(),
        source,
    })?;
    let path = heartbeat_path(runtime_dir, lease_id)?;
    let temporary = directory.join(format!(".{lease_id}.{}.tmp", Uuid::new_v4()));
    let bytes =
        serde_json::to_vec_pretty(heartbeat).map_err(|source| ProjectorError::HeartbeatJson {
            path: path.clone(),
            source,
        })?;
    std::fs::write(&temporary, bytes).map_err(|source| ProjectorError::HeartbeatIo {
        path: temporary.clone(),
        source,
    })?;
    match std::fs::rename(&temporary, &path) {
        Ok(()) => Ok(()),
        Err(first) if path.exists() => {
            std::fs::remove_file(&path).map_err(|source| ProjectorError::HeartbeatIo {
                path: path.clone(),
                source,
            })?;
            std::fs::rename(&temporary, &path).map_err(|source| {
                let _ = std::fs::remove_file(&temporary);
                ProjectorError::HeartbeatIo {
                    path: path.clone(),
                    source: if source.kind() == std::io::ErrorKind::NotFound {
                        first
                    } else {
                        source
                    },
                }
            })
        }
        Err(source) => {
            let _ = std::fs::remove_file(&temporary);
            Err(ProjectorError::HeartbeatIo { path, source })
        }
    }
}

/// Remove a bounded number of expired heartbeat artifacts belonging to retired lease UUIDs.
///
/// Only direct, regular `UUID.json` children whose decoded lease identity matches the filename are
/// candidates. The currently durable lease is always preserved, symlinks/directories are ignored,
/// and malformed or fresh artifacts are left untouched for diagnosis.
pub fn prune_retired_heartbeat_files(
    runtime_dir: &Path,
    current_lease_id: &str,
    now_unix_ms: i64,
) -> Result<usize, ProjectorError> {
    let current_lease = Uuid::parse_str(current_lease_id).map_err(|_| {
        ProjectorError::Configuration(
            "durable search projector lease_id must be a canonical UUID".to_owned(),
        )
    })?;
    let directory = heartbeat_directory(runtime_dir);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(source) => {
            return Err(ProjectorError::HeartbeatIo {
                path: directory,
                source,
            });
        }
    };
    let mut removed = 0usize;
    for (inspected, entry) in entries.enumerate() {
        if inspected >= HEARTBEAT_PRUNE_MAX_INSPECTED || removed >= HEARTBEAT_PRUNE_MAX_REMOVED {
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".json") else {
            continue;
        };
        let Ok(lease_id) = Uuid::parse_str(stem) else {
            continue;
        };
        if stem != lease_id.to_string() || lease_id == current_lease {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let heartbeat = match serde_json::from_slice::<ProjectorHeartbeat>(&bytes) {
            Ok(heartbeat) => heartbeat,
            Err(_) => continue,
        };
        if heartbeat.schema_version != HEARTBEAT_SCHEMA_VERSION
            || heartbeat.service != SERVICE_NAME
            || heartbeat.lease_id != stem
        {
            continue;
        }
        let expired = heartbeat
            .lease_expires_at_unix_ms
            .is_some_and(|expires_at| expires_at <= now_unix_ms)
            || heartbeat.updated_at_unix_ms
                <= now_unix_ms.saturating_sub(HEARTBEAT_RETENTION_MILLIS);
        if !expired {
            continue;
        }
        // Recheck immediately before deletion so a path swapped to a symlink or directory while it
        // was decoded is never followed or treated as a regular retired artifact.
        let regular = std::fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false);
        if regular && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn healthcheck(
    store: &Store,
    runtime_dir: &Path,
    max_age: Duration,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    let control = store
        .search_projection_control()
        .map_err(|error| ProjectorError::Store(error.to_string()))?;
    let lease = control
        .lease
        .as_ref()
        .ok_or_else(|| ProjectorError::UnhealthyHeartbeat {
            path: heartbeat_directory(runtime_dir),
            reason: "durable projector lease is absent".to_owned(),
        })?;
    let path = heartbeat_path(runtime_dir, &lease.lease_id)?;
    let bytes = std::fs::read(&path).map_err(|source| ProjectorError::HeartbeatIo {
        path: path.clone(),
        source,
    })?;
    let heartbeat: ProjectorHeartbeat =
        serde_json::from_slice(&bytes).map_err(|source| ProjectorError::HeartbeatJson {
            path: path.clone(),
            source,
        })?;
    if heartbeat.schema_version != HEARTBEAT_SCHEMA_VERSION
        || heartbeat.service != SERVICE_NAME
        || heartbeat.lease_id != lease.lease_id
    {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: "unexpected heartbeat schema, service identity, or lease identity".to_owned(),
        });
    }
    if heartbeat.owner.is_empty()
        || heartbeat.owner.chars().count() > 256
        || heartbeat.owner.chars().any(char::is_control)
    {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: "invalid heartbeat owner".to_owned(),
        });
    }
    let parsed_updated_at =
        OffsetDateTime::parse(&heartbeat.updated_at, &Rfc3339).map_err(|_| {
            ProjectorError::UnhealthyHeartbeat {
                path: path.clone(),
                reason: "invalid heartbeat updated_at".to_owned(),
            }
        })?;
    let parsed_updated_at_ms =
        i64::try_from(parsed_updated_at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if parsed_updated_at_ms.abs_diff(heartbeat.updated_at_unix_ms) > 1_000 {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: "heartbeat timestamps disagree".to_owned(),
        });
    }
    if matches!(
        heartbeat.phase,
        ProjectorPhase::Error | ProjectorPhase::ShuttingDown
    ) {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: format!("projector phase is {:?}", heartbeat.phase),
        });
    }
    let now_ms = i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX);
    if lease.expires_at_unix_ms <= now_ms || heartbeat.owner != lease.owner {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: "heartbeat does not match the current unexpired durable lease".to_owned(),
        });
    }
    if heartbeat.source_revision != Some(control.checkpoint.source_revision)
        || heartbeat.fence_token != Some(control.checkpoint.fence_token)
        || heartbeat.command_generation != Some(control.checkpoint.command_generation)
    {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: "heartbeat checkpoint does not match durable projector control".to_owned(),
        });
    }
    let max_age_ms = i64::try_from(max_age.as_millis()).unwrap_or(i64::MAX);
    let age = now_ms.saturating_sub(heartbeat.updated_at_unix_ms);
    if age < -5_000 || age > max_age_ms {
        return Err(ProjectorError::UnhealthyHeartbeat {
            path,
            reason: format!(
                "heartbeat age {age}ms is outside the allowed 0..={max_age_ms}ms window"
            ),
        });
    }
    Ok(heartbeat)
}

pub fn healthcheck_from_env(
    runtime_dir: &Path,
    max_age: Duration,
) -> Result<ProjectorHeartbeat, ProjectorError> {
    validate_projector_environment()?;
    let store = chancela_runtime_config::search_projector_store_from_env()
        .map_err(|error| ProjectorError::State(error.to_string()))?;
    healthcheck(&store, runtime_dir, max_age)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-projector-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn heartbeat_round_trip_is_fresh_and_identity_checked() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0.join("store")).expect("open store");
        let lease = store
            .try_acquire_search_projector_lease("test-owner", Duration::from_secs(30))
            .unwrap()
            .unwrap();
        let control = store.search_projection_control().unwrap();
        let heartbeat = Arc::new(Mutex::new(ProjectorHeartbeat::new("test-owner".to_owned())));
        assert!(
            update_owned_heartbeat(&dir.0, &heartbeat, &control, &lease, |value| {
                value.phase = ProjectorPhase::Idle;
                value.observe_control(&control);
            })
            .unwrap()
        );
        let loaded = healthcheck(&store, &dir.0, Duration::from_secs(60)).unwrap();
        assert_eq!(loaded.owner, "test-owner");
        assert_eq!(loaded.lease_id, lease.lease_id);
        assert_eq!(loaded.service, SERVICE_NAME);
    }

    #[tokio::test]
    async fn graceful_owned_shutdown_releases_lease_for_immediate_successor() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0.join("store")).expect("open store");
        let provider = StoreProvider {
            // Model the stable handle used by the PostgreSQL projector while retaining the
            // deterministic embedded store used by unit tests.
            stable_postgres: Some(store.clone()),
        };
        let lease = store
            .try_acquire_search_projector_lease("first-owner", Duration::from_secs(60))
            .expect("acquire first lease")
            .expect("first lease available");
        let heartbeat = Arc::new(Mutex::new(ProjectorHeartbeat::new(lease.owner.clone())));

        let finished = finish_owned_shutdown_and_release(&provider, &dir.0, &heartbeat, &lease)
            .await
            .expect("finish graceful owned shutdown");
        assert_eq!(finished.phase, ProjectorPhase::ShuttingDown);

        let successor = store
            .try_acquire_search_projector_lease("successor-owner", Duration::from_secs(60))
            .expect("acquire successor lease")
            .expect("successor acquires immediately without waiting for the former TTL");
        assert_ne!(successor.lease_id, lease.lease_id);
        assert_ne!(successor.owner, lease.owner);
    }

    #[tokio::test]
    async fn heartbeat_worker_renews_then_stops_promptly_during_a_long_interval() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0.join("store")).expect("open store");
        let provider = StoreProvider {
            stable_postgres: Some(store.clone()),
        };
        let options = ProjectorOptions {
            runtime_dir: dir.0.join("runtime"),
            heartbeat_interval: Duration::from_secs(60),
            health_max_age: Duration::from_secs(600),
            owner: "heartbeat-owner".to_owned(),
        };
        let lease = store
            .try_acquire_search_projector_lease(&options.owner, options.lease_ttl())
            .expect("acquire heartbeat lease")
            .expect("heartbeat lease available");
        let heartbeat = Arc::new(Mutex::new(ProjectorHeartbeat::new(options.owner.clone())));
        let shutdown = Arc::new(AtomicBool::new(false));
        let lease_lost = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat_path = heartbeat_path(&options.runtime_dir, &lease.lease_id).unwrap();
        let task = tokio::spawn(heartbeat_lease(
            provider,
            options,
            heartbeat,
            lease,
            shutdown,
            lease_lost.clone(),
            stop.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initial renewal path publishes the owned heartbeat");
        assert!(
            !lease_lost.load(Ordering::Acquire),
            "the initial durable lease renewal succeeded"
        );

        stop.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("stop interrupts the long heartbeat interval")
            .expect("heartbeat worker joins cleanly");
    }

    #[test]
    fn heartbeat_pruning_is_bounded_and_preserves_current_fresh_and_untrusted_paths() {
        let dir = TempDir::new();
        let now_ms = 1_900_000_000_000i64;
        let current_id = Uuid::new_v4().to_string();
        let expired_id = Uuid::new_v4().to_string();
        let fresh_retired_id = Uuid::new_v4().to_string();

        let mut current = ProjectorHeartbeat::new("current-owner".to_owned());
        current.lease_id.clone_from(&current_id);
        current.updated_at_unix_ms = 0;
        current.lease_expires_at_unix_ms = Some(0);
        write_heartbeat_atomic(&dir.0, &current_id, &current).unwrap();

        let mut expired = ProjectorHeartbeat::new("retired-owner".to_owned());
        expired.lease_id.clone_from(&expired_id);
        expired.updated_at_unix_ms = now_ms - HEARTBEAT_RETENTION_MILLIS - 1;
        expired.lease_expires_at_unix_ms = Some(now_ms - 1);
        write_heartbeat_atomic(&dir.0, &expired_id, &expired).unwrap();

        let mut fresh_retired = ProjectorHeartbeat::new("fresh-retired-owner".to_owned());
        fresh_retired.lease_id.clone_from(&fresh_retired_id);
        fresh_retired.updated_at_unix_ms = now_ms;
        fresh_retired.lease_expires_at_unix_ms = Some(now_ms + 60_000);
        write_heartbeat_atomic(&dir.0, &fresh_retired_id, &fresh_retired).unwrap();

        let directory = heartbeat_directory(&dir.0);
        std::fs::write(directory.join("not-a-uuid.json"), b"do not delete").unwrap();
        let nested = directory.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join(format!("{}.json", Uuid::new_v4())), b"nested").unwrap();

        assert_eq!(
            prune_retired_heartbeat_files(&dir.0, &current_id, now_ms).unwrap(),
            1
        );
        assert!(
            heartbeat_path(&dir.0, &current_id).unwrap().exists(),
            "the current durable lease artifact is never pruned, even if its timestamps look stale"
        );
        assert!(!heartbeat_path(&dir.0, &expired_id).unwrap().exists());
        assert!(heartbeat_path(&dir.0, &fresh_retired_id).unwrap().exists());
        assert!(directory.join("not-a-uuid.json").exists());
        assert!(nested.exists());
    }

    #[test]
    fn heartbeat_pruning_never_follows_a_symlink() {
        let dir = TempDir::new();
        let directory = heartbeat_directory(&dir.0);
        std::fs::create_dir_all(&directory).unwrap();
        let current_id = Uuid::new_v4().to_string();
        let linked_id = Uuid::new_v4().to_string();
        let target = dir.0.join("sentinel.json");
        std::fs::write(&target, b"must survive").unwrap();
        let link = directory.join(format!("{linked_id}.json"));

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            // Windows may require Developer Mode or the symlink privilege. The production guard is
            // still exercised on Unix CI and by the metadata-only traversal test above.
            return;
        }

        assert_eq!(
            prune_retired_heartbeat_files(&dir.0, &current_id, i64::MAX).unwrap(),
            0
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"must survive");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn heartbeat_pruning_caps_each_pass() {
        let dir = TempDir::new();
        let now_ms = 1_900_000_000_000i64;
        let current_id = Uuid::new_v4().to_string();
        for index in 0..(HEARTBEAT_PRUNE_MAX_REMOVED + 9) {
            let lease_id = Uuid::new_v4().to_string();
            let mut heartbeat = ProjectorHeartbeat::new(format!("retired-{index}"));
            heartbeat.lease_id.clone_from(&lease_id);
            heartbeat.updated_at_unix_ms = 0;
            heartbeat.lease_expires_at_unix_ms = Some(0);
            write_heartbeat_atomic(&dir.0, &lease_id, &heartbeat).unwrap();
        }
        assert_eq!(
            prune_retired_heartbeat_files(&dir.0, &current_id, now_ms).unwrap(),
            HEARTBEAT_PRUNE_MAX_REMOVED
        );
        let remaining = std::fs::read_dir(heartbeat_directory(&dir.0))
            .unwrap()
            .count();
        assert_eq!(remaining, 9);
    }

    #[test]
    fn stale_owner_writes_cannot_clobber_the_successor_lease_heartbeat() {
        let dir = TempDir::new();
        let store_dir = dir.0.join("store");
        let store = Store::open(&store_dir).expect("open durable projector store");
        let ttl = Duration::from_secs(30);
        let active_lease = store
            .try_acquire_search_projector_lease("projector-active", ttl)
            .expect("acquire active lease")
            .expect("active lease available");
        let active_control = store
            .search_projection_control()
            .expect("read active durable control");
        let standby_candidate = SearchProjectorLease {
            lease_id: "not-acquired".to_owned(),
            owner: "projector-standby".to_owned(),
            heartbeat_at: "2026-07-26T12:01:00Z".to_owned(),
            expires_at_unix_ms: i64::MAX,
            checkpoint: active_control.checkpoint,
        };
        assert!(
            store
                .try_acquire_search_projector_lease(&standby_candidate.owner, ttl)
                .expect("attempt standby lease")
                .is_none()
        );
        let active = Arc::new(Mutex::new(ProjectorHeartbeat::new(
            active_lease.owner.clone(),
        )));
        assert!(
            update_owned_heartbeat(&dir.0, &active, &active_control, &active_lease, |value| {
                value.phase = ProjectorPhase::Idle;
                value.observe_control(&active_control);
            },)
            .unwrap(),
        );
        let active_path = heartbeat_path(&dir.0, &active_lease.lease_id).unwrap();
        let active_before_overlap =
            std::fs::read(&active_path).expect("read active lease heartbeat");

        let standby = Arc::new(Mutex::new(ProjectorHeartbeat::new(
            standby_candidate.owner.clone(),
        )));
        assert!(
            !update_owned_heartbeat(
                &dir.0,
                &standby,
                &active_control,
                &standby_candidate,
                |value| {
                    value.phase = ProjectorPhase::Standby;
                },
            )
            .unwrap(),
            "a non-owner must not publish any lease heartbeat"
        );
        let active_during_overlap =
            std::fs::read(&active_path).expect("read active heartbeat during overlap");
        assert_eq!(active_during_overlap, active_before_overlap);
        let active_loaded: ProjectorHeartbeat =
            serde_json::from_slice(&active_during_overlap).expect("decode active heartbeat");
        assert_eq!(active_loaded.owner, "projector-active");
        assert_eq!(active_loaded.lease_id, active_lease.lease_id);
        assert_eq!(active_loaded.phase, ProjectorPhase::Idle);
        assert_eq!(
            active_loaded.source_revision,
            Some(active_control.checkpoint.source_revision)
        );

        assert!(
            store
                .release_search_projector_lease(&active_lease)
                .expect("release active lease")
        );
        let standby_lease = store
            .try_acquire_search_projector_lease(&standby_candidate.owner, ttl)
            .expect("acquire transferred lease")
            .expect("transferred lease available");
        let takeover_control = store
            .search_projection_control()
            .expect("read transferred durable control");
        assert!(
            update_owned_heartbeat(
                &dir.0,
                &standby,
                &takeover_control,
                &standby_lease,
                |value| {
                    value.phase = ProjectorPhase::Building;
                    value.observe_control(&takeover_control);
                },
            )
            .unwrap(),
            "the new durable owner may publish after ownership transfer"
        );
        let takeover_path = heartbeat_path(&dir.0, &standby_lease.lease_id).unwrap();
        assert_ne!(active_path, takeover_path);
        let takeover_before_stale_write =
            std::fs::read(&takeover_path).expect("read takeover heartbeat");
        let takeover_loaded: ProjectorHeartbeat =
            serde_json::from_slice(&takeover_before_stale_write)
                .expect("decode takeover heartbeat");
        assert_eq!(takeover_loaded.owner, "projector-standby");
        assert_eq!(takeover_loaded.lease_id, standby_lease.lease_id);
        assert_eq!(takeover_loaded.phase, ProjectorPhase::Building);
        assert_eq!(
            takeover_loaded.source_revision,
            Some(takeover_control.checkpoint.source_revision)
        );

        // Model the precise DB-read -> file-write race: the former owner still holds its cached
        // control snapshot when the successor has already acquired and published. It may update
        // only lease A's file, never the currently selected lease B artifact.
        assert!(
            update_owned_heartbeat(&dir.0, &active, &active_control, &active_lease, |value| {
                value.phase = ProjectorPhase::Error;
                value.last_error = Some("late stale-owner write".to_owned());
            })
            .unwrap()
        );
        assert_eq!(
            std::fs::read(&takeover_path).unwrap(),
            takeover_before_stale_write,
            "a stale owner cannot address or replace its successor's heartbeat"
        );
        let selected = healthcheck(&store, &dir.0, Duration::from_secs(60)).unwrap();
        assert_eq!(selected.lease_id, standby_lease.lease_id);
        assert_eq!(selected.owner, standby_lease.owner);
    }

    #[test]
    fn healthcheck_rejects_error_and_stale_heartbeats() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0.join("store")).expect("open store");
        let lease = store
            .try_acquire_search_projector_lease("test-owner", Duration::from_secs(30))
            .unwrap()
            .unwrap();
        let control = store.search_projection_control().unwrap();
        let mut heartbeat = ProjectorHeartbeat::new("test-owner".to_owned());
        heartbeat.observe_lease(&lease);
        heartbeat.observe_control(&control);
        heartbeat.phase = ProjectorPhase::Error;
        write_heartbeat_atomic(&dir.0, &lease.lease_id, &heartbeat).unwrap();
        assert!(healthcheck(&store, &dir.0, Duration::from_secs(60)).is_err());

        heartbeat.phase = ProjectorPhase::Idle;
        heartbeat.updated_at_unix_ms = 0;
        write_heartbeat_atomic(&dir.0, &lease.lease_id, &heartbeat).unwrap();
        assert!(healthcheck(&store, &dir.0, Duration::from_secs(60)).is_err());
    }

    #[test]
    fn postgres_projector_contract_requires_follower_role() {
        // Test the pure normalized rule without mutating the process environment, which is shared
        // by Rust's parallel test runner.
        fn valid(backend: &str, role: &str) -> bool {
            !matches!(
                backend.trim().to_ascii_lowercase().as_str(),
                "postgres" | "postgresql" | "pg"
            ) || role.trim().eq_ignore_ascii_case("follower")
        }
        assert!(valid("sqlite", ""));
        assert!(valid("postgres", "follower"));
        assert!(!valid("postgres", "auto"));
        assert!(!valid("pg", "leader"));
    }

    #[test]
    fn lease_ttl_remains_safely_above_heartbeat_interval() {
        let options = ProjectorOptions {
            runtime_dir: PathBuf::from("runtime"),
            heartbeat_interval: Duration::from_secs(10),
            health_max_age: Duration::from_secs(600),
            owner: "test".to_owned(),
        };
        assert_eq!(options.lease_ttl(), Duration::from_secs(40));
    }

    #[test]
    fn projector_config_bounds_the_cheap_poll_cadence() {
        let mut config = ExternalSearchProjectorConfig {
            enabled: false,
            index_threads: 2,
            interval_seconds: 1,
        };
        assert_eq!(
            configured_reconciliation_interval(&config),
            Duration::from_secs(5)
        );
        config.interval_seconds = 90_000;
        assert_eq!(
            configured_reconciliation_interval(&config),
            Duration::from_secs(86_400)
        );
    }

    #[test]
    fn health_window_is_jitter_safe_relative_to_heartbeat() {
        assert_eq!(
            resolve_health_max_age(Some(10), Some(20)).unwrap(),
            Duration::from_secs(20)
        );
        assert!(resolve_health_max_age(Some(10), Some(19)).is_err());
    }

    #[test]
    fn instance_id_rejects_control_characters_and_preserves_friendly_unicode() {
        assert_eq!(
            normalize_instance_id("  projetor-lisboa α  ").unwrap(),
            "projetor-lisboa α"
        );
        assert!(normalize_instance_id("projector\nforged-line").is_err());
        assert!(normalize_instance_id("\u{0000}projector").is_err());
        assert!(normalize_instance_id("   ").is_err());
    }

    #[test]
    fn projection_decision_reconciles_once_per_process_and_utc_date() {
        let checkpoint = chancela_search::SearchProjectionCheckpoint {
            source_revision: 7,
            fence_token: 3,
            command_generation: 11,
        };
        let mut control = SearchProjectionControl {
            checkpoint,
            published_checkpoint: Some(checkpoint),
            command: SearchProjectionCommand::Reconcile,
            lease: None,
            updated_at: "2026-07-26T12:00:00Z".to_owned(),
        };
        let now = OffsetDateTime::parse("2026-07-26T12:00:00Z", &Rfc3339).unwrap();
        let mut completed = SearchIndexState {
            generation: 4,
            last_completed_at: Some("2026-07-26T00:00:00Z".to_owned()),
            projection_fenced: false,
            ..SearchIndexState::default()
        };

        assert!(
            !projection_required(&control, Some(&completed), now, false),
            "a current same-day generation stays on the cheap poll path"
        );
        assert!(
            projection_required(&control, Some(&completed), now, true),
            "a new process reconciles embedded catalogs even with a current checkpoint"
        );

        completed.last_completed_at = Some("2026-07-25T23:59:59Z".to_owned());
        assert!(
            projection_required(&control, Some(&completed), now, false),
            "date-derived rows refresh after the UTC date bucket changes"
        );
        completed.last_completed_at = Some("not-a-timestamp".to_owned());
        assert!(projection_required(&control, Some(&completed), now, false));
        assert!(projection_required(&control, None, now, false));

        completed.last_completed_at = Some("2026-07-26T00:00:00Z".to_owned());
        completed.projection_fenced = true;
        assert!(projection_required(&control, Some(&completed), now, false));
        completed.projection_fenced = false;
        completed.generation = 0;
        assert!(projection_required(&control, Some(&completed), now, false));
        completed.generation = 4;

        control.published_checkpoint = None;
        assert!(projection_required(&control, Some(&completed), now, false));
        control.published_checkpoint = Some(checkpoint);
        control.command = SearchProjectionCommand::Rebuild;
        assert!(projection_required(&control, Some(&completed), now, false));
        control.command = SearchProjectionCommand::Pause;
        assert!(
            !projection_required(&control, Some(&completed), now, true),
            "a durable pause always wins over startup and calendar reconciliation"
        );
    }

    #[test]
    fn completion_bucket_is_normalized_to_utc() {
        let now = OffsetDateTime::parse("2026-07-27T00:15:00Z", &Rfc3339).unwrap();
        let mut completed = SearchIndexState {
            generation: 1,
            last_completed_at: Some("2026-07-27T01:00:00+01:00".to_owned()),
            ..SearchIndexState::default()
        };
        assert!(completed_in_utc_date(Some(&completed), now));

        completed.last_completed_at = Some("2026-07-27T00:30:00+01:00".to_owned());
        assert!(
            !completed_in_utc_date(Some(&completed), now),
            "the local offset date must not mask a previous UTC date"
        );
    }

    #[test]
    fn durable_pause_or_checkpoint_change_cancels_an_in_flight_candidate() {
        let checkpoint = chancela_search::SearchProjectionCheckpoint {
            source_revision: 7,
            fence_token: 3,
            command_generation: 11,
        };
        let lease = SearchProjectorLease {
            lease_id: "lease-a".to_owned(),
            owner: "projector-a".to_owned(),
            heartbeat_at: "2026-07-26T12:00:00Z".to_owned(),
            expires_at_unix_ms: i64::MAX,
            checkpoint,
        };
        let mut control = SearchProjectionControl {
            checkpoint,
            published_checkpoint: None,
            command: SearchProjectionCommand::Rebuild,
            lease: Some(lease.clone()),
            updated_at: "2026-07-26T12:00:00Z".to_owned(),
        };
        assert!(candidate_control_is_current(&control, checkpoint, &lease));
        control.command = SearchProjectionCommand::Pause;
        assert!(!candidate_control_is_current(&control, checkpoint, &lease));
        control.command = SearchProjectionCommand::Rebuild;
        control.checkpoint.source_revision += 1;
        assert!(!candidate_control_is_current(&control, checkpoint, &lease));
    }

    #[tokio::test]
    async fn non_shutdown_supervisor_error_truly_joins_cancelled_candidate() {
        let cancellation = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let task_cancellation = cancellation.clone();
        let task_completed = completed.clone();
        let mut task = tokio::spawn(async move {
            while !task_cancellation.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            // Deliberately longer than a hypothetical short shutdown grace: the non-shutdown
            // error path must still join rather than reuse the bounded-abort behavior.
            tokio::time::sleep(Duration::from_millis(60)).await;
            task_completed.store(true, Ordering::Release);
        });

        let started = std::time::Instant::now();
        let result = finish_candidate_after_error(
            &mut task,
            cancellation.as_ref(),
            ProjectorError::Store("injected control read failure".to_owned()),
        )
        .await;
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(
            completed.load(Ordering::Acquire),
            "poll error returned before the candidate wrapper joined"
        );
        assert!(matches!(
            result,
            Err(ProjectorError::Store(message)) if message == "injected control read failure"
        ));
    }

    #[tokio::test]
    async fn hung_refresh_and_build_wrappers_respect_child_shutdown_grace() {
        let mut hung_build = tokio::spawn(std::future::pending::<()>());
        let started = std::time::Instant::now();
        let result = finish_task_after_supervisor(
            &mut hung_build,
            None,
            Ok(true),
            Duration::from_millis(20),
        )
        .await;
        assert!(result.unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            hung_build.is_finished(),
            "hung build wrapper was not aborted"
        );

        let release_blocking = Arc::new(AtomicBool::new(false));
        let blocking_guard = release_blocking.clone();
        let mut hung_refresh = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                while !blocking_guard.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
            .await
        });
        let started = std::time::Instant::now();
        let result = finish_task_after_supervisor(
            &mut hung_refresh,
            None,
            Ok(true),
            Duration::from_millis(20),
        )
        .await;
        release_blocking.store(true, Ordering::Release);
        assert!(result.unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            hung_refresh.is_finished(),
            "hung refresh wrapper was not aborted"
        );
    }

    #[tokio::test]
    async fn process_supervisor_bounds_a_run_stuck_outside_candidate_building() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let run = tokio::spawn(std::future::pending::<
            Result<ProjectorHeartbeat, ProjectorError>,
        >());
        let started = std::time::Instant::now();
        let outcome = supervise_projector_task(
            run,
            shutdown.clone(),
            std::future::ready(()),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        assert!(
            outcome.is_none(),
            "timed-out process supervisor returns None"
        );
        assert!(shutdown.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
