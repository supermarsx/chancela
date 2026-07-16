//! Durable, filesystem-backed worker queue for distinct sync and backup jobs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chancela_connectors::{
    CancellationToken, Connector, ConnectorError, EnvSecretProvider, ErrorClass, JobPurpose,
    NetworkPolicy, SecretProvider, TargetConfig, UploadReceipt, UploadRequest, WorkerTargets,
    build_connector,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

const SCHEMA_VERSION: u32 = 1;
const MAX_JSON_BYTES: u64 = 1024 * 1024;

fn default_poll_interval_ms() -> u64 {
    1_000
}

fn default_parallel_jobs() -> usize {
    2
}

fn default_max_attempts() -> u32 {
    4
}

fn default_retry_initial_ms() -> u64 {
    1_000
}

fn default_retry_max_ms() -> u64 {
    60_000
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkerConfig {
    pub source_root: PathBuf,
    pub targets: WorkerTargets,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_parallel_jobs")]
    pub max_parallel_jobs: usize,
    #[serde(default = "default_max_attempts")]
    pub max_job_attempts: u32,
    #[serde(default = "default_retry_initial_ms")]
    pub retry_initial_ms: u64,
    #[serde(default = "default_retry_max_ms")]
    pub retry_max_ms: u64,
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.source_root.as_os_str().is_empty() {
            return Err(WorkerError::configuration("source_root is empty"));
        }
        if !(50..=60_000).contains(&self.poll_interval_ms) {
            return Err(WorkerError::configuration(
                "poll_interval_ms must be between 50 and 60000",
            ));
        }
        if !(1..=32).contains(&self.max_parallel_jobs) {
            return Err(WorkerError::configuration(
                "max_parallel_jobs must be between 1 and 32",
            ));
        }
        if !(1..=16).contains(&self.max_job_attempts) {
            return Err(WorkerError::configuration(
                "max_job_attempts must be between 1 and 16",
            ));
        }
        if self.retry_initial_ms == 0 || self.retry_max_ms < self.retry_initial_ms {
            return Err(WorkerError::configuration("retry bounds are invalid"));
        }
        self.targets.validate().map_err(WorkerError::Connector)
    }
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("configuration: {0}")]
    Configuration(String),
    #[error("{operation}: {kind:?}")]
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    #[error("invalid {0} JSON")]
    Json(&'static str),
    #[error(transparent)]
    Connector(ConnectorError),
    #[error("job {0} was not found")]
    JobNotFound(String),
    #[error("job idempotency key conflicts with an existing job")]
    IdempotencyConflict,
}

impl WorkerError {
    fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
    }

    fn io(operation: &'static str, error: &std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Job {
    pub schema_version: u32,
    pub id: String,
    pub purpose: JobPurpose,
    pub source_relative: PathBuf,
    pub destination: String,
    pub content_type: String,
    pub source_sha256: String,
    pub bytes: u64,
    pub idempotency_key: String,
    /// Tenant binding for API-created jobs. Legacy CLI jobs omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Immutable credential-reference-only target snapshot for API-created jobs. This lets a
    /// running worker consume a newly configured target without accepting a mutable config race.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetConfig>,
    pub created_unix_millis: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    RetryScheduled,
    Recovered,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobEvent {
    pub schema_version: u32,
    pub job_id: String,
    pub state: JobState,
    pub attempt: u32,
    pub target_id: Option<String>,
    pub occurred_unix_millis: u64,
    pub not_before_unix_millis: Option<u64>,
    pub error_class: Option<ErrorClass>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobReceipt {
    pub schema_version: u32,
    pub job_id: String,
    pub purpose: JobPurpose,
    pub attempt: u32,
    pub completed_unix_millis: u64,
    pub upload: UploadReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobSnapshot {
    pub job: Job,
    pub latest_event: JobEvent,
    pub receipt: Option<JobReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueResult {
    pub job: Job,
    pub created: bool,
}

#[derive(Clone, Debug)]
pub struct DurableQueue {
    root: PathBuf,
}

impl DurableQueue {
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, WorkerError> {
        let queue = Self { root: root.into() };
        for directory in [
            "staged",
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
            "cancel",
            "cancel-staged",
            "retry-staged",
            "receipts",
            "status",
            "heartbeats",
        ] {
            tokio::fs::create_dir_all(queue.root.join(directory))
                .await
                .map_err(|error| WorkerError::io("create queue directory", &error))?;
        }
        Ok(queue)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn state_path(&self, state: &str, job_id: &str) -> PathBuf {
        self.root.join(state).join(format!("{job_id}.json"))
    }

    fn receipt_path(&self, job_id: &str) -> PathBuf {
        self.root.join("receipts").join(format!("{job_id}.json"))
    }

    fn cancel_path(&self, job_id: &str) -> PathBuf {
        self.root.join("cancel").join(format!("{job_id}.cancel"))
    }

    fn staged_action_path(&self, action: &str, job_id: &str) -> PathBuf {
        self.root.join(action).join(format!("{job_id}.marker"))
    }

    fn event_dir(&self, job_id: &str) -> PathBuf {
        self.root.join("status").join(job_id)
    }

    async fn atomic_create(path: &Path, bytes: &[u8]) -> Result<bool, WorkerError> {
        let parent = path
            .parent()
            .ok_or_else(|| WorkerError::configuration("queue path has no parent"))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| WorkerError::io("create atomic-write directory", &error))?;
        let temporary = parent.join(format!(
            ".{}.{}.part",
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("queue"),
            uuid::Uuid::new_v4()
        ));
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .map_err(|error| WorkerError::io("create atomic-write temporary file", &error))?;
        file.write_all(bytes)
            .await
            .map_err(|error| WorkerError::io("write atomic queue file", &error))?;
        file.sync_all()
            .await
            .map_err(|error| WorkerError::io("sync atomic queue file", &error))?;
        drop(file);
        let created = match tokio::fs::hard_link(&temporary, path).await {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(WorkerError::io("commit immutable queue file", &error));
            }
        };
        let _ = tokio::fs::remove_file(&temporary).await;
        Ok(created)
    }

    async fn read_json<T: for<'de> Deserialize<'de>>(
        path: &Path,
        label: &'static str,
    ) -> Result<T, WorkerError> {
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|error| WorkerError::io("stat queue JSON", &error))?;
        if metadata.len() > MAX_JSON_BYTES {
            return Err(WorkerError::Json(label));
        }
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| WorkerError::io("read queue JSON", &error))?;
        serde_json::from_slice(&bytes).map_err(|_| WorkerError::Json(label))
    }

    async fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<bool, WorkerError> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|_| WorkerError::Json("queue"))?;
        Self::atomic_create(path, &bytes).await
    }

    async fn existing_job(&self, id: &str) -> Result<Option<Job>, WorkerError> {
        for state in [
            "staged",
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
        ] {
            let path = self.state_path(state, id);
            if tokio::fs::try_exists(&path)
                .await
                .map_err(|error| WorkerError::io("inspect queue state", &error))?
            {
                return Self::read_json(&path, "job").await.map(Some);
            }
        }
        Ok(None)
    }

    pub async fn enqueue(
        &self,
        source_root: &Path,
        purpose: JobPurpose,
        source_relative: PathBuf,
        destination: String,
        content_type: String,
        idempotency_key: Option<String>,
    ) -> Result<EnqueueResult, WorkerError> {
        self.enqueue_internal(
            source_root,
            purpose,
            source_relative,
            destination,
            content_type,
            idempotency_key,
            None,
            None,
            "pending",
        )
        .await
    }

    /// Stage an API-created job without making it claimable. The API publishes the staged file
    /// only after its metadata-only audit event is durably committed.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_for_target(
        &self,
        source_root: &Path,
        purpose: JobPurpose,
        source_relative: PathBuf,
        destination: String,
        content_type: String,
        idempotency_key: String,
        tenant_id: String,
        target: TargetConfig,
    ) -> Result<EnqueueResult, WorkerError> {
        target.validate().map_err(WorkerError::Connector)?;
        self.enqueue_internal(
            source_root,
            purpose,
            source_relative,
            destination,
            content_type,
            Some(idempotency_key),
            Some(tenant_id),
            Some(target),
            "staged",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_internal(
        &self,
        source_root: &Path,
        purpose: JobPurpose,
        source_relative: PathBuf,
        destination: String,
        content_type: String,
        idempotency_key: Option<String>,
        tenant_id: Option<String>,
        target: Option<TargetConfig>,
        initial_state: &'static str,
    ) -> Result<EnqueueResult, WorkerError> {
        validate_relative_source(&source_relative)?;
        if destination.trim().is_empty() || content_type.trim().is_empty() {
            return Err(WorkerError::configuration(
                "destination and content_type are required",
            ));
        }
        let idempotency_key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        validate_idempotency_key(&idempotency_key)?;
        let id = hex_digest(idempotency_key.as_bytes());
        let source = secure_source(source_root, &source_relative).await?;
        let (source_sha256, bytes) = sha256_file(&source).await?;
        let job = Job {
            schema_version: SCHEMA_VERSION,
            id: id.clone(),
            purpose,
            source_relative,
            destination,
            content_type,
            source_sha256,
            bytes,
            idempotency_key,
            tenant_id,
            target,
            created_unix_millis: unix_millis(),
        };
        if let Some(existing) = self.existing_job(&id).await? {
            if equivalent_job(&existing, &job) {
                return Ok(EnqueueResult {
                    job: existing,
                    created: false,
                });
            }
            return Err(WorkerError::IdempotencyConflict);
        }
        if !Self::write_json(&self.state_path(initial_state, &id), &job).await? {
            let existing = self
                .existing_job(&id)
                .await?
                .ok_or(WorkerError::IdempotencyConflict)?;
            if !equivalent_job(&existing, &job) {
                return Err(WorkerError::IdempotencyConflict);
            }
            return Ok(EnqueueResult {
                job: existing,
                created: false,
            });
        }
        if initial_state == "pending" {
            self.record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: id,
                state: JobState::Queued,
                attempt: 0,
                target_id: job.target.as_ref().map(|target| target.id().to_owned()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: None,
                detail: "job queued durably".to_owned(),
            })
            .await?;
        }
        Ok(EnqueueResult { job, created: true })
    }

    /// Atomically publish a staged API job to the worker-visible pending queue.
    pub async fn publish_staged(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        let staged = self.state_path("staged", job_id);
        if tokio::fs::try_exists(&staged)
            .await
            .map_err(|error| WorkerError::io("inspect staged job", &error))?
        {
            let job: Job = Self::read_json(&staged, "job").await?;
            tokio::fs::rename(&staged, self.state_path("pending", job_id))
                .await
                .map_err(|error| WorkerError::io("publish staged job", &error))?;
            self.record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: job_id.to_owned(),
                state: JobState::Queued,
                attempt: 0,
                target_id: job.target.as_ref().map(|target| target.id().to_owned()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: None,
                detail: "audited job published durably".to_owned(),
            })
            .await?;
            return Ok(());
        }
        if self.existing_job(job_id).await?.is_some() {
            Ok(())
        } else {
            Err(WorkerError::JobNotFound(job_id.to_owned()))
        }
    }

    /// Discard a stage after the API rolled its uncommitted audit event back.
    pub async fn discard_staged(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        match tokio::fs::remove_file(self.state_path("staged", job_id)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(WorkerError::io("discard staged job", &error)),
        }
    }

    pub async fn cancel(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        if self.existing_job(job_id).await?.is_none() {
            return Err(WorkerError::JobNotFound(job_id.to_owned()));
        }
        let _ = Self::atomic_create(&self.cancel_path(job_id), b"cancel\n").await?;
        Ok(())
    }

    pub async fn stage_cancel(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        if self.existing_job(job_id).await?.is_none() {
            return Err(WorkerError::JobNotFound(job_id.to_owned()));
        }
        let _ = Self::atomic_create(
            &self.staged_action_path("cancel-staged", job_id),
            b"cancel\n",
        )
        .await?;
        Ok(())
    }

    pub async fn publish_staged_cancel(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        let staged = self.staged_action_path("cancel-staged", job_id);
        if tokio::fs::try_exists(&staged)
            .await
            .map_err(|error| WorkerError::io("inspect staged cancellation", &error))?
        {
            match tokio::fs::rename(&staged, self.cancel_path(job_id)).await {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tokio::fs::remove_file(staged).await;
                    return Ok(());
                }
                Err(error) => {
                    return Err(WorkerError::io("publish staged cancellation", &error));
                }
            }
        }
        if self.is_cancelled(job_id).await? {
            Ok(())
        } else {
            Err(WorkerError::configuration("staged cancellation is missing"))
        }
    }

    pub async fn discard_staged_cancel(&self, job_id: &str) -> Result<(), WorkerError> {
        remove_if_exists(
            &self.staged_action_path("cancel-staged", job_id),
            "discard staged cancellation",
        )
        .await
    }

    /// Requeue a failed job without changing its immutable content or idempotency identity.
    pub async fn retry_failed(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        let failed = self.state_path("failed", job_id);
        if !tokio::fs::try_exists(&failed)
            .await
            .map_err(|error| WorkerError::io("inspect failed job", &error))?
        {
            return Err(WorkerError::configuration(
                "only failed jobs can be retried",
            ));
        }
        let job: Job = Self::read_json(&failed, "job").await?;
        match tokio::fs::remove_file(self.cancel_path(job_id)).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkerError::io("clear cancellation marker", &error)),
        }
        tokio::fs::rename(&failed, self.state_path("pending", job_id))
            .await
            .map_err(|error| WorkerError::io("retry failed job", &error))?;
        let attempt = self.attempt_count(job_id).await?;
        self.record_event(JobEvent {
            schema_version: SCHEMA_VERSION,
            job_id: job_id.to_owned(),
            state: JobState::Recovered,
            attempt,
            target_id: job.target.as_ref().map(|target| target.id().to_owned()),
            occurred_unix_millis: unix_millis(),
            not_before_unix_millis: None,
            error_class: None,
            detail: "operator-authorized retry queued".to_owned(),
        })
        .await
    }

    pub async fn stage_retry(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        if !tokio::fs::try_exists(self.state_path("failed", job_id))
            .await
            .map_err(|error| WorkerError::io("inspect failed job", &error))?
        {
            return Err(WorkerError::configuration(
                "only failed jobs can be retried",
            ));
        }
        let _ = Self::atomic_create(&self.staged_action_path("retry-staged", job_id), b"retry\n")
            .await?;
        Ok(())
    }

    pub async fn publish_staged_retry(&self, job_id: &str) -> Result<(), WorkerError> {
        validate_job_id(job_id)?;
        let staged = self.staged_action_path("retry-staged", job_id);
        if !tokio::fs::try_exists(&staged)
            .await
            .map_err(|error| WorkerError::io("inspect staged retry", &error))?
        {
            return Err(WorkerError::configuration("staged retry is missing"));
        }
        self.retry_failed(job_id).await?;
        remove_if_exists(&staged, "consume staged retry").await
    }

    pub async fn discard_staged_retry(&self, job_id: &str) -> Result<(), WorkerError> {
        remove_if_exists(
            &self.staged_action_path("retry-staged", job_id),
            "discard staged retry",
        )
        .await
    }

    pub async fn is_cancelled(&self, job_id: &str) -> Result<bool, WorkerError> {
        tokio::fs::try_exists(self.cancel_path(job_id))
            .await
            .map_err(|error| WorkerError::io("inspect cancellation marker", &error))
    }

    pub async fn record_event(&self, mut event: JobEvent) -> Result<(), WorkerError> {
        // Event timestamps are also the durable ordering key. Millisecond clocks can
        // produce ties for consecutive state transitions, so advance within this
        // job's stream rather than allowing a terminal event to sort ambiguously.
        if let Some(previous) = self.events(&event.job_id).await?.last() {
            event.occurred_unix_millis = event
                .occurred_unix_millis
                .max(previous.occurred_unix_millis.saturating_add(1));
        }
        let path = self.event_dir(&event.job_id).join(format!(
            "{:020}-{}.json",
            event.occurred_unix_millis,
            uuid::Uuid::new_v4()
        ));
        Self::write_json(&path, &event).await?;
        Ok(())
    }

    async fn events(&self, job_id: &str) -> Result<Vec<JobEvent>, WorkerError> {
        let directory = self.event_dir(job_id);
        if !tokio::fs::try_exists(&directory)
            .await
            .map_err(|error| WorkerError::io("inspect status directory", &error))?
        {
            return Ok(Vec::new());
        }
        let mut entries = tokio::fs::read_dir(directory)
            .await
            .map_err(|error| WorkerError::io("read status directory", &error))?;
        let mut events = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| WorkerError::io("read status entry", &error))?
        {
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                events.push(Self::read_json(&entry.path(), "status event").await?);
            }
        }
        events.sort_by_key(|event: &JobEvent| event.occurred_unix_millis);
        Ok(events)
    }

    async fn attempt_count(&self, job_id: &str) -> Result<u32, WorkerError> {
        Ok(self
            .events(job_id)
            .await?
            .into_iter()
            .filter(|event| event.state == JobState::Running)
            .count() as u32)
    }

    pub async fn snapshot(&self, job_id: &str) -> Result<JobSnapshot, WorkerError> {
        validate_job_id(job_id)?;
        let job = self
            .existing_job(job_id)
            .await?
            .ok_or_else(|| WorkerError::JobNotFound(job_id.to_owned()))?;
        let latest_event = self
            .events(job_id)
            .await?
            .into_iter()
            .max_by_key(|event| event.occurred_unix_millis)
            .ok_or_else(|| WorkerError::JobNotFound(job_id.to_owned()))?;
        let receipt_path = self.receipt_path(job_id);
        let receipt = if tokio::fs::try_exists(&receipt_path)
            .await
            .map_err(|error| WorkerError::io("inspect job receipt", &error))?
        {
            Some(Self::read_json(&receipt_path, "job receipt").await?)
        } else {
            None
        };
        Ok(JobSnapshot {
            job,
            latest_event,
            receipt,
        })
    }

    /// Return the newest durable jobs across every queue state.
    ///
    /// This is the bounded, read-only operator seam used by API/dashboard integrations. Queue
    /// files remain the source of truth: malformed job identifiers or JSON fail the read instead
    /// of disappearing from an apparently healthy status page.
    pub async fn list_snapshots(&self, limit: usize) -> Result<Vec<JobSnapshot>, WorkerError> {
        if !(1..=500).contains(&limit) {
            return Err(WorkerError::configuration(
                "snapshot list limit must be between 1 and 500",
            ));
        }
        let mut ids = BTreeSet::new();
        for state in ["pending", "running", "completed", "failed", "cancelled"] {
            let mut entries = tokio::fs::read_dir(self.root.join(state))
                .await
                .map_err(|error| WorkerError::io("read queue state directory", &error))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|error| WorkerError::io("read queue state entry", &error))?
            {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let id = path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .ok_or(WorkerError::Json("job id"))?;
                validate_job_id(id)?;
                ids.insert(id.to_owned());
            }
        }
        let mut snapshots = Vec::with_capacity(ids.len().min(limit));
        for id in ids {
            snapshots.push(self.snapshot(&id).await?);
        }
        snapshots.sort_by(|left, right| {
            right
                .job
                .created_unix_millis
                .cmp(&left.job.created_unix_millis)
                .then_with(|| right.job.id.cmp(&left.job.id))
        });
        snapshots.truncate(limit);
        Ok(snapshots)
    }

    async fn claim_next(&self) -> Result<Option<Job>, WorkerError> {
        let mut entries = tokio::fs::read_dir(self.root.join("pending"))
            .await
            .map_err(|error| WorkerError::io("read pending queue", &error))?;
        let mut paths = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| WorkerError::io("read pending entry", &error))?
        {
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                paths.push(entry.path());
            }
        }
        paths.sort();
        for pending in paths {
            let job: Job = Self::read_json(&pending, "job").await?;
            if self
                .events(&job.id)
                .await?
                .last()
                .and_then(|event| event.not_before_unix_millis)
                .is_some_and(|not_before| not_before > unix_millis())
            {
                continue;
            }
            let running = self.state_path("running", &job.id);
            match tokio::fs::rename(&pending, &running).await {
                Ok(()) => return Ok(Some(job)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(WorkerError::io("claim queued job", &error)),
            }
        }
        Ok(None)
    }

    async fn transition(&self, job_id: &str, from: &str, to: &str) -> Result<(), WorkerError> {
        tokio::fs::rename(self.state_path(from, job_id), self.state_path(to, job_id))
            .await
            .map_err(|error| WorkerError::io("transition queued job", &error))
    }

    async fn receipt(&self, receipt: &JobReceipt) -> Result<(), WorkerError> {
        let path = self.receipt_path(&receipt.job_id);
        if !Self::write_json(&path, receipt).await? {
            let existing: JobReceipt = Self::read_json(&path, "job receipt").await?;
            if existing != *receipt {
                return Err(WorkerError::IdempotencyConflict);
            }
        }
        Ok(())
    }

    pub async fn recover(&self) -> Result<usize, WorkerError> {
        let mut entries = tokio::fs::read_dir(self.root.join("running"))
            .await
            .map_err(|error| WorkerError::io("read running queue", &error))?;
        let mut recovered = 0;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| WorkerError::io("read running entry", &error))?
        {
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let job: Job = Self::read_json(&entry.path(), "job").await?;
            let (state, destination, error_class, detail) =
                if tokio::fs::try_exists(self.receipt_path(&job.id))
                    .await
                    .map_err(|error| WorkerError::io("inspect recovered receipt", &error))?
                {
                    (
                        JobState::Succeeded,
                        "completed",
                        None,
                        "completed job reconciled from its durable receipt",
                    )
                } else if self.is_cancelled(&job.id).await? {
                    (
                        JobState::Cancelled,
                        "cancelled",
                        Some(ErrorClass::Cancelled),
                        "cancelled job recovered after worker restart",
                    )
                } else {
                    (
                        JobState::Recovered,
                        "pending",
                        None,
                        "unfinished job requeued after worker restart",
                    )
                };
            self.transition(&job.id, "running", destination).await?;
            self.record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: job.id.clone(),
                state,
                attempt: self.attempt_count(&job.id).await?,
                target_id: None,
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class,
                detail: detail.to_owned(),
            })
            .await?;
            recovered += 1;
        }
        Ok(recovered)
    }

    pub async fn heartbeat(&self) -> Result<(), WorkerError> {
        let now = unix_millis();
        let path = self
            .root
            .join("heartbeats")
            .join(format!("{now:020}.heartbeat"));
        Self::atomic_create(&path, b"ready\n").await?;
        let cutoff = now.saturating_sub(10 * 60 * 1_000);
        let mut entries = tokio::fs::read_dir(self.root.join("heartbeats"))
            .await
            .map_err(|error| WorkerError::io("read heartbeat directory", &error))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| WorkerError::io("read heartbeat entry", &error))?
        {
            let old = entry
                .path()
                .file_stem()
                .and_then(|value| value.to_str())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|timestamp| timestamp < cutoff);
            if old {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
        Ok(())
    }

    pub async fn heartbeat_is_fresh(&self, max_age: Duration) -> Result<bool, WorkerError> {
        let mut entries = tokio::fs::read_dir(self.root.join("heartbeats"))
            .await
            .map_err(|error| WorkerError::io("read heartbeat directory", &error))?;
        let mut latest = 0_u64;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| WorkerError::io("read heartbeat entry", &error))?
        {
            latest = latest.max(
                entry
                    .path()
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_default(),
            );
        }
        Ok(latest > 0 && unix_millis().saturating_sub(latest) <= max_age.as_millis() as u64)
    }
}

pub struct Worker {
    config: WorkerConfig,
    source_root: PathBuf,
    queue: DurableQueue,
    connectors: BTreeMap<String, Arc<dyn Connector>>,
    secrets: Arc<dyn SecretProvider>,
}

impl Worker {
    pub async fn new(
        config: WorkerConfig,
        queue_root: impl Into<PathBuf>,
        secrets: Arc<dyn SecretProvider>,
    ) -> Result<Self, WorkerError> {
        config.validate()?;
        if config
            .targets
            .targets
            .iter()
            .any(|target| !matches!(target, TargetConfig::Local(_)))
        {
            let policy = NetworkPolicy::from_env().map_err(WorkerError::Connector)?;
            config
                .targets
                .validate_network_policy(&policy)
                .await
                .map_err(WorkerError::Connector)?;
        }
        let source_root = tokio::fs::canonicalize(&config.source_root)
            .await
            .map_err(|error| WorkerError::io("canonicalize source root", &error))?;
        let queue = DurableQueue::open(queue_root).await?;
        let mut connectors = BTreeMap::new();
        for target in &config.targets.targets {
            connectors.insert(
                target.id().to_owned(),
                build_connector(target, secrets.clone()).map_err(WorkerError::Connector)?,
            );
        }
        Ok(Self {
            config,
            source_root,
            queue,
            connectors,
            secrets,
        })
    }

    pub async fn with_environment_secrets(
        config: WorkerConfig,
        queue_root: impl Into<PathBuf>,
    ) -> Result<Self, WorkerError> {
        Self::new(config, queue_root, Arc::new(EnvSecretProvider)).await
    }

    pub fn queue(&self) -> &DurableQueue {
        &self.queue
    }

    pub async fn probe_targets(
        &self,
    ) -> BTreeMap<String, Result<chancela_connectors::ConnectorStatus, String>> {
        let mut statuses = BTreeMap::new();
        for (id, connector) in &self.connectors {
            statuses.insert(
                id.clone(),
                connector.probe().await.map_err(|error| error.to_string()),
            );
        }
        statuses
    }

    async fn process_claimed(&self, job: Job) -> Result<(), WorkerError> {
        let attempt = self.queue.attempt_count(&job.id).await?.saturating_add(1);
        let (target_id, connector) = if let Some(target) = &job.target {
            if !matches!(target, TargetConfig::Local(_)) {
                let policy = NetworkPolicy::from_env().map_err(WorkerError::Connector)?;
                target
                    .validate_network_policy(&policy)
                    .await
                    .map_err(WorkerError::Connector)?;
            }
            (
                target.id().to_owned(),
                build_connector(target, self.secrets.clone()).map_err(WorkerError::Connector)?,
            )
        } else {
            let target = self
                .config
                .targets
                .target_for(job.purpose)
                .ok_or_else(|| WorkerError::configuration("purpose target is missing"))?;
            let connector = self
                .connectors
                .get(target.id())
                .cloned()
                .ok_or_else(|| WorkerError::configuration("purpose connector is missing"))?;
            (target.id().to_owned(), connector)
        };
        self.queue
            .record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: job.id.clone(),
                state: JobState::Running,
                attempt,
                target_id: Some(target_id.clone()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: None,
                detail: "job claimed by worker".to_owned(),
            })
            .await?;
        if self.queue.is_cancelled(&job.id).await? {
            self.finish_cancelled(&job, attempt, &target_id).await?;
            return Ok(());
        }
        let source = match secure_source(&self.source_root, &job.source_relative).await {
            Ok(source) => source,
            Err(_) => {
                self.finish_failed(
                    &job,
                    attempt,
                    Some(&target_id),
                    ErrorClass::Permanent,
                    "job source is unavailable or no longer passes source-root validation",
                )
                .await?;
                return Ok(());
            }
        };
        let request = UploadRequest {
            purpose: job.purpose,
            source,
            destination: job.destination.clone(),
            source_sha256: job.source_sha256.clone(),
            bytes: job.bytes,
            idempotency_key: job.idempotency_key.clone(),
            content_type: job.content_type.clone(),
        };
        let cancellation = CancellationToken::default();
        let finished = Arc::new(AtomicBool::new(false));
        let monitor = {
            let marker = self.queue.cancel_path(&job.id);
            let cancellation = cancellation.clone();
            let finished = finished.clone();
            tokio::spawn(async move {
                while !finished.load(Ordering::Acquire) {
                    if tokio::fs::try_exists(&marker).await.unwrap_or(false) {
                        cancellation.cancel();
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        };
        let result = connector.upload(&request, &cancellation).await;
        finished.store(true, Ordering::Release);
        monitor.abort();
        match result {
            Ok(upload) => {
                let receipt = JobReceipt {
                    schema_version: SCHEMA_VERSION,
                    job_id: job.id.clone(),
                    purpose: job.purpose,
                    attempt,
                    completed_unix_millis: unix_millis(),
                    upload,
                };
                self.queue.receipt(&receipt).await?;
                self.queue
                    .transition(&job.id, "running", "completed")
                    .await?;
                self.queue
                    .record_event(JobEvent {
                        schema_version: SCHEMA_VERSION,
                        job_id: job.id.clone(),
                        state: JobState::Succeeded,
                        attempt,
                        target_id: Some(target_id.clone()),
                        occurred_unix_millis: unix_millis(),
                        not_before_unix_millis: None,
                        error_class: None,
                        detail: "connector receipt committed durably".to_owned(),
                    })
                    .await?;
            }
            Err(error) if error.class == ErrorClass::Cancelled => {
                self.finish_cancelled(&job, attempt, &target_id).await?;
            }
            Err(error) if error.is_retryable() && attempt < self.config.max_job_attempts => {
                let shift = attempt.saturating_sub(1).min(20);
                let delay = self
                    .config
                    .retry_initial_ms
                    .saturating_mul(1_u64 << shift)
                    .min(self.config.retry_max_ms);
                let not_before = unix_millis().saturating_add(delay);
                self.queue
                    .record_event(JobEvent {
                        schema_version: SCHEMA_VERSION,
                        job_id: job.id.clone(),
                        state: JobState::RetryScheduled,
                        attempt,
                        target_id: Some(target_id.clone()),
                        occurred_unix_millis: unix_millis(),
                        not_before_unix_millis: Some(not_before),
                        error_class: Some(error.class),
                        detail: error.message,
                    })
                    .await?;
                // Make the job claimable only after its not-before event is durable.
                self.queue.transition(&job.id, "running", "pending").await?;
            }
            Err(error) => {
                self.finish_failed(&job, attempt, Some(&target_id), error.class, &error.message)
                    .await?;
            }
        }
        Ok(())
    }

    async fn finish_cancelled(
        &self,
        job: &Job,
        attempt: u32,
        target_id: &str,
    ) -> Result<(), WorkerError> {
        self.queue
            .transition(&job.id, "running", "cancelled")
            .await?;
        self.queue
            .record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: job.id.clone(),
                state: JobState::Cancelled,
                attempt,
                target_id: Some(target_id.to_owned()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: Some(ErrorClass::Cancelled),
                detail: "job cancelled".to_owned(),
            })
            .await
    }

    async fn finish_failed(
        &self,
        job: &Job,
        attempt: u32,
        target_id: Option<&str>,
        error_class: ErrorClass,
        detail: &str,
    ) -> Result<(), WorkerError> {
        self.queue.transition(&job.id, "running", "failed").await?;
        self.queue
            .record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: job.id.clone(),
                state: JobState::Failed,
                attempt,
                target_id: target_id.map(ToOwned::to_owned),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: Some(error_class),
                detail: detail.to_owned(),
            })
            .await
    }

    pub async fn run_once(&self) -> Result<bool, WorkerError> {
        let Some(job) = self.queue.claim_next().await? else {
            self.queue.heartbeat().await?;
            return Ok(false);
        };
        self.process_claimed(job).await?;
        self.queue.heartbeat().await?;
        Ok(true)
    }

    pub async fn run_until(
        self: Arc<Self>,
        shutdown: CancellationToken,
    ) -> Result<(), WorkerError> {
        self.queue.recover().await?;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        while !shutdown.is_cancelled() {
            self.queue.heartbeat().await?;
            let mut jobs = JoinSet::new();
            for _ in 0..self.config.max_parallel_jobs {
                let Some(job) = self.queue.claim_next().await? else {
                    break;
                };
                let worker = self.clone();
                jobs.spawn(async move { worker.process_claimed(job).await });
            }
            if jobs.is_empty() {
                tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
                continue;
            }
            while !jobs.is_empty() {
                tokio::select! {
                    result = jobs.join_next() => {
                        if let Some(result) = result {
                            result.map_err(|_| {
                                WorkerError::configuration("worker task terminated unexpectedly")
                            })??;
                        }
                    }
                    _ = heartbeat.tick() => self.queue.heartbeat().await?,
                }
            }
        }
        Ok(())
    }
}

pub async fn load_config(path: &Path) -> Result<WorkerConfig, WorkerError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| WorkerError::io("stat worker config", &error))?;
    if metadata.len() > MAX_JSON_BYTES {
        return Err(WorkerError::Json("worker config"));
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|error| WorkerError::io("read worker config", &error))?;
    let config: WorkerConfig =
        serde_json::from_slice(&bytes).map_err(|_| WorkerError::Json("worker config"))?;
    config.validate()?;
    Ok(config)
}

async fn secure_source(root: &Path, relative: &Path) -> Result<PathBuf, WorkerError> {
    validate_relative_source(relative)?;
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .map_err(|error| WorkerError::io("canonicalize source root", &error))?;
    let source = tokio::fs::canonicalize(canonical_root.join(relative))
        .await
        .map_err(|error| WorkerError::io("canonicalize job source", &error))?;
    if !source.starts_with(&canonical_root) {
        return Err(WorkerError::configuration("job source escapes source_root"));
    }
    let metadata = tokio::fs::metadata(&source)
        .await
        .map_err(|error| WorkerError::io("stat job source", &error))?;
    if !metadata.is_file() {
        return Err(WorkerError::configuration("job source is not a file"));
    }
    Ok(source)
}

fn validate_relative_source(path: &Path) -> Result<(), WorkerError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkerError::configuration(
            "source must be a non-empty relative path without traversal",
        ));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), WorkerError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.contains(['\r', '\n'])
    {
        return Err(WorkerError::configuration("invalid idempotency key"));
    }
    Ok(())
}

fn validate_job_id(value: &str) -> Result<(), WorkerError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(WorkerError::configuration("invalid job id"))
    }
}

fn equivalent_job(left: &Job, right: &Job) -> bool {
    left.purpose == right.purpose
        && left.source_relative == right.source_relative
        && left.destination == right.destination
        && left.content_type == right.content_type
        && left.source_sha256 == right.source_sha256
        && left.bytes == right.bytes
        && left.idempotency_key == right.idempotency_key
        && left.tenant_id == right.tenant_id
        && left.target == right.target
}

async fn remove_if_exists(path: &Path, operation: &'static str) -> Result<(), WorkerError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WorkerError::io(operation, &error)),
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

async fn sha256_file(path: &Path) -> Result<(String, u64), WorkerError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| WorkerError::io("open job source", &error))?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| WorkerError::io("read job source", &error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_connectors::LocalTarget;

    struct TempFixture(PathBuf);

    impl TempFixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-worker-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create worker fixture");
            Self(path)
        }
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn audited_staging_cancel_and_retry_are_not_visible_before_publish() {
        let fixture = TempFixture::new();
        let sources = fixture.0.join("sources");
        let queue_root = fixture.0.join("queue");
        std::fs::create_dir_all(sources.join("tenant-a")).expect("create source directory");
        std::fs::write(sources.join("tenant-a/source.pdf"), b"immutable source")
            .expect("write source");
        let queue = DurableQueue::open(&queue_root).await.expect("open queue");
        let target = TargetConfig::Local(LocalTarget {
            id: "dynamic-target".to_owned(),
            root: fixture.0.join("remote"),
        });

        let staged = queue
            .stage_for_target(
                &sources,
                JobPurpose::Sync,
                PathBuf::from("tenant-a/source.pdf"),
                "exports/source.pdf".to_owned(),
                "application/pdf".to_owned(),
                "api:tenant-a:dynamic-target:request-1".to_owned(),
                "tenant-a".to_owned(),
                target.clone(),
            )
            .await
            .expect("stage job");
        assert!(staged.created);
        assert_eq!(staged.job.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(staged.job.target.as_ref(), Some(&target));
        assert!(queue.claim_next().await.expect("inspect queue").is_none());
        assert_eq!(queue.recover().await.expect("recover queue"), 0);
        assert!(
            queue
                .list_snapshots(500)
                .await
                .expect("list jobs")
                .is_empty()
        );

        queue
            .publish_staged(&staged.job.id)
            .await
            .expect("publish audited job");
        let queued = queue
            .snapshot(&staged.job.id)
            .await
            .expect("queued snapshot");
        assert_eq!(queued.latest_event.state, JobState::Queued);

        queue
            .stage_cancel(&staged.job.id)
            .await
            .expect("stage cancellation");
        assert!(
            !queue
                .is_cancelled(&staged.job.id)
                .await
                .expect("cancel state")
        );
        queue
            .publish_staged_cancel(&staged.job.id)
            .await
            .expect("publish cancellation");
        assert!(
            queue
                .is_cancelled(&staged.job.id)
                .await
                .expect("cancel state")
        );

        let claimed = queue
            .claim_next()
            .await
            .expect("claim job")
            .expect("published job");
        queue
            .record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: claimed.id.clone(),
                state: JobState::Running,
                attempt: 1,
                target_id: Some("dynamic-target".to_owned()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: None,
                detail: "test claim".to_owned(),
            })
            .await
            .expect("record running");
        queue
            .transition(&claimed.id, "running", "failed")
            .await
            .expect("fail job");
        queue
            .record_event(JobEvent {
                schema_version: SCHEMA_VERSION,
                job_id: claimed.id.clone(),
                state: JobState::Failed,
                attempt: 1,
                target_id: Some("dynamic-target".to_owned()),
                occurred_unix_millis: unix_millis(),
                not_before_unix_millis: None,
                error_class: Some(ErrorClass::Transient),
                detail: "test failure".to_owned(),
            })
            .await
            .expect("record failure");

        queue.stage_retry(&claimed.id).await.expect("stage retry");
        assert!(queue.claim_next().await.expect("inspect queue").is_none());
        assert_eq!(
            queue
                .snapshot(&claimed.id)
                .await
                .expect("failed snapshot")
                .latest_event
                .state,
            JobState::Failed
        );
        queue
            .publish_staged_retry(&claimed.id)
            .await
            .expect("publish retry");
        let retried = queue.snapshot(&claimed.id).await.expect("retried snapshot");
        assert_eq!(retried.latest_event.state, JobState::Recovered);
        assert!(
            !queue
                .is_cancelled(&claimed.id)
                .await
                .expect("cancel cleared")
        );
        assert!(queue.claim_next().await.expect("claim retry").is_some());
    }

    #[tokio::test]
    async fn queue_rejects_source_escape_and_unbounded_status_reads() {
        let fixture = TempFixture::new();
        let sources = fixture.0.join("sources");
        std::fs::create_dir_all(&sources).expect("create sources");
        std::fs::write(fixture.0.join("outside"), b"outside").expect("write outside");
        let queue = DurableQueue::open(fixture.0.join("queue"))
            .await
            .expect("open queue");
        for source in [PathBuf::from("../outside"), fixture.0.join("outside")] {
            assert!(
                queue
                    .enqueue(
                        &sources,
                        JobPurpose::Backup,
                        source,
                        "backup.cbackup".to_owned(),
                        "application/octet-stream".to_owned(),
                        None,
                    )
                    .await
                    .is_err()
            );
        }
        assert!(queue.list_snapshots(0).await.is_err());
        assert!(queue.list_snapshots(501).await.is_err());
    }
}
