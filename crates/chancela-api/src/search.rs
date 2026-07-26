//! Background full-search projection, lifecycle control, and HTTP surface.
//!
//! Source reads and index writes never run on request threads. Requests query one immutable-at-lock
//! in-memory projection; a bounded/coalescing command queue wakes the worker for incremental
//! reconciliation or an explicit rebuild. The durable rows are derived data, so a periodic
//! reconciliation also repairs any notification lost to queue backpressure. This is a logical
//! service isolated on a dedicated OS thread, not a separately deployed process. In a Postgres
//! cluster only the elected write leader builds and persists projections; followers hydrate stable
//! completed generations.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock as SyncRwLock};
use std::time::Duration as StdDuration;

use axum::Json;
use axum::extract::{Query, State};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chancela_authz::{
    ActId as AuthzActId, BookId as AuthzBookId, EntityId as AuthzEntityId, Permission, Scope,
    TenantId as AuthzTenantId,
};
use chancela_core::Book;
use chancela_search::{
    InMemoryIndex, IndexOperation, SearchAccess, SearchDocument, SearchDocumentContent,
    SearchFilters, SearchIndexPhase, SearchIndexState, SearchKind, SearchPage, SearchQuery,
};
use chancela_store::{
    StoreError, StoredDocumentSearchMetadata, StoredImportedDocumentMeta,
    StoredImportedDocumentReviewHistoryEntry, StoredPaperBookImportMeta, StoredPaperBookOcrDraft,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::actor::{CurrentActor, CurrentAttestor};
use crate::dto::{ActView, BookView, EntityView, REDACTED, ReadRedaction};
use crate::{ApiError, AppState, Authorizer, authorizer};

const MAX_CURSOR_BYTES: usize = 1_024;
const MAX_CURSOR_OFFSET: usize = 100_000;
const MAX_QUERY_CHARS: usize = 512;
const MAX_FILTER_CHARS: usize = 256;
const MAX_UUID_FILTER_CHARS: usize = 64;
const MAX_DATE_FILTER_CHARS: usize = 64;
const MAX_KIND_FILTER_CHARS: usize = 256;
const MAX_KIND_COUNT: usize = 16;
const MAX_KIND_TOKEN_CHARS: usize = 32;
const SEARCH_WORKER_THREAD: &str = "chancela-search-indexer";
const SOURCE_SETTLE_MILLIS: u64 = 75;
const SOURCE_SETTLE_MAX_MILLIS: u64 = 500;
const SOURCE_SNAPSHOT_BATCH_SIZE: usize = 256;
const SEARCH_QUERY_MAX_CONCURRENCY: usize = 4;
const SEARCH_SHUTDOWN_TIMEOUT_SECS: u64 = 5;
const SEARCH_PROJECTION_SUPERSEDED: &str = "search projection superseded by destructive change";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchCommand {
    Reconcile,
    Rebuild,
    Pause,
    Resume,
}

#[derive(Debug)]
struct ActiveSearchSnapshot {
    index: Arc<InMemoryIndex>,
    status: SearchIndexState,
}

impl Default for ActiveSearchSnapshot {
    fn default() -> Self {
        Self {
            index: Arc::new(InMemoryIndex::default()),
            status: SearchIndexState::default(),
        }
    }
}

impl ActiveSearchSnapshot {
    fn empty(status: SearchIndexState) -> Self {
        Self {
            index: Arc::new(InMemoryIndex::default()),
            status,
        }
    }

    fn from_documents(
        documents: impl IntoIterator<Item = SearchDocument>,
        status: SearchIndexState,
    ) -> Self {
        Self {
            index: Arc::new(index_from_documents(documents)),
            status,
        }
    }
}

fn index_from_documents(documents: impl IntoIterator<Item = SearchDocument>) -> InMemoryIndex {
    let mut index = InMemoryIndex::default();
    index.replace(documents);
    index
}

struct SearchServiceInner {
    /// Immutable generation served by requests. Reconciliation builds and persists the replacement
    /// privately, then swaps this single `Arc` only after the durable generation is complete.
    active: SyncRwLock<Arc<ActiveSearchSnapshot>>,
    /// Worker lifecycle/progress. This may be Reconciling/Rebuilding while `active` keeps serving the
    /// preceding completed generation.
    status: SyncRwLock<SearchIndexState>,
    queue: Mutex<VecDeque<SearchCommand>>,
    notify: Notify,
    running: AtomicBool,
    shutdown: AtomicBool,
    dropped_commands: AtomicU64,
    query_slots: Arc<Semaphore>,
    /// Number of authoritative source mutations whose durable and in-memory publication has not
    /// completed as one logical change yet. The worker never snapshots while this is non-zero.
    source_mutations_in_flight: AtomicU64,
    /// A durable tombstone has made the preceding projection unsafe to serve (destructive restore,
    /// security-sensitive delete/scope move, or interrupted persistence). Rebuild progress remains
    /// fenced across the cluster until one clean completed generation is atomically published.
    fail_closed_until_completed: AtomicBool,
    wake_epoch: AtomicU64,
    projection_writer: AtomicBool,
    projection_epoch: AtomicU64,
    projection_gate: AsyncMutex<()>,
    destructive_fence: AtomicBool,
    destructive_reset_id: SyncRwLock<Option<Uuid>>,
    #[cfg(feature = "redis")]
    remote_fence_ids: Mutex<BTreeSet<Uuid>>,
    #[cfg(feature = "redis")]
    released_remote_fence_ids: Mutex<VecDeque<Uuid>>,
    task: Mutex<Option<std::thread::JoinHandle<()>>>,
    worker_thread: SyncRwLock<Option<String>>,
}

/// Shared background-index handle carried by [`AppState`].
#[derive(Clone)]
pub struct SearchService {
    inner: Arc<SearchServiceInner>,
}

impl Default for SearchService {
    fn default() -> Self {
        Self {
            inner: Arc::new(SearchServiceInner {
                active: SyncRwLock::new(Arc::new(ActiveSearchSnapshot::default())),
                status: SyncRwLock::new(SearchIndexState::default()),
                queue: Mutex::new(VecDeque::new()),
                notify: Notify::new(),
                running: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                dropped_commands: AtomicU64::new(0),
                query_slots: Arc::new(Semaphore::new(SEARCH_QUERY_MAX_CONCURRENCY)),
                source_mutations_in_flight: AtomicU64::new(0),
                fail_closed_until_completed: AtomicBool::new(false),
                wake_epoch: AtomicU64::new(0),
                projection_writer: AtomicBool::new(false),
                projection_epoch: AtomicU64::new(0),
                projection_gate: AsyncMutex::new(()),
                destructive_fence: AtomicBool::new(false),
                destructive_reset_id: SyncRwLock::new(None),
                #[cfg(feature = "redis")]
                remote_fence_ids: Mutex::new(BTreeSet::new()),
                #[cfg(feature = "redis")]
                released_remote_fence_ids: Mutex::new(VecDeque::new()),
                task: Mutex::new(None),
                worker_thread: SyncRwLock::new(None),
            }),
        }
    }
}

impl SearchService {
    #[cfg(test)]
    pub(crate) fn destructive_test_state(&self) -> (bool, bool, usize) {
        (
            self.inner.destructive_fence.load(Ordering::Acquire),
            read_lock(&self.inner.destructive_reset_id).is_some(),
            lock_mutex(&self.inner.queue).len(),
        )
    }

    fn has_remote_fence(&self) -> bool {
        #[cfg(feature = "redis")]
        {
            !lock_mutex(&self.inner.remote_fence_ids).is_empty()
        }
        #[cfg(not(feature = "redis"))]
        {
            false
        }
    }

    fn try_query_slot(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        self.inner
            .query_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::Unavailable(
                    "a pesquisa está ocupada; aguarde um instante e tente novamente".to_owned(),
                )
            })
    }

    fn start(&self, state: AppState) {
        if self.inner.running.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.shutdown.store(false, Ordering::Release);
        let service = self.clone();
        let handle = std::thread::Builder::new()
            .name(SEARCH_WORKER_THREAD.to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build dedicated search runtime");
                runtime.block_on(service.worker(state));
            })
            .expect("spawn dedicated search worker");
        *lock_mutex(&self.inner.task) = Some(handle);
    }

    fn enqueue(&self, command: SearchCommand, capacity: usize) -> Result<(), ApiError> {
        if matches!(command, SearchCommand::Reconcile | SearchCommand::Rebuild) {
            self.inner.wake_epoch.fetch_add(1, Ordering::AcqRel);
        }
        let mut queue = lock_mutex(&self.inner.queue);
        let already_queued = match command {
            SearchCommand::Reconcile => queue
                .iter()
                .any(|item| matches!(item, SearchCommand::Reconcile | SearchCommand::Rebuild)),
            SearchCommand::Rebuild => queue
                .iter()
                .any(|item| matches!(item, SearchCommand::Rebuild)),
            SearchCommand::Pause => queue
                .iter()
                .any(|item| matches!(item, SearchCommand::Pause)),
            SearchCommand::Resume => queue
                .iter()
                .any(|item| matches!(item, SearchCommand::Resume)),
        };
        if already_queued {
            return Ok(());
        }
        match command {
            SearchCommand::Pause => {
                queue.retain(|item| {
                    !matches!(item, SearchCommand::Reconcile | SearchCommand::Rebuild)
                });
            }
            SearchCommand::Rebuild | SearchCommand::Resume => {
                queue.retain(|item| !matches!(item, SearchCommand::Reconcile));
            }
            SearchCommand::Reconcile => {}
        }
        if queue.len() >= capacity.max(1) {
            self.inner.dropped_commands.fetch_add(1, Ordering::Relaxed);
            return Err(ApiError::Unavailable(
                "fila do índice de pesquisa cheia; tente novamente".to_owned(),
            ));
        }
        if command == SearchCommand::Pause {
            queue.push_front(command);
        } else {
            queue.push_back(command);
        }
        drop(queue);
        self.inner.notify.notify_one();
        Ok(())
    }

    fn pop_command(&self) -> Option<SearchCommand> {
        lock_mutex(&self.inner.queue).pop_front()
    }

    fn defer_reconcile(&self) {
        let mut queue = lock_mutex(&self.inner.queue);
        if !queue
            .iter()
            .any(|command| matches!(command, SearchCommand::Reconcile | SearchCommand::Rebuild))
        {
            queue.push_back(SearchCommand::Reconcile);
        }
    }

    fn status_response(
        &self,
        settings: &crate::settings::SearchSettings,
        detailed: bool,
    ) -> SearchStatusResponse {
        let state = read_lock(&self.inner.status).clone();
        let now = OffsetDateTime::now_utc();
        let stale_after =
            time::Duration::seconds(i64::from(settings.interval_seconds.saturating_mul(2)));
        let stale = state.last_completed_at.as_deref().is_none_or(|completed| {
            OffsetDateTime::parse(completed, &Rfc3339)
                .map(|completed| now - completed > stale_after)
                .unwrap_or(true)
        }) || matches!(
            state.phase,
            SearchIndexPhase::Starting
                | SearchIndexPhase::Rebuilding
                | SearchIndexPhase::Reconciling
                | SearchIndexPhase::Paused
                | SearchIndexPhase::Disabled
                | SearchIndexPhase::Error
        );
        SearchStatusResponse {
            details_redacted: !detailed,
            enabled: settings.enabled,
            partial: state.phase.is_partial()
                && (state.total == 0 || state.processed < state.total),
            stale,
            content_truncated: detailed.then_some(state.truncated_document_count > 0),
            phase: state.phase,
            generation: detailed.then_some(state.generation),
            document_count: detailed.then_some(state.document_count),
            truncated_document_count: detailed.then_some(state.truncated_document_count),
            indexed_content_chars: detailed.then_some(state.indexed_content_chars),
            content_budget_chars: detailed.then_some(settings.max_total_content_chars),
            content_budget_exhausted: detailed.then_some(state.content_budget_exhausted),
            processed: detailed.then_some(state.processed),
            total: detailed.then_some(state.total),
            last_event_seq: detailed.then_some(state.last_event_seq).flatten(),
            last_started_at: detailed.then_some(state.last_started_at).flatten(),
            last_completed_at: detailed.then_some(state.last_completed_at).flatten(),
            last_error: detailed.then_some(state.last_error).flatten(),
            error_at: detailed.then_some(state.error_at).flatten(),
            updated_at: detailed.then_some(state.updated_at),
            queue_depth: detailed.then(|| lock_mutex(&self.inner.queue).len()),
            queue_capacity: detailed.then_some(settings.queue_capacity as usize),
            dropped_commands: detailed.then(|| self.inner.dropped_commands.load(Ordering::Relaxed)),
            projection_writer: detailed
                .then(|| self.inner.projection_writer.load(Ordering::Acquire)),
            worker_thread: detailed
                .then(|| read_lock(&self.inner.worker_thread).clone())
                .flatten(),
        }
    }

    async fn worker(&self, state: AppState) {
        *write_lock(&self.inner.worker_thread) = std::thread::current().name().map(str::to_owned);
        let initial_writer = match self.refresh_projection_role(&state).await {
            Ok(writer) => writer,
            Err(error) => {
                self.record_local_error(error);
                false
            }
        };
        if initial_writer {
            match self.initialize_writer_projection(&state).await {
                Ok(true) => {}
                Ok(false) => {
                    let capacity = state.settings.read().await.search.queue_capacity;
                    let _ = self.enqueue(SearchCommand::Rebuild, capacity as usize);
                }
                Err(error) => self.record_local_error(error),
            }
        } else if let Err(error) = self.hydrate_from_store(&state, true).await {
            self.record_local_error(error);
        }
        let mut last_reconcile = OffsetDateTime::UNIX_EPOCH;
        let mut last_reconciled_epoch = 0u64;
        let mut cool_down_next_reconcile = false;
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                break;
            }
            let settings = state.settings.read().await.search.clone();
            let poll_seconds = settings.interval_seconds.clamp(5, 60);
            tokio::select! {
                () = self.inner.notify.notified() => {}
                () = tokio::time::sleep(StdDuration::from_secs(u64::from(poll_seconds))) => {}
            }
            if self.inner.shutdown.load(Ordering::Acquire) {
                break;
            }
            if self.inner.destructive_fence.load(Ordering::Acquire) {
                continue;
            }
            let mut command = self.pop_command();
            let was_projection_writer = self.inner.projection_writer.load(Ordering::Acquire);
            let projection_writer = match self.refresh_projection_role(&state).await {
                Ok(writer) => writer,
                Err(error) => {
                    self.record_local_error(error);
                    continue;
                }
            };
            if !projection_writer {
                if let Err(error) = self.hydrate_from_store(&state, true).await {
                    self.record_local_error(error);
                }
                continue;
            }
            if !was_projection_writer {
                match self.initialize_writer_projection(&state).await {
                    Ok(true) => {
                        if command.is_none() {
                            command = Some(SearchCommand::Reconcile);
                        }
                    }
                    Ok(false) => command = Some(SearchCommand::Rebuild),
                    Err(error) => {
                        self.record_local_error(error);
                        continue;
                    }
                }
            }
            // The first mutation after an idle generation is handled immediately (after the short
            // settle debounce). Only a mutation that arrived while the preceding generation was
            // actively being built arms this bounded cooldown, preventing sustained write traffic
            // from driving back-to-back full corpus walks.
            if let Some(delay) =
                reconcile_burst_delay(command, cool_down_next_reconcile, settings.interval_seconds)
            {
                self.defer_reconcile();
                cool_down_next_reconcile = false;
                tokio::select! {
                    () = tokio::time::sleep(delay) => {
                        self.inner.notify.notify_one();
                    }
                    () = self.inner.notify.notified() => {}
                }
                continue;
            }
            let settled_epoch = if matches!(
                command,
                Some(SearchCommand::Reconcile | SearchCommand::Rebuild)
            ) {
                self.settle_source_mutations().await
            } else {
                self.inner.wake_epoch.load(Ordering::Acquire)
            };
            let current_phase = read_lock(&self.inner.status).phase;
            let source_changed = settled_epoch != last_reconciled_epoch;
            let periodic_due = source_changed
                && (OffsetDateTime::now_utc() - last_reconcile)
                    >= time::Duration::seconds(i64::from(settings.interval_seconds));
            let mut reconciled = false;
            let result = match command {
                Some(SearchCommand::Pause) => self.set_paused(&state).await,
                Some(SearchCommand::Resume) => self.set_resumed(&state).await.map(|_| ()),
                Some(SearchCommand::Rebuild)
                    if settings.enabled && current_phase != SearchIndexPhase::Paused =>
                {
                    reconciled = true;
                    self.reconcile(&state, true, settled_epoch).await
                }
                Some(SearchCommand::Reconcile)
                    if settings.enabled
                        && current_phase != SearchIndexPhase::Paused
                        && source_changed =>
                {
                    reconciled = true;
                    self.reconcile(&state, false, settled_epoch).await
                }
                _ if !settings.enabled => self.set_disabled(&state).await,
                _ if current_phase != SearchIndexPhase::Paused && periodic_due => {
                    reconciled = true;
                    self.reconcile(&state, false, settled_epoch).await
                }
                _ => Ok(()),
            };
            if reconciled && result.is_ok() {
                last_reconcile = OffsetDateTime::now_utc();
                last_reconciled_epoch = settled_epoch;
                cool_down_next_reconcile =
                    self.inner.wake_epoch.load(Ordering::Acquire) != settled_epoch;
            }
            if let Err(mut error) = result
                && error != SEARCH_PROJECTION_SUPERSEDED
                && !self.inner.shutdown.load(Ordering::Acquire)
            {
                if reconciled {
                    if let Err(cleanup_error) = self.discard_interrupted_generation(&state).await {
                        error = format!(
                            "{error}; failed to discard the interrupted projection: {cleanup_error}"
                        );
                    }
                    self.defer_reconcile();
                    self.inner.notify.notify_one();
                }
                self.record_error(&state, error).await;
            }
        }
        let mut status = read_lock(&self.inner.status).clone();
        status.phase = SearchIndexPhase::ShuttingDown;
        status.updated_at = now_rfc3339();
        if self.inner.projection_writer.load(Ordering::Acquire) {
            let epoch = self.inner.projection_epoch.load(Ordering::Acquire);
            let _ = self
                .persist_batch(&state, Vec::new(), &status, epoch, None)
                .await;
        } else {
            *write_lock(&self.inner.status) = status;
        }
        self.inner.running.store(false, Ordering::Release);
    }

    async fn refresh_projection_role(&self, state: &AppState) -> Result<bool, String> {
        let Some(store) = state.store.clone() else {
            self.inner.projection_writer.store(true, Ordering::Release);
            return Ok(true);
        };
        let writer = store
            .read_blocking_async(|store| {
                projection_writer_from_gate(store.cluster_assert_writable())
            })
            .await?;
        self.inner
            .projection_writer
            .store(writer, Ordering::Release);
        Ok(writer)
    }

    async fn hydrate_from_store(
        &self,
        state: &AppState,
        completed_only: bool,
    ) -> Result<bool, String> {
        let Some(store) = state.store.clone() else {
            return Ok(false);
        };
        let _projection_guard = self.inner.projection_gate.lock().await;
        if self.inner.destructive_fence.load(Ordering::Acquire) {
            return Ok(false);
        }
        let snapshot = store
            .read_blocking_async(move |store| {
                let before = store.search_index_state()?;
                if completed_only && !is_completed_snapshot(before.as_ref()) {
                    let clear_local = before.as_ref().is_none_or(|state| state.projection_fenced);
                    return Ok::<_, StoreError>((None, before, clear_local));
                }
                let documents = store.search_documents()?;
                let after = store.search_index_state()?;
                if completed_only && !completed_snapshot_unchanged(before.as_ref(), after.as_ref())
                {
                    let clear_local = after.as_ref().is_none_or(|state| state.projection_fenced);
                    return Ok((None, after, clear_local));
                }
                Ok((Some(documents), after, false))
            })
            .await
            .map_err(|error| format!("search index hydration failed: {error}"))?;
        let (documents, durable_status, clear_local) = snapshot;
        let Some(documents) = documents else {
            if clear_local {
                let status = durable_status.unwrap_or_default();
                if status.projection_fenced {
                    self.inner
                        .fail_closed_until_completed
                        .store(true, Ordering::Release);
                }
                *write_lock(&self.inner.active) =
                    Arc::new(ActiveSearchSnapshot::empty(status.clone()));
                *write_lock(&self.inner.status) = status;
            }
            return Ok(false);
        };
        let status = durable_status.unwrap_or_default();
        *write_lock(&self.inner.active) = Arc::new(ActiveSearchSnapshot::from_documents(
            documents,
            status.clone(),
        ));
        *write_lock(&self.inner.status) = status;
        self.inner
            .fail_closed_until_completed
            .store(false, Ordering::Release);
        Ok(true)
    }

    /// Install a stable completed durable generation when one exists. Only an absent, fenced, or
    /// interrupted generation is discarded before this writer builds a clean replacement.
    async fn initialize_writer_projection(&self, state: &AppState) -> Result<bool, String> {
        if self.hydrate_from_store(state, true).await? {
            let active = read_lock(&self.inner.active).clone();
            if active.status.phase == SearchIndexPhase::ShuttingDown {
                let mut resumed = active.status.clone();
                resumed.phase = SearchIndexPhase::Idle;
                resumed.updated_at = now_rfc3339();
                self.persist_active_status(state, &resumed).await?;
            }
            return Ok(true);
        }
        self.discard_interrupted_generation(state).await?;
        Ok(false)
    }

    async fn settle_source_mutations(&self) -> u64 {
        let started = tokio::time::Instant::now();
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return self.inner.wake_epoch.load(Ordering::Acquire);
            }
            let observed = self.inner.wake_epoch.load(Ordering::Acquire);
            tokio::time::sleep(StdDuration::from_millis(SOURCE_SETTLE_MILLIS)).await;
            let latest = self.inner.wake_epoch.load(Ordering::Acquire);
            let mutation_in_flight = self
                .inner
                .source_mutations_in_flight
                .load(Ordering::Acquire)
                > 0;
            if !mutation_in_flight
                && (observed == latest
                    || started.elapsed() >= StdDuration::from_millis(SOURCE_SETTLE_MAX_MILLIS))
            {
                return latest;
            }
        }
    }

    async fn discard_interrupted_generation(&self, state: &AppState) -> Result<(), String> {
        let _projection_guard = self.inner.projection_gate.lock().await;
        self.inner
            .fail_closed_until_completed
            .store(true, Ordering::Release);
        if let Some(store) = state.store.clone() {
            store
                .read_blocking_async(|store| store.clear_search_projection())
                .await
                .map_err(|error| format!("search promotion projection reset failed: {error}"))?;
        }
        let status = SearchIndexState {
            projection_fenced: true,
            updated_at: now_rfc3339(),
            ..SearchIndexState::default()
        };
        *write_lock(&self.inner.active) = Arc::new(ActiveSearchSnapshot::empty(status.clone()));
        *write_lock(&self.inner.status) = status;
        Ok(())
    }

    async fn ensure_source_epoch(&self, expected_source_epoch: u64) -> Result<(), String> {
        if self.source_epoch_is_current(expected_source_epoch) {
            return Ok(());
        }

        // The bounded source snapshots deliberately release their read locks between chunks. If a
        // source changes during that walk, the candidate can combine two points in time. Never
        // complete or activate it: discard any partially persisted derived rows, fail closed, and
        // schedule an immediate clean rebuild from the new settled epoch.
        self.defer_reconcile();
        self.inner.notify.notify_one();
        Err(SEARCH_PROJECTION_SUPERSEDED.to_owned())
    }

    fn source_epoch_is_current(&self, expected_source_epoch: u64) -> bool {
        self.inner.wake_epoch.load(Ordering::Acquire) == expected_source_epoch
            && self
                .inner
                .source_mutations_in_flight
                .load(Ordering::Acquire)
                == 0
    }

    async fn reconcile(
        &self,
        state: &AppState,
        rebuild: bool,
        settled_epoch: u64,
    ) -> Result<(), String> {
        let projection_epoch = self.inner.projection_epoch.load(Ordering::Acquire);
        let settings = state.settings.read().await.search.clone();
        let active = read_lock(&self.inner.active).clone();
        let mut progress = active.status.clone();
        progress.phase = if rebuild {
            SearchIndexPhase::Rebuilding
        } else {
            SearchIndexPhase::Reconciling
        };
        progress.projection_fenced = self
            .inner
            .fail_closed_until_completed
            .load(Ordering::Acquire);
        progress.processed = 0;
        progress.total = 0;
        progress.last_started_at = Some(now_rfc3339());
        progress.last_error = None;
        progress.error_at = None;
        progress.updated_at = now_rfc3339();
        self.persist_batch(
            state,
            Vec::new(),
            &progress,
            projection_epoch,
            Some(settled_epoch),
        )
        .await?;

        let build = build_corpus(state, &settings, &self.inner.shutdown).await?;
        self.ensure_source_epoch(settled_epoch).await?;
        let target: HashMap<String, SearchDocument> = build
            .documents
            .into_iter()
            .map(|document| (document.id.clone(), document))
            .collect();
        let target_count = target.len() as u64;
        let truncated_document_count = target
            .values()
            .filter(|document| document.content_truncated)
            .count() as u64;
        let target_ids: BTreeSet<String> = target.keys().cloned().collect();
        let current_ids = active.index.ids();
        let mut operations = Vec::with_capacity(target.len());
        for (id, document) in &target {
            if rebuild || active.index.get(id) != Some(document) {
                operations.push(IndexOperation::Upsert(Box::new(document.clone())));
            }
        }
        for id in current_ids {
            if !target_ids.contains(&id) {
                operations.push(IndexOperation::Delete(id));
            }
        }
        operations.sort_by(|left, right| operation_id(left).cmp(operation_id(right)));
        let next_index = Arc::new(index_from_documents(target.into_values()));

        progress.processed = 0;
        progress.total = operations.len() as u64;
        progress.updated_at = now_rfc3339();
        self.persist_batch(
            state,
            Vec::new(),
            &progress,
            projection_epoch,
            Some(settled_epoch),
        )
        .await?;

        let mut operations = operations.into_iter();
        loop {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err("search projection cancelled for shutdown".to_owned());
            }
            let batch: Vec<_> = operations
                .by_ref()
                .take(settings.batch_size.max(1) as usize)
                .collect();
            if batch.is_empty() {
                break;
            }
            self.ensure_source_epoch(settled_epoch).await?;
            progress.processed = progress.processed.saturating_add(batch.len() as u64);
            progress.updated_at = now_rfc3339();
            self.persist_batch(
                state,
                batch,
                &progress,
                projection_epoch,
                Some(settled_epoch),
            )
            .await?;
            self.ensure_source_epoch(settled_epoch).await?;
            tokio::task::yield_now().await;
        }

        progress.phase = SearchIndexPhase::Idle;
        progress.generation = progress.generation.saturating_add(1);
        progress.document_count = target_count;
        progress.truncated_document_count = truncated_document_count;
        progress.indexed_content_chars = build.indexed_content_chars;
        progress.content_budget_exhausted = build.content_budget_exhausted;
        progress.processed = progress.total;
        progress.last_event_seq = build.last_event_seq;
        progress.last_completed_at = Some(now_rfc3339());
        progress.projection_fenced = false;
        progress.updated_at = now_rfc3339();
        if let Err(error) = self
            .publish_completed_projection(
                state,
                next_index,
                &progress,
                projection_epoch,
                Some(settled_epoch),
            )
            .await
        {
            if self.inner.wake_epoch.load(Ordering::Acquire) != settled_epoch {
                return self.ensure_source_epoch(settled_epoch).await;
            }
            return Err(error);
        }
        Ok(())
    }

    async fn persist_batch(
        &self,
        state: &AppState,
        operations: Vec<IndexOperation>,
        status: &SearchIndexState,
        expected_epoch: u64,
        expected_source_epoch: Option<u64>,
    ) -> Result<(), String> {
        let _projection_guard = self.inner.projection_gate.lock().await;
        if self.inner.projection_epoch.load(Ordering::Acquire) != expected_epoch
            || self.inner.destructive_fence.load(Ordering::Acquire)
            || expected_source_epoch.is_some_and(|epoch| !self.source_epoch_is_current(epoch))
        {
            return Err(SEARCH_PROJECTION_SUPERSEDED.to_owned());
        }
        if let Some(store) = state.store.clone() {
            let owned_status = status.clone();
            store
                .read_blocking_async(move |store| {
                    store.apply_search_index_batch(&operations, &owned_status)?;
                    Ok::<_, StoreError>(())
                })
                .await
                .map_err(|error| format!("search index persistence failed: {error}"))?;
        }
        *write_lock(&self.inner.status) = status.clone();
        Ok(())
    }

    async fn publish_completed_projection(
        &self,
        state: &AppState,
        index: Arc<InMemoryIndex>,
        status: &SearchIndexState,
        expected_epoch: u64,
        expected_source_epoch: Option<u64>,
    ) -> Result<(), String> {
        let _projection_guard = self.inner.projection_gate.lock().await;
        if self.inner.projection_epoch.load(Ordering::Acquire) != expected_epoch
            || self.inner.destructive_fence.load(Ordering::Acquire)
            || expected_source_epoch.is_some_and(|epoch| !self.source_epoch_is_current(epoch))
        {
            return Err(SEARCH_PROJECTION_SUPERSEDED.to_owned());
        }
        if let Some(store) = state.store.clone() {
            let owned_status = status.clone();
            store
                .read_blocking_async(move |store| {
                    store.apply_search_index_batch(&[], &owned_status)
                })
                .await
                .map_err(|error| format!("search index persistence failed: {error}"))?;
        }
        if expected_source_epoch.is_some_and(|epoch| !self.source_epoch_is_current(epoch)) {
            // A source mutation raced the durable completion write. Remove the candidate while the
            // projection gate is still held so no local request can activate it.
            if let Some(store) = state.store.clone() {
                store
                    .read_blocking_async(|store| store.clear_search_projection())
                    .await
                    .map_err(|error| {
                        format!(
                            "dirty search projection cleanup failed after publish race: {error}"
                        )
                    })?;
            }
            let empty = SearchIndexState {
                updated_at: now_rfc3339(),
                ..SearchIndexState::default()
            };
            *write_lock(&self.inner.active) = Arc::new(ActiveSearchSnapshot::empty(empty.clone()));
            *write_lock(&self.inner.status) = empty;
            return Err(SEARCH_PROJECTION_SUPERSEDED.to_owned());
        }
        *write_lock(&self.inner.active) = Arc::new(ActiveSearchSnapshot {
            index,
            status: status.clone(),
        });
        *write_lock(&self.inner.status) = status.clone();
        self.inner
            .fail_closed_until_completed
            .store(false, Ordering::Release);
        state.cluster_shared.invalidation.publish(
            &crate::cluster_shared_state::InvalidationEvent::SearchProjectionCompleted {
                generation: status.generation,
            },
        );
        Ok(())
    }

    async fn persist_active_status(
        &self,
        state: &AppState,
        status: &SearchIndexState,
    ) -> Result<(), String> {
        let expected_epoch = self.inner.projection_epoch.load(Ordering::Acquire);
        let _projection_guard = self.inner.projection_gate.lock().await;
        if self.inner.projection_epoch.load(Ordering::Acquire) != expected_epoch
            || self.inner.destructive_fence.load(Ordering::Acquire)
        {
            return Err(SEARCH_PROJECTION_SUPERSEDED.to_owned());
        }
        if let Some(store) = state.store.clone() {
            let owned_status = status.clone();
            store
                .read_blocking_async(move |store| {
                    store.apply_search_index_batch(&[], &owned_status)
                })
                .await
                .map_err(|error| format!("search index persistence failed: {error}"))?;
        }
        let current = read_lock(&self.inner.active).clone();
        *write_lock(&self.inner.active) = Arc::new(ActiveSearchSnapshot {
            index: current.index.clone(),
            status: status.clone(),
        });
        *write_lock(&self.inner.status) = status.clone();
        Ok(())
    }

    async fn set_paused(&self, state: &AppState) -> Result<(), String> {
        let mut status = read_lock(&self.inner.active).status.clone();
        status.phase = SearchIndexPhase::Paused;
        status.updated_at = now_rfc3339();
        self.persist_active_status(state, &status).await
    }

    async fn set_resumed(&self, state: &AppState) -> Result<(), String> {
        let mut status = read_lock(&self.inner.active).status.clone();
        status.phase = SearchIndexPhase::Idle;
        status.updated_at = now_rfc3339();
        self.persist_active_status(state, &status).await?;
        let capacity = state.settings.read().await.search.queue_capacity;
        self.enqueue(SearchCommand::Reconcile, capacity as usize)
            .map_err(|error| format!("{error:?}"))
    }

    async fn set_disabled(&self, state: &AppState) -> Result<(), String> {
        let mut status = read_lock(&self.inner.active).status.clone();
        if status.phase == SearchIndexPhase::Disabled {
            return Ok(());
        }
        status.phase = SearchIndexPhase::Disabled;
        status.updated_at = now_rfc3339();
        self.persist_active_status(state, &status).await
    }

    async fn record_error(&self, state: &AppState, error: String) {
        let epoch = self.inner.projection_epoch.load(Ordering::Acquire);
        let mut status = read_lock(&self.inner.status).clone();
        status.phase = SearchIndexPhase::Error;
        status.last_error = Some(error);
        status.error_at = Some(now_rfc3339());
        status.updated_at = now_rfc3339();
        if self
            .persist_batch(state, Vec::new(), &status, epoch, None)
            .await
            .is_err()
        {
            *write_lock(&self.inner.status) = status;
        }
    }

    fn record_local_error(&self, error: String) {
        let mut status = read_lock(&self.inner.status).clone();
        status.phase = SearchIndexPhase::Error;
        status.last_error = Some(error);
        status.error_at = Some(now_rfc3339());
        status.updated_at = now_rfc3339();
        *write_lock(&self.inner.status) = status;
    }
}

fn reconcile_burst_delay(
    command: Option<SearchCommand>,
    dirty_during_previous_build: bool,
    interval_seconds: u32,
) -> Option<StdDuration> {
    (command == Some(SearchCommand::Reconcile) && dirty_during_previous_build)
        .then(|| StdDuration::from_secs(u64::from(interval_seconds)))
}

fn projection_writer_from_gate(gate: Result<(), StoreError>) -> Result<bool, String> {
    match gate {
        Ok(()) => Ok(true),
        Err(StoreError::NotLeader) => Ok(false),
        Err(error) => Err(format!(
            "search projection leadership check failed: {error}"
        )),
    }
}

fn is_completed_snapshot(state: Option<&SearchIndexState>) -> bool {
    state.is_some_and(|state| {
        state.generation > 0
            && state.last_completed_at.is_some()
            && matches!(
                state.phase,
                SearchIndexPhase::Idle
                    | SearchIndexPhase::Paused
                    | SearchIndexPhase::Disabled
                    | SearchIndexPhase::ShuttingDown
            )
    })
}

fn completed_snapshot_unchanged(
    before: Option<&SearchIndexState>,
    after: Option<&SearchIndexState>,
) -> bool {
    before == after && is_completed_snapshot(after)
}

/// Start the idempotent logical service on its dedicated OS thread.
pub(crate) fn spawn_search_service(state: AppState) {
    state.search_index.start(state.clone());
    let settings = state.settings.try_read().map(|guard| guard.search.clone());
    if let Ok(settings) = settings {
        let _ = state
            .search_index
            .enqueue(SearchCommand::Reconcile, settings.queue_capacity as usize);
    } else {
        state.search_index.inner.notify.notify_one();
    }
}

/// Drain and stop the worker during server graceful shutdown.
pub async fn shutdown_search_service(state: &AppState) {
    state
        .search_index
        .inner
        .shutdown
        .store(true, Ordering::Release);
    state.search_index.inner.notify.notify_waiters();
    if !reap_search_worker(
        &state.search_index,
        StdDuration::from_secs(SEARCH_SHUTDOWN_TIMEOUT_SECS),
    )
    .await
    {
        eprintln!(
            "warning: search worker did not stop within {SEARCH_SHUTDOWN_TIMEOUT_SECS}s; \
             retaining its join handle for a later reap"
        );
    }
}

async fn reap_search_worker(service: &SearchService, timeout: StdDuration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let finished = {
            let task = lock_mutex(&service.inner.task);
            task.as_ref()
                .is_none_or(std::thread::JoinHandle::is_finished)
        };
        if finished {
            let handle = lock_mutex(&service.inner.task).take();
            if let Some(handle) = handle {
                let _ = tokio::task::spawn_blocking(move || handle.join()).await;
            }
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(StdDuration::from_millis(20)).await;
    }
}

/// Wake reconciliation after settings or source mutations. The queue is bounded and periodic
/// reconciliation is the repair path if this hint encounters backpressure.
pub(crate) async fn notify_reconcile(state: &AppState) {
    let capacity = state.settings.read().await.search.queue_capacity;
    let _ = state
        .search_index
        .enqueue(SearchCommand::Reconcile, capacity as usize);
}

/// RAII fence spanning one source mutation from before its durable/ledger commit through the
/// matching in-memory read-model publication. Beginning and ending both advance the source epoch:
/// an already-running build is superseded immediately, while the final edge schedules the clean
/// post-publication generation. [`SearchService::settle_source_mutations`] refuses to snapshot
/// between those edges.
pub(crate) struct SearchSourceMutationGuard {
    service: SearchService,
    queue_capacity: usize,
}

impl Drop for SearchSourceMutationGuard {
    fn drop(&mut self) {
        let previous = self
            .service
            .inner
            .source_mutations_in_flight
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "search source-mutation guard underflow");
        let _ = self
            .service
            .enqueue(SearchCommand::Reconcile, self.queue_capacity);
        self.service.inner.notify.notify_one();
    }
}

/// Start a source-mutation fence before changing any search-backed map or committing the ledger row
/// which describes that change. Keep the returned guard alive until every matching in-memory map
/// write has been published.
pub(crate) async fn begin_source_mutation(state: &AppState) -> SearchSourceMutationGuard {
    let queue_capacity = state.settings.read().await.search.queue_capacity as usize;
    // Serialize this begin edge with the projection's final source check + active swap. If a
    // completion already owns the gate it is observably earlier than this mutation; otherwise its
    // final check sees this in-flight count (even before the wake epoch is incremented).
    let _projection_guard = state.search_index.inner.projection_gate.lock().await;
    state
        .search_index
        .inner
        .source_mutations_in_flight
        .fetch_add(1, Ordering::AcqRel);
    let _ = state
        .search_index
        .enqueue(SearchCommand::Reconcile, queue_capacity);
    state.search_index.inner.notify.notify_one();
    SearchSourceMutationGuard {
        service: state.search_index.clone(),
        queue_capacity,
    }
}

#[cfg(test)]
pub(crate) fn source_epoch_for_test(state: &AppState) -> u64 {
    state.search_index.inner.wake_epoch.load(Ordering::Acquire)
}

/// A stricter source-mutation fence for operations that can make a previously indexed document
/// unauthorized even though its immutable projection still carries the old scope (physical delete,
/// tenant transfer, or another ownership/scope move). It installs a local fail-closed tombstone
/// before the authoritative mutation can start. The projection writer also installs the durable
/// tombstone so every cluster node fails closed even if it misses the best-effort invalidation.
///
/// Ordinary title/body/status updates must use [`begin_source_mutation`]: they continue serving the
/// preceding completed generation while the replacement is built. This security mode deliberately
/// makes search unavailable until a clean completed generation is published.
#[cfg(any(feature = "postgres", test))]
pub(crate) struct SecuritySensitiveSearchSourceMutationGuard {
    source_guard: Option<SearchSourceMutationGuard>,
    invalidation: crate::cluster_shared_state::SharedInvalidationBus,
    fence_id: Option<Uuid>,
}

#[cfg(any(feature = "postgres", test))]
impl Drop for SecuritySensitiveSearchSourceMutationGuard {
    fn drop(&mut self) {
        // Publish the authoritative map's completion edge before peers are told that the mutation
        // itself ended. They still cannot serve stale text: the durable/local tombstone remains
        // fenced until the worker publishes a clean completed generation.
        drop(self.source_guard.take());
        if let Some(reset_id) = self.fence_id.take() {
            self.invalidation.publish(
                &crate::cluster_shared_state::InvalidationEvent::SearchProjectionReleased {
                    reset_id,
                },
            );
        }
    }
}

#[cfg(any(feature = "postgres", test))]
pub(crate) async fn begin_security_sensitive_source_mutation(
    state: &AppState,
) -> Result<SecuritySensitiveSearchSourceMutationGuard, ApiError> {
    let source_guard = begin_source_mutation(state).await;
    let service = &state.search_index;
    let mut publishes_cluster_fence = false;
    {
        let _projection_guard = service.inner.projection_gate.lock().await;
        service
            .inner
            .fail_closed_until_completed
            .store(true, Ordering::Release);
        let tombstone = SearchIndexState {
            phase: SearchIndexPhase::Starting,
            projection_fenced: true,
            updated_at: now_rfc3339(),
            ..SearchIndexState::default()
        };
        *write_lock(&service.inner.active) =
            Arc::new(ActiveSearchSnapshot::empty(tombstone.clone()));
        *write_lock(&service.inner.status) = tombstone;

        if let Some(store) = state.store.clone() {
            let writer = store
                .read_blocking_async(|store| {
                    projection_writer_from_gate(store.cluster_assert_writable())
                })
                .await
                .map_err(ApiError::Internal)?;
            if writer {
                store
                    .read_blocking_async(|store| store.clear_search_projection())
                    .await
                    .map_err(|error| {
                        ApiError::Internal(format!(
                            "search security-fence persistence failed: {error}"
                        ))
                    })?;
                publishes_cluster_fence = true;
            }
        }
    }

    let fence_id = publishes_cluster_fence.then(Uuid::new_v4);
    if let Some(reset_id) = fence_id {
        state.cluster_shared.invalidation.publish(
            &crate::cluster_shared_state::InvalidationEvent::SearchProjectionFenced { reset_id },
        );
    }
    service.inner.notify.notify_waiters();
    Ok(SecuritySensitiveSearchSourceMutationGuard {
        source_guard: Some(source_guard),
        invalidation: state.cluster_shared.invalidation.clone(),
        fence_id,
    })
}

fn clear_local_projection_for_fence(service: &SearchService, enabled: bool) {
    service
        .inner
        .fail_closed_until_completed
        .store(true, Ordering::Release);
    service
        .inner
        .projection_epoch
        .fetch_add(1, Ordering::AcqRel);
    service.inner.wake_epoch.fetch_add(1, Ordering::AcqRel);
    lock_mutex(&service.inner.queue).clear();
    service.inner.dropped_commands.store(0, Ordering::Release);
    let status = SearchIndexState {
        phase: if enabled {
            SearchIndexPhase::Starting
        } else {
            SearchIndexPhase::Disabled
        },
        updated_at: now_rfc3339(),
        ..SearchIndexState::default()
    };
    *write_lock(&service.inner.active) = Arc::new(ActiveSearchSnapshot::empty(status.clone()));
    *write_lock(&service.inner.status) = status;
}

/// Install a fail-closed local and durable tombstone before a destructive store transaction or
/// restore swap begins. In a Postgres cluster the durable singleton, not best-effort pub/sub, is the
/// correctness boundary every search request confirms.
pub(crate) async fn prepare_destructive_change(state: &AppState) -> Result<(), String> {
    let settings = state.settings.read().await.search.clone();
    let service = &state.search_index;
    if service
        .inner
        .destructive_fence
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("já existe uma reposição destrutiva em curso".to_owned());
    }
    let reset_id = Uuid::new_v4();
    let persistence = {
        let _projection_guard = service.inner.projection_gate.lock().await;
        *write_lock(&service.inner.destructive_reset_id) = Some(reset_id);
        clear_local_projection_for_fence(service, settings.enabled);
        if let Some(store) = state.store.clone() {
            store
                .read_blocking_async(|store| store.clear_search_projection())
                .await
                .map_err(|error| format!("search pre-fence persistence failed: {error}"))
        } else {
            Ok(())
        }
    };
    if let Err(error) = persistence {
        abort_destructive_change(state).await;
        return Err(error);
    }
    state.cluster_shared.invalidation.publish(
        &crate::cluster_shared_state::InvalidationEvent::SearchProjectionFenced { reset_id },
    );
    service.inner.notify.notify_waiters();
    Ok(())
}

/// Complete a successful destructive mutation: clear the local projection, release serving, and
/// request a clean generation from the replacement authoritative sources.
///
/// The destructive store transaction already tombstones the durable derived projection. Completion
/// must therefore contain no second fallible store write, and a saturated rebuild queue must never
/// strand the fence or turn a committed reset into an apparent request failure.
pub(crate) async fn reset_after_destructive_change(state: &AppState) {
    reset_after_destructive_change_with(state, |service, capacity| {
        service.enqueue(SearchCommand::Rebuild, capacity)
    })
    .await;
}

async fn reset_after_destructive_change_with(
    state: &AppState,
    enqueue_rebuild: impl FnOnce(&SearchService, usize) -> Result<(), ApiError>,
) {
    let settings = state.settings.read().await.search.clone();
    let service = &state.search_index;
    let reset_id = {
        let _projection_guard = service.inner.projection_gate.lock().await;
        clear_local_projection_for_fence(service, settings.enabled);
        service
            .inner
            .destructive_fence
            .store(service.has_remote_fence(), Ordering::Release);
        write_lock(&service.inner.destructive_reset_id).take()
    };
    if let Some(reset_id) = reset_id {
        state.cluster_shared.invalidation.publish(
            &crate::cluster_shared_state::InvalidationEvent::SearchProjectionReleased { reset_id },
        );
    }
    if settings.enabled
        && service.inner.running.load(Ordering::Acquire)
        && let Err(error) = enqueue_rebuild(service, settings.queue_capacity as usize)
    {
        eprintln!(
            "search: committed destructive change released safely, but the immediate rebuild \
             request was coalesced/refused ({error:?}); the worker's periodic reconcile will retry"
        );
        service.inner.notify.notify_waiters();
    }
}

/// Release a pre-fence after the authoritative mutation was refused. The prior derived projection
/// was deliberately discarded, so recovery is a clean rebuild rather than resurrecting cached text.
pub(crate) async fn abort_destructive_change(state: &AppState) {
    let settings = state.settings.read().await.search.clone();
    let service = &state.search_index;
    let reset_id = {
        let _projection_guard = service.inner.projection_gate.lock().await;
        clear_local_projection_for_fence(service, settings.enabled);
        service
            .inner
            .destructive_fence
            .store(service.has_remote_fence(), Ordering::Release);
        write_lock(&service.inner.destructive_reset_id).take()
    };
    if let Some(reset_id) = reset_id {
        state.cluster_shared.invalidation.publish(
            &crate::cluster_shared_state::InvalidationEvent::SearchProjectionReleased { reset_id },
        );
    }
    if settings.enabled && service.inner.running.load(Ordering::Acquire) {
        let _ = service.enqueue(SearchCommand::Rebuild, settings.queue_capacity as usize);
    }
}

#[cfg(feature = "redis")]
pub(crate) async fn apply_remote_destructive_fence(state: &AppState, reset_id: Uuid, fenced: bool) {
    let settings = state.settings.read().await.search.clone();
    let service = &state.search_index;
    {
        let _projection_guard = service.inner.projection_gate.lock().await;
        if fenced {
            if lock_mutex(&service.inner.released_remote_fence_ids).contains(&reset_id) {
                return;
            }
            lock_mutex(&service.inner.remote_fence_ids).insert(reset_id);
        } else {
            lock_mutex(&service.inner.remote_fence_ids).remove(&reset_id);
            let mut released = lock_mutex(&service.inner.released_remote_fence_ids);
            if !released.contains(&reset_id) {
                released.push_back(reset_id);
                while released.len() > 64 {
                    released.pop_front();
                }
            }
        }
        clear_local_projection_for_fence(service, settings.enabled);
        let local_fence = read_lock(&service.inner.destructive_reset_id).is_some();
        let remote_fence = !lock_mutex(&service.inner.remote_fence_ids).is_empty();
        service
            .inner
            .destructive_fence
            .store(local_fence || remote_fence, Ordering::Release);
    }
    if !service.inner.destructive_fence.load(Ordering::Acquire)
        && settings.enabled
        && service.inner.running.load(Ordering::Acquire)
    {
        let _ = service.enqueue(SearchCommand::Reconcile, settings.queue_capacity as usize);
    }
    service.inner.notify.notify_waiters();
}

#[cfg(feature = "redis")]
pub(crate) async fn apply_remote_completed_generation(state: &AppState, generation: u64) {
    let local = read_lock(&state.search_index.inner.active).status.clone();
    if is_completed_snapshot(Some(&local)) && local.generation >= generation {
        return;
    }
    if let Err(error) = state.search_index.hydrate_from_store(state, true).await {
        state.search_index.record_local_error(format!(
            "search projection generation {generation} hydration failed: {error}"
        ));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchStatusResponse {
    pub details_redacted: bool,
    pub enabled: bool,
    pub partial: bool,
    pub stale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_truncated: Option<bool>,
    pub phase: SearchIndexPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_document_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_content_chars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_budget_chars: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_budget_exhausted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_capacity: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_commands: Option<u64>,
    /// True only on the single node currently allowed to build and persist the shared projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_writer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_thread: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchRequest {
    q: Option<String>,
    kind: Option<String>,
    tenant_id: Option<String>,
    entity_id: Option<String>,
    book_id: Option<String>,
    act_id: Option<String>,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub page: SearchPage,
    pub next_cursor: Option<String>,
    /// More matches exist beyond the deliberately bounded offset window.
    pub pagination_truncated: bool,
    pub index: SearchStatusResponse,
}

#[derive(Debug, Serialize, Deserialize)]
struct SearchCursor {
    offset: usize,
    fingerprint: String,
}

pub async fn query(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(request): Query<SearchRequest>,
) -> Result<Json<SearchResponse>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    if !authz.holds_at_any_scope(Permission::SearchRead) {
        return Err(crate::authz::forbidden());
    }
    let settings = state.settings.read().await.search.clone();
    if !settings.enabled {
        return Err(ApiError::Conflict(
            "o índice de pesquisa está desativado".to_owned(),
        ));
    }
    let _ = confirm_search_snapshot_current(&state).await?;
    let filters = request_filters(&request)?;
    let raw_text = request.q.as_deref().unwrap_or_default();
    ensure_char_limit("q", raw_text, MAX_QUERY_CHARS)?;
    let text = raw_text.trim().to_owned();
    if !text.is_empty() && text.chars().count() < usize::from(settings.min_query_chars) {
        return Err(ApiError::Unprocessable(format!(
            "a pesquisa requer pelo menos {} caracteres",
            settings.min_query_chars
        )));
    }
    validate_query_terms(&text, settings.min_query_chars)?;
    if text.is_empty() && filters == SearchFilters::default() {
        return Err(ApiError::Unprocessable(
            "indique texto ou pelo menos um filtro de pesquisa".to_owned(),
        ));
    }
    let limit = request
        .limit
        .unwrap_or(settings.result_limit as usize)
        .clamp(1, settings.result_limit as usize);
    let active_before = read_lock(&state.search_index.inner.active).clone();
    let index_before = active_before.status.clone();
    let authority_before = authz.search_cursor_authority();
    let cursor_context = search_cursor_context(&index_before, &actor, &authority_before);
    let fingerprint = query_fingerprint(&text, &filters, limit, &cursor_context);
    let offset = match request.cursor.as_deref() {
        Some(cursor) => decode_cursor(cursor, &fingerprint)?,
        None => 0,
    };
    ensure_result_window(offset, limit)?;
    let query = SearchQuery {
        text,
        filters,
        offset,
        limit,
        snippet_chars: settings.snippet_chars as usize,
        facet_limit: settings.facet_limit as usize,
    };
    let redaction = authz.read_redaction();
    let detailed_status = authz.permits(Permission::SearchManage, Scope::Global);
    let query_slot = state.search_index.try_query_slot()?;
    let query_index = active_before.index.clone();
    // Ranking/faceting is synchronous CPU work. Move it off the async request runtime and keep the
    // bounded admission permit inside the blocking job so cancellation cannot accidentally admit
    // more than the configured process-wide concurrency.
    let mut page = tokio::task::spawn_blocking(move || {
        let _query_slot = query_slot;
        query_index.search_with_access(&query, |document| {
            visible_search_access(
                redaction.is_guest(),
                document_allowed(&authz, document),
                document,
            )
        })
    })
    .await
    .map_err(|error| ApiError::Internal(format!("a pesquisa terminou inesperadamente: {error}")))?;
    let index_after = read_lock(&state.search_index.inner.active).status.clone();
    let authority_after = authorizer(&state, &actor).await?.search_cursor_authority();
    if !same_search_generation(&index_before, &index_after) || authority_before != authority_after {
        return Err(ApiError::Conflict(
            "o índice ou as autorizações mudaram; reinicie a paginação".to_owned(),
        ));
    }
    let confirmed_index = confirm_search_snapshot_current(&state).await?;
    if !same_search_generation(&index_before, &confirmed_index) {
        return Err(ApiError::Conflict(
            "o índice mudou durante a pesquisa; reinicie a paginação".to_owned(),
        ));
    }
    let (next_cursor, pagination_truncated) = bounded_next_cursor(&mut page, &fingerprint)?;
    let index = state
        .search_index
        .status_response(&settings, detailed_status);
    Ok(Json(SearchResponse {
        page,
        next_cursor,
        pagination_truncated,
        index,
    }))
}

fn same_search_generation(left: &SearchIndexState, right: &SearchIndexState) -> bool {
    left.generation == right.generation && left.updated_at == right.updated_at
}

async fn confirm_search_snapshot_current(state: &AppState) -> Result<SearchIndexState, ApiError> {
    if state
        .search_index
        .inner
        .destructive_fence
        .load(Ordering::Acquire)
    {
        return Err(ApiError::Unavailable(
            "o índice está indisponível durante a reposição de dados".to_owned(),
        ));
    }
    let local = read_lock(&state.search_index.inner.active).status.clone();
    if !is_completed_snapshot(Some(&local))
        || !matches!(
            local.phase,
            SearchIndexPhase::Idle | SearchIndexPhase::Paused
        )
    {
        return Err(ApiError::Unavailable(
            "o índice ainda não tem uma geração estável concluída".to_owned(),
        ));
    }
    let Some(store) = state.store.clone() else {
        return Ok(local);
    };
    if !store.cluster_election_enabled() {
        return Ok(local);
    }
    let durable = store
        .read_blocking_async(|store| store.search_index_state())
        .await
        .map_err(|error| {
            ApiError::Unavailable(format!(
                "não foi possível confirmar a geração do índice: {error}"
            ))
        })?;
    if durable_confirms_local_snapshot(&local, durable.as_ref()) {
        return Ok(local);
    }

    // A missed pub/sub signal affects latency only. If the leader has completed a newer durable
    // generation, atomically hydrate it before retrying this same request; tombstones/interrupted
    // generations still clear local text and fail closed.
    if state
        .search_index
        .hydrate_from_store(state, true)
        .await
        .map_err(|error| {
            ApiError::Unavailable(format!(
                "não foi possível hidratar a geração atual do índice: {error}"
            ))
        })?
    {
        let hydrated = read_lock(&state.search_index.inner.active).status.clone();
        if is_completed_snapshot(Some(&hydrated)) {
            return Ok(hydrated);
        }
    }
    Err(ApiError::Unavailable(
        "a geração local do índice está desatualizada; aguarde a sincronização".to_owned(),
    ))
}

fn durable_confirms_local_snapshot(
    local: &SearchIndexState,
    durable: Option<&SearchIndexState>,
) -> bool {
    if !is_completed_snapshot(Some(local)) {
        return false;
    }
    let Some(durable) = durable else {
        return false;
    };
    if durable.projection_fenced {
        return false;
    }
    if is_completed_snapshot(Some(durable)) {
        return durable == local;
    }
    // A follower may keep serving its immutable completed generation while the leader constructs
    // the next non-fenced generation. The generation and completion marker identify that base.
    durable.generation == local.generation
        && durable.last_completed_at == local.last_completed_at
        && matches!(
            durable.phase,
            SearchIndexPhase::Starting
                | SearchIndexPhase::Reconciling
                | SearchIndexPhase::Rebuilding
                | SearchIndexPhase::Error
        )
}

pub async fn status(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<SearchStatusResponse>, ApiError> {
    let authz = authorizer(&state, &actor).await?;
    if !authz.holds_at_any_scope(Permission::SearchRead)
        && !authz.permits(Permission::SearchManage, Scope::Global)
    {
        return Err(crate::authz::forbidden());
    }
    let settings = state.settings.read().await.search.clone();
    Ok(Json(state.search_index.status_response(
        &settings,
        authz.permits(Permission::SearchManage, Scope::Global),
    )))
}

pub async fn rebuild(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<SearchStatusResponse>, ApiError> {
    admin_command(&state, &actor, &attestor, SearchCommand::Rebuild).await
}

pub async fn pause(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<SearchStatusResponse>, ApiError> {
    admin_command(&state, &actor, &attestor, SearchCommand::Pause).await
}

pub async fn resume(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<SearchStatusResponse>, ApiError> {
    admin_command(&state, &actor, &attestor, SearchCommand::Resume).await
}

async fn admin_command(
    state: &AppState,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    command: SearchCommand,
) -> Result<Json<SearchStatusResponse>, ApiError> {
    let authz = authorizer(state, actor).await?;
    authz.require(Permission::SearchManage, Scope::Global)?;
    let settings = state.settings.read().await.search.clone();
    if matches!(command, SearchCommand::Rebuild | SearchCommand::Resume) && !settings.enabled {
        return Err(ApiError::Conflict(
            "ative a pesquisa nas definições antes desta operação".to_owned(),
        ));
    }
    if command == SearchCommand::Rebuild
        && read_lock(&state.search_index.inner.status).phase == SearchIndexPhase::Paused
    {
        return Err(ApiError::Conflict(
            "retome o índice antes de pedir uma reconstrução".to_owned(),
        ));
    }
    let action = match command {
        SearchCommand::Rebuild => "rebuild_requested",
        SearchCommand::Pause => "pause_requested",
        SearchCommand::Resume => "resume_requested",
        SearchCommand::Reconcile => "reconcile_requested",
    };
    let actor_label = actor.resolve("search-admin");
    let payload = serde_json::to_vec(&serde_json::json!({ "action": action }))?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(
        &mut ledger,
        &actor_label,
        "search:index",
        &format!("search.{action}"),
        None,
        &payload,
    )?;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    drop(ledger);
    state
        .search_index
        .enqueue(command, settings.queue_capacity as usize)?;
    Ok(Json(state.search_index.status_response(&settings, true)))
}

#[derive(Default)]
struct DurableCorpusRows {
    imported_documents: Vec<StoredImportedDocumentMeta>,
    imported_review_history: HashMap<String, Vec<StoredImportedDocumentReviewHistoryEntry>>,
    paper_imports: Vec<(StoredPaperBookImportMeta, Vec<StoredPaperBookOcrDraft>)>,
    generated_documents: Vec<StoredDocumentSearchMetadata>,
    user_templates: Vec<(String, String)>,
}

#[derive(Debug)]
struct CorpusBuild {
    documents: Vec<SearchDocument>,
    last_event_seq: Option<u64>,
    indexed_content_chars: u64,
    content_budget_exhausted: bool,
}

struct CorpusContentBudget {
    remaining: usize,
    retained: u64,
    exhausted: bool,
}

impl CorpusContentBudget {
    fn new(max_chars: u64) -> Self {
        Self {
            remaining: usize::try_from(max_chars).unwrap_or(usize::MAX),
            retained: 0,
            exhausted: false,
        }
    }

    fn apply(&mut self, mut document: SearchDocument) -> SearchDocument {
        self.apply_body(&mut document.body, &mut document.content_truncated);
        if let Some(privileged) = &mut document.privileged {
            self.apply_body(&mut privileged.body, &mut privileged.content_truncated);
        }
        document
    }

    fn apply_body(&mut self, body: &mut String, truncated: &mut bool) {
        let body_chars = body.chars().count();
        if body_chars > self.remaining {
            *body = body.chars().take(self.remaining).collect();
            *truncated = true;
            self.retained = self.retained.saturating_add(self.remaining as u64);
            self.remaining = 0;
            self.exhausted = true;
        } else {
            self.remaining -= body_chars;
            self.retained = self.retained.saturating_add(body_chars as u64);
        }
    }
}

#[derive(Clone, Default)]
struct Relation {
    tenant_id: Option<String>,
    entity_id: Option<String>,
    entity_name: Option<String>,
    book_id: Option<String>,
    book_label: Option<String>,
    act_id: Option<String>,
}

fn ensure_projection_active(shutdown: &AtomicBool) -> Result<(), String> {
    if shutdown.load(Ordering::Acquire) {
        Err("search projection cancelled for shutdown".to_owned())
    } else {
        Ok(())
    }
}

/// Copy a mutable request-facing map in bounded chunks. The first lock only copies compact keys;
/// each deep-clone lock is capped, and all serialization/tokenization happens after this returns.
async fn snapshot_map_bounded<K, V>(
    source: &tokio::sync::RwLock<HashMap<K, V>>,
    shutdown: &AtomicBool,
) -> Result<HashMap<K, V>, String>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    ensure_projection_active(shutdown)?;
    let keys = {
        let guard = source.read().await;
        guard.keys().cloned().collect::<Vec<_>>()
    };
    let mut snapshot = HashMap::with_capacity(keys.len());
    for keys in keys.chunks(SOURCE_SNAPSHOT_BATCH_SIZE) {
        ensure_projection_active(shutdown)?;
        {
            let guard = source.read().await;
            for key in keys {
                if let Some(value) = guard.get(key) {
                    snapshot.insert(key.clone(), value.clone());
                }
            }
        }
        tokio::task::yield_now().await;
    }
    Ok(snapshot)
}

fn retained_ledger_event_chunk(
    ledger: &chancela_ledger::Ledger,
    start: usize,
    limit: usize,
    cutoff: OffsetDateTime,
) -> Vec<chancela_ledger::Event> {
    // Global sequence is monotonic, but imported/restored event timestamps are not guaranteed to
    // be. Filter every bounded sequence chunk instead of assuming the retained set is a suffix.
    let end = start.saturating_add(limit).min(ledger.len());
    ledger
        .events()
        .get(start..end)
        .unwrap_or_default()
        .iter()
        .filter(|event| event.timestamp >= cutoff)
        .cloned()
        .collect()
}

async fn retained_ledger_events_bounded(
    state: &AppState,
    cutoff: OffsetDateTime,
    shutdown: &AtomicBool,
) -> Result<Vec<chancela_ledger::Event>, String> {
    let event_count = state.ledger.read().await.len();
    let mut retained = Vec::new();
    for start in (0..event_count).step_by(SOURCE_SNAPSHOT_BATCH_SIZE) {
        ensure_projection_active(shutdown)?;
        {
            let ledger = state.ledger.read().await;
            retained.extend(retained_ledger_event_chunk(
                &ledger,
                start,
                SOURCE_SNAPSHOT_BATCH_SIZE,
                cutoff,
            ));
        }
        tokio::task::yield_now().await;
    }
    Ok(retained)
}

async fn build_corpus(
    state: &AppState,
    settings: &crate::settings::SearchSettings,
    shutdown: &AtomicBool,
) -> Result<CorpusBuild, String> {
    ensure_projection_active(shutdown)?;
    // Snapshot one bounded chunk at a time. Serialization and tokenization happen only after all
    // request-facing locks are released.
    let entities = snapshot_map_bounded(&state.entities, shutdown).await?;
    let books = snapshot_map_bounded(&state.books, shutdown).await?;
    let acts = snapshot_map_bounded(&state.acts, shutdown).await?;
    let follow_ups = snapshot_map_bounded(&state.follow_ups, shutdown).await?;
    let template_libraries =
        snapshot_map_bounded(&state.group_template_libraries, shutdown).await?;
    let template_revisions =
        snapshot_map_bounded(&state.group_template_library_revisions, shutdown).await?;
    let retention_cutoff =
        OffsetDateTime::now_utc() - time::Duration::days(i64::from(settings.event_retention_days));
    let events = retained_ledger_events_bounded(state, retention_cutoff, shutdown).await?;
    let durable = load_durable_rows(state).await?;
    let actionables = crate::dashboard::search_actionables_from_snapshot(
        state,
        &entities,
        &books,
        &acts,
        &follow_ups,
    )
    .await
    .map_err(|error| format!("Action Center search projection failed: {error:?}"))?;

    let mut entity_relations = HashMap::new();
    for entity in entities.values() {
        ensure_projection_active(shutdown)?;
        entity_relations.insert(
            entity.id.to_string(),
            Relation {
                tenant_id: Some(entity.tenant_id.to_string()),
                entity_id: Some(entity.id.to_string()),
                entity_name: Some(entity.name.clone()),
                ..Relation::default()
            },
        );
    }
    let mut book_relations = HashMap::new();
    let mut privileged_book_relations = HashMap::new();
    for book in books.values() {
        ensure_projection_active(shutdown)?;
        let mut relation = entity_relations
            .get(&book.entity_id.to_string())
            .cloned()
            .unwrap_or_default();
        relation.book_id = Some(book.id.to_string());
        relation.book_label = Some(book_label(book));
        book_relations.insert(book.id.to_string(), relation.clone());
        relation.book_label = Some(privileged_book_label(book));
        privileged_book_relations.insert(book.id.to_string(), relation);
    }
    let mut act_relations = HashMap::new();
    let mut privileged_act_relations = HashMap::new();
    for act in acts.values() {
        ensure_projection_active(shutdown)?;
        let mut relation = book_relations
            .get(&act.book_id.to_string())
            .cloned()
            .unwrap_or_default();
        relation.act_id = Some(act.id.to_string());
        act_relations.insert(act.id.to_string(), relation);
        let mut privileged_relation = privileged_book_relations
            .get(&act.book_id.to_string())
            .cloned()
            .unwrap_or_default();
        privileged_relation.act_id = Some(act.id.to_string());
        privileged_act_relations.insert(act.id.to_string(), privileged_relation);
    }

    let mut documents = Vec::with_capacity(
        entities.len()
            + books.len()
            + acts.len()
            + follow_ups.len()
            + events.len().saturating_mul(2),
    );
    let mut content_budget = CorpusContentBudget::new(settings.max_total_content_chars);
    let mut ordered_entities: Vec<_> = entities.values().collect();
    ordered_entities.sort_by_key(|entity| entity.id.0);
    let mut ordered_books: Vec<_> = books.values().collect();
    ordered_books.sort_by_key(|book| book.id.0);
    let mut ordered_acts: Vec<_> = acts.values().collect();
    ordered_acts.sort_by_key(|act| act.id.0);
    let mut ordered_follow_ups: Vec<_> = follow_ups.values().collect();
    ordered_follow_ups.sort_by(|left, right| left.id.cmp(&right.id));
    let mut ordered_libraries: Vec<_> = template_libraries.values().collect();
    ordered_libraries.sort_by_key(|library| library.id);
    let mut ordered_revisions: Vec<_> = template_revisions.values().collect();
    ordered_revisions.sort_by_key(|revision| (revision.library_id, revision.revision));

    for entity in ordered_entities {
        ensure_projection_active(shutdown)?;
        let public_view = EntityView::build(entity, ReadRedaction::Guest);
        let public = project_serializable(
            format!("entity:{}", entity.id),
            SearchKind::Entity,
            entity_relations
                .get(&entity.id.to_string())
                .cloned()
                .unwrap_or_default(),
            entity.name.clone(),
            &public_view,
            None,
            None,
            Some(format!("{:?}", entity.kind)),
            None,
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("entity:{}", entity.id),
            SearchKind::Entity,
            entity_relations
                .get(&entity.id.to_string())
                .cloned()
                .unwrap_or_default(),
            entity.name.clone(),
            entity,
            None,
            None,
            Some(format!("{:?}", entity.kind)),
            None,
            settings.max_content_chars as usize,
        );
        documents.push(content_budget.apply(with_privileged(public, privileged?)));
    }
    for book in ordered_books {
        ensure_projection_active(shutdown)?;
        let public_view = BookView::build(book, ReadRedaction::Guest);
        let public = project_serializable(
            format!("book:{}", book.id),
            SearchKind::Book,
            book_relations
                .get(&book.id.to_string())
                .cloned()
                .unwrap_or_default(),
            book_label(book),
            &public_view,
            None,
            None,
            Some(format!("{:?}", book.state)),
            None,
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("book:{}", book.id),
            SearchKind::Book,
            privileged_book_relations
                .get(&book.id.to_string())
                .cloned()
                .unwrap_or_default(),
            privileged_book_label(book),
            book,
            None,
            None,
            Some(format!("{:?}", book.state)),
            None,
            settings.max_content_chars as usize,
        );
        documents.push(content_budget.apply(with_privileged(public, privileged?)));
    }
    for act in ordered_acts {
        ensure_projection_active(shutdown)?;
        let public_view = ActView::build(act, ReadRedaction::Guest);
        let public = project_serializable(
            format!("act:{}", act.id),
            SearchKind::Act,
            act_relations
                .get(&act.id.to_string())
                .cloned()
                .unwrap_or_default(),
            public_view.title.clone(),
            &public_view,
            None,
            None,
            Some(format!("{:?}", act.state)),
            act.meeting_date.map(|date| date.to_string()),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("act:{}", act.id),
            SearchKind::Act,
            privileged_act_relations
                .get(&act.id.to_string())
                .cloned()
                .unwrap_or_default(),
            act.title.clone(),
            act,
            None,
            None,
            Some(format!("{:?}", act.state)),
            act.meeting_date.map(|date| date.to_string()),
            settings.max_content_chars as usize,
        );
        documents.push(content_budget.apply(with_privileged(public, privileged?)));
    }
    for follow_up in ordered_follow_ups {
        ensure_projection_active(shutdown)?;
        let relation = act_relations
            .get(&follow_up.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| Relation {
                act_id: Some(follow_up.act_id.to_string()),
                ..Relation::default()
            });
        let privileged_relation = privileged_act_relations
            .get(&follow_up.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| relation.clone());
        let body = format!(
            "{}\n{}\n{}",
            REDACTED,
            follow_up.status.as_str(),
            follow_up
                .due_date
                .map(|date| date.to_string())
                .unwrap_or_default()
        );
        let public = project_text(
            format!("follow_up:{}", follow_up.id),
            SearchKind::FollowUp,
            relation,
            REDACTED.to_owned(),
            body.clone(),
            None,
            None,
            Some(follow_up.status.as_str().to_owned()),
            Some(
                follow_up
                    .due_date
                    .map(|date| date.to_string())
                    .unwrap_or_else(|| format_time(follow_up.created_at)),
            ),
            body.as_bytes(),
            settings.max_content_chars as usize,
        );
        let privileged_body = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            follow_up.title,
            follow_up.detail.as_deref().unwrap_or_default(),
            follow_up.assignee.as_deref().unwrap_or_default(),
            follow_up.assignee_display.as_deref().unwrap_or_default(),
            follow_up.status.as_str(),
            follow_up
                .due_date
                .map(|date| date.to_string())
                .unwrap_or_default(),
            follow_up.created_by
        );
        let privileged = project_text(
            format!("follow_up:{}", follow_up.id),
            SearchKind::FollowUp,
            privileged_relation,
            follow_up.title.clone(),
            privileged_body.clone(),
            Some(follow_up.created_by.clone()),
            None,
            Some(follow_up.status.as_str().to_owned()),
            Some(
                follow_up
                    .due_date
                    .map(|date| date.to_string())
                    .unwrap_or_else(|| format_time(follow_up.created_at)),
            ),
            privileged_body.as_bytes(),
            settings.max_content_chars as usize,
        );
        documents.push(content_budget.apply(with_privileged(public, privileged)));
    }

    if let Ok(registry) = chancela_templates::load_registry() {
        for template in registry.specs() {
            ensure_projection_active(shutdown)?;
            documents.push(content_budget.apply(project_serializable(
                format!("template:{}", template.id),
                SearchKind::Template,
                Relation::default(),
                template.id.clone(),
                template,
                None,
                template.law_references.first().map(|reference| {
                    format!(
                        "{} {}",
                        reference.source_label,
                        reference.article.as_deref().unwrap_or_default()
                    )
                }),
                Some(format!("{:?}", template.stage)),
                None,
                settings.max_content_chars as usize,
            )?));
        }
    }
    for (id, raw) in durable.user_templates {
        ensure_projection_active(shutdown)?;
        let value =
            serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| Value::String(raw.clone()));
        let title = value
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| value.get("title").and_then(Value::as_str))
            .unwrap_or(&id)
            .to_owned();
        let public_value = public_template_metadata(&value);
        let public = project_value(
            format!("template:user:{id}"),
            SearchKind::Template,
            Relation::default(),
            title.clone(),
            &public_value,
            None,
            None,
            Some("user_created".to_owned()),
            None,
            raw.as_bytes(),
            settings.max_content_chars as usize,
        );
        let privileged = project_value(
            format!("template:user:{id}"),
            SearchKind::Template,
            Relation::default(),
            title,
            &value,
            None,
            None,
            Some("user_created".to_owned()),
            None,
            raw.as_bytes(),
            settings.max_content_chars as usize,
        );
        documents.push(content_budget.apply(with_privileged(public, privileged)));
    }
    for library in ordered_libraries {
        ensure_projection_active(shutdown)?;
        let public_value = serde_json::json!({
            "id": library.id,
            "tenant_id": library.tenant_id,
            "name": library.name,
            "status": if library.is_archived() { "archived" } else { "active" },
            "updated_at": format_time(library.updated_at),
        });
        let relation = Relation {
            tenant_id: Some(library.tenant_id.to_string()),
            ..Relation::default()
        };
        let public = project_serializable(
            format!("template:library:{}", library.id),
            SearchKind::Template,
            relation.clone(),
            library.name.clone(),
            &public_value,
            None,
            None,
            Some(if library.is_archived() {
                "archived".to_owned()
            } else {
                "active".to_owned()
            }),
            Some(format_time(library.updated_at)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("template:library:{}", library.id),
            SearchKind::Template,
            relation,
            library.name.clone(),
            library,
            None,
            None,
            Some(if library.is_archived() {
                "archived".to_owned()
            } else {
                "active".to_owned()
            }),
            Some(format_time(library.updated_at)),
            settings.max_content_chars as usize,
        )?;
        documents.push(content_budget.apply(with_privileged(public, privileged)));
    }
    for revision in ordered_revisions {
        ensure_projection_active(shutdown)?;
        let library_name = template_libraries
            .get(&revision.library_id)
            .map(|library| library.name.as_str())
            .unwrap_or("Biblioteca de modelos");
        let public_value = serde_json::json!({
            "library_id": revision.library_id,
            "tenant_id": revision.tenant_id,
            "revision": revision.revision,
            "created_at": format_time(revision.created_at),
        });
        let relation = Relation {
            tenant_id: Some(revision.tenant_id.to_string()),
            ..Relation::default()
        };
        let title = format!("{library_name} — revisão {}", revision.revision);
        let public = project_serializable(
            format!(
                "template:library:{}:revision:{}",
                revision.library_id, revision.revision
            ),
            SearchKind::Template,
            relation.clone(),
            title.clone(),
            &public_value,
            None,
            None,
            Some("revision".to_owned()),
            Some(format_time(revision.created_at)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!(
                "template:library:{}:revision:{}",
                revision.library_id, revision.revision
            ),
            SearchKind::Template,
            relation,
            title,
            revision,
            Some(revision.created_by.clone()),
            None,
            Some("revision".to_owned()),
            Some(format_time(revision.created_at)),
            settings.max_content_chars as usize,
        )?;
        documents.push(content_budget.apply(with_privileged(public, privileged)));
    }

    for diploma in chancela_law::LawCatalog::embedded().diplomas() {
        for article in &diploma.articles {
            ensure_projection_active(shutdown)?;
            let body = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                diploma.title,
                diploma.reference,
                article.label,
                article.heading,
                article.display_body(),
                article.cross_refs.join(" ")
            );
            documents.push(content_budget.apply(project_text(
                format!("law:{}:{}", diploma.id, article.number),
                SearchKind::LawArticle,
                Relation::default(),
                format!("{} — {}", article.label, article.heading),
                body.clone(),
                None,
                Some(diploma.reference.clone()),
                Some(format!("{:?}", article.verification)),
                article.source.dr_date.clone(),
                body.as_bytes(),
                settings.max_content_chars as usize,
            )));
        }
    }

    let mut last_event_seq = None;
    for event in &events {
        ensure_projection_active(shutdown)?;
        last_event_seq = Some(last_event_seq.map_or(event.seq, |seq: u64| seq.max(event.seq)));
        let relation = relation_from_scope(
            &format!(
                "{} {}",
                event.scope,
                event
                    .links
                    .iter()
                    .map(|link| link.chain.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            &entity_relations,
            &book_relations,
            &act_relations,
        );
        let public = project_serializable(
            format!("ledger_event:{}", event.seq),
            SearchKind::LedgerEvent,
            relation.clone(),
            REDACTED.to_owned(),
            &serde_json::json!({
                "seq": event.seq,
                "timestamp": format_time(event.timestamp),
                "content": REDACTED,
            }),
            None,
            None,
            Some(REDACTED.to_owned()),
            Some(format_time(event.timestamp)),
            settings.max_content_chars as usize,
        )?;
        let privileged = project_serializable(
            format!("ledger_event:{}", event.seq),
            SearchKind::LedgerEvent,
            relation,
            event.kind.clone(),
            event,
            Some(event.actor.clone()),
            None,
            Some(event.kind.clone()),
            Some(format_time(event.timestamp)),
            settings.max_content_chars as usize,
        )?;
        documents.push(content_budget.apply(with_privileged(public, privileged)));
    }

    for actionable in actionables {
        ensure_projection_active(shutdown)?;
        let relation = actionable
            .act_id
            .as_deref()
            .and_then(|id| act_relations.get(id).cloned())
            .or_else(|| {
                actionable
                    .book_id
                    .as_deref()
                    .and_then(|id| book_relations.get(id).cloned())
            })
            .or_else(|| {
                actionable
                    .entity_id
                    .as_deref()
                    .and_then(|id| entity_relations.get(id).cloned())
            })
            .unwrap_or_default();
        let mut document = project_text(
            format!("operational_action:{}", actionable.id),
            SearchKind::OperationalAction,
            relation,
            actionable.title,
            actionable.body.clone(),
            None,
            None,
            Some(actionable.status),
            actionable.due_date,
            actionable.body.as_bytes(),
            settings.max_content_chars as usize,
        );
        document.required_permission = Some(actionable.required_permission.as_str().to_owned());
        documents.push(content_budget.apply(document));
    }

    let mut imported_review_history = durable.imported_review_history;
    for imported in durable.imported_documents {
        ensure_projection_active(shutdown)?;
        let relation = imported
            .act_id
            .and_then(|id| act_relations.get(&id.to_string()).cloned())
            .unwrap_or_else(|| Relation {
                act_id: imported.act_id.map(|id| id.to_string()),
                ..Relation::default()
            });
        let report = serde_json::from_str::<Value>(&imported.technical_validation_report_json)
            .unwrap_or_else(|_| Value::String(imported.technical_validation_report_json.clone()));
        let mut body = flatten_value_to_text(&report);
        for value in [
            imported.filename.as_deref(),
            imported.declared_content_type.as_deref(),
            Some(imported.detected_content_type.as_str()),
            imported.operator_review_note.as_deref(),
            imported.operator_reviewed_by.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            body.push('\n');
            body.push_str(value);
        }
        if let Some(history) = imported_review_history.remove(&imported.id) {
            for entry in history {
                body.push('\n');
                body.push_str(entry.review_status.as_str());
                if let Some(reviewed_at) = entry.reviewed_at {
                    body.push('\n');
                    body.push_str(&format_time(reviewed_at));
                }
                for value in [entry.reviewed_by.as_deref(), entry.review_note.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    body.push('\n');
                    body.push_str(value);
                }
                for guardrail_id in entry.acknowledged_guardrail_ids {
                    body.push('\n');
                    body.push_str(&guardrail_id);
                }
            }
        }
        let source = format!(
            "{}:{}:{}",
            imported.sha256,
            imported.operator_review_status.as_str(),
            body
        );
        documents.push(
            content_budget.apply(project_text(
                format!("imported_document:{}", imported.id),
                SearchKind::ImportedDocument,
                relation,
                imported
                    .filename
                    .clone()
                    .unwrap_or_else(|| format!("Documento importado {}", imported.id)),
                body,
                Some(imported.imported_by.clone()),
                None,
                Some(imported.operator_review_status.as_str().to_owned()),
                Some(format_time(imported.imported_at)),
                source.as_bytes(),
                settings.max_content_chars as usize,
            )),
        );
    }

    for (paper, drafts) in durable.paper_imports {
        ensure_projection_active(shutdown)?;
        let relation = relation_for_paper(&paper, &entity_relations, &book_relations);
        let body = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            paper.entity_name,
            paper.entity_nipc,
            paper.book_ref,
            paper.source_filename.as_deref().unwrap_or_default(),
            paper.notes.as_deref().unwrap_or_default(),
            paper.imported_by
        );
        documents.push(
            content_budget.apply(project_text(
                format!("paper_book:{}", paper.import_id),
                SearchKind::PaperBook,
                relation.clone(),
                paper
                    .source_filename
                    .clone()
                    .unwrap_or_else(|| format!("Livro em papel {}", paper.book_ref)),
                body.clone(),
                Some(paper.imported_by.clone()),
                None,
                Some(paper.ocr_status.as_str().to_owned()),
                Some(format_time(paper.imported_at)),
                format!("{}:{body}", paper.sha256).as_bytes(),
                settings.max_content_chars as usize,
            )),
        );
        for draft in drafts {
            ensure_projection_active(shutdown)?;
            let body = format!(
                "{}\n{}\n{}\n{}\n{}",
                draft.extracted_text.as_deref().unwrap_or_default(),
                draft.review_note.as_deref().unwrap_or_default(),
                draft.engine_name,
                draft.engine_version.as_deref().unwrap_or_default(),
                draft.reviewed_by.as_deref().unwrap_or_default()
            );
            documents.push(
                content_budget.apply(project_text(
                    format!("ocr_draft:{}", draft.draft_id),
                    SearchKind::OcrDraft,
                    relation.clone(),
                    format!("OCR {} — {}", paper.book_ref, draft.draft_id),
                    body.clone(),
                    Some(draft.created_by.clone()),
                    None,
                    Some(draft.review_status.as_str().to_owned()),
                    Some(format_time(draft.created_at)),
                    format!(
                        "{}:{}:{body}",
                        draft.text_digest.as_deref().unwrap_or_default(),
                        draft.review_status.as_str()
                    )
                    .as_bytes(),
                    settings.max_content_chars as usize,
                )),
            );
        }
    }

    for generated in durable.generated_documents {
        ensure_projection_active(shutdown)?;
        let relation = act_relations
            .get(&generated.act_id.to_string())
            .cloned()
            .unwrap_or_else(|| Relation {
                act_id: Some(generated.act_id.to_string()),
                ..Relation::default()
            });
        // Generated bytes/spec/layout can carry the same narrative or custom header/footer text as
        // the act. Search the non-content metadata only; the PDF is never loaded by this projection.
        let body = format!(
            "{}\n{}\n{}",
            generated.template_id, generated.profile, generated.pdf_digest
        );
        documents.push(content_budget.apply(project_text(
            format!("generated_document:{}", generated.id),
            SearchKind::GeneratedDocument,
            relation,
            format!("Documento {}", generated.id),
            body.clone(),
            None,
            None,
            Some(generated.profile),
            Some(format_time(generated.created_at)),
            body.as_bytes(),
            settings.max_content_chars as usize,
        )));
    }

    ensure_projection_active(shutdown)?;
    Ok(CorpusBuild {
        documents,
        last_event_seq,
        indexed_content_chars: content_budget.retained,
        content_budget_exhausted: content_budget.exhausted,
    })
}

async fn load_durable_rows(state: &AppState) -> Result<DurableCorpusRows, String> {
    let Some(store) = state.store.clone() else {
        return Ok(DurableCorpusRows::default());
    };
    store
        .read_blocking_async(|store| {
            let imported_documents = store.imported_documents(None)?;
            let mut imported_review_history =
                HashMap::<String, Vec<StoredImportedDocumentReviewHistoryEntry>>::new();
            for entry in store.imported_document_review_history_all()? {
                imported_review_history
                    .entry(entry.imported_document_id.clone())
                    .or_default()
                    .push(entry);
            }
            let mut drafts_by_import = HashMap::<String, Vec<StoredPaperBookOcrDraft>>::new();
            for draft in store.paper_book_ocr_drafts_all()? {
                drafts_by_import
                    .entry(draft.import_id.clone())
                    .or_default()
                    .push(draft);
            }
            let paper = store.paper_book_imports(None)?;
            let paper_imports = paper
                .into_iter()
                .map(|import| {
                    let drafts = drafts_by_import
                        .remove(&import.import_id)
                        .unwrap_or_default();
                    (import, drafts)
                })
                .collect();
            Ok::<_, StoreError>(DurableCorpusRows {
                imported_documents,
                imported_review_history,
                paper_imports,
                generated_documents: store.document_search_metadata()?,
                user_templates: store.user_templates()?,
            })
        })
        .await
        .map_err(|error| format!("search corpus read failed: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn project_serializable<T: Serialize>(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    source: &T,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    max_content_chars: usize,
) -> Result<SearchDocument, String> {
    let source_json =
        serde_json::to_vec(source).map_err(|error| format!("search projection failed: {error}"))?;
    let value = serde_json::from_slice::<Value>(&source_json)
        .map_err(|error| format!("search projection failed: {error}"))?;
    Ok(project_value(
        id,
        kind,
        relation,
        title,
        &value,
        author,
        law,
        status,
        occurred_at,
        &source_json,
        max_content_chars,
    ))
}

fn with_privileged(mut public: SearchDocument, privileged: SearchDocument) -> SearchDocument {
    // The privileged serialization is the full source revision, so changes to hidden fields still
    // invalidate the durable projection even when the public view itself is unchanged.
    public.source_version = privileged.source_version;
    public.privileged = Some(SearchDocumentContent {
        title: privileged.title,
        body: privileged.body,
        content_truncated: privileged.content_truncated,
        entity_name: privileged.entity_name,
        book_label: privileged.book_label,
        author: privileged.author,
        law: privileged.law,
        status: privileged.status,
    });
    public
}

#[allow(clippy::too_many_arguments)]
fn project_value(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    value: &Value,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    source: &[u8],
    max_content_chars: usize,
) -> SearchDocument {
    project_text(
        id,
        kind,
        relation,
        title,
        flatten_value_to_text(value),
        author,
        law,
        status,
        occurred_at,
        source,
        max_content_chars,
    )
}

#[allow(clippy::too_many_arguments)]
fn project_text(
    id: String,
    kind: SearchKind,
    relation: Relation,
    title: String,
    body: String,
    author: Option<String>,
    law: Option<String>,
    status: Option<String>,
    occurred_at: Option<String>,
    source: &[u8],
    max_content_chars: usize,
) -> SearchDocument {
    let (body, content_truncated) = cap_text(&body, max_content_chars);
    SearchDocument {
        id,
        kind,
        tenant_id: relation.tenant_id,
        entity_id: relation.entity_id,
        entity_name: relation.entity_name,
        book_id: relation.book_id,
        book_label: relation.book_label,
        act_id: relation.act_id,
        title,
        body,
        content_truncated,
        author,
        law,
        status,
        required_permission: None,
        occurred_at,
        source_version: digest_hex(source),
        privileged: None,
    }
}

fn cap_text(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let capped: String = chars.by_ref().take(max_chars).collect();
    let truncated = chars.next().is_some();
    (capped, truncated)
}

fn public_template_metadata(value: &Value) -> Value {
    let mut public = serde_json::Map::new();
    if let Value::Object(fields) = value {
        for key in ["id", "name", "title", "family", "stage", "locale"] {
            if let Some(value) = fields.get(key)
                && (value.is_string() || value.is_number() || value.is_boolean())
            {
                public.insert(key.to_owned(), value.clone());
            }
        }
    }
    Value::Object(public)
}

fn flatten_value_to_text(value: &Value) -> String {
    fn visit(value: &Value, key: Option<&str>, out: &mut Vec<String>) {
        if key.is_some_and(sensitive_projection_key) {
            return;
        }
        match value {
            Value::Null => {}
            Value::Bool(value) => out.push(value.to_string()),
            Value::Number(value) => out.push(value.to_string()),
            Value::String(value) => {
                if !value.trim().is_empty() {
                    out.push(value.clone());
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, None, out);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    out.push(key.replace('_', " "));
                    visit(value, Some(key), out);
                }
            }
        }
    }
    let mut out = Vec::new();
    visit(value, None, &mut out);
    out.join("\n")
}

fn sensitive_projection_key(key: &str) -> bool {
    let folded = key.to_ascii_lowercase();
    folded.contains("password")
        || folded.contains("secret")
        || folded.contains("token")
        || folded == "pdf_bytes"
        || folded == "bytes"
}

fn book_label(book: &Book) -> String {
    match book.book_number {
        Some(number) => format!("{:?} n.º {number}", book.kind),
        None => format!("{:?} {}", book.kind, book.id),
    }
}

fn privileged_book_label(book: &Book) -> String {
    book.kind_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| book_label(book))
}

fn relation_from_scope(
    scope: &str,
    entities: &HashMap<String, Relation>,
    books: &HashMap<String, Relation>,
    acts: &HashMap<String, Relation>,
) -> Relation {
    let mut resolved_entity = None;
    let mut resolved_book = None;
    let mut resolved_act = None;
    let mut resolved_tenant = None;
    for token in scope.split(|character: char| !(character.is_ascii_hexdigit() || character == '-'))
    {
        if Uuid::parse_str(token).is_err() {
            continue;
        }
        if let Some(relation) = acts.get(token) {
            resolved_act = Some(relation.clone());
            continue;
        }
        if let Some(relation) = books.get(token) {
            resolved_book = Some(relation.clone());
            continue;
        }
        if let Some(relation) = entities.get(token) {
            resolved_entity = Some(relation.clone());
            continue;
        }
        if scope.contains("tenant") {
            resolved_tenant = Some(Relation {
                tenant_id: Some(token.to_owned()),
                ..Relation::default()
            });
        }
    }
    resolved_act
        .or(resolved_book)
        .or(resolved_entity)
        .or(resolved_tenant)
        .unwrap_or_default()
}

fn relation_for_paper(
    paper: &StoredPaperBookImportMeta,
    entities: &HashMap<String, Relation>,
    books: &HashMap<String, Relation>,
) -> Relation {
    books
        .get(&paper.book_ref)
        .cloned()
        .or_else(|| entities.get(&paper.entity_ref).cloned())
        .unwrap_or_default()
}

fn digest_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn now_rfc3339() -> String {
    format_time(OffsetDateTime::now_utc())
}

fn operation_id(operation: &IndexOperation) -> &str {
    match operation {
        IndexOperation::Upsert(document) => &document.id,
        IndexOperation::Delete(id) => id,
    }
}

fn request_filters(request: &SearchRequest) -> Result<SearchFilters, ApiError> {
    if let Some(raw) = request.kind.as_deref() {
        ensure_char_limit("kind", raw, MAX_KIND_FILTER_CHARS)?;
        let count = raw
            .split(',')
            .filter(|value| !value.trim().is_empty())
            .count();
        if count > MAX_KIND_COUNT {
            return Err(ApiError::Unprocessable(format!(
                "kind aceita no máximo {MAX_KIND_COUNT} valores"
            )));
        }
    }
    let kinds = request
        .kind
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .filter(|value| !value.trim().is_empty())
                .map(|value| {
                    let value = value.trim();
                    ensure_char_limit("kind", value, MAX_KIND_TOKEN_CHARS)?;
                    parse_kind(value)
                })
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let tenant_id = normalized_uuid_filter("tenant_id", request.tenant_id.as_deref())?;
    let entity_id = normalized_uuid_filter("entity_id", request.entity_id.as_deref())?;
    let book_id = normalized_uuid_filter("book_id", request.book_id.as_deref())?;
    let act_id = normalized_uuid_filter("act_id", request.act_id.as_deref())?;
    for (name, value) in [
        ("author", request.author.as_deref()),
        ("law", request.law.as_deref()),
        ("status", request.status.as_deref()),
    ] {
        if let Some(value) = value {
            ensure_char_limit(name, value, MAX_FILTER_CHARS)?;
        }
    }
    for (name, value) in [
        ("date_from", request.date_from.as_deref()),
        ("date_to", request.date_to.as_deref()),
    ] {
        if let Some(value) = value {
            ensure_char_limit(name, value, MAX_DATE_FILTER_CHARS)?;
        }
    }
    let date_from = request
        .date_from
        .as_deref()
        .map(|value| normalize_date_bound(value, false))
        .transpose()?;
    let date_to = request
        .date_to
        .as_deref()
        .map(|value| normalize_date_bound(value, true))
        .transpose()?;
    if date_from
        .as_ref()
        .zip(date_to.as_ref())
        .is_some_and(|(from, to)| from > to)
    {
        return Err(ApiError::Unprocessable(
            "date_from deve ser anterior ou igual a date_to".to_owned(),
        ));
    }
    Ok(SearchFilters {
        kinds,
        tenant_id,
        entity_id,
        book_id,
        act_id,
        author: normalized_optional(request.author.as_deref()),
        law: normalized_optional(request.law.as_deref()),
        status: normalized_optional(request.status.as_deref()),
        date_from,
        date_to,
    })
}

fn ensure_char_limit(name: &str, value: &str, max_chars: usize) -> Result<(), ApiError> {
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{name} excede o limite de {max_chars} caracteres"
        )));
    }
    Ok(())
}

fn validate_query_terms(value: &str, min_chars: u8) -> Result<(), ApiError> {
    if value.is_empty() {
        return Ok(());
    }
    let min_chars = usize::from(min_chars);
    if chancela_search::normalize(value)
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .any(|term| term.chars().count() < min_chars)
    {
        return Err(ApiError::Unprocessable(format!(
            "cada termo de pesquisa requer pelo menos {min_chars} caracteres"
        )));
    }
    Ok(())
}

fn normalized_uuid_filter(name: &str, value: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    ensure_char_limit(name, value, MAX_UUID_FILTER_CHARS)?;
    let parsed = Uuid::parse_str(value)
        .map_err(|_| ApiError::Unprocessable(format!("{name} não é um UUID válido")))?;
    Ok(Some(parsed.to_string()))
}

fn normalize_date_bound(value: &str, inclusive_end: bool) -> Result<String, ApiError> {
    let value = value.trim();
    if value.len() == 10 {
        time::Date::parse(
            value,
            time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map_err(|_| ApiError::Unprocessable("data de pesquisa inválida".to_owned()))?;
        return Ok(if inclusive_end {
            format!("{value}T23:59:59.999999999Z")
        } else {
            value.to_owned()
        });
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ApiError::Unprocessable("data de pesquisa inválida".to_owned()))?;
    Ok(format_time(parsed))
}

fn normalized_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_kind(value: &str) -> Result<SearchKind, ApiError> {
    match value {
        "act" => Ok(SearchKind::Act),
        "entity" => Ok(SearchKind::Entity),
        "book" => Ok(SearchKind::Book),
        "template" => Ok(SearchKind::Template),
        "law_article" => Ok(SearchKind::LawArticle),
        "operational_action" => Ok(SearchKind::OperationalAction),
        "ledger_event" => Ok(SearchKind::LedgerEvent),
        "follow_up" => Ok(SearchKind::FollowUp),
        "imported_document" => Ok(SearchKind::ImportedDocument),
        "paper_book" => Ok(SearchKind::PaperBook),
        "ocr_draft" => Ok(SearchKind::OcrDraft),
        "generated_document" => Ok(SearchKind::GeneratedDocument),
        other => Err(ApiError::Unprocessable(format!(
            "tipo de pesquisa desconhecido: {other}"
        ))),
    }
}

fn query_fingerprint(
    text: &str,
    filters: &SearchFilters,
    limit: usize,
    cursor_context: &str,
) -> String {
    let kinds = filters
        .kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    let canonical = serde_json::to_vec(&serde_json::json!({
        "text": chancela_search::normalize(text),
        "kinds": kinds,
        "tenant_id": filters.tenant_id.as_deref(),
        "entity_id": filters.entity_id.as_deref(),
        "book_id": filters.book_id.as_deref(),
        "act_id": filters.act_id.as_deref(),
        "author": filters.author.as_deref(),
        "law": filters.law.as_deref(),
        "status": filters.status.as_deref(),
        "date_from": filters.date_from.as_deref(),
        "date_to": filters.date_to.as_deref(),
        "limit": limit,
        "context": cursor_context,
    }))
    .expect("search cursor fingerprint JSON is infallible");
    digest_hex(&canonical)
}

fn search_cursor_subject(actor: &CurrentActor) -> String {
    if let Some(user_id) = actor.session_user_id() {
        return format!("session:{user_id}");
    }
    if let Some(principal) = actor.api_key_principal() {
        return format!("apikey:{:?}:{}", principal.kind, principal.actor_label);
    }
    format!("actor:{}", actor.resolve("search"))
}

fn search_cursor_context(
    index: &SearchIndexState,
    actor: &CurrentActor,
    authority: &str,
) -> String {
    format!(
        "{}|{}|{}|{}",
        index.generation,
        index.updated_at,
        search_cursor_subject(actor),
        authority
    )
}

fn bounded_next_cursor(
    page: &mut SearchPage,
    fingerprint: &str,
) -> Result<(Option<String>, bool), ApiError> {
    let next_offset = page.offset.checked_add(page.hits.len());
    let truncated = page.has_more
        && next_offset.is_none_or(|next| {
            next.checked_add(page.limit)
                .is_none_or(|window_end| window_end > MAX_CURSOR_OFFSET)
        });
    if truncated {
        page.has_more = false;
        return Ok((None, true));
    }
    let cursor = if page.has_more {
        next_offset
            .map(|offset| encode_cursor(offset, fingerprint))
            .transpose()?
    } else {
        None
    };
    Ok((cursor, false))
}

fn ensure_result_window(offset: usize, limit: usize) -> Result<(), ApiError> {
    if offset
        .checked_add(limit)
        .is_none_or(|window_end| window_end > MAX_CURSOR_OFFSET)
    {
        return Err(ApiError::Unprocessable(
            "cursor de pesquisa excede a janela de resultados permitida".to_owned(),
        ));
    }
    Ok(())
}

fn encode_cursor(offset: usize, fingerprint: &str) -> Result<String, ApiError> {
    let payload = serde_json::to_vec(&SearchCursor {
        offset,
        fingerprint: fingerprint.to_owned(),
    })
    .map_err(|error| ApiError::Internal(format!("falha ao codificar cursor: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(payload))
}

fn decode_cursor(cursor: &str, fingerprint: &str) -> Result<usize, ApiError> {
    if cursor.len() > MAX_CURSOR_BYTES {
        return Err(ApiError::Unprocessable(
            "cursor de pesquisa demasiado grande".to_owned(),
        ));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| ApiError::Unprocessable("cursor de pesquisa inválido".to_owned()))?;
    if payload.len() > MAX_CURSOR_BYTES {
        return Err(ApiError::Unprocessable(
            "cursor de pesquisa demasiado grande".to_owned(),
        ));
    }
    let decoded: SearchCursor = serde_json::from_slice(&payload)
        .map_err(|_| ApiError::Unprocessable("cursor de pesquisa inválido".to_owned()))?;
    if decoded.fingerprint != fingerprint {
        return Err(ApiError::Unprocessable(
            "o cursor não pertence a esta pesquisa".to_owned(),
        ));
    }
    if decoded.offset > MAX_CURSOR_OFFSET {
        return Err(ApiError::Unprocessable(
            "cursor de pesquisa excede a profundidade permitida".to_owned(),
        ));
    }
    Ok(decoded.offset)
}

fn document_allowed(authz: &Authorizer, document: &SearchDocument) -> bool {
    let scope = document_scope(document);
    if !authz.permits(Permission::SearchRead, scope) {
        return false;
    }
    let domain_permission = match document.kind {
        SearchKind::Entity => Permission::EntityRead,
        SearchKind::Book => Permission::BookRead,
        SearchKind::PaperBook | SearchKind::OcrDraft => Permission::BookImport,
        SearchKind::Act
        | SearchKind::FollowUp
        | SearchKind::GeneratedDocument
        | SearchKind::Template => Permission::ActRead,
        SearchKind::ImportedDocument => Permission::ActDraft,
        SearchKind::LawArticle => Permission::LawRead,
        SearchKind::OperationalAction => {
            let Some(permission) = document
                .required_permission
                .as_deref()
                .and_then(action_permission)
            else {
                return false;
            };
            permission
        }
        SearchKind::LedgerEvent => Permission::LedgerRead,
    };
    authz.permits(domain_permission, scope)
}

fn visible_search_access(
    guest: bool,
    domain_allowed: bool,
    document: &SearchDocument,
) -> Option<SearchAccess> {
    if !domain_allowed || (guest && document.kind == SearchKind::LedgerEvent) {
        return None;
    }
    Some(if guest {
        SearchAccess::Public
    } else {
        SearchAccess::Privileged
    })
}

fn action_permission(value: &str) -> Option<Permission> {
    match value {
        "act.read" => Some(Permission::ActRead),
        "book.read" => Some(Permission::BookRead),
        "entity.read" => Some(Permission::EntityRead),
        "ledger.read" => Some(Permission::LedgerRead),
        "data.backup" => Some(Permission::DataBackup),
        "privacy.manage" => Some(Permission::PrivacyManage),
        _ => None,
    }
}

fn document_scope(document: &SearchDocument) -> Scope {
    if let Some(id) = document
        .act_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        return Scope::Act(AuthzActId(id));
    }
    if let Some(id) = document
        .book_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        return Scope::Book(AuthzBookId(id));
    }
    if let Some(id) = document
        .entity_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        return Scope::Entity(AuthzEntityId(id));
    }
    if let Some(id) = document
        .tenant_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        return Scope::Tenant(AuthzTenantId(id));
    }
    Scope::Global
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_lock<T>(lock: &SyncRwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &SyncRwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDataDir(std::path::PathBuf);

    impl TestDataDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("chancela-search-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("create search temp dir");
            Self(path)
        }
    }

    impl Drop for TestDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn install_active(
        state: &AppState,
        documents: impl IntoIterator<Item = SearchDocument>,
        status: SearchIndexState,
    ) {
        *write_lock(&state.search_index.inner.active) = Arc::new(
            ActiveSearchSnapshot::from_documents(documents, status.clone()),
        );
        *write_lock(&state.search_index.inner.status) = status;
    }

    async fn actor_with_role(
        state: &AppState,
        username: &str,
        role_id: chancela_authz::RoleId,
        scope: Scope,
    ) -> CurrentActor {
        use chancela_authz::{RoleAssignment, RoleCatalog};
        use time::format_description::well_known::Rfc3339;

        {
            let mut roles = state.roles.write().await;
            if roles.is_empty() {
                *roles = RoleCatalog::seeded_defaults();
            }
        }
        let id = crate::users::UserId(Uuid::new_v4());
        state.users.write().await.insert(
            id,
            crate::users::User {
                id,
                username: username.to_owned(),
                display_name: username.to_owned(),
                email: None,
                created_at: OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .unwrap_or_default(),
                active: true,
                password_hash: None,
                attestation_key: None,
                retired_attestation_keys: Vec::new(),
                totp: None,
                two_factor_required: false,
                force_password_change: false,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: vec![RoleAssignment::new(role_id, scope)],
                language: Default::default(),
            },
        );
        CurrentActor::from_session_username(Some(username.to_owned()))
    }

    async fn session_token_with_role(
        state: &AppState,
        username: &str,
        role_id: chancela_authz::RoleId,
        scope: Scope,
    ) -> String {
        let _ = actor_with_role(state, username, role_id, scope).await;
        let user_id = state
            .users
            .read()
            .await
            .values()
            .find(|user| user.username == username)
            .expect("seeded search actor")
            .id;
        let token = Uuid::new_v4().to_string();
        state.sessions.write().await.insert(
            token.clone(),
            crate::session::SessionEntry {
                user_id,
                unlocked_key: None,
                expires_at: OffsetDateTime::now_utc()
                    + time::Duration::seconds(crate::actor::SESSION_TTL_SECS),
            },
        );
        token
    }

    fn completed_status(generation: u64) -> SearchIndexState {
        SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        }
    }

    #[test]
    fn cap_text_marks_only_content_beyond_the_exact_character_limit() {
        assert_eq!(cap_text("áβc", 3), ("áβc".to_owned(), false));
        assert_eq!(cap_text("áβcd", 3), ("áβc".to_owned(), true));
    }

    #[test]
    fn global_content_budget_caps_all_retained_bodies() {
        let mut budget = CorpusContentBudget::new(5);
        let first = budget.apply(project_text(
            "first".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "first".to_owned(),
            "abcd".to_owned(),
            None,
            None,
            None,
            None,
            b"first",
            100,
        ));
        let second = budget.apply(project_text(
            "second".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "second".to_owned(),
            "wxyz".to_owned(),
            None,
            None,
            None,
            None,
            b"second",
            100,
        ));
        assert_eq!(first.body, "abcd");
        assert_eq!(second.body, "w");
        assert!(second.content_truncated);
        assert_eq!(budget.retained, 5);
        assert!(budget.exhausted);
    }

    #[test]
    fn query_terms_filters_and_cursor_context_are_strictly_bounded_and_unambiguous() {
        assert!(validate_query_terms("ab x", 2).is_err());
        assert!(validate_query_terms("ab xy", 2).is_ok());
        assert!(ensure_char_limit("q", &"x".repeat(MAX_QUERY_CHARS + 1), MAX_QUERY_CHARS).is_err());

        let too_many_kinds = SearchRequest {
            kind: Some(
                std::iter::repeat_n("act", MAX_KIND_COUNT + 1)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ..SearchRequest::default()
        };
        assert!(request_filters(&too_many_kinds).is_err());

        let left = SearchFilters {
            author: Some("a|b".to_owned()),
            law: Some("c".to_owned()),
            ..SearchFilters::default()
        };
        let right = SearchFilters {
            author: Some("a".to_owned()),
            law: Some("b|c".to_owned()),
            ..SearchFilters::default()
        };
        assert_ne!(
            query_fingerprint("ata", &left, 25, "generation-a"),
            query_fingerprint("ata", &right, 25, "generation-a")
        );
        assert_ne!(
            query_fingerprint("ata", &left, 25, "generation-a"),
            query_fingerprint("ata", &left, 25, "generation-b")
        );
    }

    #[test]
    fn read_only_status_omits_global_progress_errors_queue_and_topology() {
        let service = SearchService::default();
        {
            let mut status = write_lock(&service.inner.status);
            status.last_error = Some("private topology error".to_owned());
            status.error_at = Some("2026-07-26T10:00:00Z".to_owned());
        }
        *write_lock(&service.inner.worker_thread) = Some("private-worker".to_owned());
        let settings = crate::settings::SearchSettings::default();
        let public = serde_json::to_value(service.status_response(&settings, false)).unwrap();
        assert_eq!(public["details_redacted"], true);
        for field in [
            "content_truncated",
            "generation",
            "document_count",
            "truncated_document_count",
            "indexed_content_chars",
            "content_budget_chars",
            "content_budget_exhausted",
            "processed",
            "total",
            "last_event_seq",
            "last_started_at",
            "last_completed_at",
            "last_error",
            "error_at",
            "updated_at",
            "queue_depth",
            "queue_capacity",
            "dropped_commands",
            "projection_writer",
            "worker_thread",
        ] {
            assert!(public.get(field).is_none(), "{field} must be omitted");
        }
        let managed = serde_json::to_value(service.status_response(&settings, true)).unwrap();
        assert_eq!(managed["last_error"], "private topology error");
        assert!(managed.get("generation").is_some());
        assert!(managed.get("document_count").is_some());
        assert!(managed.get("queue_capacity").is_some());
    }

    #[tokio::test]
    async fn guest_cannot_match_private_projection_while_owner_can_search_full_act_text() {
        let state = AppState::default();
        let entity = chancela_core::Entity::new(
            "Sociedade Pública",
            chancela_core::Nipc::unvalidated("unique-nipc-private-771"),
            "unique-seat-private-772",
            chancela_core::EntityKind::SociedadePorQuotas,
        );
        let mut book =
            chancela_core::Book::new(entity.id, chancela_core::BookKind::AssembleiaGeral);
        book.kind_label = Some("unique-book-label-private-773".to_owned());
        let mut act = chancela_core::Act::draft(
            book.id,
            "unique-act-title-private-774",
            chancela_core::MeetingChannel::Physical,
        );
        act.deliberations = "unique-deliberation-private-775".to_owned();
        state.entities.write().await.insert(entity.id, entity);
        state.books.write().await.insert(book.id, book);
        state.acts.write().await.insert(act.id, act);

        let shutdown = AtomicBool::new(false);
        let corpus = build_corpus(
            &state,
            &crate::settings::SearchSettings::default(),
            &shutdown,
        )
        .await
        .unwrap();
        let mut index = InMemoryIndex::default();
        index.replace(corpus.documents);
        let query = SearchQuery {
            text: "unique-deliberation-private-775".to_owned(),
            ..SearchQuery::default()
        };
        let guest = index.search_with_access(&query, |_| Some(SearchAccess::Public));
        assert_eq!(guest.total, 0);
        let guest_wire = serde_json::to_string(&guest).unwrap();
        for forbidden in [
            "unique-nipc-private-771",
            "unique-seat-private-772",
            "unique-book-label-private-773",
            "unique-act-title-private-774",
            "unique-deliberation-private-775",
        ] {
            assert!(
                !guest_wire.contains(forbidden),
                "guest search response leaked {forbidden}"
            );
        }

        let owner = index.search_with_access(&query, |_| Some(SearchAccess::Privileged));
        assert_eq!(owner.total, 1);
        assert_eq!(owner.hits[0].title, "unique-act-title-private-774");
        assert!(
            owner.hits[0]
                .snippet
                .contains("unique-deliberation-private-775")
        );
        assert!(
            owner
                .facets
                .book
                .values()
                .any(|facet| facet.label == "unique-book-label-private-773")
        );
    }

    #[test]
    fn inclusive_date_to_covers_the_whole_iso_day() {
        assert_eq!(
            normalize_date_bound("2026-07-26", true).unwrap(),
            "2026-07-26T23:59:59.999999999Z"
        );
        assert_eq!(
            normalize_date_bound("2026-07-26", false).unwrap(),
            "2026-07-26"
        );
    }

    #[test]
    fn cursors_are_bound_to_query_and_depth() {
        let cursor = encode_cursor(25, "fingerprint").unwrap();
        assert_eq!(decode_cursor(&cursor, "fingerprint").unwrap(), 25);
        assert!(ensure_result_window(25, 25).is_ok());
        assert!(decode_cursor(&cursor, "another").is_err());
        let too_deep = encode_cursor(MAX_CURSOR_OFFSET + 1, "fingerprint").unwrap();
        assert!(decode_cursor(&too_deep, "fingerprint").is_err());
        let forged_edge = encode_cursor(MAX_CURSOR_OFFSET, "fingerprint").unwrap();
        let offset = decode_cursor(&forged_edge, "fingerprint").unwrap();
        assert!(
            ensure_result_window(offset, 1).is_err(),
            "an otherwise well-formed cursor cannot push work beyond the bounded result window"
        );
    }

    #[test]
    fn unrelated_ledger_writes_do_not_invalidate_an_immutable_generation_cursor() {
        let index = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 7,
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            ..SearchIndexState::default()
        };
        let actor = CurrentActor::default();
        let authority = "search.read@global|act.read@global";
        let before = search_cursor_context(&index, &actor, authority);
        let fingerprint = query_fingerprint("assembleia", &SearchFilters::default(), 25, &before);
        let cursor = encode_cursor(25, &fingerprint).unwrap();

        let mut unrelated_ledger = chancela_ledger::Ledger::default();
        unrelated_ledger.append(
            "other-user",
            "settings",
            "settings.updated",
            None,
            b"unrelated",
        );

        let after = search_cursor_context(&index, &actor, authority);
        assert_eq!(before, after);
        assert_eq!(decode_cursor(&cursor, &fingerprint).unwrap(), 25);

        let changed_authority = search_cursor_context(&index, &actor, "search.read@global");
        let changed_fingerprint = query_fingerprint(
            "assembleia",
            &SearchFilters::default(),
            25,
            &changed_authority,
        );
        assert!(
            decode_cursor(&cursor, &changed_fingerprint).is_err(),
            "an effective-authority change remains fail closed"
        );
    }

    #[test]
    fn result_window_truncation_is_explicit_and_has_more_stays_consistent() {
        let hit = chancela_search::SearchHit {
            id: "act:window-edge".to_owned(),
            kind: SearchKind::Act,
            title: "edge".to_owned(),
            snippet: String::new(),
            content_truncated: false,
            score: 1,
            tenant_id: None,
            entity_id: None,
            entity_name: None,
            book_id: None,
            book_label: None,
            act_id: None,
            author: None,
            law: None,
            status: None,
            occurred_at: None,
        };
        let mut page = SearchPage {
            total: MAX_CURSOR_OFFSET + 50,
            offset: MAX_CURSOR_OFFSET,
            limit: 25,
            has_more: true,
            hits: vec![hit],
            facets: chancela_search::SearchFacets::default(),
            facets_truncated: false,
        };

        let (next, truncated) = bounded_next_cursor(&mut page, "fingerprint").unwrap();
        assert!(truncated);
        assert!(next.is_none());
        assert!(!page.has_more);
    }

    #[test]
    fn retained_ledger_snapshot_filters_bounded_chunks_with_nonmonotonic_timestamps() {
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(30);
        let mut ledger = chancela_ledger::Ledger::default();
        for index in 0..10_000 {
            ledger.append(
                "actor",
                "settings",
                &format!("event.{index}"),
                None,
                b"payload",
            );
        }
        let mut events = ledger.events().to_vec();
        for event in &mut events[..9_990] {
            event.timestamp = cutoff - time::Duration::days(1);
        }
        for event in &mut events[9_990..] {
            event.timestamp = cutoff + time::Duration::seconds(1);
        }
        // Restored/imported ledger timestamps need not be monotonic in global sequence order.
        events[2].timestamp = cutoff + time::Duration::seconds(2);
        events[4_000].timestamp = cutoff + time::Duration::seconds(3);
        events[9_995].timestamp = cutoff - time::Duration::seconds(1);
        let (ledger, _) = chancela_ledger::Ledger::try_from_events(events);

        let retained = (0..ledger.len())
            .step_by(SOURCE_SNAPSHOT_BATCH_SIZE)
            .flat_map(|start| {
                retained_ledger_event_chunk(&ledger, start, SOURCE_SNAPSHOT_BATCH_SIZE, cutoff)
            })
            .collect::<Vec<_>>();

        assert_eq!(retained.len(), 11);
        assert_eq!(
            retained.iter().map(|event| event.seq).collect::<Vec<_>>(),
            vec![
                2, 4_000, 9_990, 9_991, 9_992, 9_993, 9_994, 9_996, 9_997, 9_998, 9_999
            ]
        );
    }

    #[test]
    fn guest_search_cannot_match_or_facet_full_ledger_event_content() {
        let secret = "private-ledger-sentinel-8831";
        let public = project_text(
            "ledger_event:42".to_owned(),
            SearchKind::LedgerEvent,
            Relation::default(),
            REDACTED.to_owned(),
            REDACTED.to_owned(),
            None,
            None,
            Some(REDACTED.to_owned()),
            Some("2026-07-26T10:00:00Z".to_owned()),
            b"public",
            1_000,
        );
        let privileged = project_text(
            "ledger_event:42".to_owned(),
            SearchKind::LedgerEvent,
            Relation::default(),
            secret.to_owned(),
            secret.to_owned(),
            Some(secret.to_owned()),
            None,
            Some(secret.to_owned()),
            Some("2026-07-26T10:00:00Z".to_owned()),
            secret.as_bytes(),
            1_000,
        );
        let mut index = InMemoryIndex::default();
        index.upsert(with_privileged(public, privileged));
        let query = SearchQuery {
            text: secret.to_owned(),
            ..SearchQuery::default()
        };

        let guest = index.search_with_access(&query, |document| {
            visible_search_access(true, true, document)
        });
        assert_eq!(guest.total, 0);
        assert!(!serde_json::to_string(&guest).unwrap().contains(secret));

        let privileged = index.search_with_access(&query, |document| {
            visible_search_access(false, true, document)
        });
        assert_eq!(privileged.total, 1);
        assert!(privileged.hits[0].snippet.contains(secret));
        assert_eq!(privileged.facets.status.get(secret), Some(&1));
    }

    #[test]
    fn command_queue_is_bounded_and_reports_backpressure() {
        let service = SearchService::default();
        service.enqueue(SearchCommand::Pause, 1).unwrap();

        let error = service.enqueue(SearchCommand::Resume, 1).unwrap_err();

        assert!(matches!(error, ApiError::Unavailable(_)));
        assert_eq!(lock_mutex(&service.inner.queue).len(), 1);
        assert_eq!(service.inner.dropped_commands.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn query_admission_is_bounded_and_reports_backpressure() {
        let service = SearchService::default();
        let permits = (0..SEARCH_QUERY_MAX_CONCURRENCY)
            .map(|_| service.try_query_slot().unwrap())
            .collect::<Vec<_>>();

        assert!(matches!(
            service.try_query_slot(),
            Err(ApiError::Unavailable(_))
        ));

        drop(permits);
        assert!(service.try_query_slot().is_ok());
    }

    #[test]
    fn mutation_bursts_coalesce_and_explicit_rebuild_supersedes_reconcile() {
        let service = SearchService::default();
        for _ in 0..10_000 {
            service.enqueue(SearchCommand::Reconcile, 4).unwrap();
        }
        assert_eq!(lock_mutex(&service.inner.queue).len(), 1);
        assert_eq!(service.inner.wake_epoch.load(Ordering::Acquire), 10_000);

        service.enqueue(SearchCommand::Rebuild, 4).unwrap();
        let queue = lock_mutex(&service.inner.queue);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.front(), Some(&SearchCommand::Rebuild));
    }

    #[test]
    fn only_a_dirty_during_build_follow_up_uses_the_configured_cadence() {
        assert_eq!(
            reconcile_burst_delay(Some(SearchCommand::Reconcile), false, 30),
            None,
            "the first idle mutation remains immediate"
        );
        assert_eq!(
            reconcile_burst_delay(Some(SearchCommand::Reconcile), true, 30),
            Some(StdDuration::from_secs(30)),
            "sustained dirty epochs are limited to one full walk per interval"
        );
        assert_eq!(
            reconcile_burst_delay(Some(SearchCommand::Rebuild), true, 30),
            None,
            "an audited explicit rebuild is not hidden behind mutation cadence"
        );
    }

    #[tokio::test]
    async fn debounce_has_a_hard_maximum_under_continuous_mutations() {
        let service = SearchService::default();
        let producer = service.clone();
        let updates = tokio::spawn(async move {
            for _ in 0..100 {
                producer.inner.wake_epoch.fetch_add(1, Ordering::AcqRel);
                tokio::time::sleep(StdDuration::from_millis(20)).await;
            }
        });
        let started = tokio::time::Instant::now();
        let _ = service.settle_source_mutations().await;
        let elapsed = started.elapsed();
        updates.abort();
        assert!(
            elapsed <= StdDuration::from_millis(SOURCE_SETTLE_MAX_MILLIS + 150),
            "continuous writes exceeded the bounded debounce: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn in_flight_begin_edge_supersedes_before_the_wake_epoch_increment() {
        let state = AppState::default();
        let service = state.search_index.clone();
        let expected_epoch = service.inner.wake_epoch.load(Ordering::Acquire);

        // Deterministically pause at the exact historical race: begin_source_mutation has published
        // its in-flight edge, but enqueue has not advanced wake_epoch yet.
        service
            .inner
            .source_mutations_in_flight
            .fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            service.inner.wake_epoch.load(Ordering::Acquire),
            expected_epoch
        );
        assert!(!service.source_epoch_is_current(expected_epoch));

        let status = completed_status(7);
        assert_eq!(
            service
                .persist_batch(&state, Vec::new(), &status, 0, Some(expected_epoch),)
                .await
                .unwrap_err(),
            SEARCH_PROJECTION_SUPERSEDED
        );
        assert_eq!(
            service
                .publish_completed_projection(
                    &state,
                    Arc::new(InMemoryIndex::default()),
                    &status,
                    0,
                    Some(expected_epoch),
                )
                .await
                .unwrap_err(),
            SEARCH_PROJECTION_SUPERSEDED
        );
        service
            .inner
            .source_mutations_in_flight
            .fetch_sub(1, Ordering::AcqRel);
    }

    #[tokio::test]
    async fn settle_never_snapshots_while_a_source_mutation_guard_is_live() {
        let state = AppState::default();
        let guard = begin_source_mutation(&state).await;
        let service = state.search_index.clone();
        let settling = tokio::spawn(async move { service.settle_source_mutations().await });

        tokio::time::sleep(StdDuration::from_millis(SOURCE_SETTLE_MAX_MILLIS + 100)).await;
        assert!(
            !settling.is_finished(),
            "the hard debounce bound must not override a live source-mutation fence"
        );

        drop(guard);
        tokio::time::timeout(StdDuration::from_secs(2), settling)
            .await
            .expect("settle completes after the publication edge")
            .expect("settle task succeeds");
    }

    #[tokio::test]
    async fn corpus_build_observes_shutdown_cancellation() {
        let state = AppState::default();
        let shutdown = AtomicBool::new(true);
        let error = build_corpus(
            &state,
            &crate::settings::SearchSettings::default(),
            &shutdown,
        )
        .await
        .unwrap_err();
        assert!(error.contains("cancelled for shutdown"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_snapshot_releases_request_facing_lock_between_clone_chunks() {
        #[derive(Debug)]
        struct SlowClone(Arc<std::sync::atomic::AtomicUsize>);
        impl Clone for SlowClone {
            fn clone(&self) -> Self {
                self.0.fetch_add(1, Ordering::AcqRel);
                std::thread::sleep(StdDuration::from_millis(1));
                Self(self.0.clone())
            }
        }

        let clones = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let source = Arc::new(tokio::sync::RwLock::new(
            (0..600)
                .map(|id| (id, SlowClone(clones.clone())))
                .collect::<HashMap<_, _>>(),
        ));
        let shutdown = Arc::new(AtomicBool::new(false));
        let snapshot_source = source.clone();
        let snapshot_shutdown = shutdown.clone();
        let snapshot = tokio::spawn(async move {
            snapshot_map_bounded(&snapshot_source, &snapshot_shutdown).await
        });
        while clones.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }

        let writer_guard = tokio::time::timeout(StdDuration::from_millis(450), source.write())
            .await
            .expect("writer acquires between bounded clone chunks");
        assert!(
            clones.load(Ordering::Acquire) < 600,
            "the request-facing lock was not retained for the whole deep snapshot"
        );
        drop(writer_guard);
        assert_eq!(snapshot.await.unwrap().unwrap().len(), 600);
    }

    #[test]
    fn canonical_scope_prefers_the_most_specific_act_relation() {
        let entity_id = Uuid::new_v4().to_string();
        let book_id = Uuid::new_v4().to_string();
        let act_id = Uuid::new_v4().to_string();
        let entity = Relation {
            entity_id: Some(entity_id.clone()),
            ..Relation::default()
        };
        let book = Relation {
            entity_id: Some(entity_id.clone()),
            book_id: Some(book_id.clone()),
            ..Relation::default()
        };
        let act = Relation {
            entity_id: Some(entity_id.clone()),
            book_id: Some(book_id.clone()),
            act_id: Some(act_id.clone()),
            ..Relation::default()
        };
        let resolved = relation_from_scope(
            &format!("entity:{entity_id}/book:{book_id}/act:{act_id}"),
            &[(entity_id, entity)].into_iter().collect(),
            &[(book_id, book)].into_iter().collect(),
            &[(act_id.clone(), act)].into_iter().collect(),
        );
        assert_eq!(resolved.act_id.as_deref(), Some(act_id.as_str()));
    }

    #[tokio::test]
    async fn committed_source_mutation_schedules_reconciliation_immediately() {
        let state = AppState::default();
        let mut ledger = state.ledger.write().await;
        ledger.append("tester", "settings", "test.mutated", None, b"changed");
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await
            .unwrap();
        drop(ledger);
        assert!(
            lock_mutex(&state.search_index.inner.queue)
                .iter()
                .any(|command| matches!(command, SearchCommand::Reconcile))
        );
    }

    #[test]
    fn postgres_follower_gate_never_owns_projection_writes() {
        assert!(!projection_writer_from_gate(Err(StoreError::NotLeader)).unwrap());
        assert!(projection_writer_from_gate(Ok(())).unwrap());
    }

    #[test]
    fn followers_only_hydrate_stable_completed_generations() {
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 4,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            ..SearchIndexState::default()
        };
        assert!(is_completed_snapshot(Some(&completed)));

        let mut partial = completed.clone();
        partial.phase = SearchIndexPhase::Reconciling;
        assert!(!is_completed_snapshot(Some(&partial)));

        let mut never_completed = completed.clone();
        never_completed.generation = 0;
        never_completed.last_completed_at = None;
        assert!(!is_completed_snapshot(Some(&never_completed)));

        let changed_generation = SearchIndexState {
            generation: 5,
            ..completed.clone()
        };
        assert!(!completed_snapshot_unchanged(
            Some(&completed),
            Some(&changed_generation)
        ));
        let mut fenced = completed.clone();
        fenced.phase = SearchIndexPhase::Starting;
        fenced.projection_fenced = true;
        assert!(!durable_confirms_local_snapshot(&completed, Some(&fenced)));
        let mut in_progress = completed.clone();
        in_progress.phase = SearchIndexPhase::Reconciling;
        assert!(durable_confirms_local_snapshot(
            &completed,
            Some(&in_progress)
        ));
    }

    #[test]
    fn final_query_confirmation_rejects_a_hydrated_generation_change() {
        let before = completed_status(4);
        let mut hydrated = before.clone();
        hydrated.generation = 5;
        hydrated.updated_at = "2026-07-26T10:00:01Z".to_owned();

        assert!(!same_search_generation(&before, &hydrated));
        assert!(same_search_generation(&hydrated, &hydrated));
    }

    #[tokio::test]
    async fn writer_initialization_hydrates_a_healthy_completed_projection_without_clearing_it() {
        let dir = TestDataDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let store = state.store.clone().expect("durable store");
        let document = project_text(
            "act:healthy-promotion".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "healthy promotion".to_owned(),
            "healthy promotion body".to_owned(),
            None,
            None,
            Some("sealed".to_owned()),
            Some("2026-07-26T10:00:00Z".to_owned()),
            b"healthy",
            1_000,
        );
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 9,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        store
            .read_blocking_async({
                let document = document.clone();
                let completed = completed.clone();
                move |store| {
                    store.apply_search_index_batch(
                        &[IndexOperation::Upsert(Box::new(document))],
                        &completed,
                    )
                }
            })
            .await
            .unwrap();

        assert!(
            state
                .search_index
                .initialize_writer_projection(&state)
                .await
                .unwrap(),
            "a completed durable generation is immediately reusable"
        );
        let active = read_lock(&state.search_index.inner.active).clone();
        assert_eq!(active.status.generation, 9);
        assert_eq!(active.index.len(), 1);
        assert_eq!(active.index.get("act:healthy-promotion"), Some(&document));
        let durable = store
            .read_blocking_async(|store| store.search_index_state())
            .await
            .unwrap()
            .expect("completed durable status remains");
        assert_eq!(durable, completed);
    }

    #[tokio::test]
    async fn routine_reconcile_progress_keeps_serving_the_previous_immutable_generation() {
        let state = AppState::default();
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 3,
            document_count: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        let old = project_text(
            "act:old-stable".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "old stable".to_owned(),
            "old stable".to_owned(),
            None,
            None,
            None,
            None,
            b"old",
            1_000,
        );
        install_active(&state, [old.clone()], completed.clone());
        let mut progress = completed.clone();
        progress.phase = SearchIndexPhase::Reconciling;
        progress.updated_at = "2026-07-26T10:00:01Z".to_owned();

        state
            .search_index
            .persist_batch(&state, Vec::new(), &progress, 0, None)
            .await
            .unwrap();

        assert_eq!(
            read_lock(&state.search_index.inner.status).phase,
            SearchIndexPhase::Reconciling
        );
        let still_active = read_lock(&state.search_index.inner.active).clone();
        assert_eq!(still_active.status, completed);
        assert_eq!(still_active.index.get("act:old-stable"), Some(&old));

        let replacement = project_text(
            "act:new-stable".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "new stable".to_owned(),
            "new stable".to_owned(),
            None,
            None,
            None,
            None,
            b"new",
            1_000,
        );
        let mut next = progress;
        next.phase = SearchIndexPhase::Idle;
        next.generation = 4;
        next.last_completed_at = Some("2026-07-26T10:00:02Z".to_owned());
        next.updated_at = "2026-07-26T10:00:02Z".to_owned();
        state
            .search_index
            .publish_completed_projection(
                &state,
                Arc::new(index_from_documents([replacement.clone()])),
                &next,
                0,
                None,
            )
            .await
            .unwrap();
        let active = read_lock(&state.search_index.inner.active).clone();
        assert_eq!(active.status.generation, 4);
        assert_eq!(active.index.get("act:new-stable"), Some(&replacement));
        assert!(active.index.get("act:old-stable").is_none());
    }

    #[tokio::test]
    async fn failed_mid_batch_cleanup_removes_candidate_only_rows_before_retry() {
        let dir = TestDataDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let store = state.store.clone().expect("durable store");
        let stale_candidate = project_text(
            "act:interrupted-candidate-only".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "interrupted candidate".to_owned(),
            "must not survive the retry boundary".to_owned(),
            None,
            None,
            None,
            None,
            b"interrupted",
            1_000,
        );
        let interrupted = SearchIndexState {
            phase: SearchIndexPhase::Reconciling,
            generation: 3,
            processed: 1,
            total: 2,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:01Z".to_owned(),
            ..SearchIndexState::default()
        };
        store
            .read_blocking_async({
                let stale_candidate = stale_candidate.clone();
                let interrupted = interrupted.clone();
                move |store| {
                    store.apply_search_index_batch(
                        &[IndexOperation::Upsert(Box::new(stale_candidate))],
                        &interrupted,
                    )
                }
            })
            .await
            .unwrap();

        state
            .search_index
            .discard_interrupted_generation(&state)
            .await
            .expect("interrupted candidate cleanup succeeds");

        assert!(store.search_documents().unwrap().is_empty());
        let durable = store
            .search_index_state()
            .unwrap()
            .expect("durable fail-closed tombstone");
        assert!(durable.projection_fenced);
        assert!(read_lock(&state.search_index.inner.active).index.is_empty());
        assert!(
            state
                .search_index
                .inner
                .fail_closed_until_completed
                .load(Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn ordinary_content_mutation_keeps_the_previous_generation_serviceable() {
        let state = AppState::default();
        let mut entity = chancela_core::Entity::new(
            "Stable Search Name, Lda.",
            chancela_core::Nipc::unvalidated("ordinary-search-content"),
            "Lisboa",
            chancela_core::EntityKind::SociedadePorQuotas,
        );
        let relation = Relation {
            tenant_id: Some(entity.tenant_id.to_string()),
            entity_id: Some(entity.id.to_string()),
            ..Relation::default()
        };
        let document = project_text(
            format!("entity:{}", entity.id),
            SearchKind::Entity,
            relation,
            entity.name.clone(),
            entity.name.clone(),
            None,
            None,
            None,
            None,
            b"ordinary-content",
            1_000,
        );
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        install_active(&state, [document], completed_status(3));
        let global_reader = actor_with_role(
            &state,
            "search-content-global-reader",
            chancela_authz::READER_ROLE_ID,
            Scope::Global,
        )
        .await;

        let content_guard = begin_source_mutation(&state).await;
        entity.name = "Updated Search Name, Lda.".to_owned();
        state.entities.write().await.insert(entity.id, entity);

        assert_eq!(
            query(
                State(state.clone()),
                global_reader,
                Query(SearchRequest {
                    q: Some("Stable Search Name".to_owned()),
                    ..SearchRequest::default()
                }),
            )
            .await
            .expect("content-only mutation keeps the prior generation readable")
            .0
            .page
            .total,
            1
        );
        drop(content_guard);
    }

    #[tokio::test]
    async fn entity_deleted_during_a_bounded_build_cannot_activate_the_stale_candidate() {
        let dir = TestDataDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let store = state.store.clone().expect("durable store");
        let entity = chancela_core::Entity::new(
            "Delete While Building, Lda.",
            chancela_core::Nipc::unvalidated("delete-during-search-build"),
            "Lisboa",
            chancela_core::EntityKind::SociedadePorQuotas,
        );
        let search_id = format!("entity:{}", entity.id);
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        let build = build_corpus(
            &state,
            &crate::settings::SearchSettings::default(),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        let stale = build
            .documents
            .into_iter()
            .find(|document| document.id == search_id)
            .expect("entity candidate");
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 8,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        let global_reader = actor_with_role(
            &state,
            "search-delete-global-reader",
            chancela_authz::READER_ROLE_ID,
            Scope::Global,
        )
        .await;
        store
            .read_blocking_async({
                let stale = stale.clone();
                let completed = completed.clone();
                move |store| {
                    store.apply_search_index_batch(
                        &[IndexOperation::Upsert(Box::new(stale))],
                        &completed,
                    )
                }
            })
            .await
            .unwrap();
        install_active(&state, [stale], completed);
        assert_eq!(
            query(
                State(state.clone()),
                global_reader.clone(),
                Query(SearchRequest {
                    q: Some("Delete While Building".to_owned()),
                    ..SearchRequest::default()
                }),
            )
            .await
            .expect("stable pre-delete generation is searchable")
            .0
            .page
            .total,
            1
        );

        let build_epoch = state.search_index.inner.wake_epoch.load(Ordering::Acquire);
        let security_fence = begin_security_sensitive_source_mutation(&state)
            .await
            .expect("security fence starts before deletion");
        state.entities.write().await.remove(&entity.id);

        assert_eq!(
            state
                .search_index
                .ensure_source_epoch(build_epoch)
                .await
                .unwrap_err(),
            SEARCH_PROJECTION_SUPERSEDED
        );
        drop(security_fence);
        assert!(read_lock(&state.search_index.inner.active).index.is_empty());
        assert!(store.search_documents().unwrap().is_empty());
        assert!(
            store
                .search_index_state()
                .unwrap()
                .unwrap()
                .projection_fenced
        );
        assert!(matches!(
            query(
                State(state.clone()),
                global_reader,
                Query(SearchRequest {
                    q: Some("Delete While Building".to_owned()),
                    ..SearchRequest::default()
                }),
            )
            .await,
            Err(ApiError::Unavailable(_))
        ));
        assert_eq!(
            lock_mutex(&state.search_index.inner.queue).front(),
            Some(&SearchCommand::Reconcile)
        );
    }

    #[tokio::test]
    async fn tenant_move_during_a_bounded_build_cannot_activate_old_scope_metadata() {
        let dir = TestDataDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let store = state.store.clone().expect("durable store");
        let old_tenant = chancela_core::TenantId::new();
        let new_tenant = chancela_core::TenantId::new();
        let entity = chancela_core::Entity::new(
            "Move While Building, Lda.",
            chancela_core::Nipc::unvalidated("tenant-move-search-build"),
            "Porto",
            chancela_core::EntityKind::SociedadePorQuotas,
        )
        .in_tenant(old_tenant);
        let search_id = format!("entity:{}", entity.id);
        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        let build = build_corpus(
            &state,
            &crate::settings::SearchSettings::default(),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
        let stale = build
            .documents
            .into_iter()
            .find(|document| document.id == search_id)
            .expect("entity candidate");
        let old_tenant_id = old_tenant.to_string();
        assert_eq!(stale.tenant_id.as_deref(), Some(old_tenant_id.as_str()));
        let old_tenant_reader = actor_with_role(
            &state,
            "search-old-tenant-reader",
            chancela_authz::OWNER_ROLE_ID,
            crate::authz::scope_of_tenant(old_tenant),
        )
        .await;
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 11,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        store
            .read_blocking_async({
                let stale = stale.clone();
                let completed = completed.clone();
                move |store| {
                    store.apply_search_index_batch(
                        &[IndexOperation::Upsert(Box::new(stale))],
                        &completed,
                    )
                }
            })
            .await
            .unwrap();
        install_active(&state, [stale], completed);
        assert_eq!(
            query(
                State(state.clone()),
                old_tenant_reader.clone(),
                Query(SearchRequest {
                    q: Some("Move While Building".to_owned()),
                    ..SearchRequest::default()
                }),
            )
            .await
            .expect("old tenant can read the stable pre-move generation")
            .0
            .page
            .total,
            1
        );

        let build_epoch = state.search_index.inner.wake_epoch.load(Ordering::Acquire);
        let security_fence = begin_security_sensitive_source_mutation(&state)
            .await
            .expect("security fence starts before tenant move");
        state
            .entities
            .write()
            .await
            .get_mut(&entity.id)
            .unwrap()
            .tenant_id = new_tenant;

        assert_eq!(
            state
                .search_index
                .ensure_source_epoch(build_epoch)
                .await
                .unwrap_err(),
            SEARCH_PROJECTION_SUPERSEDED
        );
        drop(security_fence);
        assert!(read_lock(&state.search_index.inner.active).index.is_empty());
        assert!(store.search_documents().unwrap().is_empty());
        assert!(
            store
                .search_index_state()
                .unwrap()
                .unwrap()
                .projection_fenced
        );
        assert!(matches!(
            query(
                State(state.clone()),
                old_tenant_reader,
                Query(SearchRequest {
                    q: Some("Move While Building".to_owned()),
                    ..SearchRequest::default()
                }),
            )
            .await,
            Err(ApiError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn follower_clears_tombstone_but_retains_last_completed_snapshot_during_normal_rebuild() {
        let dir = TestDataDir::new();
        let state = AppState::with_data_dir(dir.0.clone());
        let store = state.store.clone().expect("durable store");
        let secret = "follower-secret-49217";
        let document = project_text(
            "act:follower-secret".to_owned(),
            SearchKind::Act,
            Relation::default(),
            secret.to_owned(),
            secret.to_owned(),
            None,
            None,
            None,
            None,
            secret.as_bytes(),
            1_000,
        );
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 4,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        store
            .read_blocking_async({
                let document = document.clone();
                let completed = completed.clone();
                move |store| {
                    store.apply_search_index_batch(
                        &[IndexOperation::Upsert(Box::new(document))],
                        &completed,
                    )
                }
            })
            .await
            .unwrap();
        assert!(
            state
                .search_index
                .hydrate_from_store(&state, true)
                .await
                .unwrap()
        );
        assert_eq!(read_lock(&state.search_index.inner.active).index.len(), 1);

        let in_progress = SearchIndexState {
            phase: SearchIndexPhase::Reconciling,
            updated_at: "2026-07-26T10:00:01Z".to_owned(),
            ..completed.clone()
        };
        store
            .read_blocking_async(move |store| store.apply_search_index_batch(&[], &in_progress))
            .await
            .unwrap();
        assert!(
            !state
                .search_index
                .hydrate_from_store(&state, true)
                .await
                .unwrap()
        );
        assert_eq!(
            read_lock(&state.search_index.inner.active).index.len(),
            1,
            "ordinary non-fenced rebuild retains the last completed follower snapshot"
        );

        store
            .read_blocking_async(|store| store.clear_search_projection())
            .await
            .unwrap();
        assert!(
            !state
                .search_index
                .hydrate_from_store(&state, true)
                .await
                .unwrap()
        );
        assert!(
            read_lock(&state.search_index.inner.active).index.is_empty(),
            "a durable tombstone clears stale follower text even when pub/sub was missed"
        );
        assert!(read_lock(&state.search_index.inner.status).projection_fenced);
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL at DATABASE_URL"]
    async fn postgres_two_node_search_promotion_discards_interrupted_generation() {
        let Some(database_url) = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let leader =
            chancela_store::Store::open_backend(chancela_store::StoreBackendSelection::Postgres {
                database_url: database_url.clone(),
            })
            .expect("open search leader");
        assert!(leader.cluster_is_leader(), "first node must own the lock");
        let follower_store =
            chancela_store::Store::open_backend(chancela_store::StoreBackendSelection::Postgres {
                database_url,
            })
            .expect("open search follower");
        assert!(!follower_store.cluster_is_leader());

        leader.clear_search_projection().unwrap();
        let stable = project_text(
            "act:postgres-stable".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "stable".to_owned(),
            "stable".to_owned(),
            None,
            None,
            None,
            None,
            b"stable",
            1_000,
        );
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 12,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        leader
            .apply_search_index_batch(&[IndexOperation::Upsert(Box::new(stable))], &completed)
            .unwrap();

        let follower = AppState {
            store: Some(follower_store.clone()),
            ..AppState::default()
        };
        assert!(
            follower
                .search_index
                .hydrate_from_store(&follower, true)
                .await
                .unwrap()
        );
        assert_eq!(
            read_lock(&follower.search_index.inner.active)
                .status
                .generation,
            12
        );

        let refreshed = project_text(
            "act:postgres-refreshed".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "refreshed".to_owned(),
            "refreshed".to_owned(),
            None,
            None,
            None,
            None,
            b"refreshed",
            1_000,
        );
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 13,
            document_count: 1,
            processed: 1,
            total: 1,
            last_completed_at: Some("2026-07-26T10:00:02Z".to_owned()),
            updated_at: "2026-07-26T10:00:02Z".to_owned(),
            ..completed
        };
        leader
            .apply_search_index_batch(
                &[
                    IndexOperation::Delete("act:postgres-stable".to_owned()),
                    IndexOperation::Upsert(Box::new(refreshed.clone())),
                ],
                &completed,
            )
            .unwrap();
        confirm_search_snapshot_current(&follower)
            .await
            .expect("a normal completed generation hydrates before the request is retried");
        let follower_active = read_lock(&follower.search_index.inner.active).clone();
        assert_eq!(follower_active.status.generation, 13);
        assert_eq!(
            follower_active.index.get("act:postgres-refreshed"),
            Some(&refreshed)
        );
        assert!(follower_active.index.get("act:postgres-stable").is_none());

        let partial = project_text(
            "act:postgres-partial-secret".to_owned(),
            SearchKind::Act,
            Relation::default(),
            "partial-secret".to_owned(),
            "partial-secret".to_owned(),
            None,
            None,
            None,
            None,
            b"partial-secret",
            1_000,
        );
        let interrupted = SearchIndexState {
            phase: SearchIndexPhase::Reconciling,
            processed: 1,
            total: 2,
            updated_at: "2026-07-26T10:00:01Z".to_owned(),
            ..completed
        };
        leader
            .apply_search_index_batch(&[IndexOperation::Upsert(Box::new(partial))], &interrupted)
            .unwrap();

        drop(leader);
        assert!(
            follower_store.cluster_try_promote().unwrap(),
            "follower wins the released advisory lock"
        );
        follower
            .cluster_promotion_handoff()
            .await
            .expect("promotion handoff");
        follower_store.cluster_enable_writes();
        assert!(
            follower
                .search_index
                .refresh_projection_role(&follower)
                .await
                .unwrap()
        );
        assert!(
            !follower
                .search_index
                .initialize_writer_projection(&follower)
                .await
                .unwrap(),
            "an interrupted durable generation must be discarded, never hydrated"
        );
        assert!(
            read_lock(&follower.search_index.inner.active)
                .index
                .is_empty()
        );
        assert!(follower_store.search_documents().unwrap().is_empty());
        let durable = follower_store
            .search_index_state()
            .unwrap()
            .expect("promotion tombstone");
        assert!(durable.projection_fenced);
        assert_eq!(durable.phase, SearchIndexPhase::Starting);
    }

    #[tokio::test]
    async fn pre_destructive_fence_clears_before_mutation_and_serializes_local_resets() {
        let state = AppState::default();
        let secret = "commit-window-secret-73126";
        let completed = SearchIndexState {
            phase: SearchIndexPhase::Idle,
            generation: 1,
            last_completed_at: Some("2026-07-26T10:00:00Z".to_owned()),
            updated_at: "2026-07-26T10:00:00Z".to_owned(),
            ..SearchIndexState::default()
        };
        install_active(
            &state,
            [project_text(
                "act:commit-window".to_owned(),
                SearchKind::Act,
                Relation::default(),
                secret.to_owned(),
                secret.to_owned(),
                None,
                None,
                None,
                None,
                secret.as_bytes(),
                1_000,
            )],
            completed,
        );

        prepare_destructive_change(&state)
            .await
            .expect("first fence");
        assert!(read_lock(&state.search_index.inner.active).index.is_empty());
        assert!(
            state
                .search_index
                .inner
                .destructive_fence
                .load(Ordering::Acquire)
        );
        assert!(
            prepare_destructive_change(&state).await.is_err(),
            "a concurrent destructive mutation cannot overwrite the active reset id"
        );
        assert!(matches!(
            confirm_search_snapshot_current(&state).await,
            Err(ApiError::Unavailable(_))
        ));
        abort_destructive_change(&state).await;
        assert!(
            !state
                .search_index
                .inner
                .destructive_fence
                .load(Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn committed_entity_becomes_searchable_without_periodic_wait() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let state = AppState::default();
        spawn_search_service(state.clone());
        let initial_deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
        while read_lock(&state.search_index.inner.status).generation == 0 {
            assert!(tokio::time::Instant::now() < initial_deadline);
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        let baseline = read_lock(&state.search_index.inner.status).generation;
        let token = session_token_with_role(
            &state,
            "search-real-handler-owner",
            chancela_authz::OWNER_ROLE_ID,
            Scope::Global,
        )
        .await;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/entities")
            .header("content-type", "application/json")
            .header(crate::actor::SESSION_HEADER, token)
            .body(Body::from(
                serde_json::json!({
                    "name": "Sociedade Instantânea",
                    "nipc": "search-mutation-handler",
                    "seat": "Lisboa",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": true
                })
                .to_string(),
            ))
            .expect("entity request");
        let response = crate::router(state.clone())
            .oneshot(request)
            .await
            .expect("entity handler responds");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("entity response body");
        let created: serde_json::Value =
            serde_json::from_slice(&body).expect("entity response json");
        let expected_search_id = format!(
            "entity:{}",
            created["id"].as_str().expect("created entity id")
        );

        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(5);
        loop {
            let generation = read_lock(&state.search_index.inner.status).generation;
            let active = read_lock(&state.search_index.inner.active).clone();
            let found = active
                .index
                .search(&SearchQuery {
                    text: "instantanea".to_owned(),
                    ..SearchQuery::default()
                })
                .hits
                .iter()
                .any(|hit| hit.id == expected_search_id);
            if generation > baseline && found {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "committed entity was not indexed by the mutation wake; status={:?}; documents={:?}",
                read_lock(&state.search_index.inner.status),
                read_lock(&state.search_index.inner.active)
                    .index
                    .snapshot()
                    .into_iter()
                    .map(|document| (document.id, document.title))
                    .collect::<Vec<_>>()
            );
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        shutdown_search_service(&state).await;
    }

    #[tokio::test]
    async fn destructive_change_purges_memory_before_starting_a_clean_generation() {
        let state = AppState::default();
        spawn_search_service(state.clone());
        let initial_deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
        while read_lock(&state.search_index.inner.status).generation == 0 {
            assert!(tokio::time::Instant::now() < initial_deadline);
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        let secret = "destroyed-search-secret-99173";
        let active = read_lock(&state.search_index.inner.active).clone();
        let mut documents = active.index.snapshot();
        documents.push(project_text(
            "act:destroyed-secret".to_owned(),
            SearchKind::Act,
            Relation::default(),
            secret.to_owned(),
            secret.to_owned(),
            None,
            None,
            None,
            None,
            secret.as_bytes(),
            1_000,
        ));
        install_active(&state, documents, active.status.clone());

        reset_after_destructive_change(&state).await;
        assert!(
            read_lock(&state.search_index.inner.active).index.is_empty(),
            "the stale in-memory projection must be gone before the reset call returns"
        );
        assert_eq!(read_lock(&state.search_index.inner.status).generation, 0);

        let rebuild_deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
        loop {
            let status = read_lock(&state.search_index.inner.status).clone();
            if status.generation > 0 && status.phase == SearchIndexPhase::Idle {
                break;
            }
            assert!(
                tokio::time::Instant::now() < rebuild_deadline,
                "clean post-reset generation did not complete: {status:?}"
            );
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        assert_eq!(
            read_lock(&state.search_index.inner.active)
                .index
                .search(&SearchQuery {
                    text: secret.to_owned(),
                    ..SearchQuery::default()
                })
                .total,
            0
        );
        shutdown_search_service(&state).await;
    }

    #[tokio::test]
    async fn committed_reset_releases_fence_even_when_immediate_rebuild_queue_is_full() {
        let state = AppState::default();
        state
            .search_index
            .inner
            .running
            .store(true, Ordering::Release);

        prepare_destructive_change(&state)
            .await
            .expect("first destructive fence");
        let enqueue_attempted = Arc::new(AtomicBool::new(false));
        let attempted = enqueue_attempted.clone();
        reset_after_destructive_change_with(&state, move |_service, _capacity| {
            attempted.store(true, Ordering::Release);
            Err(ApiError::Unavailable(
                "injected full post-commit rebuild queue".to_owned(),
            ))
        })
        .await;

        let (fenced, reset_id, queue_depth) = state.search_index.destructive_test_state();
        assert!(!fenced, "post-commit completion must release the fence");
        assert!(!reset_id, "the completed reset id must be discarded");
        assert_eq!(queue_depth, 0);
        assert!(
            enqueue_attempted.load(Ordering::Acquire),
            "the test must reach the injected post-commit enqueue failure"
        );

        prepare_destructive_change(&state)
            .await
            .expect("a later destructive operation can retry");
        state
            .search_index
            .inner
            .running
            .store(false, Ordering::Release);
        abort_destructive_change(&state).await;
    }

    #[tokio::test]
    async fn projection_completes_on_the_dedicated_named_worker_thread() {
        let state = AppState::default();
        spawn_search_service(state.clone());
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
        loop {
            if read_lock(&state.search_index.inner.status).generation > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "dedicated search projection did not finish"
            );
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        assert_eq!(
            read_lock(&state.search_index.inner.worker_thread).as_deref(),
            Some(SEARCH_WORKER_THREAD)
        );
        shutdown_search_service(&state).await;
    }

    #[tokio::test]
    async fn graceful_shutdown_allows_repeated_service_start_without_retaining_worker_threads() {
        let state = AppState::default();
        for _ in 0..2 {
            spawn_search_service(state.clone());
            let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
            loop {
                let status = read_lock(&state.search_index.inner.status).clone();
                if status.generation > 0 && status.phase == SearchIndexPhase::Idle {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "search worker did not complete startup"
                );
                tokio::time::sleep(StdDuration::from_millis(20)).await;
            }
            shutdown_search_service(&state).await;
            assert!(!state.search_index.inner.running.load(Ordering::Acquire));
            assert!(lock_mutex(&state.search_index.inner.task).is_none());
        }
    }

    #[tokio::test]
    async fn timed_out_shutdown_retains_the_worker_handle_until_it_can_be_reaped() {
        let service = SearchService::default();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::Builder::new()
            .name("blocked-search-worker-test".to_owned())
            .spawn(move || {
                let _ = release_rx.recv();
            })
            .unwrap();
        *lock_mutex(&service.inner.task) = Some(handle);

        assert!(!reap_search_worker(&service, StdDuration::from_millis(25)).await);
        assert!(
            lock_mutex(&service.inner.task).is_some(),
            "a timeout must not detach and lose the only join handle"
        );

        release_tx.send(()).unwrap();
        assert!(reap_search_worker(&service, StdDuration::from_secs(1)).await);
        assert!(lock_mutex(&service.inner.task).is_none());
    }

    #[tokio::test]
    async fn operational_actions_are_real_action_center_rows() {
        let actionables = crate::dashboard::search_actionables(&AppState::default())
            .await
            .unwrap();
        assert!(
            actionables.iter().any(|actionable| {
                actionable.id.starts_with("alert:")
                    && actionable.body.contains("recommended_next_steps")
                    && actionable.required_permission == Permission::DataBackup
            }),
            "the default backup-freshness Action Center alert must be projected as an action"
        );
    }
}
