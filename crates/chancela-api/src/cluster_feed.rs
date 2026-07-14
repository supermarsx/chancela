//! **wp16 Phase 1 — follower change-feed: covered read-model refresh with fail-closed delta apply.**
//!
//! This is the read-path half of wp16 (P0 landed leader election + step-down + failover handoff in
//! [`crate::cluster`]). A FOLLOWER (a non-leader Postgres node) must observe the leader's appends and
//! keep its in-memory ledger + core aggregate read models fresh **without** a full reload on every
//! change, so it can serve those covered projections from a verified prefix. The LEADER is unchanged
//! except that, after a durable append commits, it emits a `NOTIFY` so followers wake immediately (see
//! [`crate::AppState::persist_write_through`]). Write redirect is a later phase (P2).
//!
//! Everything DB-touching here is feature-gated behind `postgres`; the default SQLite / in-memory
//! build compiles only the pure delta-apply core (which is unit-tested without a database) and a
//! no-op [`spawn_cluster_feed`], so the embedded editions are totally unaffected.
//!
//! ## Consistency model (plan §2.4)
//!
//! - **The leader is strongly consistent** — it is the sole writer and serves reads from the exact
//!   chain it just extended.
//! - **A follower serves covered read models from a verified prefix.** This phase covers the ledger,
//!   entities, books, acts, follow-ups, registry extracts, and signed-document projection. It does
//!   **not** refresh file-backed sidecars such as settings, users, roles, delegations, privacy
//!   registers, or law-cache state; `/health.cluster.read_model_scope` says this explicitly. When the
//!   database is reachable and the aggregate snapshot/reload succeeds, observed lag is normally
//!   bounded by the larger of NOTIFY latency and the seq-poll interval. DB errors or refresh failures
//!   leave the follower behind instead of reporting caught up. A follower's chain is always a
//!   **verified prefix** of the leader's — never a fork, never invalid data (P2 will proxy
//!   read-after-write / integrity reads to the leader; this phase does not).
//!
//! ## Staying fresh: NOTIFY (fast) + seq-poll (correctness backstop) — plan §2.2
//!
//! Two wake sources feed one reconcile routine:
//!
//! 1. **`LISTEN chancela_ledger`** on a **dedicated** connection (never the store's writer / read
//!    pool) — near-real-time, but `NOTIFY` is best-effort (a listener that dropped between reconnect
//!    and re-`LISTEN` can miss a signal), so it is only the *fast path*.
//! 2. **Seq-poll (required):** every `CHANCELA_CHANGEFEED_POLL_INTERVAL` (default 5s) the reconcile
//!    runs regardless. This catches missed notifications once Postgres can be queried again; it is a
//!    correctness backstop, not a production HA/read-freshness certification. `seq` monotonicity makes
//!    "give me everything after my last-applied `seq`" idempotent across duplicate wakes.
//!
//! ## Applying the delta: fail-closed continuity, incremental ledger, simple aggregate refresh (§2.3)
//!
//! On a wake the follower pulls the ordered ledger tail `seq > last_applied` and calls [`apply_delta`],
//! which:
//!
//! - **Verifies the delta chains cleanly onto the current in-memory head** — the first delta event's
//!   `seq` must equal `head_len` and its `prev_hash` must equal the current head hash, and the delta
//!   must be internally contiguous. If it does **not** (a gap, a fork, a wrong `prev_hash`, or a
//!   whole-chain re-verify failure), the delta is **rejected and the in-memory ledger is left
//!   untouched** — the follower then triggers a full reload from the durable store rather than
//!   corrupt its state. This is the correctness linchpin: the in-memory ledger is **always** a valid
//!   extension of the durable chain, never a fork.
//! - **Extends the ledger incrementally** on success (no full `store.load`) by adopting the already-
//!   persisted, hash-bearing tail events and re-verifying (the seam plus the whole chain).
//!
//! Core aggregate read-models (`entities`/`books`/`acts`/…) are hydrated from their own tables, not
//! from ledger events, so before publishing a verified ledger tail the follower also fetches them via
//! [`chancela_store::Store::cluster_load_aggregates`] — the plan's sanctioned **simple v1** refresh
//! (`O(aggregates)`, events-free). If that refresh fails, the candidate ledger is not published; the
//! feed falls back to a full durable reload and remains visibly behind if reload also fails. A
//! targeted (changed-keys) refresh is a later optimization; this phase favours correctness over
//! cleverness. The document / signed-document read models additionally self-heal on read (store
//! fallback on a miss), but file-backed sidecars remain out of scope for this feed.
//!
//! ## Cache coherence (§5.1)
//!
//! [`crate::cache::VerifyMemo`] is `(head-hash, len)`-keyed, so applying a delta advances the head and
//! the stale verdict key can never match again — it self-invalidates for free (a follower can never
//! serve a verify verdict for a chain state it no longer holds). Only the non-head-keyed moka/redis
//! cache-aside is driven off the feed here.

use crate::AppState;

#[cfg(feature = "postgres")]
use std::collections::HashMap;

#[cfg(feature = "postgres")]
use chancela_core::ActId;
#[cfg(feature = "postgres")]
use chancela_ledger::Ledger;
#[cfg(feature = "postgres")]
use chancela_store::{AggregateSnapshot, StoreError, StoredSignedDocument};

/// wp16 P1 — the outcome of applying a change-feed delta to the in-memory ledger.
#[cfg(any(feature = "postgres", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeltaOutcome {
    /// The delta held nothing new (empty, or entirely already-applied) — the ledger was untouched.
    NoOp,
    /// The delta extended the chain; the ledger now has `new_len` events with head `new_head`.
    Applied {
        /// The ledger length after applying the delta.
        new_len: usize,
        /// The new chain head hash (`None` only for an empty chain, impossible on `Applied`).
        new_head: Option<[u8; 32]>,
    },
    /// **Fail-closed:** the delta did not cleanly extend the current head (gap / fork / wrong
    /// `prev_hash` / whole-chain re-verify failure). The ledger was left **untouched**; the caller
    /// must full-reload from the durable store rather than adopt a suspect tail.
    Reject(String),
}

/// **The pure, fail-closed delta-apply core (plan §2.3).** Given the current in-memory `ledger` and
/// an ordered tail of already-persisted `delta` events, extend the ledger **iff** the delta is a
/// clean continuation of the current head; otherwise leave the ledger untouched and return
/// [`DeltaOutcome::Reject`] so the caller full-reloads. Unit-tested without a DB and used verbatim by
/// the live feed, so the two can never drift.
///
/// Idempotent against overlapping `NOTIFY` + poll deltas: events at or below the current head are
/// dropped before the seam is checked, so a redundant delta is a [`DeltaOutcome::NoOp`], never a
/// spurious reject.
#[cfg(any(feature = "postgres", test))]
pub(crate) fn apply_delta(
    ledger: &mut chancela_ledger::Ledger,
    delta: &[chancela_ledger::Event],
) -> DeltaOutcome {
    let expected_seq = ledger.len() as u64;
    let expected_prev = ledger.head().unwrap_or([0u8; 32]);

    // Drop any already-applied prefix so an overlapping NOTIFY+poll delta is idempotent, not a fork.
    let fresh: Vec<&chancela_ledger::Event> =
        delta.iter().filter(|e| e.seq >= expected_seq).collect();
    let Some(first) = fresh.first() else {
        return DeltaOutcome::NoOp;
    };

    // Seam check: the delta must begin exactly at the head and its first event must point back at
    // the current head hash. A gap (missing middle) or a fork (wrong prev_hash) is rejected.
    if first.seq != expected_seq {
        return DeltaOutcome::Reject(format!(
            "gap: delta begins at seq {} but the in-memory head expects seq {expected_seq}",
            first.seq
        ));
    }
    if first.prev_hash != expected_prev {
        return DeltaOutcome::Reject(format!(
            "fork: delta seq {} prev_hash does not extend the current in-memory head",
            first.seq
        ));
    }
    // Internal continuity of the delta itself (dense seq + backward hash chain).
    for pair in fresh.windows(2) {
        if pair[1].seq != pair[0].seq + 1 {
            return DeltaOutcome::Reject(format!(
                "non-contiguous delta: seq {} is not followed by {}",
                pair[0].seq,
                pair[0].seq + 1
            ));
        }
        if pair[1].prev_hash != pair[0].hash {
            return DeltaOutcome::Reject(format!(
                "broken chain within delta at seq {}",
                pair[1].seq
            ));
        }
    }

    // Adopt the persisted tail verbatim (do NOT re-mint / re-hash) and re-verify the whole chain.
    // Building a fresh candidate means a re-verify failure leaves the caller's `ledger` untouched.
    let mut combined = ledger.events().to_vec();
    combined.extend(fresh.into_iter().cloned());
    let (candidate, status) = chancela_ledger::Ledger::try_from_events(combined);
    match status {
        Ok(_) => {
            let new_len = candidate.len();
            let new_head = candidate.head();
            *ledger = candidate;
            DeltaOutcome::Applied { new_len, new_head }
        }
        Err(e) => DeltaOutcome::Reject(format!("delta failed whole-chain re-verification: {e}")),
    }
}

const CLUSTER_READ_MODEL_SCOPE: &str = "ledger_core_aggregates_signed_documents";

/// wp16 P1 — a follower's covered-feed indicator (plan §2.4): durable `MAX(seq)` vs this node's
/// in-memory applied `seq`, scoped to the ledger + core aggregate/signed-document read models this
/// feed actually refreshes. It deliberately does not certify file-backed sidecars such as settings,
/// users, roles, delegations, privacy registers, or law-cache state.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ClusterReplicaLag {
    /// This node's cluster role: `"leader"` or `"follower"`.
    pub role: &'static str,
    /// Scope of the freshness signal. This is intentionally narrow to avoid overclaiming all reads.
    pub read_model_scope: &'static str,
    /// The highest `seq` this node has applied in memory (`None` for an empty ledger).
    pub applied_seq: Option<u64>,
    /// The durable `MAX(seq)` observed in Postgres (`None` if unavailable / empty).
    pub durable_max_seq: Option<i64>,
    /// Whether the durable-head query succeeded. If `false`, `lag` is unknown rather than zero.
    pub lag_available: bool,
    /// How many events behind the durable head this node is for [`Self::read_model_scope`]. `None`
    /// means Postgres could not provide the durable head for this observation.
    pub lag: Option<u64>,
}

/// Pure lag arithmetic (plan §2.4): how many events a follower at `applied_seq` trails the durable
/// `durable_max`. Never negative (a follower cannot be ahead of the durable chain it replicates).
fn compute_lag(durable_max: Option<i64>, applied_seq: Option<u64>) -> u64 {
    match (durable_max, applied_seq) {
        (Some(durable), Some(applied)) => (durable - applied as i64).max(0) as u64,
        // Durable has `durable + 1` events (seq 0..=durable); we have applied none.
        (Some(durable), None) => (durable + 1).max(0) as u64,
        (None, _) => 0,
    }
}

/// Extract the act id from a ledger event `scope` (the `…/act:{aid}` segment), for targeted
/// document-cache invalidation. `None` when the scope is not act-scoped.
#[cfg(any(feature = "postgres", test))]
fn act_id_from_scope(scope: &str) -> Option<String> {
    let rest = scope.split("act:").nth(1)?;
    let id = rest.split('/').next().unwrap_or(rest).trim();
    (!id.is_empty()).then(|| id.to_owned())
}

#[cfg(feature = "postgres")]
struct FeedSnapshot {
    aggregates: AggregateSnapshot,
    signed_documents: HashMap<ActId, StoredSignedDocument>,
}

impl AppState {
    /// wp16 P1 — the follower read-lag indicator (plan §2.4), or `None` when this node is not part of
    /// an electing (Postgres) cluster. Exposed on `/health`.
    pub(crate) async fn cluster_read_lag(&self) -> Option<ClusterReplicaLag> {
        let store = self.store.as_ref()?;
        if !store.cluster_election_enabled() {
            return None;
        }
        let is_leader = store.cluster_is_leader();
        let applied_seq = {
            let len = self.ledger.read().await.len();
            (len > 0).then(|| (len - 1) as u64)
        };
        let durable_max_result = store.cluster_durable_max_seq();
        let durable_max_seq = durable_max_result.as_ref().ok().copied().flatten();
        let lag_available = durable_max_result.is_ok();
        Some(ClusterReplicaLag {
            role: if is_leader { "leader" } else { "follower" },
            read_model_scope: CLUSTER_READ_MODEL_SCOPE,
            applied_seq,
            durable_max_seq,
            lag_available,
            // A leader is authoritative for the covered feed; a follower trails the durable head.
            lag: match (is_leader, durable_max_result) {
                (true, _) => Some(0),
                (false, Ok(durable_max)) => Some(compute_lag(durable_max, applied_seq)),
                (false, Err(_)) => None,
            },
        })
    }

    /// wp16 P1 — one reconcile pass for a FOLLOWER: pull the ledger tail since the last-applied `seq`,
    /// apply it incrementally with the fail-closed continuity check ([`apply_delta`]), refresh the
    /// aggregate maps + caches, and recompute the degraded gate. A leader is a no-op (its own write
    /// path keeps its ledger authoritative). Blocking store ops run on the blocking pool so a DB stall
    /// never blocks a runtime worker.
    #[cfg(feature = "postgres")]
    pub(crate) async fn cluster_feed_reconcile(&self) {
        let Some(store) = self.store.clone() else {
            return;
        };
        if store.cluster_is_leader() {
            return;
        }
        let last = (self.ledger.read().await.len() as i64) - 1;
        let delta = match tokio::task::spawn_blocking({
            let store = store.clone();
            move || store.cluster_events_since(last)
        })
        .await
        {
            Ok(Ok(delta)) => delta,
            Ok(Err(e)) => {
                eprintln!("cluster feed: delta fetch failed ({e}); retrying next tick");
                return;
            }
            Err(e) => {
                eprintln!("cluster feed: delta fetch task panicked ({e})");
                return;
            }
        };
        if delta.is_empty() {
            return;
        }
        // Build the candidate from the latest in-memory ledger, but do not publish it until the
        // aggregate snapshot is also available. That keeps a transient aggregate-refresh failure from
        // advancing the ledger and then getting stuck with stale read models on later empty deltas.
        let mut candidate = self.ledger.read().await.clone();
        let outcome = apply_delta(&mut candidate, &delta);
        match outcome {
            DeltaOutcome::NoOp => {}
            DeltaOutcome::Applied { new_len, .. } => {
                let Some(snapshot) = self.cluster_load_feed_snapshot(&store).await else {
                    eprintln!(
                        "cluster feed: aggregate refresh failed after a valid delta; falling back \
                         to a full durable reload before advancing in-memory state"
                    );
                    self.cluster_full_reload(&store).await;
                    return;
                };
                self.cluster_swap_delta_state(candidate, snapshot).await;
                self.cluster_invalidate_caches(&delta).await;
                // wp16 P3b: the ledger delta also covers this tick's user/role/delegation/settings/
                // credential mutations (each such mutation appended a ledger event), so refresh the
                // DB-backed sidecars this feed does not otherwise carry, keeping a follower's shared
                // auth/config state consistent with the leader.
                if self.sidecars_db_backed {
                    crate::sidecar_store::reload_into_state(self, &store).await;
                }
                {
                    let ledger = self.ledger.read().await;
                    crate::refresh_degraded(self, &ledger).await;
                }
                eprintln!(
                    "cluster feed: applied {} event(s); covered feed advanced to seq {}",
                    delta.len(),
                    new_len.saturating_sub(1)
                );
            }
            DeltaOutcome::Reject(reason) => {
                eprintln!(
                    "cluster feed: FAIL-CLOSED — delta did not extend the current head ({reason}); \
                     discarding it and triggering a full reload from the durable store"
                );
                self.cluster_full_reload(&store).await;
            }
        }
    }

    /// wp16 P1 — fetch the bounded aggregate read-models that must move forward with an accepted
    /// ledger delta (plan §2.3 simple v1): events-free re-read of
    /// `entities`/`books`/`acts`/`registry_extracts`/`follow_ups` plus the signed-document read model.
    /// The caller publishes nothing if this fails; it falls back to a full durable reload instead.
    #[cfg(feature = "postgres")]
    async fn cluster_load_feed_snapshot(
        &self,
        store: &chancela_store::Store,
    ) -> Option<FeedSnapshot> {
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            move || {
                let aggregates = store.cluster_load_aggregates()?;
                let signed = store.all_signed_documents()?;
                Ok::<_, StoreError>(FeedSnapshot {
                    aggregates,
                    signed_documents: signed,
                })
            }
        })
        .await;
        match result {
            Ok(Ok(value)) => Some(value),
            Ok(Err(e)) => {
                eprintln!("cluster feed: aggregate refresh failed ({e})");
                None
            }
            Err(e) => {
                eprintln!("cluster feed: aggregate refresh task panicked ({e})");
                None
            }
        }
    }

    /// Publish a verified candidate ledger together with its aggregate snapshot. Locks are acquired
    /// in the same front-of-state order documented on [`AppState`] so readers never observe a ledger
    /// advanced by this feed while the aggregate maps are still from the prior head.
    #[cfg(feature = "postgres")]
    async fn cluster_swap_delta_state(&self, ledger: Ledger, snapshot: FeedSnapshot) {
        let mut entities = self.entities.write().await;
        let mut books = self.books.write().await;
        let mut acts = self.acts.write().await;
        let mut follow_ups = self.follow_ups.write().await;
        let mut registry_extracts = self.registry_extracts.write().await;
        let mut signed_documents = self.signed_documents.write().await;
        let mut live_ledger = self.ledger.write().await;

        *entities = snapshot.aggregates.entities;
        *books = snapshot.aggregates.books;
        *acts = snapshot.aggregates.acts;
        *follow_ups = snapshot.aggregates.follow_ups;
        *registry_extracts = snapshot.aggregates.registry_extracts;
        *signed_documents = snapshot.signed_documents;
        *live_ledger = ledger;
    }

    /// wp16 P1 — the fail-closed remedy when a delta does not extend the current head: reload the
    /// authoritative durable state wholesale (which re-verifies the whole chain on load) and swap it
    /// into memory. The head changes wholesale, so the cache-aside is invalidated and the degraded
    /// gate recomputed. A failure logs and keeps the current state rather than half-applying.
    #[cfg(feature = "postgres")]
    async fn cluster_full_reload(&self, store: &chancela_store::Store) {
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            move || {
                let loaded = store.load()?;
                let signed = store.all_signed_documents()?;
                Ok::<_, chancela_store::StoreError>((loaded, signed))
            }
        })
        .await;
        let (loaded, signed) = match result {
            Ok(Ok(value)) => value,
            Ok(Err(e)) => {
                eprintln!(
                    "cluster feed: full reload failed ({e}); keeping current in-memory state"
                );
                return;
            }
            Err(e) => {
                eprintln!("cluster feed: full reload task panicked ({e})");
                return;
            }
        };
        self.cluster_swap_loaded_state(loaded, signed).await;
        // wp16 P3b: a full durable reload must also refresh the DB-backed sidecars (users/roles/
        // delegations/settings/credentials) so a follower recovering from a rejected delta does not
        // keep stale shared auth/config state.
        if self.sidecars_db_backed {
            crate::sidecar_store::reload_into_state(self, store).await;
        }
        self.cache.invalidate(&crate::cache::CacheKey::CaeCatalog);
        {
            let ledger = self.ledger.read().await;
            crate::refresh_degraded(self, &ledger).await;
        }
    }

    /// Publish a full durable reload as one ordered state swap.
    #[cfg(feature = "postgres")]
    async fn cluster_swap_loaded_state(
        &self,
        loaded: chancela_store::LoadedState,
        signed_documents_snapshot: HashMap<ActId, StoredSignedDocument>,
    ) {
        let mut entities = self.entities.write().await;
        let mut books = self.books.write().await;
        let mut acts = self.acts.write().await;
        let mut follow_ups = self.follow_ups.write().await;
        let mut registry_extracts = self.registry_extracts.write().await;
        let mut signed_documents = self.signed_documents.write().await;
        let mut ledger = self.ledger.write().await;

        *entities = loaded.entities;
        *books = loaded.books;
        *acts = loaded.acts;
        *follow_ups = loaded.follow_ups;
        *registry_extracts = loaded.registry_extracts;
        *signed_documents = signed_documents_snapshot;
        *ledger = loaded.ledger;
    }

    /// wp16 P1 — cache coherence for a follower after a delta apply (plan §5.1/§5.2). [`VerifyMemo`]
    /// is head-keyed and self-invalidates as the head advances; only the non-head-keyed moka/redis
    /// cache-aside is driven off the feed here (fail-open: a missed invalidation at worst serves a
    /// slightly stale entry until TTL, never corrupts correctness).
    #[cfg(feature = "postgres")]
    async fn cluster_invalidate_caches(&self, delta: &[chancela_ledger::Event]) {
        self.cache.invalidate(&crate::cache::CacheKey::CaeCatalog);
        for event in delta {
            if let Some(act_id) = act_id_from_scope(&event.scope) {
                self.cache
                    .invalidate(&crate::cache::CacheKey::ActDocuments(act_id));
            }
        }
    }
}

/// Resolve the follower seq-poll backstop interval from `CHANCELA_CHANGEFEED_POLL_INTERVAL`
/// (whole seconds, default 5s, clamped `>= 1s` so a misconfig can never busy-spin).
#[cfg(feature = "postgres")]
fn feed_poll_interval() -> std::time::Duration {
    let secs = std::env::var("CHANCELA_CHANGEFEED_POLL_INTERVAL")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    std::time::Duration::from_secs(secs)
}

/// Mount the follower change-feed as a background task. No-op unless the backend is an electing one
/// (Postgres); the default SQLite / in-memory build spawns nothing. Must be called from within the
/// server's tokio runtime (it is, from [`crate::app`]).
#[cfg(feature = "postgres")]
pub(crate) fn spawn_cluster_feed(state: AppState) {
    let Some(store) = state.store.clone() else {
        return;
    };
    if !store.cluster_election_enabled() {
        return;
    }
    let poll = feed_poll_interval();
    let dsn = store.cluster_listen_dsn();
    eprintln!(
        "cluster: follower change-feed active (LISTEN {} + {}s seq-poll backstop); applies the \
         leader's appends incrementally with a fail-closed continuity check",
        chancela_store::CLUSTER_CHANGE_CHANNEL,
        poll.as_secs()
    );
    tokio::spawn(async move { feed_loop(state, poll, dsn).await });
}

/// The no-op change-feed on non-electing (SQLite / in-memory) builds — the embedded editions never
/// run a follower.
#[cfg(not(feature = "postgres"))]
pub(crate) fn spawn_cluster_feed(_state: AppState) {}

/// The follower feed loop: reconcile on either a `NOTIFY` wake (fast path) or a seq-poll tick
/// (correctness backstop), whichever fires first. Priming once on entry lets a follower that booted
/// behind the leader converge without waiting a full poll interval.
#[cfg(feature = "postgres")]
async fn feed_loop(state: AppState, poll: std::time::Duration, dsn: Option<String>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
    if let Some(dsn) = dsn {
        let tx = tx.clone();
        // The LISTEN connection is dedicated and synchronous, run on its own OS thread so it never
        // blocks a tokio worker and never touches the store's writer / read pool (plan §2.2).
        std::thread::spawn(move || listen_thread(dsn, tx));
    }
    // Retain one sender so `rx.recv()` never resolves to `None` (which would busy-loop the select)
    // even when no listener thread is spawned or the listener has exited — the poll tick still drives.
    let _keepalive = tx;

    let mut ticker = tokio::time::interval(poll);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    state.cluster_feed_reconcile().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = rx.recv() => {}
        }
        state.cluster_feed_reconcile().await;
    }
}

/// The dedicated blocking `LISTEN chancela_ledger` listener (plan §2.2). Runs on its own OS thread
/// with its **own** synchronous connection (never the store's writer / pool). Each notification wakes
/// a reconcile; a bounded timeout returns periodically so a dropped connection is detected and
/// re-established (and a reconcile re-primed after every reconnect). Purely a latency optimization —
/// the seq-poll backstop continues retrying even if this thread never runs.
#[cfg(feature = "postgres")]
fn listen_thread(dsn: String, tx: tokio::sync::mpsc::Sender<()>) {
    use postgres::fallible_iterator::FallibleIterator;

    /// Wake a reconcile; `false` iff the receiver is gone (feed loop ended) so the thread can exit.
    fn wake(tx: &tokio::sync::mpsc::Sender<()>) -> bool {
        !matches!(
            tx.try_send(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
        )
    }

    let channel = chancela_store::CLUSTER_CHANGE_CHANNEL;
    loop {
        if tx.is_closed() {
            return;
        }
        let mut client = match postgres::Client::connect(&dsn, postgres::NoTls) {
            Ok(client) => client,
            Err(e) => {
                eprintln!(
                    "cluster feed: LISTEN connect failed ({e}); seq-poll backstop still active, \
                     retrying in 2s"
                );
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };
        if let Err(e) = client.batch_execute(&format!("LISTEN {channel}")) {
            eprintln!("cluster feed: LISTEN {channel} failed ({e}); retrying in 2s");
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }
        // Re-poll immediately after (re)subscribing so any append missed while the listener was down
        // is picked up at once, not only on the next poll tick.
        if !wake(&tx) {
            return;
        }
        loop {
            let next = client
                .notifications()
                .timeout_iter(std::time::Duration::from_secs(5))
                .next();
            match next {
                // A notification arrived — wake a reconcile (coalesced: a full channel already has a
                // pending wake, which is sufficient).
                Ok(Some(_)) => {
                    if !wake(&tx) {
                        return;
                    }
                }
                // Timeout with no notification — loop; the seq-poll tick covers correctness.
                Ok(None) => {}
                Err(e) => {
                    eprintln!("cluster feed: LISTEN stream error ({e}); reconnecting");
                    break;
                }
            }
            if tx.is_closed() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chancela_ledger::{Event, Ledger};

    /// Build a ledger of `n` appended, self-consistent events and return the event vector. A keyword
    /// (`settings`) scope joins only the genesis-kind-free `application` + `global` chains, so any
    /// prefix re-verifies cleanly (the domain's `book:`/`company:` genesis-kind rules don't apply).
    fn chain_of(n: usize) -> Vec<Event> {
        let mut ledger = Ledger::new();
        for _ in 0..n {
            ledger.append("api", "settings", "settings.updated", None, b"{}");
        }
        ledger.events().to_vec()
    }

    /// A follower ledger holding the first `k` events of `full`.
    fn follower_at(full: &[Event], k: usize) -> Ledger {
        Ledger::try_from_events(full[..k].to_vec()).0
    }

    #[test]
    fn apply_delta_extends_on_a_valid_tail() {
        let full = chain_of(5);
        let mut follower = follower_at(&full, 2);
        let outcome = apply_delta(&mut follower, &full[2..]);
        assert!(
            matches!(outcome, DeltaOutcome::Applied { new_len: 5, .. }),
            "a valid tail advances the follower to the full chain: {outcome:?}"
        );
        // Length == MAX(seq)+1, chain intact, head == the leader's head.
        assert_eq!(follower.len(), 5);
        assert_eq!(follower.verify(), Ok(5));
        assert_eq!(follower.head(), Ledger::try_from_events(full).0.head());
    }

    #[test]
    fn apply_delta_is_noop_on_empty_or_fully_overlapping_delta() {
        let full = chain_of(4);
        let mut follower = follower_at(&full, 4);
        // Empty delta.
        assert_eq!(apply_delta(&mut follower, &[]), DeltaOutcome::NoOp);
        // A delta of events the follower already has (overlap) is idempotent, not a spurious reject.
        assert_eq!(apply_delta(&mut follower, &full[..4]), DeltaOutcome::NoOp);
        assert_eq!(follower.len(), 4);
    }

    #[test]
    fn apply_delta_trims_overlap_then_extends() {
        let full = chain_of(6);
        let mut follower = follower_at(&full, 3);
        // Delta overlaps (seq 1..6): the already-applied prefix is dropped, the rest extends cleanly.
        let outcome = apply_delta(&mut follower, &full[1..]);
        assert!(matches!(outcome, DeltaOutcome::Applied { new_len: 6, .. }));
        assert_eq!(follower.verify(), Ok(6));
    }

    #[test]
    fn delta_candidate_can_be_discarded_if_aggregate_refresh_fails() {
        let full = chain_of(5);
        let visible = follower_at(&full, 2);
        let old_head = visible.head();

        // Reconcile applies to a candidate ledger first. If the aggregate snapshot cannot be loaded,
        // the candidate is dropped and the visible state stays behind for the next poll/full reload.
        let mut candidate = visible.clone();
        let outcome = apply_delta(&mut candidate, &full[2..]);
        assert!(matches!(outcome, DeltaOutcome::Applied { new_len: 5, .. }));
        assert_eq!(candidate.len(), 5);
        assert_eq!(candidate.verify(), Ok(5));

        assert_eq!(visible.len(), 2, "visible ledger did not advance");
        assert_eq!(
            visible.head(),
            old_head,
            "visible lag cannot report caught up"
        );
        assert_eq!(visible.verify(), Ok(2));
    }

    #[test]
    fn apply_delta_rejects_a_gap_and_leaves_the_ledger_untouched() {
        let full = chain_of(5);
        let mut follower = follower_at(&full, 2);
        // Skip seq 2: the delta starts at seq 3, which does not extend a head expecting seq 2.
        let outcome = apply_delta(&mut follower, &full[3..]);
        assert!(
            matches!(outcome, DeltaOutcome::Reject(_)),
            "a gapped delta must be rejected fail-closed: {outcome:?}"
        );
        // Fail-closed: the follower is unchanged (still a valid 2-event prefix, never a fork).
        assert_eq!(follower.len(), 2);
        assert_eq!(follower.verify(), Ok(2));
    }

    #[test]
    fn apply_delta_rejects_a_fork_at_the_seam() {
        let full = chain_of(5);
        let mut follower = follower_at(&full, 2);
        // Tamper the first delta event's prev_hash so it no longer points at the current head.
        let mut forked: Vec<Event> = full[2..].to_vec();
        forked[0].prev_hash = [0xAB; 32];
        let outcome = apply_delta(&mut follower, &forked);
        assert!(
            matches!(outcome, DeltaOutcome::Reject(reason) if reason.contains("fork")),
            "a delta that does not extend the current head must be rejected"
        );
        assert_eq!(follower.len(), 2, "the ledger must never become a fork");
        assert_eq!(follower.verify(), Ok(2));
    }

    #[test]
    fn apply_delta_rejects_a_delta_broken_internally() {
        let full = chain_of(6);
        let mut follower = follower_at(&full, 2);
        // Break the link between the 2nd and 3rd delta events (wrong backward hash).
        let mut broken: Vec<Event> = full[2..].to_vec();
        broken[2].prev_hash = [0x11; 32];
        let outcome = apply_delta(&mut follower, &broken);
        assert!(matches!(outcome, DeltaOutcome::Reject(_)));
        assert_eq!(follower.len(), 2, "a broken delta must not be half-applied");
    }

    #[test]
    fn verify_verdict_is_correct_for_the_new_head_after_a_delta_apply() {
        // The VerifyMemo is (head, len)-keyed, so applying a delta advances the head and the memo can
        // never return the stale verdict. Prove it: cache the OLD verdict, apply the delta, and show
        // the memo returns the fresh verdict for the NEW head (not the stale one).
        let memo = crate::cache::VerifyMemo::default();
        let full = chain_of(5);
        let mut follower = follower_at(&full, 2);

        assert_eq!(
            memo.verdict(&follower),
            Ok(2),
            "verdict for the 2-event head"
        );
        let outcome = apply_delta(&mut follower, &full[2..]);
        assert!(matches!(outcome, DeltaOutcome::Applied { new_len: 5, .. }));
        assert_eq!(
            memo.verdict(&follower),
            Ok(5),
            "after the delta advanced the head, the memo recomputes for the new head (no stale hit)"
        );
    }

    #[test]
    fn compute_lag_reflects_applied_seq_vs_durable_max() {
        // Caught up: applied seq == durable max → 0 lag.
        assert_eq!(compute_lag(Some(9), Some(9)), 0);
        // Behind by 3 events.
        assert_eq!(compute_lag(Some(9), Some(6)), 3);
        // A fresh follower with an empty ledger behind a durable chain of `max+1` events.
        assert_eq!(compute_lag(Some(4), None), 5);
        // Unknown durable head (query failed) or empty durable chain → no reported lag.
        assert_eq!(compute_lag(None, Some(3)), 0);
        assert_eq!(compute_lag(None, None), 0);
        // A follower is never reported as "ahead" of the durable chain it replicates.
        assert_eq!(compute_lag(Some(2), Some(5)), 0);
    }

    #[test]
    fn cluster_health_status_names_its_narrow_read_model_scope() {
        let status = ClusterReplicaLag {
            role: "follower",
            read_model_scope: CLUSTER_READ_MODEL_SCOPE,
            applied_seq: Some(9),
            durable_max_seq: Some(9),
            lag_available: true,
            lag: Some(0),
        };
        let json = serde_json::to_value(status).expect("serializes");
        assert_eq!(
            json["read_model_scope"],
            "ledger_core_aggregates_signed_documents"
        );
        assert_eq!(json["lag_available"], true);
        assert_eq!(json["lag"], 0);
    }

    #[test]
    fn cluster_health_status_can_report_unknown_lag() {
        let status = ClusterReplicaLag {
            role: "follower",
            read_model_scope: CLUSTER_READ_MODEL_SCOPE,
            applied_seq: Some(3),
            durable_max_seq: None,
            lag_available: false,
            lag: None,
        };
        let json = serde_json::to_value(status).expect("serializes");
        assert_eq!(json["lag_available"], false);
        assert_eq!(json["lag"], serde_json::Value::Null);
    }

    #[test]
    fn act_id_from_scope_extracts_the_act_segment() {
        assert_eq!(
            act_id_from_scope("entity:E1/book:B1/act:A9"),
            Some("A9".to_owned())
        );
        assert_eq!(
            act_id_from_scope("book:B1/act:ABC/extra"),
            Some("ABC".to_owned())
        );
        assert_eq!(act_id_from_scope("entity:E1/book:B1"), None);
        assert_eq!(act_id_from_scope("settings"), None);
    }

    // ── Live-Postgres change-feed tests (§2.2/§2.3) ───────────────────────────────────────────────
    //
    // These exercise the real seq-poll and LISTEN/NOTIFY wiring against a live Postgres. They are
    // `#[ignore]` so the offline suite never needs a database; run them with `DATABASE_URL`:
    //   DATABASE_URL=postgres://... cargo test -p chancela-api --features postgres -- --ignored
    // The first opener wins the writer advisory lock (leader); the second comes up a follower. Tests
    // compare the follower to the leader (not to absolute counts) so leftover rows never break them.
    #[cfg(feature = "postgres")]
    mod live {
        use super::*;
        use chancela_ledger::Ledger;
        use chancela_store::{Store, StoreBackendSelection};

        fn live_url() -> Option<String> {
            std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
        }

        fn open(url: &str) -> Store {
            Store::open_backend(StoreBackendSelection::Postgres {
                database_url: url.to_owned(),
            })
            .expect("open postgres store")
        }

        /// Append `n` fresh events onto `leader_ledger` and persist each through the leader store,
        /// mirroring a real durable write (without emitting NOTIFY — the poll path must still retry).
        fn append_via_leader(leader: &Store, leader_ledger: &mut Ledger, n: usize) {
            for _ in 0..n {
                leader_ledger.append("api", "settings", "settings.updated", None, b"{}");
                let event = leader_ledger.events().last().expect("appended").clone();
                leader
                    .persist(|tx| tx.append_event(&event))
                    .expect("persist durable event");
            }
        }

        #[tokio::test]
        #[ignore = "requires a live Postgres (set DATABASE_URL)"]
        async fn seq_poll_reconciles_a_follower_without_any_notify() {
            let Some(url) = live_url() else { return };
            let leader = open(&url);
            assert!(leader.cluster_is_leader(), "first opener wins the lock");
            let follower_store = open(&url);
            assert!(
                !follower_store.cluster_is_leader(),
                "second opener is a follower"
            );

            // A follower node that boots empty (no prior load).
            let follower = AppState {
                store: Some(follower_store),
                ..AppState::default()
            };

            // Leader appends a first batch; the follower reconciles via the seq-poll path alone
            // (we deliberately never call `cluster_notify_append`, simulating a missed NOTIFY).
            let mut leader_ledger = leader.load().expect("leader load").ledger;
            append_via_leader(&leader, &mut leader_ledger, 3);
            follower.cluster_feed_reconcile().await;
            {
                let ledger = follower.ledger.read().await;
                assert_eq!(
                    ledger.len(),
                    leader_ledger.len(),
                    "follower covered feed reached the leader ledger"
                );
                assert!(ledger.verify().is_ok(), "reconciled chain verifies");
                assert_eq!(
                    ledger.head(),
                    leader_ledger.head(),
                    "same head as the leader"
                );
            }

            // A second batch must apply INCREMENTALLY (delta seam-verified onto the current head).
            append_via_leader(&leader, &mut leader_ledger, 2);
            follower.cluster_feed_reconcile().await;
            {
                let ledger = follower.ledger.read().await;
                assert_eq!(ledger.len(), leader_ledger.len());
                assert!(ledger.verify().is_ok());
                assert_eq!(ledger.head(), leader_ledger.head());
            }

            // The covered-feed lag indicator reports zero once reconciled.
            let lag = follower
                .cluster_read_lag()
                .await
                .expect("cluster lag present");
            assert_eq!(lag.role, "follower");
            assert_eq!(lag.read_model_scope, CLUSTER_READ_MODEL_SCOPE);
            assert_eq!(
                lag.lag,
                Some(0),
                "a reconciled follower reports zero covered-feed lag"
            );
        }

        #[test]
        #[ignore = "requires a live Postgres (set DATABASE_URL)"]
        fn notify_reaches_a_dedicated_listener() {
            use postgres::fallible_iterator::FallibleIterator;

            let Some(url) = live_url() else { return };
            let leader = open(&url);
            assert!(leader.cluster_is_leader());

            // A dedicated peripheral listener, exactly as the feed's listen thread uses.
            let mut listener =
                postgres::Client::connect(&url, postgres::NoTls).expect("listen conn");
            listener
                .batch_execute(&format!(
                    "LISTEN {}",
                    chancela_store::CLUSTER_CHANGE_CHANNEL
                ))
                .expect("LISTEN");

            leader.cluster_notify_append(4242).expect("leader NOTIFY");

            let note = listener
                .notifications()
                .timeout_iter(std::time::Duration::from_secs(5))
                .next()
                .expect("no listener error")
                .expect("a notification arrives on the change channel");
            assert_eq!(note.channel(), chancela_store::CLUSTER_CHANGE_CHANNEL);
            assert_eq!(note.payload(), "4242", "payload carries the new MAX(seq)");
        }
    }
}
