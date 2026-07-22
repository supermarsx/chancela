//! **wp16 Phase 4 — consolidated chaos / failover / split-brain resilience suite.**
//!
//! The user demanded *extensive* proof that the single-writer cluster is resilient and fail-safe.
//! This module is the home for that proof. It is organised by the plan's §9 scenarios and split in
//! two layers:
//!
//! 1. **Offline, in-process simulations (run in CI on every `cargo test`).** A real N-node cluster
//!    cannot run in this sandbox, so these drive the *exact same pure cores the live code uses* —
//!    [`crate::cluster::transition`] (election state machine), [`crate::cluster_feed::apply_delta`]
//!    (fail-closed delta apply), [`crate::cluster_route::route_write`] (write redirect), and
//!    [`crate::cluster_watchdog::watchdog_decide`] (self-fence) — over a tiny simulator of a single
//!    Postgres advisory lock shared by several members. Because the live loops call these same
//!    functions verbatim, a green simulation is a real (not theatrical) correctness signal for the
//!    decision logic and the hash-chain invariants.
//! 2. **Live multi-node scenarios (`#[cfg(feature = "postgres")]`, `#[ignore]`).** These open several
//!    real [`chancela_store::Store`] handles against ONE Postgres and exercise the actual advisory
//!    lock / epoch / handoff end-to-end. They are `#[ignore]` so the offline suite never needs a
//!    server; run them against a throwaway Postgres with:
//!    `DATABASE_URL=postgres://... cargo test -p chancela-api --features postgres -- --ignored`.
//!
//! ## What still needs a REAL soak run (honest, per plan §9.5)
//!
//! Green here is necessary but NOT sufficient to claim production HA for a legal ledger. What these
//! tests do NOT and cannot cover in-sandbox: long-duration randomized chaos soak, real cross-host
//! network partitions, load-balancer behaviour under failover, RTO under production latency, and the
//! wedged-but-TCP-alive leader whose session Postgres must reap before a peer can promote. Those
//! require a documented multi-node soak run (`docs/HA-FAILOVER.md`) before trusting real data.

use std::sync::Arc;
use std::sync::Mutex;

use chancela_ledger::{Event, Ledger};

use crate::cluster::{LockEvent, NodeRole, RoleState, transition};
use crate::cluster_feed::{DeltaOutcome, apply_delta};
use crate::cluster_route::{WriteMode, WriteRoute, route_write};
use crate::cluster_watchdog::{WatchdogAction, WatchdogObservation, watchdog_decide};
use axum::http::Method;

// ================================================================================================
// A tiny in-process model of ONE Postgres advisory lock shared by N members.
// ================================================================================================
//
// It mirrors the two properties the whole design rests on (plan §1.2): (1) at most ONE session holds
// the key at a time — `pg_try_advisory_lock` succeeds for exactly one and fails for the rest; and
// (2) the lock auto-releases when its holding session "dies". A monotonic `epoch` is bumped on each
// acquisition, exactly as `ensure_cluster_table_and_bump_epoch` does while holding the lock.

#[derive(Default)]
struct SharedLock {
    inner: Mutex<LockInner>,
}

#[derive(Default)]
struct LockInner {
    holder: Option<usize>,
    epoch: i64,
}

impl SharedLock {
    /// `pg_try_advisory_lock`: succeeds (and bumps the epoch) iff currently unheld. Returns the epoch
    /// the winner now owns, or `None` if the lock is held by someone else.
    fn try_acquire(&self, node: usize) -> Option<i64> {
        let mut inner = self.inner.lock().unwrap();
        match inner.holder {
            Some(h) if h != node => None,
            _ => {
                inner.holder = Some(node);
                inner.epoch += 1;
                Some(inner.epoch)
            }
        }
    }

    /// Session death (crash / partition to PG): the holder releases the lock.
    fn release_if_holder(&self, node: usize) {
        let mut inner = self.inner.lock().unwrap();
        if inner.holder == Some(node) {
            inner.holder = None;
        }
    }

    fn current_epoch(&self) -> i64 {
        self.inner.lock().unwrap().epoch
    }

    fn holder(&self) -> Option<usize> {
        self.inner.lock().unwrap().holder
    }
}

/// A simulated member. `role` is driven ONLY through the real [`transition`] state machine so the
/// simulation can never diverge from the live supervisor's decisions.
struct Member {
    id: usize,
    node_role: NodeRole,
    role: RoleState,
    my_epoch: i64,
}

impl Member {
    fn new(id: usize, node_role: NodeRole) -> Self {
        Self {
            id,
            node_role,
            role: RoleState::Follower,
            my_epoch: -1,
        }
    }

    /// One promotion poll: try the lock; fold the outcome through the real state machine.
    fn poll_promote(&mut self, lock: &SharedLock) {
        if self.role != RoleState::Follower {
            return;
        }
        // A pinned follower never contends for the lock (mirrors `acquire_writer_lock` returning
        // early), so it can never even transiently hold it and block a real candidate.
        if !self.node_role.may_promote() {
            self.role = transition(self.role, self.node_role, LockEvent::Unavailable);
            return;
        }
        let event = match lock.try_acquire(self.id) {
            Some(epoch) => {
                self.my_epoch = epoch;
                LockEvent::Acquired
            }
            None => LockEvent::Unavailable,
        };
        self.role = transition(self.role, self.node_role, event);
    }

    /// One leader verify tick: still the sole holder AND still own the current epoch? Any doubt steps
    /// down through the real state machine (fail-closed).
    fn poll_verify(&mut self, lock: &SharedLock) {
        if self.role != RoleState::Leader {
            return;
        }
        let holds = lock.holder() == Some(self.id) && lock.current_epoch() == self.my_epoch;
        let event = if holds {
            LockEvent::Held
        } else {
            LockEvent::Lost
        };
        self.role = transition(self.role, self.node_role, event);
    }

    fn is_leader(&self) -> bool {
        self.role == RoleState::Leader
    }
}

/// Drive a whole cluster to a stable state: everyone polls to promote, then every leader verifies.
fn settle(members: &mut [Member], lock: &SharedLock) {
    for m in members.iter_mut() {
        m.poll_promote(lock);
    }
    for m in members.iter_mut() {
        m.poll_verify(lock);
    }
}

// ================================================================================================
// §9.2 — ELECTION: N candidates contend → exactly ONE leader, the rest followers.
// ================================================================================================

#[test]
fn election_yields_exactly_one_leader_among_n_candidates() {
    let lock = SharedLock::default();
    let mut members: Vec<Member> = (0..5).map(|i| Member::new(i, NodeRole::Auto)).collect();
    settle(&mut members, &lock);

    let leaders = members.iter().filter(|m| m.is_leader()).count();
    assert_eq!(
        leaders, 1,
        "exactly one node may win the single advisory lock"
    );
    assert_eq!(
        members.iter().filter(|m| !m.is_leader()).count(),
        4,
        "every other node is a follower"
    );
    assert!(
        lock.holder().is_some(),
        "the winner physically holds the lock"
    );
}

#[test]
fn a_pinned_follower_never_wins_even_if_it_reaches_the_lock_first() {
    let lock = SharedLock::default();
    // The pinned follower polls first; it must refuse leadership regardless.
    let mut members = vec![
        Member::new(0, NodeRole::Follower),
        Member::new(1, NodeRole::Auto),
    ];
    settle(&mut members, &lock);
    assert!(!members[0].is_leader(), "a pinned follower never leads");
    assert!(members[1].is_leader(), "the auto node takes leadership");
}

// ================================================================================================
// §9.3 — FAILOVER: kill the leader → a follower promotes, bumps epoch, catches up with NO seq gap /
// duplicate and an intact hash-chain across the handoff.
// ================================================================================================

/// Append `n` self-consistent events onto a fresh ledger (the leader's durable chain).
fn leader_chain(n: usize) -> Ledger {
    let mut ledger = Ledger::new();
    for _ in 0..n {
        ledger.append("api", "settings", "settings.updated", None, b"{}");
    }
    ledger
}

/// Assert a ledger is a dense `0..len` run with an intact backward hash-chain (no gap, no dup, no
/// fork).
fn assert_dense_and_intact(ledger: &Ledger) {
    let events = ledger.events();
    for (i, e) in events.iter().enumerate() {
        assert_eq!(
            e.seq, i as u64,
            "seq must be the dense row index (no gap/dup)"
        );
    }
    assert_eq!(
        ledger.verify(),
        Ok(events.len() as u64),
        "the whole hash-chain must re-verify"
    );
}

#[test]
fn failover_handoff_preserves_a_dense_intact_chain_with_no_gap_or_duplicate() {
    let lock = SharedLock::default();
    let mut leader = Member::new(0, NodeRole::Auto);
    let mut follower = Member::new(1, NodeRole::Auto);
    leader.poll_promote(&lock);
    follower.poll_promote(&lock);
    assert!(leader.is_leader() && !follower.is_leader());
    let epoch_before = leader.my_epoch;

    // The leader wrote a durable chain; the follower had only replicated a prefix (it lagged the last
    // two appends the dying leader committed).
    let durable = leader_chain(7);
    let mut follower_ledger = Ledger::try_from_events(durable.events()[..5].to_vec()).0;

    // Leader crashes → its session drops → the advisory lock auto-releases.
    lock.release_if_holder(leader.id);
    leader.poll_verify(&lock);
    assert!(!leader.is_leader(), "a crashed leader is no longer leader");

    // The follower promotes and fences the old leader with a strictly higher epoch.
    follower.poll_promote(&lock);
    assert!(follower.is_leader(), "the follower promotes");
    assert!(
        follower.my_epoch > epoch_before,
        "each promotion bumps the monotonic leader_epoch (fence)"
    );

    // Handoff catch-up (§4.2 step 3): the new leader applies the durable tail it was missing BEFORE
    // its first append. `apply_delta` is the exact core the live handoff/feed uses.
    let outcome = apply_delta(&mut follower_ledger, &durable.events()[5..]);
    assert!(
        matches!(outcome, DeltaOutcome::Applied { new_len: 7, .. }),
        "catch-up cleanly extends the chain: {outcome:?}"
    );
    assert_dense_and_intact(&follower_ledger);
    assert_eq!(
        follower_ledger.head(),
        durable.head(),
        "the new leader holds the exact durable head — no fork across the handoff"
    );

    // The first NEW append after promotion gets MAX(seq)+1 with the genuine durable head as prev_hash.
    follower_ledger.append("api", "settings", "settings.updated", None, b"{}");
    assert_eq!(follower_ledger.len(), 8);
    assert_eq!(follower_ledger.events()[7].seq, 7, "next seq is MAX(seq)+1");
    assert_dense_and_intact(&follower_ledger);
}

// ================================================================================================
// §9.4 — SPLIT-BRAIN / PARTITION (the critical ones): no two writers, no fork, stale epoch fenced.
// ================================================================================================

#[test]
fn two_nodes_never_both_hold_the_lock_under_contention() {
    let lock = SharedLock::default();
    let mut a = Member::new(0, NodeRole::Auto);
    let mut b = Member::new(1, NodeRole::Auto);
    // Both race for the lock repeatedly; the single-holder guarantee must never yield two leaders.
    for _ in 0..50 {
        a.poll_promote(&lock);
        b.poll_promote(&lock);
        a.poll_verify(&lock);
        b.poll_verify(&lock);
        assert!(
            !(a.is_leader() && b.is_leader()),
            "two sessions must never both be leader (PG single-holder guarantee)"
        );
    }
    assert!(a.is_leader() ^ b.is_leader(), "exactly one is the leader");
}

#[test]
fn a_leader_partitioned_from_postgres_steps_down_and_cannot_write() {
    // Scenario A (plan §7.1): the leader loses its PG session → the lock is released → it must fence
    // itself (its verify sees the lock gone) and its write gate closes. Model the write gate as
    // "leader role required"; a stepped-down node's writes are refused.
    let lock = SharedLock::default();
    let mut leader = Member::new(0, NodeRole::Auto);
    leader.poll_promote(&lock);
    assert!(leader.is_leader());

    // Partition to PG: the session dies, releasing the lock.
    lock.release_if_holder(leader.id);
    leader.poll_verify(&lock);

    assert!(
        !leader.is_leader(),
        "a partitioned leader fails its verify and steps down (fail-closed)"
    );
    // The watchdog reaches the same verdict on a verify failure/timeout — belt and suspenders.
    assert_eq!(
        watchdog_decide(WatchdogObservation::VerifyTimedOut),
        WatchdogAction::Fence,
        "the self-fence watchdog independently fences a leader it cannot re-verify"
    );
}

#[test]
fn a_stale_epoch_zombie_leader_is_fenced() {
    // A deposed leader that still believes it leads (`my_epoch` frozen at the old value) is fenced the
    // moment it verifies against the bumped durable epoch (§4.3). Simulate: node 0 leads at epoch 1,
    // node 1 takes over (epoch 2); node 0 wakes still thinking it is leader.
    let lock = SharedLock::default();
    let mut zombie = Member::new(0, NodeRole::Auto);
    zombie.poll_promote(&lock);
    let old_epoch = zombie.my_epoch;

    // A new leader takes the lock (after the old session dropped) → epoch bumps past the zombie's.
    lock.release_if_holder(zombie.id);
    let mut successor = Member::new(1, NodeRole::Auto);
    successor.poll_promote(&lock);
    assert!(lock.current_epoch() > old_epoch);

    // The zombie force-believes it is still leader, then verifies: it neither holds the lock nor owns
    // the current epoch ⇒ fenced.
    zombie.role = RoleState::Leader; // simulate the "hasn't noticed yet" window
    zombie.poll_verify(&lock);
    assert!(
        !zombie.is_leader(),
        "a stale-epoch zombie is fenced on its next verify — it cannot write over the new leader"
    );
}

#[test]
fn a_duplicate_seq_delta_can_never_fork_the_chain() {
    // The last-line-of-defence: even if a second writer somehow produced an event at an already-used
    // seq, a follower/new-leader applying it detects the fork at the seam and REJECTS it fail-closed
    // (mirroring the durable `events.seq` PK collision, plan §7.3). No fork is ever adopted.
    let durable = leader_chain(4);
    let mut node = Ledger::try_from_events(durable.events().to_vec()).0;

    // A rogue "event" claiming seq 3 (already committed) with a divergent prev_hash — a fork attempt.
    let mut forked = durable.events()[3].clone();
    forked.prev_hash = [0xEE; 32];
    let outcome = apply_delta(&mut node, std::slice::from_ref(&forked));
    // seq 3 <= head(4) ⇒ trimmed as already-applied ⇒ NoOp (never adopts the divergent bytes).
    assert_eq!(
        outcome,
        DeltaOutcome::NoOp,
        "a duplicate-seq event is dropped, never adopted as a fork"
    );
    assert_dense_and_intact(&node);
}

// ================================================================================================
// §9.2 — FOLLOWER FRESHNESS: converges to the leader head; a forking delta is rejected + reloads.
// ================================================================================================

#[test]
fn a_follower_converges_to_the_leader_head_via_incremental_deltas() {
    let durable = leader_chain(10);
    let mut follower = Ledger::new();
    // Apply the leader's chain in three staggered deltas (as NOTIFY + poll would deliver them).
    for range in [0..4usize, 4..7, 7..10] {
        let outcome = apply_delta(&mut follower, &durable.events()[range]);
        assert!(matches!(outcome, DeltaOutcome::Applied { .. }));
    }
    assert_eq!(follower.len(), 10, "the follower caught up to the leader");
    assert_eq!(
        follower.head(),
        durable.head(),
        "same head, bounded lag → 0"
    );
    assert_dense_and_intact(&follower);
}

#[test]
fn a_delta_that_would_fork_is_rejected_and_triggers_a_reload() {
    let durable = leader_chain(6);
    let mut follower = Ledger::try_from_events(durable.events()[..3].to_vec()).0;
    // A tampered delta whose seam does not extend the follower's head.
    let mut forked: Vec<Event> = durable.events()[3..].to_vec();
    forked[0].prev_hash = [0x01; 32];
    let outcome = apply_delta(&mut follower, &forked);
    assert!(
        matches!(outcome, DeltaOutcome::Reject(_)),
        "a forking delta is rejected fail-closed (the live feed then full-reloads)"
    );
    assert_eq!(
        follower.len(),
        3,
        "the follower is left untouched, never forked"
    );
    assert_dense_and_intact(&follower);
}

// ================================================================================================
// §9.2 — WRITE-REDIRECT DURING FAILOVER: a write on a follower 307s to the leader, or 503 when
// leaderless mid-failover — never a local follower write.
// ================================================================================================

#[test]
fn a_write_on_a_follower_redirects_to_the_leader() {
    let route = route_write(
        &Method::POST,
        false, // follower
        Some("https://leader.example:8443"),
        WriteMode::Redirect,
        "/v1/acts",
    );
    assert_eq!(
        route,
        WriteRoute::Redirect("https://leader.example:8443/v1/acts".to_owned()),
        "a follower write is redirected to the leader, never served locally"
    );
}

#[test]
fn a_write_mid_failover_with_no_known_leader_is_503_never_a_local_write() {
    // The no-leader window (t0+ → t2, plan §6.2): the follower has no fresh leader address → 503 +
    // Retry-After, NOT a local follower write and NOT a broken redirect.
    let route = route_write(&Method::POST, false, None, WriteMode::Redirect, "/v1/acts");
    assert!(
        matches!(route, WriteRoute::Unavailable(_)),
        "leaderless mid-failover ⇒ 503 + Retry-After, never a local write: {route:?}"
    );
}

// ================================================================================================
// §5.3 — SESSION / RATE-LIMIT COHERENCE UNDER FAILOVER: state set on the old leader is honored after
// failover (shared store, from P3a). Modeled with a shared-backend fake (two nodes, one Redis).
// ================================================================================================

use crate::cluster_shared_state::{SessionLookup, SessionMutation, SessionStore};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
struct SharedSessionBackend {
    map: Arc<Mutex<HashMap<String, crate::cluster_shared_state::SessionPut>>>,
}

impl SessionStore for SharedSessionBackend {
    fn put(
        &self,
        token: &str,
        put: crate::cluster_shared_state::SessionPut,
        _ttl: Duration,
    ) -> SessionMutation {
        self.map.lock().unwrap().insert(token.to_owned(), put);
        SessionMutation::Stored
    }
    fn resolve(&self, token: &str, _ttl: Duration) -> SessionLookup {
        match self.map.lock().unwrap().get(token) {
            Some(put) => SessionLookup::Found {
                user_id: put.user_id,
                issued_at_unix: put.issued_at_unix,
            },
            None => SessionLookup::NotFound,
        }
    }
    fn revoke(&self, token: &str) -> SessionMutation {
        self.map.lock().unwrap().remove(token);
        SessionMutation::Stored
    }
    fn revoke_by_digest(&self, digest: &str) -> SessionMutation {
        self.map
            .lock()
            .unwrap()
            .retain(|token, _| crate::session::session_token_digest(token) != digest);
        SessionMutation::Stored
    }
    fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> crate::cluster_shared_state::SessionListResult {
        let sessions = self
            .map
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, put)| put.user_id == user_id)
            .map(|(token, put)| crate::cluster_shared_state::SharedSessionInfo {
                session_id: put.session_id,
                token_sha256: crate::session::session_token_digest(token),
                issued_at_unix: put.issued_at_unix,
                last_seen_unix: put.issued_at_unix,
                device: put.device.clone(),
                ip: put.ip.clone(),
            })
            .collect();
        crate::cluster_shared_state::SessionListResult::Sessions(sessions)
    }
    fn clear_all(&self) -> SessionMutation {
        self.map.lock().unwrap().clear();
        SessionMutation::Stored
    }
    fn kind(&self) -> &'static str {
        "shared-fake"
    }
}

#[test]
fn a_session_minted_on_the_old_leader_is_honored_after_failover() {
    // Two handles over ONE shared backend model two nodes pointed at one Redis.
    let old_leader = SharedSessionBackend::default();
    let new_leader = old_leader.clone(); // the promoted follower shares the same Redis
    let uid = Uuid::new_v4();
    let ttl = Duration::from_secs(60);

    // A user signs in on the OLD leader.
    let issued_at_unix = 1_700_000_000;
    old_leader.put("session-tok", crate::cluster_shared_state::SessionPut::identity(uid, issued_at_unix), ttl);
    // Failover happens; the client's next request lands on the NEW leader — the session is still valid.
    assert_eq!(
        new_leader.resolve("session-tok", ttl),
        SessionLookup::Found {
            user_id: uid,
            issued_at_unix,
        },
        "a session set before failover is honored on the node that took over"
    );
    // A revoke on either node is cluster-wide (the throttle/auth stays coherent post-failover).
    new_leader.revoke("session-tok");
    assert_eq!(
        old_leader.resolve("session-tok", ttl),
        SessionLookup::NotFound
    );
}

// ================================================================================================
// LIVE multi-node scenarios (real Postgres). `#[ignore]`; run with DATABASE_URL. §9.2–9.4 end-to-end.
// ================================================================================================

#[cfg(feature = "postgres")]
mod live {
    use chancela_ledger::Ledger;
    use chancela_store::{Store, StoreBackendSelection};

    use crate::AppState;

    fn live_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
    }

    fn open(url: &str) -> Store {
        Store::open_backend(StoreBackendSelection::Postgres {
            database_url: url.to_owned(),
        })
        .expect("open postgres store")
    }

    /// Append `n` durable events through the leader (mirrors a real write; no NOTIFY so the follower
    /// must reconcile via seq-poll).
    fn append_via_leader(leader: &Store, ledger: &mut Ledger, n: usize) {
        for _ in 0..n {
            ledger.append("api", "settings", "settings.updated", None, b"{}");
            let event = ledger.events().last().expect("appended").clone();
            leader
                .persist(|tx| tx.append_event(&event))
                .expect("persist durable event");
        }
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn election_exactly_one_leader_and_the_second_is_a_follower() {
        let Some(url) = live_url() else { return };
        let a = open(&url);
        assert!(
            a.cluster_is_leader(),
            "the first opener wins the advisory lock"
        );
        let b = open(&url);
        assert!(
            !b.cluster_is_leader(),
            "a second node against the same PG is a follower, never a co-leader"
        );
        assert!(a.cluster_leader_epoch() >= 1);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    async fn failover_handoff_resumes_writing_with_no_gap_and_an_intact_chain() {
        let Some(url) = live_url() else { return };
        let leader = open(&url);
        assert!(leader.cluster_is_leader());
        let follower_store = open(&url);
        assert!(!follower_store.cluster_is_leader());

        // The leader writes a durable chain; a follower AppState replicates a prefix via the feed.
        let mut leader_ledger = leader.load().expect("leader load").ledger;
        append_via_leader(&leader, &mut leader_ledger, 4);

        let follower = AppState {
            store: Some(follower_store.clone()),
            ..AppState::default()
        };
        follower.cluster_feed_reconcile().await;

        // The leader dies → its writer session drops → the advisory lock auto-releases.
        drop(leader);

        // The follower promotes and runs the full handoff gate (catch-up + chain re-verify) BEFORE it
        // may write again.
        assert!(
            follower_store
                .cluster_try_promote()
                .expect("promotion succeeds"),
            "the follower wins the freed lock"
        );
        follower
            .cluster_promotion_handoff()
            .await
            .expect("handoff catch-up + chain re-verify succeeds");
        follower_store.cluster_enable_writes();

        // Assert the durable chain is dense + intact and the in-memory head matches durable MAX(seq).
        let reloaded = follower_store.load().expect("reload after handoff");
        let events = reloaded.ledger.events();
        for (i, e) in events.iter().enumerate() {
            assert_eq!(
                e.seq, i as u64,
                "no seq gap or duplicate across the handoff"
            );
        }
        assert_eq!(
            reloaded.ledger.verify(),
            Ok(events.len() as u64),
            "chain intact"
        );
        {
            let mem = follower.ledger.read().await;
            assert_eq!(
                mem.head(),
                reloaded.ledger.head(),
                "in-memory == durable head"
            );
        }
        drop(follower_store);
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn a_partitioned_leader_step_down_makes_writes_fail_closed() {
        let Some(url) = live_url() else { return };
        let leader = open(&url);
        assert!(leader.cluster_is_leader());
        assert!(
            leader.cluster_verify_leader().is_ok(),
            "healthy leader verifies"
        );

        // Model the watchdog / partition step-down: proactively fence.
        leader.cluster_step_down();
        assert!(
            !leader.cluster_is_leader(),
            "a fenced node is no longer leader"
        );
        assert!(
            leader.cluster_assert_writable().is_err(),
            "a stepped-down node's write gate fails closed (503 NotLeader)"
        );
        drop(leader);
    }
}
