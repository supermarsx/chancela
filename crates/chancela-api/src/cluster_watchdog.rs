//! **wp16 Phase 4 — leader self-fence watchdog: proactive, deadline-bounded fail-closed step-down.**
//!
//! P0 landed the write-path fence (every durable append re-verifies lock + `leader_epoch` before it
//! commits) and a supervisor whose leader tick re-verifies + heartbeats each poll ([`crate::cluster`]).
//! That already steps a leader down when it *notices* a lost lock. This module closes the remaining
//! **liveness** gap (plan §7.5 / §1.6): a leader that is partitioned from Postgres, or whose writer
//! session has wedged, must stop being considered writable *within a bounded deadline* — not only
//! when the next write happens to arrive, and not only if the supervisor's own verify returns.
//!
//! ## Why a *separate*, timeout-bounded task
//!
//! The supervisor runs verify + heartbeat + promotion polling on one loop and `.await`s a blocking
//! `verify` with no timeout. If the writer connection wedges (a partition where TCP never resets, or a
//! `persist`/`verify` holding the writer mutex indefinitely), that whole loop stalls: no step-down, no
//! re-election consideration. The watchdog is an **independent** task that wraps its verify in a
//! [`tokio::time::timeout`]. If leadership cannot be *proven* within the deadline — verify errors,
//! verify times out, or the task panics — it **proactively fences**: [`Store::cluster_step_down`],
//! which flips the atomic role flags to follower + writes-disabled and therefore succeeds even while
//! the writer connection is still wedged (the fence must never block on the resource it is fencing).
//!
//! ## Honest scope (what this does and does *not* solve)
//!
//! - **Safety (no fork) is already guaranteed** by P0: writes only commit on the lock-holding session
//!   and a duplicate `seq` fails the PK. The watchdog does not add safety; it adds *fast liveness* —
//!   a partitioned/wedged leader stops serving as writer quickly instead of wedging the cluster.
//! - After a fence the supervisor's next follower tick tries to re-promote; if the DB is still
//!   unreachable it stays a fenced follower (fail-closed), which is correct.
//! - A leader that is wedged but whose Postgres session is *still TCP-alive* keeps the advisory lock
//!   held DB-side, so a peer cannot promote until Postgres reaps that session. Fully resolving that
//!   still needs writer-session `statement_timeout` + `tcp_keepalives` (or process self-kill), per
//!   plan §7.5 — the watchdog fences *this* node's writes fast, but cross-node failover of a
//!   TCP-alive wedged leader is bounded by Postgres session reaping, not by this task. Documented
//!   honestly in `docs/HA-FAILOVER.md`.
//!
//! ## Config (env)
//!
//! - `CHANCELA_LEADER_WATCHDOG_INTERVAL` (default `3s`, clamped `>= 1s`) — how often the leader
//!   re-verifies, and the per-check deadline. A leader that cannot prove leadership within one
//!   interval fences. Set below `CHANCELA_NODE_STALE_AFTER` so a fenced leader stops writing well
//!   before followers would still treat its advertised address as fresh.
//!
//! Inert unless the durable backend is an electing one (Postgres): the default SQLite / in-memory
//! build compiles this module but [`spawn_leader_watchdog`] returns immediately, so the embedded
//! editions are unaffected.

use std::time::Duration;

use chancela_store::Store;

use crate::AppState;

/// What the watchdog observed about this node's leadership on one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchdogObservation {
    /// This node is not the leader — nothing for the watchdog to guard.
    NotLeader,
    /// Leadership was re-proven within the deadline: still holds the lock + owns the epoch.
    LeaderHealthy,
    /// The verify returned an error (lost lock, stolen epoch, broken/errored writer session).
    VerifyFailed,
    /// The verify did not return within the deadline (partition to Postgres / wedged writer session).
    /// This is the case the watchdog exists for: a leader that cannot even *answer* whether it still
    /// leads must be fenced rather than assumed healthy.
    VerifyTimedOut,
}

/// The action the watchdog takes for a given [`WatchdogObservation`]. Pure so it is unit-tested
/// without a database and used verbatim by the live loop, so the two can never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchdogAction {
    /// Not the leader — do nothing.
    Idle,
    /// Leadership proven — keep leading.
    Continue,
    /// **Fail-closed:** proactively step down (partition / wedge / verify failure / timeout).
    Fence,
}

/// **The pure watchdog decision.** A leader is fenced on ANY inability to *prove* it still leads —
/// an error OR a timeout are both treated as "cannot prove leadership ⇒ fail closed". Only a positive
/// re-verification within the deadline keeps it leading.
pub(crate) fn watchdog_decide(observation: WatchdogObservation) -> WatchdogAction {
    match observation {
        WatchdogObservation::NotLeader => WatchdogAction::Idle,
        WatchdogObservation::LeaderHealthy => WatchdogAction::Continue,
        WatchdogObservation::VerifyFailed | WatchdogObservation::VerifyTimedOut => {
            WatchdogAction::Fence
        }
    }
}

/// Resolved watchdog config.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WatchdogConfig {
    /// Re-verify period *and* the per-check deadline: a leader that cannot prove leadership within one
    /// interval fences.
    pub interval: Duration,
}

impl WatchdogConfig {
    /// Resolve from `CHANCELA_LEADER_WATCHDOG_INTERVAL` (whole seconds, default 3s, clamped `>= 1s` so
    /// a misconfig can never busy-spin the loop).
    pub(crate) fn from_env() -> Self {
        let secs = std::env::var("CHANCELA_LEADER_WATCHDOG_INTERVAL")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(3)
            .max(1);
        Self {
            interval: Duration::from_secs(secs),
        }
    }
}

/// Mount the leader self-fence watchdog as a background task. No-op unless the backend is an electing
/// one (Postgres); the default SQLite / in-memory build spawns nothing. Must be called from within the
/// server's tokio runtime (it is, from [`crate::app`]).
pub(crate) fn spawn_leader_watchdog(state: AppState) {
    let Some(store) = state.store.clone() else {
        return;
    };
    if !store.cluster_election_enabled() {
        return;
    }
    let config = WatchdogConfig::from_env();
    eprintln!(
        "cluster: leader self-fence watchdog active (interval/deadline={:?}); a leader that cannot \
         re-prove lock+epoch within the deadline proactively steps down (fail-closed)",
        config.interval
    );
    tokio::spawn(async move { watchdog_loop(store, config).await });
}

/// The watchdog loop: every `interval`, if this node is the leader, re-verify leadership with a
/// deadline and fence on any failure/timeout.
async fn watchdog_loop(store: Store, config: WatchdogConfig) {
    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let observation = observe(&store, config.interval).await;
        if let WatchdogAction::Fence = watchdog_decide(observation) {
            // Fail-closed fence: flip role flags (atomic — succeeds even if the writer is wedged) so
            // the write gate refuses immediately. The supervisor re-enters election on its next tick.
            store.cluster_step_down();
            eprintln!(
                "cluster: WATCHDOG FENCED this leader ({observation:?}) — proactively stepped down to \
                 a read-only follower; writes return 503 until re-elected (plan §7.5)"
            );
        }
    }
}

/// Run one deadline-bounded leadership re-verification off the blocking pool (so a DB stall never
/// blocks a runtime worker) and classify the result. A follower is [`WatchdogObservation::NotLeader`]
/// and never touches the DB.
async fn observe(store: &Store, deadline: Duration) -> WatchdogObservation {
    if !store.cluster_is_leader() {
        return WatchdogObservation::NotLeader;
    }
    let verify_store = store.clone();
    let verify = tokio::task::spawn_blocking(move || verify_store.cluster_verify_leader());
    match tokio::time::timeout(deadline, verify).await {
        // Verify returned within the deadline.
        Ok(Ok(Ok(()))) => WatchdogObservation::LeaderHealthy,
        // Verify returned an error (lost lock / stolen epoch / broken session) — it already stepped
        // the store down internally; the watchdog re-fences idempotently to be certain.
        Ok(Ok(Err(_))) => WatchdogObservation::VerifyFailed,
        // The blocking task panicked — treat as an inability to prove leadership.
        Ok(Err(_)) => WatchdogObservation::VerifyFailed,
        // The deadline elapsed with no answer — the wedged/partitioned-leader case this task exists
        // for. The spawned verify is left to unwind on its own; we fence now.
        Err(_) => WatchdogObservation::VerifyTimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_follower_is_idle_never_fenced() {
        assert_eq!(
            watchdog_decide(WatchdogObservation::NotLeader),
            WatchdogAction::Idle
        );
    }

    #[test]
    fn a_healthy_leader_keeps_leading() {
        assert_eq!(
            watchdog_decide(WatchdogObservation::LeaderHealthy),
            WatchdogAction::Continue
        );
    }

    #[test]
    fn verify_failure_fences_fail_closed() {
        // A leader that verifies false (lost lock / stolen epoch / broken session) is fenced.
        assert_eq!(
            watchdog_decide(WatchdogObservation::VerifyFailed),
            WatchdogAction::Fence
        );
    }

    #[test]
    fn a_wedged_or_partitioned_leader_times_out_and_is_fenced() {
        // The core P4 property: a leader that cannot even ANSWER whether it still leads (verify never
        // returns within the deadline — a DB partition or a wedged writer session) is fenced, not
        // assumed healthy. This is the liveness gap the watchdog closes.
        assert_eq!(
            watchdog_decide(WatchdogObservation::VerifyTimedOut),
            WatchdogAction::Fence
        );
    }

    #[test]
    fn only_a_positive_reverification_avoids_fencing() {
        // Exhaustive: every observation that is not an explicit healthy re-verification fences (or is
        // idle for a follower). There is no "assume still leader" path.
        for obs in [
            WatchdogObservation::VerifyFailed,
            WatchdogObservation::VerifyTimedOut,
        ] {
            assert_eq!(
                watchdog_decide(obs),
                WatchdogAction::Fence,
                "{obs:?} must fence"
            );
        }
        assert_ne!(
            watchdog_decide(WatchdogObservation::LeaderHealthy),
            WatchdogAction::Fence
        );
    }

    #[test]
    fn watchdog_interval_defaults_and_clamps_to_one_second() {
        // Unset in this test process → the 3s default; the resolver clamps `>= 1s` for any config so a
        // garbage / zero value can never busy-spin the loop.
        let cfg = WatchdogConfig::from_env();
        assert!(cfg.interval >= Duration::from_secs(1));
        assert_eq!(cfg.interval, Duration::from_secs(3));
    }
}
