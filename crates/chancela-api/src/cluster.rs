//! **wp16 Phase 0 — Postgres advisory-lock leader election, step-down and handoff.**
//!
//! This is the API-layer half of wp16 P0; the Postgres-advisory-lock primitives live in
//! `chancela_store`'s `pg_cluster` module and are reached through the [`chancela_store::Store`]
//! `cluster_*` facade. Everything here is inert unless the durable backend is an *electing* one
//! (Postgres): the default SQLite / in-memory build compiles this module but
//! [`spawn_cluster_supervisor`] returns immediately, so the embedded editions are totally
//! unaffected.
//!
//! ## The model
//!
//! Multiple `chancela-server` nodes can point at one Postgres. The writer advisory lock is used as a
//! bounded local election primitive: the holder is treated as LEADER for this process's write path,
//! and non-holders are FOLLOWERS that reject writes with `503`. This is not a production HA
//! certification, consensus protocol, multi-writer mode, or zero-RTO promise; independent follower
//! reads, a change feed, and write redirects are later phases.
//!
//! ## Fail-closed checks
//!
//! - **Write gate.** [`crate::AppState::persist_write_through`] calls
//!   [`chancela_store::Store::cluster_assert_writable`] before every durable append. On Postgres that
//!   re-verifies — on the writer session itself — that this node still holds the advisory lock and
//!   owns the current `leader_epoch`, failing closed (`503`) on ANY doubt. A follower, or a leader
//!   that silently lost its lock, is rejected before this code commits a durable write.
//! - **Step-down.** The supervisor's leader tick re-verifies + heartbeats each poll; any failure
//!   flips the node to follower immediately.
//! - **Handoff gate.** A newly-promoted follower runs [`crate::AppState::cluster_promotion_handoff`]
//!   — catch up to durable `MAX(seq)`, re-verify the whole chain from Postgres, discard any stale
//!   in-memory tail — BEFORE it resumes writing. A durable chain that fails re-verification puts the
//!   node into DEGRADED read-only mode rather than writing over a suspect chain (§4.2 / §4.4).
//!
//! ## Config (env)
//!
//! - `CHANCELA_NODE_ROLE` = `auto` (default; elect via the lock) | `leader` | `follower` (never
//!   promote).
//! - `CHANCELA_NODE_ADDRESS` = this node's stable identity, recorded in `cluster_leader`.
//! - `CHANCELA_PROMOTE_POLL_INTERVAL` (default `1s`) — follower promotion poll period.
//! - `CHANCELA_HEARTBEAT_INTERVAL` (default `2s`) — leader heartbeat period.

use std::time::Duration;

use chancela_store::Store;

use crate::AppState;
use crate::error::ApiError;

/// This node's configured role, from `CHANCELA_NODE_ROLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeRole {
    /// Try to become leader; fall back to follower (the default polling-election mode).
    Auto,
    /// Pinned leader (campaigns for the lock exactly like `Auto`; the pin documents deployment
    /// intent).
    Leader,
    /// Pinned follower: never campaign for leadership. Stays read-only for the whole process life.
    Follower,
}

impl NodeRole {
    /// Parse the role, defaulting to [`NodeRole::Auto`] for unset / empty / unrecognised values (an
    /// unknown role must never hard-fail startup; the safe default is "elect via the lock").
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("leader") => NodeRole::Leader,
            Some("follower") => NodeRole::Follower,
            _ => NodeRole::Auto,
        }
    }

    /// Whether this role is allowed to campaign for leadership (only a pinned follower is not).
    pub(crate) fn may_promote(self) -> bool {
        !matches!(self, NodeRole::Follower)
    }
}

/// The pure role state a node can be in, cluster-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoleState {
    /// Not the writer — read-only, rejects writes with `503`.
    Follower,
    /// The writer-leader — the only node that appends.
    Leader,
}

/// The outcome of a lock/liveness operation the supervisor observed this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockEvent {
    /// A follower acquired the writer advisory lock.
    Acquired,
    /// A leader confirmed it still holds the lock + owns the epoch.
    Held,
    /// A leader lost the lock / epoch / its session — must step down (fail-closed).
    Lost,
    /// A follower's promotion attempt found the lock still held by the live leader.
    Unavailable,
}

/// **The pure election state machine.** Given the current role, the configured [`NodeRole`], and the
/// observed [`LockEvent`], compute the next role — fail-closed (a leader that lost the lock, or is
/// even unsure, becomes a follower; a pinned follower never becomes leader). Unit-tested without a
/// DB and used verbatim by the live supervisor so the two can never drift.
pub(crate) fn transition(current: RoleState, role: NodeRole, event: LockEvent) -> RoleState {
    match (current, event) {
        // A follower is promoted only by actually acquiring the lock, and only if allowed to lead.
        (RoleState::Follower, LockEvent::Acquired) if role.may_promote() => RoleState::Leader,
        (RoleState::Follower, _) => RoleState::Follower,
        // A leader steps down the instant it cannot prove it still holds the lock (fail-closed).
        (RoleState::Leader, LockEvent::Lost) | (RoleState::Leader, LockEvent::Unavailable) => {
            RoleState::Follower
        }
        (RoleState::Leader, _) => RoleState::Leader,
    }
}

/// Resolved cluster supervisor config.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClusterConfig {
    /// This node's configured role.
    pub role: NodeRole,
    /// Follower promotion poll period.
    pub poll_interval: Duration,
    /// Leader heartbeat period.
    pub heartbeat_interval: Duration,
}

impl ClusterConfig {
    /// Resolve from the environment, clamping intervals to a sane minimum so a misconfig can never
    /// busy-spin the poll loop.
    pub(crate) fn from_env() -> Self {
        Self {
            role: NodeRole::parse(std::env::var("CHANCELA_NODE_ROLE").ok().as_deref()),
            poll_interval: env_duration_secs("CHANCELA_PROMOTE_POLL_INTERVAL", 1),
            heartbeat_interval: env_duration_secs("CHANCELA_HEARTBEAT_INTERVAL", 2),
        }
    }
}

/// Parse a whole-seconds duration from `var`, falling back to `default_secs`; clamps to `>= 1s`.
fn env_duration_secs(var: &str, default_secs: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default_secs)
        .max(1);
    Duration::from_secs(secs)
}

/// What one supervisor poll produced.
#[derive(Debug)]
enum Tick {
    /// Still the leader (verified + heartbeated).
    StillLeader,
    /// Was leader, lost it — stepped down to follower (fail-closed).
    SteppedDown,
    /// Still a follower (or pinned follower).
    StillFollower,
    /// Just won the lock — the caller must run the handoff before writing.
    Promoted,
    /// A transient poll error (logged; the loop retries next tick).
    Error(String),
}

/// Mount the leader-election supervisor as a background task. No-op unless the backend is an
/// electing one (Postgres): the default SQLite / in-memory build spawns nothing. Must be called from
/// within the server's tokio runtime (it is, from [`crate::app`]).
pub(crate) fn spawn_cluster_supervisor(state: AppState) {
    let Some(store) = state.store.clone() else {
        return;
    };
    if !store.cluster_election_enabled() {
        return;
    }
    let config = ClusterConfig::from_env();
    eprintln!(
        "cluster: leader-election supervisor active (role={:?}, poll={:?}, heartbeat={:?}); \
         this node booted as {}",
        config.role,
        config.poll_interval,
        config.heartbeat_interval,
        if store.cluster_is_leader() {
            "LEADER"
        } else {
            "follower"
        }
    );
    tokio::spawn(async move { supervisor_loop(state, store, config).await });
}

/// The supervisor poll loop: a leader re-verifies + heartbeats each tick (stepping down on any
/// failure); a follower attempts promotion and, on success, runs the failover handoff before writes
/// resume.
async fn supervisor_loop(state: AppState, store: Store, config: ClusterConfig) {
    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_heartbeat = tokio::time::Instant::now();
    loop {
        ticker.tick().await;
        let now = tokio::time::Instant::now();
        let want_heartbeat = now.duration_since(last_heartbeat) >= config.heartbeat_interval;
        // Run the (blocking) Postgres lock/liveness ops off the async worker so a partition to the DB
        // stalls this task, never a runtime worker.
        let store_tick = store.clone();
        let role = config.role;
        let tick = match tokio::task::spawn_blocking(move || {
            cluster_tick(&store_tick, role, want_heartbeat)
        })
        .await
        {
            Ok(tick) => tick,
            Err(_) => continue,
        };
        match tick {
            Tick::StillLeader => {
                if want_heartbeat {
                    last_heartbeat = now;
                }
            }
            Tick::SteppedDown => {
                eprintln!(
                    "cluster: STEPPED DOWN — lost the writer advisory lock / leader_epoch / DB \
                     session; now a read-only follower, writes return 503 until re-elected"
                );
            }
            Tick::StillFollower => {}
            Tick::Promoted => {
                eprintln!(
                    "cluster: won the writer advisory lock — running failover handoff (catch up to \
                     durable MAX(seq) + re-verify the chain) before resuming writes"
                );
                store.cluster_disable_writes();
                match state.cluster_promotion_handoff().await {
                    Ok(()) => {
                        store.cluster_enable_writes();
                        last_heartbeat = tokio::time::Instant::now();
                        eprintln!(
                            "cluster: promotion handoff complete — now LEADER at epoch {}; writes \
                             resumed with an intact, caught-up chain",
                            store.cluster_leader_epoch()
                        );
                    }
                    Err(e) => {
                        store.cluster_disable_writes();
                        eprintln!(
                            "cluster: promotion handoff FAILED ({e:?}) — holding the lock in \
                             DEGRADED read-only mode (no writes) rather than writing over a suspect \
                             chain; operator attention required"
                        );
                    }
                }
            }
            Tick::Error(e) => {
                eprintln!("cluster: election poll error ({e}); retrying next tick");
            }
        }
    }
}

/// One blocking supervisor poll. Decides the action from the current role, performs the lock/liveness
/// op, and folds the outcome through the pure [`transition`] so behaviour matches the unit-tested
/// state machine exactly.
fn cluster_tick(store: &Store, role: NodeRole, want_heartbeat: bool) -> Tick {
    let current = if store.cluster_is_leader() {
        RoleState::Leader
    } else {
        RoleState::Follower
    };
    match current {
        RoleState::Leader => {
            // Fail-closed fence: still hold the lock + own the epoch (and, when due, heartbeat)?
            // Short-circuits so a failed fence never attempts a heartbeat on a dead session.
            let lost = store.cluster_verify_leader().is_err()
                || (want_heartbeat && store.cluster_heartbeat().is_err());
            let event = if lost {
                LockEvent::Lost
            } else {
                LockEvent::Held
            };
            match transition(current, role, event) {
                RoleState::Leader => Tick::StillLeader,
                RoleState::Follower => Tick::SteppedDown,
            }
        }
        RoleState::Follower => {
            if !role.may_promote() {
                return Tick::StillFollower;
            }
            let event = match store.cluster_try_promote() {
                Ok(true) => LockEvent::Acquired,
                Ok(false) => LockEvent::Unavailable,
                Err(e) => return Tick::Error(e.to_string()),
            };
            match transition(current, role, event) {
                RoleState::Leader => Tick::Promoted,
                RoleState::Follower => Tick::StillFollower,
            }
        }
    }
}

fn validate_handoff_ledger_len(
    loaded_len: usize,
    durable_max_seq: Option<i64>,
) -> Result<(), String> {
    match durable_max_seq {
        Some(max) if max < 0 => Err(format!("durable MAX(seq) is negative: {max}")),
        Some(max) => {
            let expected = i64::try_from(loaded_len)
                .map_err(|_| format!("loaded ledger length {loaded_len} does not fit i64"))?;
            let actual = max
                .checked_add(1)
                .ok_or_else(|| format!("durable MAX(seq) {max} cannot be incremented"))?;
            if expected == actual {
                Ok(())
            } else {
                Err(format!(
                    "loaded ledger length {loaded_len} does not match durable MAX(seq) {max}"
                ))
            }
        }
        None if loaded_len == 0 => Ok(()),
        None => Err(format!(
            "durable MAX(seq) is NULL but loaded ledger length is {loaded_len}"
        )),
    }
}

impl AppState {
    /// **Promotion handoff gate (§4.2 / §4.4).** Run by a newly-promoted follower AFTER it wins the
    /// advisory lock and BEFORE its first append: re-read the authoritative durable state from
    /// Postgres (which re-verifies the whole hash chain), verify that loaded ledger length matches
    /// durable `MAX(seq)`, reload the durable projections needed by write handlers, and only then
    /// swap the durable state into memory. Any read, verification, or length mismatch fails closed:
    /// the node stays read-only/degraded rather than writing over uncertain state. A no-op when
    /// there is no store.
    ///
    /// Because the reload makes in-memory `events.len()` equal durable `MAX(seq)+1`, the first new
    /// append gets the correct next `seq` with the genuine durable head as its `prev_hash` — no gap,
    /// no duplicate, no reorder.
    pub(crate) async fn cluster_promotion_handoff(&self) -> Result<(), ApiError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        // wp28-soak BUG-1 (site 3): `load` / `cluster_durable_max_seq` / `all_signed_documents` /
        // `all_pending_cmd_sessions` are SYNCHRONOUS `postgres` store ops (their connection is driven
        // by an internal `block_on`). This fn is `.await`ed on the supervisor's tokio worker during
        // failover, so calling them inline panicked ("Cannot start a runtime from within a runtime")
        // and aborted the promoting node on the FIRST promotion. Gather every durable read off the
        // worker in a SINGLE blocking task; the async state swap below is unchanged. Semantics are
        // preserved: any read error → DEGRADED read-only + error return, and the reads keep their
        // original relative order (load → durable MAX(seq) → signed docs → pending sessions).
        let store_read = store.clone();
        let gathered = tokio::task::spawn_blocking(move || {
            let loaded = store_read.load().map_err(|e| e.to_string())?;
            let durable_max = store_read
                .cluster_durable_max_seq()
                .map_err(|e| e.to_string())?;
            let signed = store_read
                .all_signed_documents()
                .map_err(|e| e.to_string())?;
            let pending = store_read
                .all_pending_cmd_sessions()
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((loaded, durable_max, signed, pending))
        })
        .await;
        let (loaded, durable_max, signed, pending) = match gathered {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                *self.degraded.write().await = true;
                return Err(ApiError::Internal(format!(
                    "promotion handoff durable read failed: {e}"
                )));
            }
            Err(_) => {
                *self.degraded.write().await = true;
                return Err(ApiError::Internal(
                    "promotion handoff durable-read task panicked".to_owned(),
                ));
            }
        };
        // §4.2 step d: a broken durable chain must NOT be extended — go read-only and alarm.
        if let Err(e) = &loaded.chain_status {
            *self.degraded.write().await = true;
            return Err(ApiError::Internal(format!(
                "promotion handoff: durable ledger failed re-verification ({e}); entering DEGRADED \
                 read-only mode"
            )));
        }
        let durable_len = loaded.ledger.len();
        if let Err(msg) = validate_handoff_ledger_len(durable_len, durable_max) {
            *self.degraded.write().await = true;
            return Err(ApiError::Internal(format!(
                "promotion handoff refused mismatched durable ledger state: {msg}"
            )));
        }
        // Swap the authoritative durable state in, discarding any stale in-memory tail (§4.4).
        *self.entities.write().await = loaded.entities;
        *self.books.write().await = loaded.books;
        *self.acts.write().await = loaded.acts;
        *self.follow_ups.write().await = loaded.follow_ups;
        *self.registry_extracts.write().await = loaded.registry_extracts;
        *self.ledger.write().await = loaded.ledger;
        *self.signed_documents.write().await = signed;
        *self.pending_signatures.write().await = pending;
        // The chain re-verified: lift any degraded gate this node was holding.
        *self.degraded.write().await = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_role_parses_and_defaults_to_auto() {
        assert_eq!(NodeRole::parse(Some("leader")), NodeRole::Leader);
        assert_eq!(NodeRole::parse(Some(" Follower ")), NodeRole::Follower);
        assert_eq!(NodeRole::parse(Some("AUTO")), NodeRole::Auto);
        // Unset / empty / garbage all default to Auto (never a hard boot failure).
        assert_eq!(NodeRole::parse(None), NodeRole::Auto);
        assert_eq!(NodeRole::parse(Some("")), NodeRole::Auto);
        assert_eq!(NodeRole::parse(Some("weird")), NodeRole::Auto);
    }

    #[test]
    fn only_pinned_follower_refuses_to_promote() {
        assert!(NodeRole::Auto.may_promote());
        assert!(NodeRole::Leader.may_promote());
        assert!(!NodeRole::Follower.may_promote());
    }

    #[test]
    fn auto_follower_promotes_on_acquiring_the_lock() {
        assert_eq!(
            transition(RoleState::Follower, NodeRole::Auto, LockEvent::Acquired),
            RoleState::Leader
        );
    }

    #[test]
    fn pinned_follower_never_promotes_even_on_acquire() {
        // Defence in depth: even if it somehow acquired the lock, a pinned follower stays a follower.
        assert_eq!(
            transition(RoleState::Follower, NodeRole::Follower, LockEvent::Acquired),
            RoleState::Follower
        );
    }

    #[test]
    fn follower_stays_follower_while_lock_unavailable() {
        assert_eq!(
            transition(RoleState::Follower, NodeRole::Auto, LockEvent::Unavailable),
            RoleState::Follower
        );
    }

    #[test]
    fn leader_stays_leader_while_lock_held() {
        assert_eq!(
            transition(RoleState::Leader, NodeRole::Auto, LockEvent::Held),
            RoleState::Leader
        );
    }

    #[test]
    fn leader_steps_down_on_lost_lock_fail_closed() {
        // The core fail-closed transition: a leader that cannot prove it still holds the lock becomes
        // a follower immediately, regardless of configured role.
        assert_eq!(
            transition(RoleState::Leader, NodeRole::Leader, LockEvent::Lost),
            RoleState::Follower
        );
        assert_eq!(
            transition(RoleState::Leader, NodeRole::Auto, LockEvent::Unavailable),
            RoleState::Follower
        );
    }

    #[test]
    fn full_lifecycle_auto_follower_to_leader_and_back() {
        let role = NodeRole::Auto;
        // Boots as a follower behind a live leader.
        let mut s = RoleState::Follower;
        s = transition(s, role, LockEvent::Unavailable);
        assert_eq!(s, RoleState::Follower);
        // Old leader dies → this follower wins the lock → promotes.
        s = transition(s, role, LockEvent::Acquired);
        assert_eq!(s, RoleState::Leader);
        // Leads for a while.
        s = transition(s, role, LockEvent::Held);
        assert_eq!(s, RoleState::Leader);
        // Then loses its DB session → steps down (fail-closed).
        s = transition(s, role, LockEvent::Lost);
        assert_eq!(s, RoleState::Follower);
    }

    #[test]
    fn cluster_config_from_env_clamps_and_defaults() {
        // Defaults (env unset in this test process): 1s poll, 2s heartbeat, auto role.
        let cfg = ClusterConfig::from_env();
        assert!(cfg.poll_interval >= Duration::from_secs(1));
        assert!(cfg.heartbeat_interval >= Duration::from_secs(1));
    }

    #[test]
    fn env_duration_clamps_to_one_second_minimum() {
        // A garbage / zero value must never yield a busy-spin (0s) interval.
        assert_eq!(
            env_duration_secs("CHANCELA_NO_SUCH_VAR_XYZ", 0),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn handoff_ledger_len_validation_fails_closed_on_mismatch() {
        assert!(validate_handoff_ledger_len(0, None).is_ok());
        assert!(validate_handoff_ledger_len(1, Some(0)).is_ok());
        assert!(validate_handoff_ledger_len(3, Some(2)).is_ok());

        assert!(validate_handoff_ledger_len(1, None).is_err());
        assert!(validate_handoff_ledger_len(2, Some(2)).is_err());
        assert!(validate_handoff_ledger_len(0, Some(0)).is_err());
        assert!(validate_handoff_ledger_len(1, Some(-1)).is_err());
        assert!(validate_handoff_ledger_len(1, Some(i64::MAX)).is_err());
    }

    #[tokio::test]
    async fn cluster_not_leader_error_maps_to_503() {
        use axum::body::to_bytes;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;

        let response = AppState::not_leader_error().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("não é o líder"),
            "not-leader body is returned: {body}"
        );
    }
}
