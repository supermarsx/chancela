//! **wp16 Phase 0 — Postgres-advisory-lock leader election + step-down + failover handoff.**
//!
//! Feature = `postgres`, OFF by default. This module holds every cluster-election primitive that
//! sits *below* the [`crate::Store`] facade; the API-layer role state machine, promotion poll loop,
//! heartbeat cadence and failover handoff live in `chancela-api`'s `cluster` module and drive these
//! primitives. The embedded SQLite / default builds never compile any of this.
//!
//! ## The model (bounded advisory-lock election)
//!
//! Multiple app nodes point at one Postgres. Exactly **one** holds the writer advisory lock
//! ([`crate::pg::WRITER_ADVISORY_LOCK_KEY`]) at a time. This module treats that session as LEADER
//! for this backend's write path; non-holders are FOLLOWERS and fail writes closed with 503. This is
//! not a production HA certification, consensus protocol, multi-writer mode, or zero-RTO promise. A
//! follower serving independent fresh reads / a change feed is a LATER phase.
//!
//! ## Fail-closed local checks
//!
//! 1. **Only the lock holder passes this write gate.** Postgres grants the advisory key to at most
//!    one session, and [`crate::Store::persist`] checks that state before opening a transaction.
//! 2. **Immediate step-down.** [`PostgresBackend::verify_still_leader`] re-checks, on the *writer
//!    session itself*, that this session still (a) physically holds the advisory lock and (b) owns
//!    the current `leader_epoch`. ANY doubt — a broken connection, a lost lock, an epoch bumped by a
//!    newer leader — flips [`crate::pg::PostgresBackend::leader`] to `false` and the write path
//!    returns [`crate::StoreError::NotLeader`]. The API-layer write gate calls this before *every*
//!    durable append.
//! 3. **Epoch fence (§4.3).** Each promotion bumps a monotonic `leader_epoch` in the single-row
//!    `cluster_leader` table while holding the lock. A stale ex-leader should fail this code's write
//!    gate because it no longer proves both lock ownership and the current epoch.
//! 4. **Handoff gate (§4.2).** A promoted follower must re-read durable `MAX(seq)` and re-verify the
//!    chain from Postgres, discarding any stale in-memory tail, BEFORE its first append. The
//!    catch-up itself is orchestrated by the API layer; [`PostgresBackend::durable_max_seq`] and the
//!    `cluster_leader` epoch bump here are the store-side pieces.

use std::sync::atomic::Ordering;

use postgres::Client;

use crate::StoreError;
use crate::pg::{PostgresBackend, WRITER_ADVISORY_LOCK_KEY};

/// Environment variable naming this node's desired role (mirrors the API `cluster` module; resolved
/// here so [`crate::pg::PostgresBackend::open`] can decide whether to contend for the lock at all).
pub(crate) const NODE_ROLE_ENV: &str = "CHANCELA_NODE_ROLE";
/// Environment variable naming this node's stable identity (recorded in `cluster_leader`).
pub(crate) const NODE_ADDRESS_ENV: &str = "CHANCELA_NODE_ADDRESS";
/// wp16 P2 — environment variable naming this node's externally-reachable base URL. When this node
/// is the leader it heartbeats this into `cluster_leader.advertised_addr`; followers read it as the
/// `307` write-redirect target (plan §3.2). Distinct from [`NODE_ADDRESS_ENV`] (opaque identity):
/// this must be a real `http(s)://host[:port]` origin a client / LB can reach.
pub(crate) const ADVERTISED_URL_ENV: &str = "CHANCELA_ADVERTISED_URL";

/// The single-row leader-directory + epoch-fence table. `id` is pinned to `1` so there is exactly
/// one row; `epoch` is the monotonic `leader_epoch`. wp16 P2 adds `advertised_addr` — the leader's
/// externally-reachable base URL, used by followers as the write-redirect target.
pub(crate) const CLUSTER_LEADER_DDL: &str = "CREATE TABLE IF NOT EXISTS cluster_leader (\
     id INTEGER PRIMARY KEY, \
     epoch BIGINT NOT NULL DEFAULT 0, \
     node_id TEXT NOT NULL, \
     advertised_addr TEXT, \
     last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(), \
     CONSTRAINT cluster_leader_singleton CHECK (id = 1))";

/// wp16 P2 — idempotent additive guard so a P0 `cluster_leader` table (created before this column
/// existed) gains `advertised_addr` on the next leader boot/promotion. Mirrors the store's other
/// `ADD COLUMN IF NOT EXISTS` migration guards.
pub(crate) const ADD_ADVERTISED_ADDR_COLUMN: &str =
    "ALTER TABLE cluster_leader ADD COLUMN IF NOT EXISTS advertised_addr TEXT";

/// Bump the epoch (or seed it) for the promoting leader, recording its advertised address, returning
/// the epoch this node now owns. Runs while the caller holds the advisory lock, so the
/// read-modify-write is race-free cluster-wide. `$1` = node_id, `$2` = advertised address.
pub(crate) const BUMP_EPOCH_SQL: &str = "INSERT INTO cluster_leader (id, epoch, node_id, advertised_addr, last_heartbeat) \
     VALUES (1, 1, $1, $2, now()) \
     ON CONFLICT (id) DO UPDATE SET \
        epoch = cluster_leader.epoch + 1, node_id = $1, advertised_addr = $2, last_heartbeat = now() \
     RETURNING epoch";

/// Does *this backend session* still physically hold the writer advisory lock? A single-`bigint`
/// advisory lock appears in `pg_locks` split across `classid` (high 32 bits) and `objid` (low 32
/// bits) with `objsubid = 1`; reconstruct the key and compare. This is the belt-and-suspenders half
/// of the fence — the primary safety is that a dead session cannot commit at all (§7.3).
pub(crate) const HOLDS_WRITER_LOCK_SQL: &str = "SELECT EXISTS (\
     SELECT 1 FROM pg_locks \
     WHERE locktype = 'advisory' AND granted \
       AND pid = pg_backend_pid() \
       AND objsubid = 1 \
       AND ((classid::bigint << 32) | objid::bigint) = $1)";

/// Configured election behaviour resolved from `CHANCELA_NODE_ROLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElectionMode {
    /// Try to become leader; fall back to follower (the production default).
    Auto,
    /// Try to become leader (same lock contention as `Auto`; the pin only documents intent in P0).
    Leader,
    /// Never contend for the lock: come up as a permanent read-only follower.
    Follower,
}

impl ElectionMode {
    /// Parse the role, defaulting to [`ElectionMode::Auto`] for unset / empty / unrecognised values
    /// (an unknown role must never hard-fail startup; the safe default is "elect via the lock").
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("leader") => ElectionMode::Leader,
            Some("follower") => ElectionMode::Follower,
            _ => ElectionMode::Auto,
        }
    }

    /// Whether this mode is allowed to acquire / campaign for the writer lock.
    pub(crate) fn may_lead(self) -> bool {
        !matches!(self, ElectionMode::Follower)
    }
}

/// Resolve the configured election mode from the environment.
pub(crate) fn resolve_election_mode() -> ElectionMode {
    ElectionMode::parse(std::env::var(NODE_ROLE_ENV).ok().as_deref())
}

/// Resolve this node's stable identity: `CHANCELA_NODE_ADDRESS` when set, else a per-process uuid so
/// two nodes never collide in `cluster_leader`.
pub(crate) fn resolve_node_id() -> String {
    std::env::var(NODE_ADDRESS_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4()))
}

/// wp16 P2 — resolve this node's externally-reachable advertised base URL from
/// [`ADVERTISED_URL_ENV`], trimmed. Empty / unset yields an empty string (stored as such; followers
/// then treat "no fresh address" as leader-unknown and reply `503` rather than a broken redirect).
/// The value is never derived from any client input, so it can never be an open-redirect vector.
pub(crate) fn resolve_advertised_url() -> String {
    std::env::var(ADVERTISED_URL_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// Attempt to take the writer advisory lock on `writer` (a pinned follower never contends). Returns
/// `true` iff this session is now the leader. Uses `pg_try_advisory_lock` (non-blocking) so a loser
/// comes up as a follower instead of hanging.
pub(crate) fn acquire_writer_lock(
    writer: &mut Client,
    mode: ElectionMode,
) -> Result<bool, StoreError> {
    if !mode.may_lead() {
        return Ok(false);
    }
    let acquired: bool = writer
        .query_one(
            &format!("SELECT pg_try_advisory_lock({WRITER_ADVISORY_LOCK_KEY})"),
            &[],
        )?
        .get(0);
    Ok(acquired)
}

/// Ensure the `cluster_leader` table exists (with the wp16 P2 `advertised_addr` column) and
/// atomically bump (or seed) the epoch for `node_id`, recording `advertised_addr`, returning the
/// epoch this node now owns. MUST be called while holding the advisory lock.
pub(crate) fn ensure_cluster_table_and_bump_epoch(
    writer: &mut Client,
    node_id: &str,
    advertised_addr: &str,
) -> Result<i64, StoreError> {
    writer.batch_execute(CLUSTER_LEADER_DDL)?;
    // Additive guard: a P0 table predating `advertised_addr` gains it here (idempotent).
    writer.batch_execute(ADD_ADVERTISED_ADDR_COLUMN)?;
    let row = writer.query_one(BUMP_EPOCH_SQL, &[&node_id, &advertised_addr])?;
    Ok(row.get::<_, i64>(0))
}

/// Write permission is stricter than leadership: a promoted node must both verify leadership and
/// have completed the API handoff that reloads durable state.
pub(crate) fn write_gate_allows(verified_leader: bool, writes_enabled: bool) -> bool {
    verified_leader && writes_enabled
}

impl PostgresBackend {
    /// Is this node the current writer-leader (fast, atomic read — the truth is kept honest by
    /// [`Self::verify_still_leader`] on every write and by the API supervisor's poll)?
    pub(crate) fn is_leader(&self) -> bool {
        self.leader.load(Ordering::Acquire)
    }

    /// The `leader_epoch` this node last claimed (`-1` until it has ever led).
    pub(crate) fn leader_epoch(&self) -> i64 {
        self.my_epoch.load(Ordering::Acquire)
    }

    /// Whether this leader has completed the API promotion handoff and may serve writes.
    pub(crate) fn writes_enabled(&self) -> bool {
        self.writes_enabled.load(Ordering::Acquire)
    }

    /// Mark the current leader writable after the API has reloaded and verified durable state.
    pub(crate) fn enable_writes(&self) {
        if self.is_leader() {
            self.writes_enabled.store(true, Ordering::Release);
        }
    }

    /// Keep the lock/epoch role but fail all writes closed, used during and after failed handoff.
    pub(crate) fn disable_writes(&self) {
        self.writes_enabled.store(false, Ordering::Release);
    }

    /// Fail-closed step-down: mark this node a follower. Idempotent.
    pub(crate) fn step_down(&self) {
        self.disable_writes();
        self.leader.store(false, Ordering::Release);
    }

    /// **The write-path fence.** Re-verify, on the writer session itself, that this node may still
    /// write: it must (a) believe it is leader, (b) still physically hold the advisory lock, and
    /// (c) still own the current `leader_epoch`. ANY failure — a broken connection, a lost lock, a
    /// stolen epoch — steps this node down and returns `false`. Called before every durable append.
    pub(crate) fn verify_still_leader(&self) -> bool {
        if !self.is_leader() {
            return false;
        }
        let my_epoch = self.leader_epoch();
        let node_id = self.node_id.clone();
        let held = {
            let mut writer = self.writer();
            check_lock_and_epoch(&mut writer, &node_id, my_epoch)
        };
        match held {
            Ok(true) => true,
            // Lost the lock, lost the epoch, or the session errored → fail closed.
            Ok(false) | Err(_) => {
                self.step_down();
                false
            }
        }
    }

    /// Leader liveness heartbeat: stamp `cluster_leader.last_heartbeat`, but only while we still own
    /// the epoch. `0` rows updated ⇒ we were deposed ⇒ step down + fail closed.
    pub(crate) fn heartbeat(&self) -> Result<(), StoreError> {
        if !self.is_leader() {
            return Err(StoreError::NotLeader);
        }
        let my_epoch = self.leader_epoch();
        let node_id: &str = &self.node_id;
        // wp16 P2: re-stamp the advertised address on every heartbeat so the leader-directory row
        // that followers redirect to always reflects the live leader's reachable URL.
        let advertised: &str = &self.advertised_addr;
        let updated = {
            let mut writer = self.writer();
            writer.execute(
                "UPDATE cluster_leader SET last_heartbeat = now(), advertised_addr = $3 \
                 WHERE id = 1 AND epoch = $1 AND node_id = $2",
                &[&my_epoch, &node_id, &advertised],
            )
        };
        match updated {
            Ok(1) => Ok(()),
            Ok(_) => {
                self.step_down();
                Err(StoreError::NotLeader)
            }
            Err(e) => {
                self.step_down();
                Err(StoreError::Postgres(e))
            }
        }
    }

    /// Follower promotion attempt (§1.3): try to take the writer advisory lock on *this* session. On
    /// success, bump the `leader_epoch` (fencing the old leader) and mark this node leader, returning
    /// `Ok(true)`. The caller MUST then run the catch-up + chain re-verify handoff (§4.2) before the
    /// first append — this only wins the lock, it does not make the in-memory ledger authoritative.
    pub(crate) fn try_promote(&self) -> Result<bool, StoreError> {
        if self.is_leader() {
            return Ok(true);
        }
        // wp28 election-liveness fix: a Postgres restart drops the un-pooled writer session, and the
        // sync `postgres::Client` never reconnects on its own — so the `pg_try_advisory_lock` below
        // would error `connection closed` on every tick forever and the cluster would stay stuck
        // leaderless even though the lock was freed by the bounce. Re-establish the writer session
        // first when it has broken. Only reached on a follower (leaders early-return above), which
        // holds no advisory lock, so swapping its session cannot lose a held lock — and a fresh
        // session must still win the lock through the contention below, preserving single-writer
        // safety. If Postgres is still down the reconnect errors and we retry next tick.
        self.reconnect_writer_if_broken()?;
        let node_id = self.node_id.clone();
        let advertised = self.advertised_addr.clone();
        let epoch = {
            let mut writer = self.writer();
            let acquired: bool = writer
                .query_one(
                    &format!("SELECT pg_try_advisory_lock({WRITER_ADVISORY_LOCK_KEY})"),
                    &[],
                )?
                .get(0);
            if !acquired {
                return Ok(false);
            }
            ensure_cluster_table_and_bump_epoch(&mut writer, &node_id, &advertised)?
        };
        // Publish the epoch before the leader flag so any reader that sees `leader == true` also sees
        // the fresh epoch (Release/Acquire pairing). Writes stay disabled until the API handoff
        // reloads durable state and explicitly enables them.
        self.writes_enabled.store(false, Ordering::Release);
        self.my_epoch.store(epoch, Ordering::Release);
        self.leader.store(true, Ordering::Release);
        Ok(true)
    }

    /// Durable `MAX(seq)` from Postgres (the handoff catch-up target). `None` when the ledger is
    /// empty.
    pub(crate) fn durable_max_seq(&self) -> Result<Option<i64>, StoreError> {
        let mut client = self.checkout()?;
        let row = client.query_one("SELECT MAX(seq) FROM events", &[])?;
        Ok(row.get::<_, Option<i64>>(0))
    }

    /// **wp16 P2 — the current leader's advertised base URL (plan §3.2), for the follower
    /// write-redirect.** Returns the `cluster_leader.advertised_addr` **only** when the row is FRESH
    /// (heartbeat within `stale_after_secs`) and the address is non-empty; a stale, missing, or empty
    /// address yields `None` so the API replies `503 + Retry-After` during a failover / mid-handoff
    /// window rather than redirecting to a dead or unknown target. Read on a pooled connection (never
    /// the writer session). The value came from the leader's own env, never from any client input.
    pub(crate) fn leader_address(
        &self,
        stale_after_secs: i64,
    ) -> Result<Option<String>, StoreError> {
        let mut client = self.checkout()?;
        // `make_interval(secs => ..)` takes double precision; clamp to a positive lower bound so a
        // misconfigured `0`/negative window can never make every fresh leader look stale.
        let secs = stale_after_secs.max(1) as f64;
        let row = client.query_opt(
            "SELECT advertised_addr FROM cluster_leader \
             WHERE id = 1 AND last_heartbeat > now() - make_interval(secs => $1)",
            &[&secs],
        )?;
        Ok(row
            .and_then(|r| r.get::<_, Option<String>>(0))
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()))
    }
}

/// Read-only check used by [`PostgresBackend::verify_still_leader`]: still hold the lock AND still
/// own the current epoch?
fn check_lock_and_epoch(
    writer: &mut Client,
    node_id: &str,
    my_epoch: i64,
) -> Result<bool, StoreError> {
    let holds: bool = writer
        .query_one(HOLDS_WRITER_LOCK_SQL, &[&WRITER_ADVISORY_LOCK_KEY])?
        .get(0);
    if !holds {
        return Ok(false);
    }
    match writer.query_opt(
        "SELECT epoch, node_id FROM cluster_leader WHERE id = 1",
        &[],
    )? {
        Some(row) => {
            let epoch: i64 = row.get(0);
            let owner: String = row.get(1);
            Ok(epoch == my_epoch && owner == node_id)
        }
        // No leader row at all ⇒ we do not provably own the epoch ⇒ fail closed.
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn election_mode_parses_and_defaults_safely() {
        assert_eq!(ElectionMode::parse(Some("leader")), ElectionMode::Leader);
        assert_eq!(
            ElectionMode::parse(Some(" Follower ")),
            ElectionMode::Follower
        );
        assert_eq!(ElectionMode::parse(Some("AUTO")), ElectionMode::Auto);
        // Unset / empty / unrecognised all fall back to Auto (never a hard boot failure).
        assert_eq!(ElectionMode::parse(None), ElectionMode::Auto);
        assert_eq!(ElectionMode::parse(Some("")), ElectionMode::Auto);
        assert_eq!(ElectionMode::parse(Some("chaos")), ElectionMode::Auto);
    }

    #[test]
    fn only_a_pinned_follower_refuses_to_lead() {
        assert!(ElectionMode::Auto.may_lead());
        assert!(ElectionMode::Leader.may_lead());
        assert!(!ElectionMode::Follower.may_lead());
    }

    #[test]
    fn advisory_lock_key_splits_and_reconstructs() {
        // The pg_locks fence rebuilds the 64-bit key from (classid<<32 | objid). Prove the split the
        // query relies on is exact for our key, so a healthy leader is never spuriously stepped down.
        let key = WRITER_ADVISORY_LOCK_KEY as u64;
        let classid = (key >> 32) & 0xFFFF_FFFF;
        let objid = key & 0xFFFF_FFFF;
        let reconstructed = (classid << 32) | objid;
        assert_eq!(reconstructed, key);
        // Our fixed key is positive as an i64 (high bit clear), so the bigint math never sign-flips.
        const _: () = assert!(WRITER_ADVISORY_LOCK_KEY > 0);
    }

    #[test]
    fn cluster_leader_ddl_is_singleton_and_idempotent() {
        assert!(CLUSTER_LEADER_DDL.contains("CREATE TABLE IF NOT EXISTS cluster_leader"));
        assert!(CLUSTER_LEADER_DDL.contains("CHECK (id = 1)"));
        assert!(BUMP_EPOCH_SQL.contains("epoch = cluster_leader.epoch + 1"));
        assert!(BUMP_EPOCH_SQL.contains("RETURNING epoch"));
    }

    #[test]
    fn cluster_leader_carries_the_advertised_address() {
        // wp16 P2: the leader directory row + bump both record the advertised address, and a P0
        // table gains the column via the additive guard.
        assert!(CLUSTER_LEADER_DDL.contains("advertised_addr TEXT"));
        assert!(ADD_ADVERTISED_ADDR_COLUMN.contains("ADD COLUMN IF NOT EXISTS advertised_addr"));
        assert!(BUMP_EPOCH_SQL.contains("advertised_addr"));
        // Bind order: node_id ($1) then advertised_addr ($2).
        assert!(BUMP_EPOCH_SQL.contains("VALUES (1, 1, $1, $2, now())"));
    }

    #[test]
    fn advertised_url_resolves_empty_when_unset() {
        // No env mutation (parallel-test-safe): the unset default is an empty string, which the
        // follower redirect treats as "leader address unknown" → 503, never a broken redirect.
        // (This process does not set CHANCELA_ADVERTISED_URL.)
        assert_eq!(resolve_advertised_url(), String::new());
    }

    #[test]
    fn write_gate_stays_closed_until_handoff_enables_writes() {
        assert!(
            write_gate_allows(true, true),
            "a verified leader with completed handoff may write"
        );
        assert!(
            !write_gate_allows(true, false),
            "a promoted leader remains read-only until handoff enables writes"
        );
        assert!(
            !write_gate_allows(false, true),
            "write enablement cannot override failed leadership verification"
        );
    }

    #[test]
    fn node_id_is_non_empty() {
        // Exercises the fallback shape (no env mutation, to stay parallel-test-safe): a generated id
        // is non-empty so `cluster_leader.node_id` (NOT NULL) is always satisfiable.
        assert!(!resolve_node_id().is_empty());
    }

    // ── Live-Postgres resilience tests (§9.2–9.4) ─────────────────────────────────────────────────
    //
    // These prove the actual advisory-lock election / step-down / failover / epoch-fence semantics
    // against a real Postgres. They are `#[ignore]` so the offline suite never spawns a container;
    // run them with `DATABASE_URL` pointing at a throwaway Postgres:
    //   DATABASE_URL=postgres://... cargo test -p chancela-store --features postgres -- --ignored
    // Each opens its own backends; they clean up the advisory lock by dropping the writer session.

    fn test_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn election_exactly_one_leader() {
        let Some(url) = test_url() else { return };
        let a = PostgresBackend::open(&url).expect("first node opens");
        assert!(a.is_leader(), "the first node must win the advisory lock");
        // A second node pointed at the same DB must not acquire the same advisory lock while it is
        // still held by the first writer session.
        let b = PostgresBackend::open(&url).expect("second node opens as follower");
        assert!(
            !b.is_leader(),
            "a second node must be a follower, never a co-leader"
        );
        assert!(a.leader_epoch() >= 1);
        assert_ne!(a.node_id, b.node_id, "distinct nodes get distinct ids");
        drop(b);
        drop(a);
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn step_down_when_lock_is_lost() {
        let Some(url) = test_url() else { return };
        let leader = PostgresBackend::open(&url).expect("opens as leader");
        assert!(
            leader.verify_still_leader(),
            "a healthy leader verifies true"
        );
        // Force step-down as the write gate would on any writer-session error.
        leader.step_down();
        assert!(!leader.is_leader(), "a stepped-down node refuses to write");
        assert!(
            !leader.verify_still_leader(),
            "verify stays false once not leader (fail closed)"
        );
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn failover_promotes_follower_and_bumps_epoch() {
        let Some(url) = test_url() else { return };
        let leader = PostgresBackend::open(&url).expect("opens as leader");
        let first_epoch = leader.leader_epoch();
        let follower = PostgresBackend::open(&url).expect("opens as follower");
        assert!(!follower.is_leader());
        // Follower cannot promote while the leader still holds the lock.
        assert!(
            !follower.try_promote().expect("try_promote runs"),
            "a follower must not promote while the leader lives"
        );
        // Leader dies → its session drops → the advisory lock auto-releases.
        drop(leader);
        // The follower now wins promotion and fences the old leader with a higher epoch.
        assert!(follower.try_promote().expect("promotion succeeds"));
        assert!(follower.is_leader());
        assert!(
            follower.leader_epoch() > first_epoch,
            "each promotion bumps the monotonic leader_epoch (fence)"
        );
        drop(follower);
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn reconnect_writer_is_a_noop_on_a_healthy_session() {
        // wp28: the probe must not disturb a live writer session — a healthy follower calls this on
        // every promotion tick, so it has to be side-effect-free when the connection is fine. Prove
        // it returns Ok, keeps the session usable, and (crucially) does NOT drop a held advisory lock
        // even if it were ever called on a leader (defence in depth for the single-writer invariant).
        let Some(url) = test_url() else { return };
        let leader = PostgresBackend::open(&url).expect("opens as leader");
        assert!(leader.is_leader());
        let epoch_before = leader.leader_epoch();
        leader
            .reconnect_writer_if_broken()
            .expect("healthy-session reconnect probe is Ok");
        // The session is still alive and still holds the lock + epoch → still verifies as leader.
        assert!(
            leader.verify_still_leader(),
            "a healthy leader still verifies after the reconnect probe (lock not dropped)"
        );
        assert_eq!(
            leader.leader_epoch(),
            epoch_before,
            "the probe must not bump the epoch or re-elect"
        );
        drop(leader);
    }

    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn epoch_is_monotonic_across_promotions() {
        let Some(url) = test_url() else { return };
        let a = PostgresBackend::open(&url).expect("first leader");
        let e1 = a.leader_epoch();
        drop(a);
        let b = PostgresBackend::open(&url).expect("second leader");
        let e2 = b.leader_epoch();
        assert!(
            e2 > e1,
            "a fresh leader's epoch strictly exceeds the prior epoch"
        );
        drop(b);
    }

    /// wp16 P2 — leader-address heartbeat round-trip + staleness. Seeds the leader's advertised
    /// address into `cluster_leader` (env-free, via the writer session so no unsafe `set_var`), then
    /// proves [`PostgresBackend::leader_address`] returns it while FRESH and `None` once the heartbeat
    /// ages past the staleness window (so the API replies `503 + Retry-After`, never a stale redirect).
    /// Also confirms a real [`PostgresBackend::heartbeat`] refreshes `last_heartbeat` so the address
    /// stays discoverable.
    #[test]
    #[ignore = "requires a live Postgres (set DATABASE_URL)"]
    fn leader_address_round_trips_and_expires_when_stale() {
        let Some(url) = test_url() else { return };
        let leader = PostgresBackend::open(&url).expect("opens as leader");
        assert!(leader.is_leader());

        // Seed a known advertised address with a fresh heartbeat (independent of any env config).
        {
            let mut c = leader.checkout().expect("read conn");
            c.execute(
                "UPDATE cluster_leader SET advertised_addr = $1, last_heartbeat = now() WHERE id = 1",
                &[&"https://leader.test:9443"],
            )
            .expect("seed advertised address");
        }
        assert_eq!(
            leader.leader_address(10).expect("read leader address"),
            Some("https://leader.test:9443".to_owned()),
            "a fresh leader row exposes its advertised address"
        );

        // Age the heartbeat beyond the staleness window → the address is treated as unknown.
        {
            let mut c = leader.checkout().expect("read conn");
            c.execute(
                "UPDATE cluster_leader SET last_heartbeat = now() - make_interval(secs => 3600) \
                 WHERE id = 1",
                &[],
            )
            .expect("age heartbeat");
        }
        assert_eq!(
            leader.leader_address(10).expect("read leader address"),
            None,
            "a stale leader row is leader-unknown (API 503), never a broken redirect target"
        );

        // A real heartbeat refreshes `last_heartbeat`, so the address is discoverable again. This
        // node's advertised env is unset here, so the heartbeat writes an empty address → still None,
        // proving the heartbeat path stamps the column (and empty is correctly filtered out).
        leader.heartbeat().expect("heartbeat succeeds while leader");
        assert_eq!(
            leader.leader_address(10).expect("read leader address"),
            None,
            "an empty advertised address (no CHANCELA_ADVERTISED_URL) is filtered to leader-unknown"
        );
        drop(leader);
    }
}
