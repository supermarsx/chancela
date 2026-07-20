# High availability: single-writer leader election & failover (wp16)

This document explains how to run **N `chancela-server` app nodes against one PostgreSQL**, how
failover works, the honest recovery-time objective (RTO), and — importantly — the soak-testing
caveat you must clear **before** trusting this with legal data.

> **Scope.** HA applies only to the self-hosted `chancela-server` + `postgres` feature. The embedded
> desktop/browser editions are single-user SQLite; leader election is meaningless there and none of
> this code runs (it is inert without the Postgres backend).

## The model in one paragraph

The ledger is an append-only, hash-chained legal record whose `seq` is a dense `0,1,2,…` run
allocated in-memory. Two writers cannot both extend it without forking the chain, so the design is
**single-writer leader + read-only followers, never multi-master**. Exactly one node holds a
PostgreSQL **session-level advisory lock** (`pg_advisory_lock`); holding it *is* being the leader and
the only writer. Postgres guarantees at most one holder of a lock key database-wide — that
single-holder guarantee **is** the split-brain prevention. There is no consensus protocol to get
wrong.

## Running N app nodes on one Postgres

Point every node at the same `DATABASE_URL`. On boot each node runs `pg_try_advisory_lock`
(non-blocking): the winner becomes **LEADER**, the rest come up as read-serving **FOLLOWERS** that
poll for promotion.

| Env var | Meaning | Default |
|---|---|---|
| `CHANCELA_NODE_ROLE` | `auto` (elect via the lock) \| `leader` \| `follower` (never elect) | `auto` |
| `CHANCELA_NODE_ADDRESS` | this node's stable identity, recorded in `cluster_leader` | per-process uuid |
| `CHANCELA_ADVERTISED_URL` | this node's externally-reachable `http(s)://host[:port]` (leader heartbeats it; followers 307 writes here) | unset |
| `CHANCELA_CLUSTER_WRITE_MODE` | `redirect` (307) \| `proxy` (reverse-proxy to leader) | `redirect` |
| `CHANCELA_PROMOTE_POLL_INTERVAL` | follower promotion poll period (s) | `1` |
| `CHANCELA_HEARTBEAT_INTERVAL` | leader heartbeat period (s) | `2` |
| `CHANCELA_CHANGEFEED_POLL_INTERVAL` | follower `MAX(seq)` reconcile backstop (s) | `5` |
| `CHANCELA_NODE_STALE_AFTER` | how old a leader heartbeat may be before its address is "unknown" (s) | `10` |
| `CHANCELA_LEADER_WATCHDOG_INTERVAL` | leader self-fence re-verify period **and** per-check deadline (s) | `3` |
| `REDIS_URL` / `REDIS_URL_FILE` | **required in multi-node** for shared sessions + global rate-limits | — |

**Getting writes to the leader.** Two supported front doors:

1. **Portable default — 307 redirect.** A mutating request (`POST/PUT/PATCH/DELETE`) that lands on a
   follower is answered `307 Temporary Redirect` with `Location: <leader>/<same-path>` (method + body
   preserved), read from the leader's heartbeated `cluster_leader.advertised_addr`. The client
   re-issues the exact write to the leader. Requires clients to follow cross-host redirects (browsers
   and react-query do; API-key/MCP clients must be configured to). If the leader address is unknown
   or stale (a brief failover window), the follower replies `503 + Retry-After` — never a local write,
   never a broken redirect.
2. **Recommended production — leader-aware load balancer.** Put an LB in front that health-checks each
   node's `/health` role and routes writes to the current leader, reads to any healthy node. Clients
   hit one VIP; the LB does the split. Combine with 307 as a backstop.

**Redis is load-bearing in multi-node** (not optional): sessions minted on one node must be honored on
another, and sign-in/rate-limit buckets must be global or an attacker gets N× attempts by spraying
across nodes. Sessions and limits are Redis-backed and **fail-closed** on a Redis outage. The unlocked
signing key stays node-local (never written to Redis).

## Failover timeline & honest RTO

```
t0    Leader process dies (crash / OOM / node loss).
t0+   Its Postgres TCP session tears down → the advisory lock auto-releases
        (teardown latency = TCP/keepalive + PG session cleanup; ms–seconds).
t1    A follower's promotion poll wins pg_try_advisory_lock (≤ CHANCELA_PROMOTE_POLL_INTERVAL)
        and bumps leader_epoch (fences the old leader).
t1→t2 The new leader runs the HANDOFF GATE before it writes: catch up to durable MAX(seq),
        re-verify the whole hash-chain from Postgres, discard any stale in-memory tail.
t2    Writes resume. First append = MAX(seq)+1 with the genuine durable head as prev_hash
        (no gap, no duplicate, no reorder).
```

- **Crash case:** single-digit-second RTO is realistic (`session-teardown + promote-poll + handoff`).
- **In-flight writes:** a write that hadn't committed is lost (client gets no/5xx) → retry lands on
  the new leader. Use **idempotency keys** so a write that *did* commit before the crash isn't
  duplicated on retry.
- **No-leader window (t0+ → t2):** mutations get `503 + Retry-After`; reads continue from any follower.

## The leader self-fence watchdog (wp16 P4)

Safety (no fork) comes from P0: writes only commit on the lock-holding session, and a duplicate `seq`
fails the durable primary-key constraint. The residual risk is **liveness** — a leader that is
partitioned from Postgres, or whose writer session has *wedged*, must stop being considered the writer
quickly instead of wedging the cluster.

The **watchdog** is an independent background task on every node. On the leader it periodically
(`CHANCELA_LEADER_WATCHDOG_INTERVAL`, default 3s) re-verifies, within a **deadline**, that it still
holds the advisory lock and owns the current `leader_epoch`. On **any** inability to prove leadership —
verify errors, verify *times out* (the partitioned/wedged case), or the check panics — it
**proactively steps down** (fail-closed): it flips to follower and disables writes via atomic role
flags, so the fence succeeds even while the writer connection is still wedged. The write gate then
refuses (`503`) and the supervisor re-enters election on its next tick. This closes the "wedged/
partitioned leader keeps writing until the next write discovers it" gap without waiting for a write.

**Honest limit (plan §7.5).** The watchdog fences *this node's writes* fast. But a leader that is
wedged while its Postgres session is still **TCP-alive** keeps the advisory lock held DB-side, so a
*peer* cannot promote until Postgres reaps that session. Fully resolving cross-node failover of a
TCP-alive wedged leader still requires setting **`statement_timeout` + `tcp_keepalives`** on the
writer session (so Postgres reaps a dead-but-open session and releases the lock), or a process
self-kill. Configure those at the database/connection level for production.

## HA target — say it plainly

This is **single-writer HA with automatic failover for crashes**, not zero-RTO and not multi-writer.
Read availability is ~continuous (any surviving follower serves reads). Write availability is
"restored within seconds of a leader crash, bounded by operator action / session reaping on a
partition." Do **not** claim "no downtime writes."

## ⚠️ Soak-testing caveat — read before trusting legal data

The implementation is verified: the election/step-down/handoff/epoch/watchdog logic and the
hash-chain continuity invariants are proven by unit + in-process simulation tests
(`cargo test -p chancela-api --lib -- cluster watchdog`, and `-p chancela-store`), and by live
multi-node `#[ignore]` tests you can run against a real Postgres:

```
DATABASE_URL=postgres://… cargo test -p chancela-store --features postgres -- --ignored
DATABASE_URL=postgres://… cargo test -p chancela-api    --features postgres -- --ignored
REDIS_URL=redis://…       cargo test -p chancela-api    --features redis    -- --ignored
```

**Green CI is necessary but NOT sufficient to claim production HA for a legal ledger.** These cannot
be exercised in the build sandbox and require a documented, real-cluster soak run before sign-off:

- long-duration randomized chaos soak (kill/restart/partition loop under a sustained write workload,
  asserting full chain integrity after every cycle);
- real cross-host network partitions (not in-process simulation);
- load-balancer behaviour under failover and RTO measurement under production-like latency;
- the wedged-but-TCP-alive leader self-fence timing with `statement_timeout`/`tcp_keepalives` tuned.

Do not enable multi-node in production for legal records until that soak run is completed and recorded.
