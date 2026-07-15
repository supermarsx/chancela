# Deployment

Chancela ships one codebase in three shapes:

- **Desktop** — a Tauri single-user app with an embedded SQLite store (offline).
- **Self-hosted server** — the `chancela-server` binary (Axum HTTP API + the web
  UI) on `127.0.0.1:8080`, backed by SQLite or PostgreSQL.
- **MCP server** — an optional stdio bridge for AI-assisted drafting (see
  [Capabilities](capabilities.md#clients-desktop-web-api-mcp)).

This page covers the server editions. For the **secure production path**, use the
hardened images described in
[Security & Hardening](security/hardened-docker.md).

!!! info "Single-writer by design"
    Every server profile below — including Postgres — is **single-writer,
    single-node**. The app holds authoritative state in memory and allocates the
    ledger sequence in process, so exactly one writer instance may run. Postgres
    is a *durability* upgrade (PG-native backup/inspection tooling), **not**
    horizontal scale or HA. The only exception is the multi-node overlay, where
    an advisory-lock election guarantees exactly one writer among the replicas.

## Choosing a profile

| Profile | Backend | When to use | Compose file |
|---|---|---|---|
| `single-node` | SQLite (SQLCipher) | Simplest self-host; file-level encryption at rest | `docker/docker-compose.yml` |
| `validation-worker` | SQLite | `single-node` plus a bounded isolation/health sidecar | `docker/docker-compose.yml` |
| `postgres` | PostgreSQL 16 + Redis 7 | Networked DB, PG-native backup tooling | `docker/docker-compose.yml` |
| Hardened `single-node` / `postgres` | as above | Production posture: distroless, read-only rootfs, digest-pinned | `docker-compose.hardened.yml` |
| Multi-node overlay | PostgreSQL 16 + Redis 7 | Leader + read-followers with failover (see [HA](#multi-node-leaderfollower)) | `docker/docker-compose.cluster.yml` |

## Single node (SQLite)

The simplest deployment. One `chancela-server` container, an embedded
SQLCipher-encrypted SQLite store on a named volume, no external database. Run
from the repository root:

```sh
docker compose -f docker/docker-compose.yml --profile single-node up --build
```

The app publishes on `127.0.0.1:8080` (loopback only). Override the host port:

```sh
CHANCELA_HOST_PORT=18080 docker compose -f docker/docker-compose.yml --profile single-node up
```

The container runs non-root (UID/GID `65532`), read-only rootfs, all
capabilities dropped, `no-new-privileges:true`, `/tmp` as tmpfs scratch, with a
`GET /health` healthcheck and a persistent volume at `/var/lib/chancela`.

You can validate this profile with the shipped Docker smoke scripts without
rebuilding an image:

```sh
scripts/docker-smoke.sh --compose-profile chancela-server:local
```

```powershell
scripts\docker-smoke.ps1 -Image chancela-server:local -ComposeProfile
```

### Validation-worker sidecar

Adds a bounded second container (same image, its own volume, internal port
`8081`) for isolation and health validation. It is a deployment-profile
placeholder, **not** a dedicated async worker (the repo ships no separate worker
entrypoint yet):

```sh
docker compose -f docker/docker-compose.yml --profile validation-worker up --build
```

## Postgres durability backend + Redis cache

Brings up the app compiled with the Postgres backend, a `postgres:16-alpine`
service, and a `redis:7-alpine` cache-aside. Postgres and Redis are **not**
published to the host — they are reachable only on the compose network.

1. Create the real secret files from the committed templates and fill them in:

    ```sh
    cp docker/secrets/postgres_password.example docker/secrets/postgres_password
    cp docker/secrets/database_url.example      docker/secrets/database_url
    cp docker/secrets/credential_key.example    docker/secrets/credential_key
    # edit each: a strong password in BOTH postgres_password and database_url
    # (they must match); a high-entropy value in credential_key.
    ```

2. Start the profile:

    ```sh
    docker compose -f docker/docker-compose.yml --profile postgres up --build
    ```

See [Configuration → Secrets](configuration.md#secrets-postgres-profile) for what
each secret does. The credential-store root key
(`CHANCELA_CREDENTIAL_KEY_FILE`) is **required** on Postgres — there is no
SQLCipher-derived key source on this backend.

The app is built with
`CARGO_FEATURES="chancela-server/sqlcipher chancela-server/postgres chancela-server/redis"`
and still keeps a small writable volume at `/var/lib/chancela` for the credential
sidecar (`provider-credentials.enc.json`), the CAE/law/TSL caches, and the JSON
sidecars. The `postgres:16-alpine` service takes its database/user from
`CHANCELA_PG_DB` / `CHANCELA_PG_USER` (defaults `chancela`), is **not** published
to the host, and is reached only on the compose network; the app waits for its
`pg_isready` health before serving. `redis:7-alpine` runs AOF persistence with
`maxmemory` + `allkeys-lru` and is a pure cache — the app is fully correct with
Redis down. All three services carry `deploy.resources.limits`.

!!! warning "Never scale this profile"
    The profile pins `deploy.replicas: 1`. Because the app is
    in-memory-authoritative and allocates the ledger `seq` in process, two
    instances against one Postgres would violate the single-writer design.
    Postgres is durability, **not** scale-out — for availability across hosts use
    the [multi-node overlay](#multi-node-leaderfollower), which elects exactly one
    writer.

!!! note "Encryption at rest on Postgres"
    Vanilla PostgreSQL has no transparent whole-DB encryption, so this profile
    does **not** provide SQLCipher's file-level ciphertext. Protect the
    `chancela-pgdata` volume with host disk encryption (LUKS or an encrypted
    block device) — this is disk-level only: a DB superuser or a live memory dump
    still sees plaintext, a materially weaker guarantee than SQLCipher. The
    credential store keeps its own app-layer XChaCha20-Poly1305 encryption
    regardless. TLS to Postgres (`sslmode=verify-full`) is not wired in this lane
    — the backend uses `NoTls` on the local compose network; a remote Postgres
    deployment needs a future TLS connector first.

### Backup and restore on Postgres

The in-app backup endpoint (`POST /v1/backup`, SQLite `VACUUM INTO`) is
**unsupported on the Postgres backend** — there is no `.db` file to snapshot or
swap. Use **PG-native tooling**: `pg_dump` / `pg_restore` for logical backups, or
PITR (WAL archiving + base backups) for point-in-time recovery. For example:

```sh
docker compose -f docker/docker-compose.yml --profile postgres \
  exec postgres pg_dump -U chancela chancela > chancela-$(date -u +%Y%m%dT%H%M%SZ).sql
```

!!! info "Write throughput on Postgres"
    On SQLite a store write is a microsecond-scale local file write; on Postgres
    it becomes a network round-trip. The app routes those hot store calls through
    `spawn_blocking` so a tokio worker is not blocked while the single ledger
    write lock is held. Throughput remains bounded by the single-writer design.

## Hardened images (production path)

The hardened variant pairs `Dockerfile.hardened` (multi-stage, distroless,
digest-pinned, non-root) with a tightened runtime (read-only rootfs, size-capped
tmpfs, `cap_drop: [ALL]`, `no-new-privileges`, PID-1 init, pids/fd/CPU/memory/log
caps, internal-only DB network). It is **additive** — it does not replace the
base compose.

=== "Single node (SQLite)"

    ```sh
    docker compose -f docker-compose.hardened.yml --profile single-node up --build
    ```

=== "Postgres + Redis"

    ```sh
    # create the secret files first (see Postgres profile above)
    docker compose -f docker-compose.hardened.yml --profile postgres up --build
    ```

The full rationale, per-measure threat mapping, secrets handling, and optional
supply-chain steps (Trivy/Grype scan, Syft SBOM, cosign signing) are documented
in [Security & Hardening](security/hardened-docker.md).

## Multi-node (leader/follower)

For availability beyond a single host, an **additive overlay**
(`docker/docker-compose.cluster.yml`) scales the app against one shared Postgres.
Exactly one instance is elected writer via a PostgreSQL **session-level advisory
lock** (`CHANCELA_NODE_ROLE=auto`); the rest serve reads and `307`-redirect
writes to the leader. This is safe to scale because only one *instance* ever
writes.

```sh
docker compose \
  -f docker/docker-compose.yml -f docker/docker-compose.cluster.yml \
  --profile postgres --profile cluster up --build --scale chancela-cluster=3
```

Redis is **required** in multi-node (cluster-wide sessions + global rate-limits).
Put a leader-aware load balancer in front, or rely on `307` redirects for clients
that follow cross-host redirects. On leader loss the advisory lock auto-releases,
a follower wins the poll, bumps the `leader_epoch` to fence the old leader, and
runs a handoff gate (catch up to durable `MAX(seq)` + re-verify the whole
hash-chain) before writing.

!!! warning "Before production legal use"
    Multi-node is single-writer HA with automatic failover for crashes — **not**
    zero-RTO and not multi-writer. A documented real-cluster soak run is required
    before running it for legal data. See
    [`docs/HA-FAILOVER.md`](https://github.com/supermarsx/chancela/blob/main/docs/HA-FAILOVER.md).

## Building the image on its own

```sh
# base image
docker build -f docker/Dockerfile.server -t chancela-server .

# hardened image
docker build -f Dockerfile.hardened -t chancela-server:hardened .
```

The build context is the **repository root** so the Dockerfile can see the whole
Rust + web workspace. A first build compiles the Rust workspace in release mode
and takes several minutes; subsequent builds reuse the BuildKit cache.
