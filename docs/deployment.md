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
| `worker` | SQLite (SQLCipher) | `single-node` plus the durable sync/backup connector worker on a shared data volume | `docker/docker-compose.yml` |
| `postgres` | PostgreSQL 18.4 + Redis 8.8 | Networked DB, PG-native backup tooling | `docker/docker-compose.yml` |
| Hardened `single-node` / `postgres` | as above | Production posture: distroless, read-only rootfs, digest-pinned | `docker-compose.hardened.yml` |
| Multi-node overlay | PostgreSQL 18.4 + Redis 8.8 | Leader + read-followers with failover (see [HA](#multi-node-leaderfollower)) | `docker/docker-compose.cluster.yml` |

## Images are built from source

Chancela publishes **no** container images to Docker Hub or any other registry.
`chancela-server` and `chancela-worker` are built locally from this repository,
so building is the first-run step — not an optimisation you can skip:

```sh
git clone <your-clone-url> chancela && cd chancela
docker compose up --build -d          # builds, then starts the single-node profile
```

The first build compiles the Rust workspace in a container and takes several
minutes; later builds reuse the layer cache. Nothing needs to be installed on
the host beyond Docker itself.

!!! warning "`docker compose pull` is not part of the flow"
    There is nothing to pull for the app services. Every buildable service
    declares `pull_policy: build`, so `docker compose up` builds a missing image
    instead of asking a registry for one, and `docker compose pull` reports them
    as `Skipped` and exits 0 — it only fetches the pinned third-party images
    (Postgres, Redis, `alpine/openssl`). If you are on an older Compose that
    still errors on buildable services, use `docker compose pull
    --ignore-buildable`, or simply skip `pull` altogether.

To rebuild after changing code, pass `--build` again (`docker compose up --build
-d`) or run `docker compose build` first; a plain `up` reuses the image that is
already tagged locally.

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
`8081`) for isolation and health validation. It remains a deployment-profile
placeholder and is unrelated to the dedicated connector worker:

```sh
docker compose -f docker/docker-compose.yml --profile validation-worker up --build
```

### Durable sync and backup worker

The `worker` profile starts `chancela-server` and the dedicated non-root
`chancela-worker` image together:

```sh
docker compose -f docker/docker-compose.yml --profile worker up --build
```

Both services mount `chancela-data` at `/var/lib/chancela`. The API owns
tenant-scoped connector configuration, materializes only server-selected
artifacts below `/var/lib/chancela/worker/sources`, and publishes audited jobs
to `/var/lib/chancela/worker/queue`; the worker consumes that queue and writes
status/receipts there. The config and secret directories are separate read-only
mounts. Set `CHANCELA_CONNECTOR_ALLOWED_HOSTS` before selecting a network
target — an administrator can then narrow it in-app, but never exceed it — and
set `CHANCELA_CONNECTOR_SECRETS_HOST_DIR` to a protected directory
for file-backed credentials. See [Sync, backup, and connector worker](connectors-worker.md).

## Postgres durability backend + Redis cache

Brings up the app compiled with the Postgres backend, a
`postgres:18.4-alpine3.23` service, and a `redis:8.8.0-alpine3.23`
cache-aside. Postgres and Redis are **not**
published to the host — they are reachable only on the compose network.

On a fresh clone, one command generates the missing secrets and starts the
profile:

```sh
sh docker/up.sh -d --build
```

The wrapper is equivalent to the two explicit steps below, and additionally
pins the `-f docker/docker-compose.yml` form that `--profile postgres`
requires (see the note at the end of this section).

1. Create the three secret files. `--generate` fills in whichever are
   **missing**, with cryptographically random values:

    ```sh
    sh docker/preflight-secrets.sh --generate
    ```

    It is strictly create-if-absent: an existing secret is never rewritten,
    rotated or overwritten. That is not a convenience — all three are
    write-once in practice:

    | Secret | Why it can never be regenerated in place |
    | --- | --- |
    | `postgres_password` | `POSTGRES_PASSWORD_FILE` is read **only** when Postgres initialises `chancela-pgdata`. Once that volume exists the password is baked into the database, and a new file would leave the app unable to authenticate — a failure that looks like corruption. |
    | `database_url` | Embeds that same password inline, so it is derived from `postgres_password` in the same step. Generating one without the other desynchronises the pair. |
    | `credential_key` | Encrypts stored provider credentials. A new key makes every already-stored credential undecryptable. |

    Consequently, if `postgres_password` is missing while the
    `chancela-pgdata` volume still exists, `--generate` **refuses** rather than
    inventing a password the database will reject. Restore the secret from your
    backup, or discard the database with `down -v` and generate clean.

    To supply your own values instead, copy the templates and edit them — the
    same password must appear in both `postgres_password` and `database_url`:

    ```sh
    cp docker/secrets/postgres_password.example docker/secrets/postgres_password
    cp docker/secrets/database_url.example      docker/secrets/database_url
    cp docker/secrets/credential_key.example    docker/secrets/credential_key
    ```

    Generated files are written with no trailing newline and mode `0600`. On a
    Windows/NTFS checkout the mode is not honoured (Git for Windows and Docker
    Desktop report `0644` regardless) and the directory ACL is the only
    protection; on the Linux hosts this profile targets, `0600` applies.

2. Check them before starting anything (`--generate` runs this check too):

    ```sh
    sh docker/preflight-secrets.sh
    ```

3. Start the profile:

    ```sh
    docker compose -f docker/docker-compose.yml --profile postgres up --build
    ```

!!! warning "Skipping step 1 fails at the Docker daemon, not in the app"

    The three secret files are gitignored, so a fresh checkout does not have
    them. Compose only logs `secret file chancela_postgres_password does not
    exist` as a warning and hands the path to the daemon anyway, which fails
    the container with a message naming a path you have never edited:

    ```
    Container chancela-postgres-1  Error response from daemon: invalid mount
    config for type "bind": bind source path does not exist:
    .../docker/secrets/postgres_password
    ```

    Some daemons instead create a **directory** at that path. Postgres then
    reads `POSTGRES_PASSWORD_FILE` as a directory, and re-running the `cp` from
    step 1 nests the file *inside* it instead of fixing anything. Delete the
    directory (`rm -rf docker/secrets/postgres_password`) before generating
    again. `docker/preflight-secrets.sh` detects both states, and
    `docker/up.sh` runs it for you before Compose ever sees the path.

See [Configuration → Secrets](configuration.md#secrets-postgres-profile) for what
each secret does. The credential-store root key
(`CHANCELA_CREDENTIAL_KEY_FILE`) is **required** on Postgres — there is no
SQLCipher-derived key source on this backend.

The same applies to **any Linux or macOS deployment**, in Docker or not: there is
no OS credential-sealing provider outside Windows, so unless the SQLite store is
SQLCipher-encrypted you must supply `CHANCELA_CREDENTIAL_KEY_FILE` or signature-
provider credentials cannot be saved. The server says so at startup rather than
waiting for someone to fail a save in Settings. See
[Configuration → Where the root key comes from](configuration.md#where-the-root-key-comes-from).

The app is built with
`CARGO_FEATURES="chancela-server/sqlcipher chancela-server/postgres chancela-server/redis"`
and still keeps a small writable volume at `/var/lib/chancela` for the credential
sidecar (`provider-credentials.enc.json`), the CAE/law/TSL caches, and the JSON
sidecars. The PostgreSQL 18.4 service takes its database/user from
`CHANCELA_PG_DB` / `CHANCELA_PG_USER` (defaults `chancela`), is **not** published
to the host, and is reached only on the compose network. A one-shot,
network-disabled `postgres-tls-init` service creates/renews the private CA and
server certificate in `chancela-pg-tls`; PostgreSQL health performs a real
`sslmode=verify-full` query before the app starts. Redis 8.8 runs AOF persistence with
`maxmemory` + `allkeys-lru` and is a pure cache — the app is fully correct with
Redis down. All three services carry `deploy.resources.limits`.

!!! danger "Upgrading an existing PostgreSQL 16 volume"
    PostgreSQL major-version data directories are not binary-compatible, and
    PostgreSQL 18 also moved the official image's `PGDATA` beneath
    `/var/lib/postgresql/18/docker`. Do not point 18.4 at an existing 16 data
    directory. Take and verify a `pg_dump`/`pg_dumpall` backup (or perform a
    deliberate `pg_upgrade`), start 18.4 with a fresh volume, restore, and run
    the ledger verification checks before returning the deployment to service.

!!! warning "Redis 8 licensing"
    Redis 8 is distributed under the RSALv2, SSPLv1, or AGPLv3 choices. Review
    the selected licence for the deployment/distribution model. Chancela uses
    Redis only as an optional cache and remains correct if the service is
    omitted.

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
    regardless. PostgreSQL transport is always authenticated with
    `sslmode=verify-full`: the compose CA is mounted read-only into the app, and
    insecure TLS modes fail closed. Managed/remote Postgres deployments must
    mount their provider CA and set `CHANCELA_PG_TLS_ROOT_CERT` accordingly.

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
    it becomes a network round-trip. The write path is asynchronous:
    `AppState::persist_write_through` is an `async fn`, and the durable store
    transaction itself is a **synchronous** driver call (the store keeps a sync
    `postgres`+r2d2 / rusqlite driver by design — no `tokio-postgres`/sqlx swap).
    To keep a tokio worker from blocking on that synchronous call, it is offloaded
    onto tokio's blocking thread pool via `Store::persist_blocking_async`, a thin
    wrapper that runs the existing sync `Store::persist` inside
    `tokio::task::spawn_blocking`. The async worker thread is freed for other
    requests while the write is in flight, but the ledger write lock is still held
    across the `.await` (a held lock cannot interleave sequence numbers), so
    **throughput remains bounded by the single-writer design** — the offload frees
    the worker thread, not the write lock.

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
    [High availability & failover](HA-FAILOVER.md).

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
