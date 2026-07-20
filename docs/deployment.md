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

Profiles are **two independent axes** that combine. Pick exactly one *backend*
profile — each starts exactly one app service — and add any *sidecar* profiles
you want. A sidecar profile starts no app service of its own, so
`--profile worker` on its own gives you a worker and nothing else; that is
deliberate, and it is what lets the same sidecar run against either backend.

| Profile | Axis | Backend | When to use | Compose file |
|---|---|---|---|---|
| `single-node` | backend | SQLite (SQLCipher) | Simplest self-host; file-level encryption at rest | `docker/docker-compose.yml` |
| `postgres` | backend | PostgreSQL 18.4 + Redis 8.8 | Networked DB, PG-native backup tooling | `docker/docker-compose.yml` |
| `worker` | sidecar | either | The durable sync/backup connector worker, on the chosen backend's data volume | `docker/docker-compose.yml` |
| Hardened `single-node` / `postgres` | backend | as above | Production posture: distroless, read-only rootfs, digest-pinned | `docker-compose.hardened.yml` |
| Multi-node overlay | backend | PostgreSQL 18.4 + Redis 8.8 | Leader + read-followers with failover (see [HA](#multi-node-leaderfollower)) | `docker/docker-compose.cluster.yml` |

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
docker compose --profile single-node up --build
```

The app publishes on `127.0.0.1:8080` (loopback only). Override the host port:

```sh
CHANCELA_HOST_PORT=18080 docker compose --profile single-node up
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

### Durable sync and backup worker

The `worker` profile adds the dedicated non-root `chancela-worker` image. Pair it
with a backend profile, which is what starts `chancela-server` alongside it:

```sh
docker compose --profile single-node --profile worker up --build
```

`worker` is an **additive** profile: it enables the worker and no app service, so
you pair it with a backend profile. That is what lets it run against Postgres
too, which was previously impossible — `--profile postgres --profile worker`
used to start the SQLite app alongside the Postgres one and the second container
died with "port is already allocated". The worker mounts the app's data volume,
and that volume differs per backend (`chancela-data` for SQLite,
`chancela-app-data` for Postgres), so the Postgres form names it:

```sh
CHANCELA_APP_DATA_VOLUME=chancela-app-data \
  docker compose --profile postgres --profile worker up --build
```

The app and worker share that volume at `/var/lib/chancela`. The API owns
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

On a fresh clone this is the whole procedure — there is **no host-side secret
step**:

```sh
docker compose --profile postgres up -d --build
```

No `-f` and no wrapper script: the repo-root `docker-compose.yml` `include`s
`docker/docker-compose.yml`, so this starts `server-postgres` alone. The
single-node `server-sqlite` service stays down, because a `--profile` on the
command line REPLACES the `COMPOSE_PROFILES=single-node` default in `.env`
rather than adding to it. (The former `docker/up.sh` wrapper existed only to
pin an explicit `-f` form; it is gone, together with the override files that
made it necessary.)

### How the secrets get created

The profile needs three secrets. They live in the `chancela-secrets` **named
volume**, which the one-shot `secrets-init` service fills before Postgres or the
app start (`depends_on: … condition: service_completed_successfully`, the same
sequencing as `postgres-tls-init`). Compose creates named volumes itself, so
nothing has to exist on the host beforehand.

| Secret | Consumed as | Owner / mode inside the volume |
| --- | --- | --- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` (postgres) | `70:70`, `0400` |
| `database_url` | `DATABASE_URL_FILE` (app) | `65532:65532`, `0400` |
| `credential_key` | `CHANCELA_CREDENTIAL_KEY_FILE` (app) | `65532:65532`, `0400` |

Each file is readable only by the one process that needs it, and none of the
values is ever placed in `environment:` — that would expose them in `docker
inspect` and in the container's process environment.

Generation is strictly **create-if-absent**: `up` never rotates a secret that
the volume already holds. That is not a convenience — all three are write-once
in practice:

| Secret | Why it can never be regenerated in place |
| --- | --- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` is read **only** when Postgres initialises `chancela-pgdata`. Once that volume exists the password is baked into the database, and a new value would leave the app unable to authenticate — a failure that looks like corruption. |
| `database_url` | Embeds that same password inline, so it is always derived from `postgres_password` in the same run, never generated independently. The password uses a URL-safe alphabet precisely so one literal string is valid in both files. |
| `credential_key` | Encrypts stored provider credentials. A new key makes every already-stored credential undecryptable. |

Consequently `secrets-init` **refuses to start the stack** — rather than invent
a value — when a secret is absent but state that only that secret unlocks is
present: an initialised `chancela-pgdata`, or an existing provider-credential
store. Restore the secret (see below), or discard the state with
`down -v` and start clean. It also refuses if `database_url` exists without
`postgres_password`, since the password is then recoverable only from the URL.

### Managing the secrets yourself

Put the values in `docker/secrets/` and `secrets-init` **adopts** them —
copies them into the volume instead of generating. This is also the migration
path for an installation created before this change: leave the existing files
where they are and the first `up` picks them up, so the running database keeps
its password.

```sh
# your own values …
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key

# … or generate them host-side, consistently and only once
sh docker/preflight-secrets.sh --generate
```

The same password must appear in both `postgres_password` and `database_url`;
`--generate` guarantees that by deriving the URL from the password file it just
wrote. Host files are written with no trailing newline and mode `0600` — not
honoured on a Windows/NTFS checkout, where the directory ACL is the only
protection.

Adoption happens **only while the volume lacks that secret**. Once a value is in
the volume, the volume is authoritative and a differing host file is ignored
(with a note in the `secrets-init` log). To re-adopt, remove the volume — which
means discarding the database too, so treat it as a reinstall.

!!! note "Why a volume and not `secrets:` with `file:`"

    Compose's `secrets:` mechanism requires a host path, and a bind to a file
    that does not exist yet cannot be fixed by an init container: Compose
    creates every container — validating every bind mount — before it starts the
    first one. A missing secret file is only a warning, and the daemon then
    either fails the container with `invalid mount config for type "bind": bind
    source path does not exist` or silently creates a **directory** there, which
    copying the template over does not fix. A named volume has neither failure
    mode. `docker/preflight-secrets.sh` still detects the leftover-directory
    state if you hit it from an older checkout.

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
docker compose --profile postgres \
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
