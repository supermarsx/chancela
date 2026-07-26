# Deployment

Chancela ships one codebase in three shapes:

- **Desktop** — a Tauri single-user app with an embedded SQLite store (offline).
- **Self-hosted server** — the `chancela-server` binary (Axum HTTP API + the web
  UI) plus the isolated `chancela-search-projector`, backed by SQLite or
  PostgreSQL.
- **MCP server** — an optional stdio bridge for AI-assisted drafting (see
  [Capabilities](capabilities.md#clients-desktop-web-api-mcp)).

This page covers the server editions. For the **secure production path**, use the
hardened images described in
[Security & Hardening](security/hardened-docker.md).

!!! info "Single-writer by design"
Every server profile below — including Postgres — is **single-writer,
single-node**. The app holds authoritative state in memory and allocates the
ledger sequence in process, so exactly one writer instance may run. Postgres
is a _durability_ upgrade (PG-native backup/inspection tooling), **not**
horizontal scale or HA. The only exception is the multi-node overlay, where
an advisory-lock election guarantees exactly one writer among the replicas.

## Choosing a profile

Profiles are **two independent axes** that combine. Pick exactly one _backend_
profile — each starts exactly one API service and its matching unscaled search
projector — and add any optional _sidecar_ profiles you want. A sidecar profile
starts no app service of its own, so
`--profile worker` on its own gives you a worker and nothing else; that is
deliberate, and it is what lets the same sidecar run against either backend.

| Profile                             | Axis    | Backend                     | When to use                                                                   | Compose file                        |
| ----------------------------------- | ------- | --------------------------- | ----------------------------------------------------------------------------- | ----------------------------------- |
| `single-node`                       | backend | SQLite (SQLCipher)          | Simplest self-host; file-level encryption at rest                             | `docker/docker-compose.yml`         |
| `postgres`                          | backend | PostgreSQL 18.4 + Redis 8.8 | Networked DB, PG-native backup tooling                                        | `docker/docker-compose.yml`         |
| `worker`                            | sidecar | either                      | The durable sync/backup connector worker, on the chosen backend's data volume | `docker/docker-compose.yml`         |
| Hardened `single-node` / `postgres` | backend | as above                    | Production posture: distroless, read-only rootfs, digest-pinned               | `docker-compose.hardened.yml`       |
| Multi-node overlay                  | backend | PostgreSQL 18.4 + Redis 8.8 | Leader + read-followers with failover (see [HA](#multi-node-leaderfollower))  | `docker/docker-compose.cluster.yml` |

Every backend profile also starts exactly one `chancela-search-projector`.
Request-serving API processes run in `query-only` search mode; the projector
builds and fences durable generations under its own CPU/memory limit and has no
listening socket. The desktop and a bare development `cargo run` keep the
embedded mode so offline/local workflows do not acquire a sidecar dependency.

## Published images and source builds

After every fully green push to `main`, normal CI publishes three unsigned images
to GHCR: `chancela-server`, `chancela-worker`, and
`chancela-search-projector`. CI first pushes all three by canonical digest, then
creates each `sha-<full-commit>` tag only when that tag is absent. A rerun
preserves an existing tag after verifying its source revision and
`linux/amd64` platform digest. No moving `latest` tag is published. BuildKit
provenance and SBOM attestations remain attached. CI validates the actual
BuildKit SLSA v1 and SPDX payloads on each built reference, tag decision, and
final reread; attestation descriptors without non-empty, structurally valid
payloads fail publication. The published
`chancela-server` image includes the SQLCipher, PostgreSQL, and
Redis feature set, so the same immutable digest can safely back both
`CHANCELA_SERVER_IMAGE` and `CHANCELA_POSTGRES_IMAGE`; runtime configuration
still selects exactly one backend.

The successful job uploads
`dist/ghcr-publication/chancela-image-set.json`. This complete image-set
manifest records, for all three images, the exact repository, full-SHA tag
digest, and runnable `linux/amd64` platform digest. A green workflow **and** the
validated complete manifest are the publication boundary; a tag left behind by
an interrupted job is not evidence that the whole set exists.

Optional cosign signing consumes this artifact rather than publishing another
image set. The signing workflow selects a successful `main` push CI run for the
exact commit, validates all three digest references, and signs/verifies each
digest. It cannot build or retag an image, so the signed server, worker, and
search projector remain the same bytes described by the deployment manifest.

Compose deliberately retains `build:` and `pull_policy: build`, so a checkout
builds the exact local source by default:

```sh
git clone <your-clone-url> chancela && cd chancela
docker compose up --build -d          # builds, then starts the single-node profile
```

The first build compiles the Rust workspace in a container and takes several
minutes; later builds reuse the layer cache. Nothing needs to be installed on
the host beyond Docker itself.

To deploy the exact CI artifacts instead, set `CHANCELA_SERVER_IMAGE`,
`CHANCELA_POSTGRES_IMAGE`, `CHANCELA_WORKER_IMAGE`, and
`CHANCELA_SEARCH_PROJECTOR_IMAGE` to the `repository@sha256:…` references from
the validated image-set manifest and use a deployment override that removes
`build:`/`pull_policy: build`. The full-SHA tags remain human-readable lookup
keys, but production deployment pins the manifest's exact digest references so
components from different commits cannot be mixed.

To rebuild after changing code, pass `--build` again (`docker compose up --build
-d`) or run `docker compose build` first; a plain `up` reuses the image that is
already tagged locally.

## Single node (SQLite)

The simplest deployment. One query-serving `chancela-server`, one isolated
`chancela-search-projector`, and an embedded SQLCipher-encrypted SQLite store on
a shared named volume, with no external database. Run from the repository root:

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
The projector is unprivileged and socketless, writes a bounded heartbeat beneath
`/var/lib/chancela/search-projector`, and is limited independently (default
`1.5` CPU / `1 GiB`; override with `CHANCELA_SEARCH_PROJECTOR_CPUS` and
`CHANCELA_SEARCH_PROJECTOR_MEMORY`). Both normal and hardened profiles enforce
a 128-process PID ceiling. Set `CHANCELA_SEARCH_INSTANCE_ID` to a friendly
1–128-character heartbeat/lease prefix; when omitted, the container hostname is
used and the runtime still appends per-process uniqueness. Heartbeats run every
`CHANCELA_SEARCH_HEARTBEAT_SECONDS` (Compose default `15`); both the container
healthcheck and API diagnostics use
`CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS` (default `600`) and reject a freshness
window smaller than two heartbeat intervals.

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

The app, projector, and optional worker share that volume at
`/var/lib/chancela`. The API owns
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
cache-aside. Postgres and Redis are **not** published to the host and attach
only to the internal `backend` network. The API has one interface on that
backend plane and another on the normal ingress/outbound network; the role
initializer and Postgres projector are backend-only.

On a fresh clone this is the whole procedure — there is **no host-side secret
step**:

```sh
CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
  docker compose --profile postgres up -d --build
```

The acknowledgement is mandatory and must be set only when the selected
PostgreSQL **database is dedicated to Chancela**. The projector initializer
revokes database-global `PUBLIC CONNECT`, `CREATE`, and `TEMPORARY`,
public-schema `CREATE`, and current/default public routine `EXECUTE`.
Applying that policy to a database shared with another application would break
that application and is unsupported.

No `-f` and no wrapper script: the repo-root `docker-compose.yml` `include`s
`docker/docker-compose.yml`, so this starts one Postgres API, its restricted
role initializer and projector, Postgres, and Redis. The single-node
`server-sqlite` service stays down, because a `--profile` on the command line
REPLACES the `COMPOSE_PROFILES=single-node` default in `.env` rather than adding
to it. (The former `docker/up.sh` wrapper existed only to pin an explicit `-f`
form; it is gone, together with the override files that made it necessary.)

### How the secrets get created

The profile creates five secret values in five separate **named volumes**.
The former combined `chancela-secrets` volume is a read-only migration source
for `secrets-init` only and is never attached to a steady-state service. The
one-shot initializer fills the split volumes before Postgres or the API starts
(`depends_on: … condition:
service_completed_successfully`, the same sequencing as
`postgres-tls-init`). Compose creates named volumes itself, so nothing has to
exist on the host beforehand.

| Secret                     | Consumed as                                                          | Volume file posture                 |
| -------------------------- | -------------------------------------------------------------------- | ----------------------------------- |
| `postgres_password`        | `POSTGRES_PASSWORD_FILE` (Postgres and role initializer)             | root-owned `0444` in its own volume |
| `database_url`             | `DATABASE_URL_FILE` (API and role initializer)                       | root-owned `0444` in its own volume |
| `credential_key`           | `CHANCELA_CREDENTIAL_KEY_FILE` (API only)                            | root-owned `0444` in its own volume |
| `search_database_password` | projector role initializer only                                      | root-owned `0444` in its own volume |
| `search_database_url`      | `CHANCELA_SEARCH_DATABASE_URL_FILE` (projector and role initializer) | root-owned `0444` in its own volume |

Each volume directory is `0755` and each consumer mount is read-only. The
`0444` mode is deliberate because Postgres, the API, and the initializer use
different non-root UIDs; secrecy comes from attaching each per-secret volume
only to its declared consumers, not from pretending one Unix owner can serve
them all. No value is placed directly in `environment:`. The long-running
projector gets only `search_database_url`, never the API owner URL, role
password, or `credential_key`.

After the API reports healthy (so schema migration and the `meta` readiness
marker are complete), `search-projector-role-init` creates/reasserts the fixed
`chancela_search_projector` role. It removes role memberships and all existing
memberships in both directions, refuses any object-owning role, and removes all
existing schema/table/sequence/routine grants. It closes `PUBLIC` database and
routine defaults, then grants column-level `SELECT` only for the exact corpus
fields plus `meta`, and column-level DML for derived search state (with table
`DELETE` only on `search_documents`). Before `COMMIT`, owner-side assertions
verify all role flags, membership/ownership absence, database/schema ACLs,
routine/default privileges, and forbidden broad object capabilities so any
failure rolls back the whole change. Verification then logs in through
`search_database_url`, rechecks every allowed and forbidden column, and executes
real denials for `CREATE SCHEMA`, temporary tables, a side-effect-free transient
public routine, raw blobs, provider credentials, source writes, and
authoritative control fields. On `settings`, the exact read grant is only
`(id, json)`. The projector fails closed instead of falling back to
`DATABASE_URL_FILE` when its restricted URL is absent.
The role remains explicitly bounded at 32 connections: a rolling deployment
may briefly overlap active and standby projector processes, each with the
Postgres backend's 10-connection read pool plus one follower writer connection
(22 total), while leaving bounded headroom for initializer and deployment
probes.

Generation is strictly **create-if-absent**: `up` never silently rotates a
secret that the volume already holds. A fully prepared inode is published by
same-filesystem hard link, which is atomic and cannot replace a concurrently
created destination; a racing value is accepted only when it matches exactly.
All five destinations are re-read and pair-validated before startup proceeds.
That is not a convenience — the first
three are write-once in practice, and projector-role rotation must be an
explicit coordinated operation:

| Secret                                             | Why it can never be regenerated in place                                                                                                                                                                                                                   |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `postgres_password`                                | `POSTGRES_PASSWORD_FILE` is read **only** when Postgres initialises `chancela-pgdata`. Once that volume exists the password is baked into the database, and a new value would leave the app unable to authenticate — a failure that looks like corruption. |
| `database_url`                                     | Embeds that same password inline, so it is always derived from `postgres_password` in the same run, never generated independently. The password uses a URL-safe alphabet precisely so one literal string is valid in both files.                           |
| `credential_key`                                   | Encrypts stored provider credentials. A new key makes every already-stored credential undecryptable.                                                                                                                                                       |
| `search_database_password` / `search_database_url` | Authenticate only the derived-search role. Rotate the pair together, then rerun the role initializer; never substitute the API owner URL.                                                                                                                  |

Both database passwords must be at least 32 characters and contain only URI
unreserved characters (`A-Z a-z 0-9 . _ ~ -`). The generator uses 36 random
bytes and emits 48 URL-safe characters. Both URLs are checked as exact
**local-Compose** endpoints at `postgres:5432` with `sslmode=verify-full`;
external database URLs require a separate managed deployment path.

Consequently `secrets-init` **refuses to start the stack** — rather than invent
a value — when a secret is absent but state that only that secret unlocks is
present: an initialised `chancela-pgdata`, or an existing provider-credential
store in either the single-node or cluster app-data volume. Host preflight
discovers volumes from Compose project/volume labels—including custom project
names—and probes for a nonempty `PG_VERSION` or exact nonempty secret file; it
never treats volume existence alone as state. Restore the secret (see below),
or discard the state with
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
cp docker/secrets/search_database_password.example docker/secrets/search_database_password
cp docker/secrets/search_database_url.example      docker/secrets/search_database_url

# … or generate them host-side, consistently and only once
sh docker/preflight-secrets.sh --generate
```

The same API password must appear in both `postgres_password` and
`database_url`; a separate password must appear in both
`search_database_password` and `search_database_url`. `--generate` guarantees
both relationships by deriving each URL from its password file. Host files are
written with no trailing newline and mode `0600` — not honoured on a
Windows/NTFS checkout, where the directory ACL is the only protection.
Empty values, symbolic links, embedded CR/LF bytes, case-insensitive
`CHANGE_ME`, short passwords, non-URI-safe passwords, and mismatched local URLs
all fail before publication.

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
Redis down. The API, projector, PostgreSQL, and Redis services all carry
`deploy.resources.limits`.
On Postgres, the projector sees the application-data volume read-only. Its only
writable non-database path is a separate `chancela-search-runtime` heartbeat
volume, which query-only APIs mount read-only. Before any API, role initializer,
or projector consumes it, the networkless `search-runtime-init` one-shot uses
only `CHOWN` capability to reassert the volume root as `65532:65532` mode
`0700`. SQLite necessarily keeps the shared data volume writable because the
projector updates derived tables inside the same SQLCipher database file.
Heartbeat schema v2 stores one file per canonical lease UUID at
`<runtime>/search-projector-heartbeats/<lease_id>.json`. The API and CLI
healthcheck select only the lease ID in durable projector control. A rolling
standby writes no file, including during standby shutdown; a stale owner can
touch only its retired lease file. The live CI lifecycle smoke holds both
processes against the same database/runtime and requires the durable lease,
lease-scoped file set, selected owner, and API freshness to remain unchanged.

That SQLite mount is the complete data root: it includes `settings.json`, the
`settings.pending-audit.json` commit journal, and legacy backup/privacy JSON
fallbacks. A pending journal or an existing settings/fallback file that cannot
be read or decoded blocks a projector candidate; only an absent settings file
selects defaults.

On Postgres, the `settings` table is authoritative for the main settings row and
the `backup-recovery-drill-receipts`, `privacy-dpia-records`,
`privacy-breach-playbooks`, and `privacy-transfer-controls` singleton rows.
When a backup/privacy row is absent, the read-only application-data mount still
provides the corresponding legacy JSON fallback for an upgrade. A present
database row always wins, even if the legacy file is malformed. Do not narrow
that mount to a cache subdirectory: the compatibility inputs are intentionally
part of the complete `/var/lib/chancela` root.

The projector is fixed to `CHANCELA_NODE_ROLE=follower`, so it cannot win the
authoritative ledger-writer election during an API restart; it writes only
fenced, derived search generations.
The single-node Postgres profile also waits for `server-postgres` to pass its
healthcheck before the projector starts, ensuring schema setup and the shared
application-data volume are initialized by the API first. The cluster overlay
replaces that dependency with the healthy scaled `chancela-cluster` service, so
it does not accidentally start an extra fourth API process.

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

The in-app backup endpoint (`POST /v1/backup`) creates a portable Chancela
logical bundle on Postgres, and recovery-drill preflight can verify that bundle
without changing live data. It is application-level recovery evidence, not a
replacement for database operations. Maintain **PG-native** `pg_dump` /
`pg_restore` backups and PITR (WAL archiving + base backups) for production
recovery objectives. For example:

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
    sh docker/preflight-secrets.sh --generate
    CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
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
writes to the leader. This is safe to scale because only one _instance_ ever
writes.

```sh
CHANCELA_PROJECTOR_DEDICATED_DATABASE=true docker compose \
  -f docker/docker-compose.yml -f docker/docker-compose.cluster.yml \
  --profile postgres --profile cluster up --build --scale chancela-cluster=3
```

The overlay replaces the base `server-postgres` profile with the deliberately
unselected `single-node-postgres` profile. The command above therefore starts
only the elected `chancela-cluster` API replicas and one unscaled search
projector; it cannot also start the standalone API as an unintended extra
writer.

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

# isolated search projector
docker build -f docker/Dockerfile.search-projector -t chancela-search-projector .

# hardened image
docker build -f Dockerfile.hardened -t chancela-server:hardened .
```

The build context is the **repository root** so the Dockerfile can see the whole
Rust + web workspace. A first build compiles the Rust workspace in release mode
and takes several minutes; subsequent builds reuse the BuildKit cache.
