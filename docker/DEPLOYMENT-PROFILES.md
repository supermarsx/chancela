# Docker Deployment Profiles

This directory contains bounded Docker Compose profiles for local and
single-node container deployment validation. They improve ARC-40/41/42 coverage
for container posture, but they are not production attestation evidence.

## Profiles

### `single-node`

Starts one `chancela-server` container from the existing server image:

```sh
docker compose -f docker/docker-compose.yml --profile single-node up --build
```

The service uses:

- non-root UID/GID `65532:65532`
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges:true`
- `/tmp` as tmpfs scratch
- a persistent named volume mounted at `/var/lib/chancela`
- a container healthcheck against `GET /health`

The host port defaults to `127.0.0.1:8080`. Override it with
`CHANCELA_HOST_PORT`, for example:

```sh
CHANCELA_HOST_PORT=18080 docker compose -f docker/docker-compose.yml --profile single-node up
```

The existing Docker smoke scripts can validate this profile without rebuilding
an image:

```sh
scripts/docker-smoke.sh --compose-profile chancela-server:local
```

```powershell
scripts\docker-smoke.ps1 -Image chancela-server:local -ComposeProfile
```

### `validation-worker`

Starts the `server` service plus a bounded `validation-worker` sidecar that
reuses the same server image:

```sh
docker compose -f docker/docker-compose.yml --profile validation-worker up --build
```

The sidecar has the same non-root, read-only, capability-dropped posture as the
server. It binds only inside the Compose network on port `8081`, has its own
persistent named volume, and exposes a healthcheck against its internal
`/health` endpoint.

Current limitation: this is a deployment-profile placeholder for isolation and
health validation. It is not a dedicated asynchronous worker, validation queue,
or production sidecar implementation because the repository does not currently
ship a separate worker image or worker entrypoint.

### `postgres`

Brings up the self-hosted Postgres stack: the `chancela` app built with the
PostgreSQL durability backend plus an optional Redis cache-aside, a `postgres`
service, and a `redis` service.

```sh
# 1. Create the real secrets from the templates (see docker/secrets/README.md):
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
# ...then edit them (strong password in BOTH postgres_password and database_url).

# 2. Start the profile (builds the postgres+redis feature image):
docker compose -f docker/docker-compose.yml --profile postgres up --build
```

**What it is — and is not.** This is a **durability** upgrade, **not** scale-out.
The app holds authoritative domain state in memory and allocates the ledger
`seq` in process, so **exactly one** `chancela` instance may write. The profile
pins `deploy.replicas: 1` and you must never scale it: two instances against one
Postgres would violate the single-writer design. Postgres enables PG-native
backup/inspection tooling and a networked database process - it does **not** buy
HA, failover, or horizontal scale (that is a separate, much larger effort). This
profile is **still a single-node deployment**.

Services and posture:

- **`chancela`** (app): built with
  `CARGO_FEATURES="chancela-server/sqlcipher chancela-server/postgres chancela-server/redis"`.
  Same hardening as `server` (non-root `65532`, read-only rootfs, `cap_drop:
  ALL`, `no-new-privileges`, `/tmp` tmpfs). Keeps a small writable named volume
  at `/var/lib/chancela` — still required on Postgres for the credential sidecar
  (`provider-credentials.enc.json`), the CAE/law/TSL caches, and the JSON
  sidecars. Loopback host port (default `127.0.0.1:8080`, override with
  `CHANCELA_HOST_PORT`). Startup waits only for `postgres` health; Redis remains
  a fail-open cache service.
- **`postgres`** (`postgres:16-alpine`, version-tagged): `POSTGRES_DB`/`POSTGRES_USER`
  (override with `CHANCELA_PG_DB`/`CHANCELA_PG_USER`), `POSTGRES_PASSWORD_FILE`
  docker secret, named volume `chancela-pgdata` for the data directory,
  `pg_isready` healthcheck, `no-new-privileges`, resource limits. Not published
  to the host - reachable only on the compose network. The app runs idempotent
  schema creation/checks on boot under an advisory writer lock, so this profile
  does not need an init SQL job.
- **`redis`** (`redis:7-alpine`, version-tagged): AOF persistence on `chancela-redisdata`,
  `maxmemory` + `allkeys-lru`, `redis-cli ping` healthcheck, `no-new-privileges`,
  resource limits. This is only a cache service: the app is fully correct with
  Redis down or absent because cache operations fail open.

All three services carry `deploy.resources.limits` (honoured by `docker compose
up` v2).

#### Secrets

File-based docker secrets under `docker/secrets/` (real files gitignored;
`*.example` templates committed — see `docker/secrets/README.md`):

| Secret file         | Injected as                         | Purpose |
| ------------------- | ----------------------------------- | ------- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE`             | Postgres superuser password. |
| `database_url`      | `DATABASE_URL_FILE`                  | Full libpq URL incl. the same password; references the `postgres` service. |
| `credential_key`    | `CHANCELA_CREDENTIAL_KEY_FILE`       | Provider-credential store root key (**required** on PG). |

#### Encryption at rest — be honest about the difference

Postgres has **no** transparent whole-DB encryption in vanilla community builds,
so this profile does **not** give you SQLCipher's file-level ciphertext-at-rest.
The at-rest posture for Postgres data is:

- **Volume/disk encryption** (host-provided: LUKS or an encrypted block device)
  for the `chancela-pgdata` volume.

This is disk-level: a DB superuser or a live memory dump still sees plaintext —
a materially weaker guarantee than SQLCipher. The credential store keeps its own
app-layer XChaCha20-Poly1305 encryption regardless (its root key comes from
`CHANCELA_CREDENTIAL_KEY_FILE`, since `DerivedFromDbKey` needs SQLCipher).

**TLS to Postgres (`sslmode=verify-full`) is not implemented in this lane.** The
current backend uses `NoTls` and the compose profile assumes the local Compose
network. A remote Postgres deployment needs a future TLS connector before it can
claim verified transport security.

#### Backup and restore on Postgres

The in-app backup endpoint (`POST /v1/backup`, SQLite `VACUUM INTO`) is
**Unsupported on the Postgres backend** — there is no `.db` file to snapshot or
swap. Use **PG-native tooling**: `pg_dump` / `pg_restore` for logical backups, or
PITR (WAL archiving + base backups) for point-in-time recovery. Example:

```sh
docker compose -f docker/docker-compose.yml --profile postgres \
  exec postgres pg_dump -U chancela chancela > chancela-$(date -u +%Y%m%dT%H%M%SZ).sql
```

#### Performance note

On SQLite the write-through store transaction is a microsecond-scale local file
write. On Postgres it becomes a network round-trip; the app routes those hot
store calls through `spawn_blocking` so a tokio worker is not blocked while the
single ledger write lock is held. Throughput is still bounded by the
single-writer design.

## Image Signing And Attestation

These profiles do not sign, attest, notarize, push, or verify images. They only
build or run local Docker images. Do not describe images produced by these
commands as signed or attested unless a separate signing and provenance pipeline
has been configured and its evidence is available.

## HA And Multi-Node Limits

These profiles are single-host profiles. They do not provide:

- high availability
- distributed locking
- database failover
- rolling updates
- registry promotion controls
- runtime admission policy enforcement

Use them as local smoke and bounded deployment coverage, not as a complete
production deployment architecture.

This applies to the `postgres` profile too: swapping the durability backend to
PostgreSQL does **not** relax the single-writer constraint. The app remains
in-memory-authoritative and allocates the ledger `seq` in process, so the
profile is pinned to one writer (`deploy.replicas: 1`) and is still a single-node
deployment.
