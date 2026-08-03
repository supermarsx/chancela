# Hardened Docker images and operations

This page documents the **hardened** container artifacts for `chancela-server`
and the isolated `chancela-search-projector`, and how to run them safely:

- [`Dockerfile.hardened`](https://github.com/supermarsx/chancela/blob/main/Dockerfile.hardened) — a security-tightened,
  digest-pinned, distroless, non-root image.
- [`docker-compose.hardened.yml`](https://github.com/supermarsx/chancela/blob/main/docker-compose.hardened.yml) — hardened
  runtime profiles (`single-node` and `postgres`).
- [`docker/Dockerfile.search-projector`](https://github.com/supermarsx/chancela/blob/main/docker/Dockerfile.search-projector) —
  a socketless, distroless, non-root projector image with its own heartbeat.

These are **additive** variants. They do not replace the existing
`docker/Dockerfile.server` and `docker/docker-compose.yml`; they layer a
stricter posture on top. For the deployment-profile scope and its honest limits
(single-writer, single-node, no HA), see the
[Deployment overview](../deployment.md).

> Scope note: these profiles are single-host, single-writer deployments. They
> improve container posture; they are not a complete production architecture and
> do not provide high availability, failover, or horizontal scale.

---

## System requirements

### Host resources

| Profile | CPU (min) | CPU (rec.) | RAM (min) | RAM (rec.) | Free disk |
| ------- | --------- | ---------- | --------- | ---------- | --------- |
| `single-node` (API + projector + SQLite) | 4 cores | 6 cores | 3 GB | 6 GB | 5 GB runtime |
| `postgres` (API + projector + Postgres + Redis) | 8 cores | 10 cores | 6 GB | 10 GB | 10 GB+ runtime |

The per-service `deploy.resources.limits` are the ceiling, not the footprint:
the API caps at `2.0` CPU / `1 GB`, the search projector at `1.5` CPU /
`1 GB`, Postgres at `2.0` CPU / `1 GB`, and Redis at `1.0` CPU / `320 MB`.
Size the host above the sum of the ceilings for the profile you run.

**Build host:** a first `--build` compiles the Rust workspace in release mode.
Budget **8–12 GB free disk** for the BuildKit cargo/registry cache and image
layers, and expect a multi-minute cold build. Subsequent builds reuse the cache
mounts and are much faster.

**Data volume:** the durable named volume (`/var/lib/chancela`, and
`chancela-pgdata` on the Postgres profile) grows with usage. Start with a few GB
of headroom and monitor it; put the Postgres data volume on **encrypted storage**
(see [Secrets and encryption at rest](#secrets-and-encryption-at-rest)).

### Software

| Component | Version | Notes |
| --------- | ------- | ----- |
| Linux kernel | 5.10+ | Needed for a modern seccomp/BPF filter and cgroup v2 accounting. |
| cgroups | v2 | Required for the memory / CPU / **pids** limits to be enforced. |
| Docker Engine | 24.0+ | BuildKit is the default builder; `docker compose up` honours `deploy.resources.limits`. |
| Docker Compose | v2.24.4+ | v2 syntax, `deploy.resources.limits.pids`, and the cluster overlay's safe `!override` dependency replacement. |
| PostgreSQL | 18.4 (`postgres:18.4-alpine3.23`) | `postgres` profile only. Pinned by digest. |
| Redis | 8.8 (`redis:8.8.0-alpine3.23`) | `postgres` profile only, cache-aside. Pinned by digest; review its RSALv2/SSPLv1/AGPLv3 licensing. |

Linux is the target runtime. Docker Desktop on macOS/Windows works for local
builds and smoke tests, but the read-only-rootfs, seccomp, and capability
semantics are Linux-native and only fully apply on a Linux host/VM.

---

## Build and run

Run every command from the **repository root** (the build context is the repo
root so the Dockerfile can see the whole workspace).

### Single node (SQLite, no external database)

```sh
docker compose -f docker-compose.hardened.yml --profile single-node up --build
```

The app publishes on `127.0.0.1:8080` (loopback only). Override the host port:

```sh
CHANCELA_HOST_PORT=18080 docker compose -f docker-compose.hardened.yml --profile single-node up
```

### Postgres durability backend + Redis cache

1. Generate validated, internally consistent host secret files (see
   [Secrets](#secrets-and-encryption-at-rest)):

   ```sh
   sh docker/preflight-secrets.sh --generate
   ```

2. Confirm the target database is dedicated to Chancela, then start:

   Acknowledge it by uncommenting `CHANCELA_PROJECTOR_DEDICATED_DATABASE=true`
   in the repo-root `.env` (identical on every platform), or by setting it for
   the shell. In PowerShell this must be a **separate statement** — PowerShell
   has no inline `VAR=value command` prefix, so the bash form below would leave
   the acknowledgement unset and the initializer would refuse to run:

   ```powershell
   $env:CHANCELA_PROJECTOR_DEDICATED_DATABASE = "true"
   docker compose -f docker-compose.hardened.yml --profile postgres up --build
   ```

   ```sh
   CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
     docker compose -f docker-compose.hardened.yml --profile postgres up --build
   ```

### Build the image on its own

Normal CI publishes `chancela-server`, `chancela-worker`, and
`chancela-search-projector` to GHCR only after every required `main` check
passes. Those images carry provenance/SBOM attestations but remain explicitly
unsigned. `--build` still builds the reviewed checkout locally; to build
standalone:

```sh
docker build -f Dockerfile.hardened -t chancela-server:hardened .
docker build -f docker/Dockerfile.search-projector -t chancela-search-projector:hardened .
```

All repository-built services declare `pull_policy: build`, so `up` builds a missing image
rather than attempting a registry pull, and `docker compose pull` skips them and
fetches only the digest-pinned third-party images. See
[Deployment](../deployment.md#published-images-and-source-builds).

### Validate the compose file without building

```sh
docker compose -f docker-compose.hardened.yml --profile postgres config
```

(`config` requires the secret files to exist; generate them first, as above.)

---

## Hardening checklist and why

Each measure below maps to a concrete threat it reduces. "App" = the API and
projector services built from our own code (`server-*`, `search-projector-*`);
"Infra" = the official
`postgres` / `redis` images.

### Image build

- [x] **Multi-stage build.** Rust and Node toolchains, source, and build caches
  never reach the final image → smaller attack surface, no compilers/package
  managers to abuse post-exploit.
- [x] **Distroless final base** (`gcr.io/distroless/cc-debian13:nonroot`). No
  shell, no package manager, no general userland → far fewer binaries an attacker
  can pivot through.
- [x] **All base images pinned by digest** (`@sha256:…`), not floating tags → a
  repushed/poisoned upstream tag cannot silently change what you ship
  (supply-chain integrity, reproducible builds).
- [x] **Non-root, numeric UID/GID** (`USER 65532:65532`). Numeric so
  `runAsNonRoot`-style checks pass without `/etc/passwd` → a container escape
  starts as an unprivileged user, not root.
- [x] **No secrets baked in.** All configuration and secrets come from the
  environment / docker secrets at runtime; `.dockerignore` excludes
  `docker/secrets`, `.git`, `target`, and `node_modules` from the build context →
  no credential or VCS history leaks into an image layer.
- [x] **Pinned dependency versions.** `cargo build --locked` (exact `Cargo.lock`)
  and `npm ci` (exact lockfile) → builds are reproducible and cannot pull
  unexpected transitive versions.
- [x] **OCI provenance labels.** `org.opencontainers.image.*` record source
  (`github.com/chancela/chancela`), licence
  (`LicenseRef-Chancela-NonCommercial`), and the base image digest →
  traceability for audits and scanners.

> **Known tradeoff — busybox for the healthcheck.** Distroless has no HTTP
> client, so the image copies a single static `busybox` binary (pinned by digest)
> used only by `HEALTHCHECK`. busybox is a multi-call binary that includes an
> `sh` applet, so this is the one shell present in the final image. It is a
> single ~1 MB static file with no package manager; combined with the non-root
> user and read-only root filesystem, it cannot be used to install or persist
> anything. The clean long-term fix is a dedicated `chancela-server healthcheck`
> subcommand so busybox can be dropped entirely.

### Runtime (App services)

- [x] **Read-only root filesystem** (`read_only: true`). The image layer is
  immutable at runtime → an attacker cannot drop a payload onto the root fs or
  tamper with binaries.
- [x] **Writable paths are explicit and bounded.** `/tmp` is a size-capped
  `tmpfs` (`/tmp:size=64m`); durable state lives on a **named volume** at
  `/var/lib/chancela` only → nothing else is writable, and `/tmp` cannot exhaust
  host memory.
- [x] **All Linux capabilities dropped** (`cap_drop: [ALL]`, none added back) →
  removes privileged operations (raw sockets, mount, ptrace, etc.) even if the
  process is compromised.
- [x] **No privilege escalation** (`security_opt: [no-new-privileges:true]`) → a
  setuid binary cannot raise privileges; blocks a common escape primitive.
- [x] **seccomp + AppArmor defaults.** The Docker daemon's default seccomp
  profile (blocks ~44 dangerous syscalls) and the `docker-default` AppArmor
  profile apply automatically. See [Custom seccomp](#optional-custom-seccomp-profile)
  to pin a profile explicitly.
- [x] **PID 1 init** (`init: true`, tini) → reaps zombies and forwards signals
  for a clean, prompt shutdown (`SIGTERM` drain).
- [x] **Process cap** (`deploy.resources.limits.pids: 256`) → blunts fork-bomb
  style local DoS.
- [x] **File-descriptor cap** (`ulimits.nofile` 1024/2048) → bounds fd
  exhaustion.
- [x] **CPU / memory limits + reservations** → a single container cannot starve
  the host or its neighbours.
- [x] **Log growth cap** (`json-file`, `max-size: 10m`, `max-file: 3`) → a chatty
  or attacked container cannot fill host disk with logs.
- [x] **Loopback-only published port** (`host_ip: 127.0.0.1`) → the API is not
  reachable off-host by accident; front it with a reverse proxy/TLS terminator
  for real ingress.
- [x] **Restart policy** (`unless-stopped`) → automatic recovery from crashes
  without restarting on an explicit stop.
- [x] **Healthcheck** against `GET /health` → orchestrators detect and replace an
  unhealthy container; `depends_on: condition: service_healthy` gates startup.

### Runtime (Infra services: Postgres, Redis)

- [x] **Not published to the host** — Postgres (`5432`) and Redis (`6379`) are on
  an `internal: true` compose network with **no route to the host or outside
  world**; only the API/projector backend services can reach them → the
  database and cache are never exposed.
- [x] **No privilege escalation** (`no-new-privileges:true`) on top of the
  images' own privilege drop to their internal users.
- [x] **Least-privilege capabilities.** `cap_drop: [ALL]` then add back only what
  each official entrypoint needs (Postgres: `CHOWN, DAC_OVERRIDE, FOWNER, SETGID,
  SETUID` to chown its data dir and drop to the `postgres` user; Redis: `CHOWN,
  SETGID, SETUID`) → far below the default full capability set.
- [x] **Size-capped tmpfs** for `/tmp` and the Postgres socket dir
  (`/var/run/postgresql`) → keeps writes off the host and bounds memory.
- [x] **pids / fd / CPU / memory / log caps** as above.
- [x] **Images pinned by digest.**

> **Why the infra images are not `read_only`/`cap_drop:[ALL]`-with-nothing-added:**
> the official `postgres`/`redis` entrypoints run briefly as root to `initdb` /
> chown their data directory and then drop to an internal user. Forcing a
> read-only root fs or removing `CHOWN`/`SETUID`/`SETGID` breaks that bootstrap.
> The app container — our own code — gets the maximal posture; the stateful images
> get every hardening that does not break their documented startup contract.

---

## Secrets and encryption at rest

**Never bake secrets into an image or commit real secret files.** The Postgres
profile uses **file-based docker secrets** mounted at `/run/secrets/*`. The real
files live under `docker/secrets/` and are **gitignored**; only `*.example`
templates are committed.

Generate them with the repository helper, which enforces the same policy as the
normal profile: both database passwords are at least 32 URI-unreserved
characters (`A-Z a-z 0-9 . _ ~ -`), URLs exactly target the local
`postgres:5432` service with `sslmode=verify-full`, and symbolic links, CR/LF,
empty values, or case-insensitive `CHANGE_ME` placeholders fail before startup.
Those exact URL checks intentionally do not describe an external managed
PostgreSQL deployment.

| Secret file | Injected as | Purpose |
| ----------- | ----------- | ------- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` | Postgres user password. |
| `database_url` | `DATABASE_URL_FILE` | Full libpq URL **including the same password**; mounted read-only into the API only and references the `postgres` service by name. |
| `credential_key` | `CHANCELA_CREDENTIAL_KEY_FILE` | Provider-credential store root key, mounted read-only into the API only. **Required** on Postgres (no SQLCipher `DerivedFromDbKey` source); the projector cannot decrypt signing-provider credentials. |
| `search_database_password` | role initializer only | Independent password for the fixed, restricted `chancela_search_projector` role. |
| `search_database_url` | `CHANCELA_SEARCH_DATABASE_URL_FILE` | Projector-only URL containing that independent password. The projector fails closed rather than falling back to the API owner URL. |

The normal Compose profile publishes these as five separate root-owned `0444`
files in `0755` named-volume roots. That mode is intentionally readable by the
different non-root UIDs of the explicitly attached consumers; confidentiality
comes from per-secret volume attachment and read-only consumer mounts. The
legacy combined volume is read-only and visible only to the migration
initializer. Hardened Compose uses one file-backed Compose secret per value.
Because local Compose implements those values as bind mounts and cannot remap
their ownership, a networkless one-shot preserves the operator as owner, sets
group `65532` and mode `0640`, and must finish before the non-root preflight
runs as `65532:65532`. The API, Postgres, role initializer, and projector start
only after that preflight succeeds. Thus the operator retains rotation access,
the declared runtime identity gets group-read access, and neither other host
users nor unrelated containers receive a world-readable fallback.

The one-shot role initializer waits for the API's schema-readiness health gate,
removes memberships in both directions and inherited/old grants, refuses an
object-owning role, applies the exact corpus/projection column allowlist, and
asserts the complete effective posture before committing. It then logs in as
the restricted role and proves that database/schema/temp creation, public
routine execution, raw PDF/import bytes, entity/event writes, authoritative
control fields, and `provider_credentials` are denied. The long-running projector mounts only
`search_database_url`; on Postgres its application-data mount is
read-only and heartbeat writes go to a separate runtime volume. Its fixed
32-connection role cap covers a rolling active/standby process overlap
(`2 × (10 pooled reads + 1 follower writer)`) plus deployment probes without
turning the role into an unbounded login. A networkless, root one-shot with
only `CHOWN` capability verifies that fresh runtime volume as `65532:65532`
mode `0700` before the API, role verifier, or projector starts.

!!! danger "Dedicated PostgreSQL database required"

    The role boundary depends on database-global hardening: `PUBLIC CONNECT`,
    `CREATE`, and `TEMPORARY` are revoked on the database, `PUBLIC CREATE` is
    revoked on schema `public`, and existing plus API-owner default routine
    `EXECUTE` is revoked. The initializer refuses to run unless
    `CHANCELA_PROJECTOR_DEDICATED_DATABASE=true` is supplied explicitly.
    Never set it for a database shared with another application.

The only readable `settings` columns are `id` and `json`; live ACL probes also
deny singleton `INSERT`, `UPDATE`, and `DELETE`. Those two columns carry the
main settings row and the fixed database-authoritative backup/privacy
singletons. The read-only application-data mount deliberately remains the whole
`/var/lib/chancela` root so a missing singleton can consume its legacy JSON
fallback during an upgrade. A present database row wins over that file.

SQLite gives the API and projector the same complete writable data mount so the
projector sees `settings.json`, its `settings.pending-audit.json` commit journal,
and every legacy backup/privacy input atomically. An existing journal or an
unreadable/malformed settings or fallback document fails projector startup
closed rather than publishing defaults or empty controls. CI exercises those
failure states, stale status/heartbeat reporting, recovery after repair, and
Postgres authority over malformed legacy fallbacks. It also starts an
overlapping Postgres standby on the same restricted database role and runtime
volume, then selects
`search-projector-heartbeats/<current-durable-lease-id>.json` and proves that
the durable lease, scoped-file set, selected owner, and API freshness stay
unchanged before, during, and after standby shutdown.

Generate the internally consistent, non-placeholder files:

```sh
sh docker/preflight-secrets.sh --generate
```

The password inside `database_url` **must match** `postgres_password`, or the API
cannot authenticate. The password inside `search_database_url` must separately
match `search_database_password`; never put the API role in that URL. Example
(fictional) API `database_url`:

```
postgres://chancela:S0meLongRandomValue_0123456789abcdef@postgres:5432/chancela?sslmode=verify-full
```

Full details: [`docker/secrets/README.md`](https://github.com/supermarsx/chancela/blob/main/docker/secrets/README.md).

### The credential root key

`CHANCELA_CREDENTIAL_KEY_FILE` supplies the root key for the provider-credential
store (app-layer XChaCha20-Poly1305). On the SQLite (`single-node`) build the key
can be derived from the SQLCipher database key; on Postgres there is no such
source, so the operator **must** supply this secret. Treat it like a master key:
back it up out of band, rotate it deliberately, and never log or commit it.

### Encryption at rest

Vanilla Postgres has **no** transparent whole-DB encryption, so this profile does
**not** provide SQLCipher's file-level ciphertext for the Postgres data. Protect
the `chancela-pgdata` volume with **host volume/disk encryption** (LUKS or an
encrypted block device). This is disk-level: a DB superuser or a live memory dump
still sees plaintext — a materially weaker guarantee than SQLCipher. PostgreSQL
transport is authenticated with `sslmode=verify-full`; the isolated TLS-init
container writes a private CA/server certificate volume that is mounted
read-only by Postgres and the app. A remote Postgres must use its provider CA.

### Zero-knowledge object-root warning

Zero-knowledge repositories keep only opaque immutable ciphertext in
`<data_dir>/zk-repositories`; keys and decryption remain in trusted clients. PostgreSQL does not
share that filesystem automatically. In a multi-node deployment, mount the same protected object
root on every node and set `CHANCELA_ZK_SHARED_OBJECT_ROOT` to that exact path. Without the explicit
setting the repository API returns `503` fail-closed. Never configure a node-local path and describe
it as HA. Include the shared root in encrypted off-site backup custody: the built-in backup manifest
digests it recursively, but zero-knowledge encryption still leaves GDPR, retention, access-control,
and breach-response obligations in force.
See the
[Deployment overview](../deployment.md) for the
full at-rest discussion.

---

## Optional supply-chain steps

These are **recommended** add-ons, not part of the compose run. They need their
own tooling and, for signing, a key/identity you control. Example commands
(replace the image reference with your own):

### Vulnerability scan

```sh
# Trivy
trivy image chancela-server:hardened

# or Grype
grype chancela-server:hardened
```

### Software Bill of Materials (SBOM)

```sh
# Syft — SPDX JSON
syft chancela-server:hardened -o spdx-json=chancela-sbom.spdx.json

# BuildKit can also attach an SBOM + provenance attestation at build time:
docker buildx build -f Dockerfile.hardened \
  --sbom=true --provenance=mode=max \
  -t chancela-server:hardened .
```

### Sign and verify (cosign)

```sh
# Keyless (OIDC) signing
cosign sign chancela-server:hardened

# or key-based
cosign generate-key-pair
cosign sign --key cosign.key chancela-server:hardened
cosign verify --key cosign.pub chancela-server:hardened
```

> Do **not** describe images produced by the compose profiles as signed or
> attested unless a signing/provenance pipeline has actually run and its evidence
> is available.

### Refreshing pinned digests

The `FROM … @sha256:…` pins in `Dockerfile.hardened` and the image digests in
`docker-compose.hardened.yml` are intentionally frozen. Refresh them **on
purpose** (e.g. to pick up a base image security fix) rather than reverting to
floating tags. Resolve the current digest for a tag with:

```sh
docker buildx imagetools inspect rust:1.97.0-slim-trixie --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect node:24.18.0-trixie-slim --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect gcr.io/distroless/cc-debian13:nonroot --format '{{.Manifest.Digest}}'
```

Then update the digest in the relevant `FROM`/`image:` line and rebuild.

### Optional: custom seccomp profile

The daemon default seccomp profile applies automatically. To pin an explicit or
stricter profile, add it to a service:

```yaml
security_opt:
  - no-new-privileges:true
  - seccomp=./docker/seccomp/chancela.json
```

Start from Docker's [default profile](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)
and remove syscalls the app does not need. Test thoroughly — an over-tight
profile causes hard-to-diagnose runtime failures.

---

## Operational safety

- **Non-root by default.** The app runs as UID/GID `65532`. If you mount extra
  host paths, ensure that user can read/write them; do not "fix" a permission
  error by running as root.
- **Read-only root filesystem.** Nothing writes to the image at runtime. If a
  future feature needs a new writable path, add a size-capped `tmpfs` (ephemeral)
  or a named volume (durable) — do **not** disable `read_only`.
- **Backups.** On SQLite (`single-node`) the in-app backup endpoint uses
  `VACUUM INTO`. On Postgres the same endpoint creates an application-level
  logical bundle that recovery-drill preflight can verify. It does not replace
  PG-native `pg_dump`/`pg_restore`, WAL archiving, or base backups for PITR.
  Example:

  ```sh
  docker compose -f docker-compose.hardened.yml --profile postgres \
    exec postgres pg_dump -U chancela chancela > chancela-$(date -u +%Y%m%dT%H%M%SZ).sql
  ```

- **Upgrade flow.** Pull/refresh the pinned base digests → rebuild the image →
  scan (Trivy/Grype) → deploy → confirm `GET /health` reports healthy. Because
  the root fs is read-only and state lives on named volumes, upgrades replace the
  container without touching persistent data. Snapshot/back up the data volume
  before a major upgrade.
- **Single writer.** Never scale the writer service (`server-sqlite` / `server-postgres`). The
  app holds authoritative state in memory and allocates the ledger sequence in
  process; two writers against one store violate the design. See the
  [Deployment overview](../deployment.md).
- **Loopback ingress.** The published port binds `127.0.0.1` only. For real
  ingress, put a TLS-terminating reverse proxy in front rather than publishing
  the port on `0.0.0.0`.
