# Extras

Operational concerns beyond the core install: what an operator typically needs
around Chancela to run it responsibly. The hardened container guide covers the
container-security side; this page points at the surrounding pieces.

## Backups, restore, and recovery

- **SQLite (`single-node`)** — the in-app backup endpoint
  (`POST /v1/backup`, SQLite `VACUUM INTO`) applies. Restore verifies every
  member and that the snapshot ledger verifies before an atomic database swap.
- **Postgres** — the in-app backup endpoint is **unsupported** (there is no `.db`
  file). Use PG-native tooling — `pg_dump`/`pg_restore` for logical backups, or
  WAL archiving + base backups for point-in-time recovery:

    ```sh
    docker compose -f docker/docker-compose.yml --profile postgres \
      exec postgres pg_dump -U chancela chancela > chancela-$(date -u +%Y%m%dT%H%M%SZ).sql
    ```

- **Ledger recovery plane** — on integrity failure the server drops to read-only
  degraded mode; recover with **reanchor** (tamper-evident linkage repair) or
  **restore** (verified snapshot swap) from the Integrity settings section. See
  [Capabilities → Ledger](capabilities.md#append-only-hash-chained-ledger).
- **Book export / preservation packages** — export verifiable book bundles and
  preservation packages for off-system archival (see
  [Capabilities → Export/import](capabilities.md#book-export-import-with-fixity)).

## Timestamping (TSA)

Configure a Time-Stamping Authority URL (`CHANCELA_TSA_URL`, and TSA providers in
the Signing settings section) to obtain RFC 3161 timestamps used by the PAdES/
XAdES `-T` evidence. Timestamping strengthens the evidentiary record but is not a
substitute for a qualified signature.

## Reverse proxy / TLS

The server binds `127.0.0.1` and does **not** terminate TLS itself. For real
ingress, put a TLS-terminating reverse proxy (nginx, Caddy, Traefik) in front:

- terminate HTTPS and forward to the app's loopback port;
- in multi-node, make the proxy **leader-aware** (route writes to the leader by
  reading the `/health` role, reads to any node) or let clients follow the `307`
  write redirects.

The optional Postgres backend uses a rustls connector and requires authenticated
`verify-full` transport. `CHANCELA_PG_SSLMODE` takes precedence over
`DATABASE_URL`; `verify-ca` is accepted and hardened to `verify-full`, while
`disable`, `prefer`, and `require` fail closed. CI now creates an ephemeral CA
and hostname-valid server certificate and runs the ignored live
`sslmode_verify_full_opens_and_roundtrips_on_postgres` test. That proves the
connector and CI certificate path, not production remote-database, CA-custody,
HA, failover, or RPO/RTO readiness.

The API emits `Strict-Transport-Security` on responses. It is useful only after
the app is behind a real HTTPS-terminating proxy because browsers ignore HSTS
over plain HTTP. Set `CHANCELA_HSTS_MAX_AGE`,
`CHANCELA_HSTS_INCLUDE_SUBDOMAINS`, and `CHANCELA_HSTS_PRELOAD` deliberately for
the deployed hostname; header emission in the app is not proof that TLS, HSTS
preload, or external deployment has been validated.

## Runtime limits and sessions

- **HTTP rate limiting** - the running server enables an in-memory per-client-IP
  token bucket by default (`CHANCELA_RATE_LIMIT_ENABLED`,
  `CHANCELA_RATE_LIMIT_PER_SECOND`, `CHANCELA_RATE_LIMIT_BURST`). Health,
  readiness, and metrics probes are exempt. Trusting `X-Forwarded-For` /
  `X-Real-IP` is opt-in through `CHANCELA_RATE_LIMIT_TRUST_FORWARDED_FOR` and
  should be used only behind a trusted reverse proxy.
- **Session lifetime** - `CHANCELA_SESSION_MAX_LIFETIME` caps the absolute
  wall-clock age of a session on top of the existing sliding idle expiry.

These controls are local in-memory single-node runtime hardening. They are not
cluster-wide/distributed rate limiting, HA, SQLCipher-at-rest proof, legal/DR/
security certification, or external deployment proof.

## Monitoring and healthchecks

- **Liveness** — `GET /health` reports liveness, the crate version, persistence
  status, and the ledger chain status (including whether the server is in
  degraded read-only mode). The compose files already wire a container
  healthcheck against it.
- **Cheap probes** — `GET /livez` is a dependency-free process liveness probe.
  `GET /readyz` is a narrow readiness probe for degraded read-only mode only:
  it returns `503` when the integrity chain has failed closed and `200`
  otherwise. It does not prove database, Redis, remote signing, trust-list, or
  multi-node dependency readiness. Both probes are also available under the
  integration alias (`/api/livez`, `/api/readyz`).
- **Prometheus metrics** — `GET /metrics` renders Prometheus text and is also
  mounted at `/api/metrics` for integration clients. It is intentionally
  unauthenticated for scraper compatibility, so deployments must keep it on an
  internal network or behind a reverse-proxy/network allowlist. Do not expose it
  directly to the public internet.
- **Multi-node** — `/health` also advertises the node role (leader/follower);
  use it for leader-aware load-balancer routing and failover detection.
- **Logs** — server logs are structured JSON by default (`CHANCELA_LOG` or
  `RUST_LOG` controls the filter; `CHANCELA_LOG_FORMAT=pretty` is for local
  development). The hardened compose caps log growth (`json-file`,
  `max-size: 10m`, `max-file: 3`) so a chatty or attacked container cannot fill
  host disk. The Platform settings section exposes a live log tail.

## SBOM and vulnerability scanning

The compose profiles build local images; they do **not** sign, attest, or scan.
Add these as deliberate supply-chain steps (full commands in
[Security & Hardening → Optional supply-chain steps](security/hardened-docker.md#optional-supply-chain-steps)):

- **Scan** — `trivy image chancela-server:hardened` or `grype …`.
- **SBOM** — `syft chancela-server:hardened -o spdx-json=…`, or attach SBOM +
  provenance at build time with `docker buildx build --sbom=true --provenance=mode=max`.
- **Sign / verify** — `cosign sign` / `cosign verify` (keyless OIDC or key-based).

Do not describe images as signed or attested unless a signing/provenance pipeline
has actually run and its evidence is available.

## Law-corpus human legal review

The bundled law corpus is tiered for honesty:
**Verified** (human-approved), **automated_review** (authentic text, not yet
human-approved), and **Pending** (placeholder, no body — shows the
`[NÃO VERIFICADO / fonte pendente]` marker). See
[Capabilities → Law corpus](capabilities.md#law-corpus-honesty-tiers).

Promoting an article to **Verified** is a deliberate human legal-review step: it
requires the complete verbatim body, a full source (diploma, article, DR
reference, URL), and the human legal-approval marker. The build-time authenticity
gate refuses to mark anything Verified or automated_review without a complete
source and a real body — so the review workflow is what turns automatically
vendored text into human-approved Verified text. Never present pending or
paraphrased statute text as authoritative.

## Encryption at rest

- **SQLite** — the store is SQLCipher-encrypted (file-level ciphertext), keyed by
  `CHANCELA_DB_KEY` / its configured source.
- **Postgres** — no transparent whole-DB encryption; protect the data volume with
  host disk encryption (LUKS / encrypted block device). This is disk-level, a
  materially weaker guarantee than SQLCipher.
- **Provider credentials** — always app-layer XChaCha20-Poly1305 regardless of
  backend, keyed by the credential root key. Its honest protection level depends
  on how the root key is sealed (DPAPI / SQLCipher-derived vs a plain file). See
  [Configuration → Provider-credential store](configuration.md#provider-credential-store).
