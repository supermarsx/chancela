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

TLS to a remote Postgres (`sslmode=verify-full`) is **not** wired in the current
backend (it uses `NoTls` on the local compose network); a remote database needs a
TLS connector first.

## Monitoring and healthchecks

- **Liveness** — `GET /health` reports liveness, the crate version, persistence
  status, and the ledger chain status (including whether the server is in
  degraded read-only mode). The compose files already wire a container
  healthcheck against it.
- **Multi-node** — `/health` also advertises the node role (leader/follower);
  use it for leader-aware load-balancer routing and failover detection.
- **Logs** — the hardened compose caps log growth (`json-file`, `max-size: 10m`,
  `max-file: 3`) so a chatty or attacked container cannot fill host disk. The
  Platform settings section exposes a live log tail.

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
