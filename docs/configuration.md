# Configuration

Chancela is configured in two places:

1. **Environment variables / docker secrets** — bootstrap settings read at
   startup (address, data dir, database backend, trust sources, integrations).
2. **In-app Settings** — everything an operator tunes at runtime, persisted in
   the store and gated by RBAC.

Secrets are always supplied at runtime (environment or docker secret files); none
are baked into an image.

## Core environment variables

| Variable | Purpose |
|---|---|
| `CHANCELA_ADDR` | Bind address for the server, e.g. `0.0.0.0:8080` inside the container. |
| `CHANCELA_DATA_DIR` | Durable data directory (SQLite store, credential sidecar, CAE/law/TSL caches, JSON sidecars). Compose mounts a named volume at `/var/lib/chancela`. |
| `CHANCELA_ZK_SHARED_OBJECT_ROOT` | Required before zero-knowledge repository routes are enabled with PostgreSQL/HA. It must resolve exactly to the shared-mounted `<CHANCELA_DATA_DIR>/zk-repositories` directory on every node so backup/restore addresses the same opaque-object root. It is not an encryption key. |
| `CHANCELA_HOST_PORT` | Host port the compose file publishes on `127.0.0.1` (default `8080`). |
| `CHANCELA_WEB_DIST` | Path to the built web UI assets (set by the image). |
| `CHANCELA_CORS_ALLOWED_ORIGINS` | Optional comma-separated exact HTTP(S) origins allowed to call the API from a companion WebView/browser. Blank/unset keeps same-origin only; wildcards and malformed origins fail startup closed. |
| `CHANCELA_SESSION_MAX_LIFETIME` | Absolute session lifetime in seconds (default seven days), independent of the sliding 24-hour idle expiry. A non-positive value disables the absolute cap. |

### Remote companion and session durability

The companion CORS policy is deliberately narrow. A typical Tauri Android shell uses
`CHANCELA_CORS_ALLOWED_ORIGINS=http://tauri.localhost`; a hosted shell uses its exact HTTPS origin.
Do not include a path or a wildcard, and do not treat CORS as a substitute for HTTPS, firewalling,
or RBAC. The allowlist permits the API's bounded methods and `Accept`, `Authorization`,
`Content-Type`, and `X-Chancela-Session` request headers. Cookie credentials are not enabled.

With a successfully opened SQLite data directory, password-authenticated sessions survive API
restart through `<CHANCELA_DATA_DIR>/sessions.json`. The file contains only token SHA-256 digests,
user ids, issue times, and expiries; plaintext bearer tokens, passwords, and unlocked attestation
keys never persist. Writes are atomic with Windows rollback recovery, and Unix files are mode
`0600`. On Windows, secure `CHANCELA_DATA_DIR` with an operator/service-account-only ACL because
new files inherit that directory ACL. The file is excluded from backups, and restore/factory-reset
flows invalidate it so restoring a snapshot cannot resurrect an old session. Without a durable
store, sessions are intentionally memory-only and disappear on restart.

Postgres/HA uses Redis rather than a node-local session file. `REDIS_URL`/`REDIS_URL_FILE` is
load-bearing for multi-node authentication: session keys are token digests, the exact issue time is
shared, revocation is cluster-wide, and lookup fails closed while Redis is unavailable. A restore
or factory reset first advances a shared session epoch and aborts before durable mutation if Redis
cannot confirm it, so old sessions cannot reappear against restored data. An unlocked attestation
signing key always remains local process memory, so a restart or node change requires a fresh
sign-in before attested signing even though the restored session can still authenticate.

## Connector worker

The `worker` Compose profile shares only the server's durable data volume. Its
configuration and credentials remain read-only runtime inputs.

| Variable | Purpose |
|---|---|
| `CHANCELA_WORKER_CONFIG` | Host path to the worker JSON configuration mounted read-only at `/etc/chancela-worker/config.json`. |
| `CHANCELA_CONNECTOR_ALLOWED_HOSTS` | Required comma-separated exact host/IP/CIDR allowlist for non-local targets. Wildcards are rejected; private DNS results also require an explicit IP/CIDR. |
| `CHANCELA_CONNECTOR_SECRETS_DIR` | In-container canonical root for file-backed connector secrets. Compose fixes this to `/run/chancela-connector-secrets`. |
| `CHANCELA_CONNECTOR_SECRETS_HOST_DIR` | Protected host directory mounted read-only at the connector secrets root. |
| `CHANCELA_CONNECTOR_SECRET_<NAME>` | Direct runtime secret value. References in target configuration must use this strict namespace. |
| `CHANCELA_CONNECTOR_SECRET_<NAME>_FILE` | File containing the secret; it must canonicalize beneath `CHANCELA_CONNECTOR_SECRETS_DIR` without symlink components and be at most 64 KiB. |

API-created jobs use server-derived paths below
`<CHANCELA_DATA_DIR>/worker/sources` and the durable queue at
`<CHANCELA_DATA_DIR>/worker/queue`. These locations are not caller-configurable
API fields. See [Sync, backup, and connector worker](connectors-worker.md) for
target schemas, RBAC, and the outbound-network boundary.

## Database backend

| Variable | Purpose |
|---|---|
| `CHANCELA_DB_BACKEND` | `sqlite` (default) or `postgres`. |
| `DATABASE_URL` / `DATABASE_URL_FILE` | libpq connection string for the Postgres backend (the `_FILE` form reads a docker secret). |
| `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` / `CHANCELA_DB_KEY_SOURCE` | SQLCipher database key (and its source) for the encrypted SQLite store. |
| `CHANCELA_CACHE` / `REDIS_URL` / `REDIS_URL_FILE` | Optional Redis cache-aside on SQLite/single-node; **required** in multi-node for shared sessions, session-reset epochs, and rate-limits. |

## Provider-credential store

The signature-provider credential store encrypts API keys, client secrets,
HTTP-Basic passwords, and PKCS#12 material at rest with **XChaCha20-Poly1305**
(per-field random nonce; AAD binds mode/provider/entry/field/key-version), keyed
by an HKDF-SHA256-derived master key.

| Variable | Purpose |
|---|---|
| `CHANCELA_CREDENTIAL_KEY` / `CHANCELA_CREDENTIAL_KEY_FILE` | Root key for the credential store. **Required** on the Postgres backend (no SQLCipher-derived source). |
| `CHANCELA_CREDENTIAL_STRICT` | Fail-closed unless the resolved protection level is confidential. |

The root key can also come from an OS-sealed envelope (Windows DPAPI) or be
derived from the SQLCipher DB key on SQLite. Treat it like a master key: back it
up out of band, rotate it deliberately, never log or commit it. See
[`docs/security/hardened-docker.md`](security/hardened-docker.md#the-credential-root-key).

## Trust, signature, and integration variables

Trust sources and signing providers can be seeded by environment and refined in
Settings.

| Area | Variables |
|---|---|
| Trust lists (TSL / LOTL) | `CHANCELA_TSL_URL`, `CHANCELA_LOTL_URL`, `CHANCELA_TSL_TRUST_ANCHOR`, `CHANCELA_TSL_TRUST_ANCHOR_SHA256` |
| Timestamping (TSA) | `CHANCELA_TSA_URL` |
| CMD (Chave Móvel Digital) | `CHANCELA_CMD_ENV`, `CHANCELA_CMD_APPLICATION_ID`, `CHANCELA_CMD_AMA_CERT_PEM`, `CHANCELA_CMD_HTTP_BASIC_USERNAME`, `CHANCELA_CMD_HTTP_BASIC_PASSWORD` |
| CSC / QTSP cloud signing | `CHANCELA_CSC_PROVIDERS`, plus per-provider `CHANCELA_CSC_<NAME>_CLIENT_ID` / `_CLIENT_SECRET` / `_ACCESS_TOKEN` |
| SCAP (professional attributes) | `CHANCELA_SCAP_BASE_URL`, `CHANCELA_SCAP_APPLICATION_ID`, `CHANCELA_SCAP_SECRET`, `CHANCELA_SCAP_ENV`, `CHANCELA_SCAP_PROVIDER_FILTER` |
| Cartão de Cidadão (local) | `CHANCELA_PTEID_PKCS`, `CHANCELA_LOCAL_SIGNING` |
| Company registry / CAE | `CHANCELA_REGISTRY_URL`, `CHANCELA_REGISTRY_EMAIL`, `CHANCELA_CAE_URL` |
| Law corpus | `CHANCELA_LAW_URL`, `CHANCELA_WRITE_VALIDATOR_CORPUS` |
| Paper-book OCR | `CHANCELA_PAPER_BOOK_OCR_COMMAND`, `CHANCELA_PAPER_BOOK_OCR_ENGINE_NAME`, `CHANCELA_PAPER_BOOK_OCR_TIMEOUT_SECS`, and related `CHANCELA_PAPER_BOOK_OCR_*` |
| MCP server | `CHANCELA_MCP_ENABLED`, `CHANCELA_MCP_API_KEY`, `CHANCELA_MCP_TRANSPORT`, `CHANCELA_MCP_BIND`, `CHANCELA_MCP_BASE_URL`, `CHANCELA_MCP_ENABLED_TOOLS`, `CHANCELA_AI_ENABLED` |

`CHANCELA_TSL_URL` overrides the pinned Portuguese Trusted List URL; `CHANCELA_LOTL_URL`
overrides the pinned EU List of Trusted Lists (LOTL) URL used by the LOTL → member-state
bootstrap. Both default to the pinned public endpoints and can also be set per-refresh from
Settings — they are **locations, not trust**.

### Provisioning and rotating the Trusted-List signing anchor

The Trusted List is the system's root of trust: it declares which CAs are "qualified". Its own
XML-DSig signature carries the signer certificate *inside* the list, so verifying that signature
against the embedded certificate only proves the bytes are self-consistent — anyone can mint a
self-signed list that verifies against its own key. To be authentic, the signer certificate must
match a **trust anchor the operator provisions out of band**: the EU LOTL / national-scheme
XML-DSig **signing certificate** (a *public* X.509 certificate — not a secret, not a credential).

**No default anchor is ever shipped.** With no anchor configured the anchor set is empty and every
list — including a cryptographically self-consistent, self-signed one — is reported *untrusted*
(fail-closed). `CHANCELA_TSL_URL` / `CHANCELA_LOTL_URL` are URLs, never anchors; provisioning a
signing certificate is a required, deliberate step at deploy time.

Provision the anchor either way, or both — the two sources are a **union** (a signer matching **any**
configured certificate or fingerprint is anchored):

- **Environment:** `CHANCELA_TSL_TRUST_ANCHOR` names a file holding one or more PEM
  `CERTIFICATE` blocks (or a single raw-DER certificate); `CHANCELA_TSL_TRUST_ANCHOR_SHA256`
  holds one or more hex SHA-256 fingerprints of the signer certificate's DER (comma/semicolon/
  whitespace-separated, optional `:` byte separators). A variable that is *set but unparseable*
  is a hard error — a misconfigured anchor trusts nothing rather than silently degrading.
- **Settings** (`signing.tsl_trust_anchor_certs` / `signing.tsl_trust_anchor_sha256`): the same
  anchors as application config — a list of PEM certificate strings and a list of 64-character
  sha256 hex fingerprints. Invalid PEM or a malformed fingerprint is rejected on save with `422`.
  At runtime the settings anchors are **unioned with** the environment anchors (settings-first,
  environment as fallback).

**Rotation:** because matching is by the exact signing certificate (equivalently its SHA-256
fingerprint), configure **multiple** anchors to span a key rollover. Add the incoming signing
certificate (or its fingerprint) alongside the outgoing one *before* the scheme switches keys;
both are trusted during the overlap, and the retired one can be removed after the cut-over. This
is the intended mechanism — there is no certificate-path build to an issuing CA, so the anchor
must be the actual publishing certificate(s).

## Multi-node variables

Used only by the cluster overlay (see [Deployment → Multi-node](deployment.md#multi-node-leaderfollower)):

| Variable | Purpose |
|---|---|
| `CHANCELA_NODE_ROLE` | `auto` (advisory-lock election), `leader`, or `follower`. |
| `CHANCELA_NODE_ADDRESS` / `CHANCELA_ADVERTISED_URL` | Per-node internal / externally-reachable URL for `307` write redirects. |
| `CHANCELA_CLUSTER_WRITE_MODE` | `redirect` or `proxy`. |
| `CHANCELA_LEADER_WATCHDOG_INTERVAL` / `CHANCELA_NODE_STALE_AFTER` / `CHANCELA_HEARTBEAT_INTERVAL` / `CHANCELA_PROMOTE_POLL_INTERVAL` / `CHANCELA_CHANGEFEED_POLL_INTERVAL` | Election/heartbeat/watchdog timing. |

## Secrets (Postgres profile)

The `postgres` compose profile reads three file-based docker secrets from
`docker/secrets/`. The real files are **gitignored** — only the `*.example`
templates are committed, so never commit a real secret.

| Secret file | Injected as | Purpose |
|---|---|---|
| `postgres_password` | `POSTGRES_PASSWORD_FILE` | Postgres superuser password. |
| `database_url` | `DATABASE_URL_FILE` | Full libpq URL **including the same password**; references the `postgres` service by name. |
| `credential_key` | `CHANCELA_CREDENTIAL_KEY_FILE` | Provider-credential store root key (required on Postgres — there is no SQLCipher `DerivedFromDbKey` source). |

### Setting up the secret files

Copy each template, then fill it in with a strong value:

```sh
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
```

Generate strong values, e.g.:

```sh
openssl rand -base64 32 > docker/secrets/postgres_password   # also paste into database_url
openssl rand -base64 48 > docker/secrets/credential_key
```

The password inside `database_url` **must match** `postgres_password`, otherwise
the app cannot authenticate to Postgres. The template uses
`sslmode=verify-full`. Before Postgres starts, the isolated
`postgres-tls-init` service creates or renews a private compose CA and a server
certificate valid for `postgres`/`localhost`; the CA is mounted read-only into
the app and selected with `CHANCELA_PG_TLS_ROOT_CERT`. Insecure
`disable`/`prefer`/`require` modes are rejected by the backend even on the local
compose network.

The authoritative copy of these instructions lives next to the (gitignored)
secrets directory in `docker/secrets/README.md`.

## In-app Settings sections

Settings is a deep-linkable segmented sub-navigation (`?sec=`) in the web UI.
Document-style sections autosave (a single `PUT /v1/settings`, gated on
`settings.manage`); several sections are standalone surfaces that manage their
own data and self-gate on their own permissions.

| Section | Configures |
|---|---|
| **Appearance** (`aparencia`) | Theme (light/dark), the leather-texture background/buttons and grain, and custom primary/secondary/background/surface colour overrides. |
| **Identity** (`identidade`) | Organization name and the default audit-actor note. |
| **Documents** (`documentos`) | Document locale, default *ata* numbering scheme, and the CAE update URL. |
| **Signing** (`assinaturas`) | Preferred signature family, TSA/TSL URLs, and the multi-row TSL sources + TSA providers. |
| **Management** (`gestao`) | Reminders, registry auto-update, retained-export cleanup, backup-recovery policy, entity columns, AI toggle. |
| **Platform** (`operacoes`) | API server, MCP stdio server, logging overrides, audit, and a live platform-log tail. |
| **Privacy** (`privacidade`) | GDPR/DSR tooling: privacy compliance, processor and DPIA registers. |
| **Users** (`utilizadores`) | User roster CRUD. |
| **API keys** (`chaves-api`) | Create / list / revoke / rotate API keys (`chk_…`). |
| **Provider credentials** (`fornecedores-assinatura`) | The encrypted signature-provider credential store (multi-key / priority-failover; see below). |
| **Roles** (`funcoes`) | RBAC roles-as-data management (self-gates `role.manage`). |
| **Delegations** (`delegacoes`) | Scoped, time-bounded permission delegations. |
| **Integrity** (`integridade`) | Ledger integrity, book export/import, reanchor/restore recovery plane. |
| **Data** (`dados`) | Data-management resets and start-over. |
| **About** (`sobre`) | Read-only build/version info. |

### Signature providers (multi-key, priority, failover)

The **Provider credentials** section configures the signature rails. Modes are
`cmd`, `csc`, `scap`, and `pkcs12`. CSC and SCAP support per-provider endpoints +
HTTP auth; **CSC and PKCS#12 support multiple ordered instances** with a priority
order you can reorder for **failover**. Every secret input is write-only — the
API returns only a per-field `configured` flag plus the last four characters,
never the stored value.
