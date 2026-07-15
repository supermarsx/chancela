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
| `CHANCELA_HOST_PORT` | Host port the compose file publishes on `127.0.0.1` (default `8080`). |
| `CHANCELA_WEB_DIST` | Path to the built web UI assets (set by the image). |

## Database backend

| Variable | Purpose |
|---|---|
| `CHANCELA_DB_BACKEND` | `sqlite` (default) or `postgres`. |
| `DATABASE_URL` / `DATABASE_URL_FILE` | libpq connection string for the Postgres backend (the `_FILE` form reads a docker secret). |
| `CHANCELA_DB_KEY` / `CHANCELA_DB_KEY_FILE` / `CHANCELA_DB_KEY_SOURCE` | SQLCipher database key (and its source) for the encrypted SQLite store. |
| `CHANCELA_CACHE` / `REDIS_URL` | Optional Redis cache-aside. Fail-open on SQLite/single-node; **required** in multi-node for shared sessions + rate-limits. |

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
| Trust lists (TSL) | `CHANCELA_TSL_URL`, `CHANCELA_TSL_TRUST_ANCHOR`, `CHANCELA_TSL_TRUST_ANCHOR_SHA` |
| Timestamping (TSA) | `CHANCELA_TSA_URL` |
| CMD (Chave Móvel Digital) | `CHANCELA_CMD_ENV`, `CHANCELA_CMD_APPLICATION_ID`, `CHANCELA_CMD_AMA_CERT_PEM`, `CHANCELA_CMD_HTTP_BASIC_USERNAME`, `CHANCELA_CMD_HTTP_BASIC_PASSWORD` |
| CSC / QTSP cloud signing | `CHANCELA_CSC_PROVIDERS`, plus per-provider `CHANCELA_CSC_<NAME>_CLIENT_ID` / `_CLIENT_SECRET` / `_ACCESS_TOKEN` |
| SCAP (professional attributes) | `CHANCELA_SCAP_BASE_URL`, `CHANCELA_SCAP_APPLICATION_ID`, `CHANCELA_SCAP_SECRET`, `CHANCELA_SCAP_ENV`, `CHANCELA_SCAP_PROVIDER_FILTER` |
| Cartão de Cidadão (local) | `CHANCELA_PTEID_PKCS`, `CHANCELA_LOCAL_SIGNING` |
| Company registry / CAE | `CHANCELA_REGISTRY_URL`, `CHANCELA_REGISTRY_EMAIL`, `CHANCELA_CAE_URL` |
| Law corpus | `CHANCELA_LAW_URL`, `CHANCELA_WRITE_VALIDATOR_CORPUS` |
| Paper-book OCR | `CHANCELA_PAPER_BOOK_OCR_COMMAND`, `CHANCELA_PAPER_BOOK_OCR_ENGINE_NAME`, `CHANCELA_PAPER_BOOK_OCR_TIMEOUT_SECS`, and related `CHANCELA_PAPER_BOOK_OCR_*` |
| MCP server | `CHANCELA_MCP_ENABLED`, `CHANCELA_MCP_API_KEY`, `CHANCELA_MCP_TRANSPORT`, `CHANCELA_MCP_BIND`, `CHANCELA_MCP_BASE_URL`, `CHANCELA_MCP_ENABLED_TOOLS`, `CHANCELA_AI_ENABLED` |

## Multi-node variables

Used only by the cluster overlay (see [Deployment → Multi-node](deployment.md#multi-node-leaderfollower)):

| Variable | Purpose |
|---|---|
| `CHANCELA_NODE_ROLE` | `auto` (advisory-lock election), `leader`, or `follower`. |
| `CHANCELA_NODE_ADDRESS` / `CHANCELA_ADVERTISED_URL` | Per-node internal / externally-reachable URL for `307` write redirects. |
| `CHANCELA_CLUSTER_WRITE_MODE` | `redirect` or `proxy`. |
| `CHANCELA_LEADER_WATCHDOG_INTERVAL` / `CHANCELA_NODE_STALE_AFTER` / `CHANCELA_HEARTBEAT_INTERVAL` / `CHANCELA_PROMOTE_POLL_INTERVAL` / `CHANCELA_CHANGEFEED_POLL_INTERVAL` | Election/heartbeat/watchdog timing. |

## Secrets (Postgres profile)

File-based docker secrets under `docker/secrets/` (real files are gitignored;
only `*.example` templates are committed):

| Secret file | Injected as | Purpose |
|---|---|---|
| `postgres_password` | `POSTGRES_PASSWORD_FILE` | Postgres user password. |
| `database_url` | `DATABASE_URL_FILE` | Full libpq URL **including the same password**; references the `postgres` service by name. |
| `credential_key` | `CHANCELA_CREDENTIAL_KEY_FILE` | Provider-credential store root key (required on Postgres). |

Generate strong values, e.g.:

```sh
openssl rand -base64 32 > docker/secrets/postgres_password   # also paste into database_url
openssl rand -base64 48 > docker/secrets/credential_key
```

The password inside `database_url` **must match** `postgres_password`.

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
