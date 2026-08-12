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
| `CHANCELA_TEMPLATE_HISTORY_LIMIT` | Retained saves per user-authored template (default `25`; values are clamped to `1..100`). Editable as a non-secret server override and applied after restart. |
| `CHANCELA_SEARCH_RUNTIME` | Search execution topology for the API: `embedded` (default for desktop/dev) or `query-only` (Compose; completed generations come from the isolated projector). |

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
| `CHANCELA_CONNECTOR_ALLOWED_HOSTS` | Comma-separated exact host/IP/CIDR allowlist for non-local targets, and a **ceiling** the in-app setting can only narrow (see below). Wildcards are rejected; private DNS results also require an explicit IP/CIDR. |
| `CHANCELA_CONNECTOR_SECRETS_DIR` | In-container canonical root for file-backed connector secrets. Compose fixes this to `/run/chancela-connector-secrets`. |
| `CHANCELA_CONNECTOR_SECRETS_HOST_DIR` | Protected host directory mounted read-only at the connector secrets root. |
| `CHANCELA_CONNECTOR_SECRET_<NAME>` | Direct runtime secret value. References in target configuration must use this strict namespace. |
| `CHANCELA_CONNECTOR_SECRET_<NAME>_FILE` | File containing the secret; it must canonicalize beneath `CHANCELA_CONNECTOR_SECRETS_DIR` without symlink components and be at most 64 KiB. |

## Full-search projector

The backend Compose profiles start exactly one socketless
`chancela-search-projector` and put every API process in `query-only` mode. The
desktop and bare server default to embedded indexing for compatibility and
offline operation.

| Variable                                                             | Purpose                                                                                                                                                                                                                                        |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CHANCELA_SEARCH_PROJECTOR_IMAGE`                                    | Image override used by both SQLite and Postgres projector services. Pin production deployments to the same immutable `sha-…` commit as the server.                                                                                             |
| `CHANCELA_SEARCH_RUNTIME_DIR`                                        | Non-secret heartbeat/runtime directory; the image defaults to `/var/lib/chancela/search-projector`.                                                                                                                                            |
| `CHANCELA_SEARCH_HEARTBEAT_SECONDS`                                  | Projector heartbeat interval (image and Compose default `15`).                                                                                                                                                                                 |
| `CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS`                             | Shared projector/API heartbeat freshness window (default `600`). It must be at least twice `CHANCELA_SEARCH_HEARTBEAT_SECONDS`; invalid pairs fail closed instead of producing a flapping healthcheck.                                         |
| `CHANCELA_SEARCH_INSTANCE_ID`                                        | Optional friendly projector identity prefix (1–128 characters) shown in the heartbeat/lease owner. Omit it to use the container hostname; the runtime adds a PID and opaque suffix for uniqueness.                                             |
| `CHANCELA_SEARCH_DATABASE_URL` / `CHANCELA_SEARCH_DATABASE_URL_FILE` | PostgreSQL projector connection. Exactly one is required when `CHANCELA_DB_BACKEND=postgres`; there is deliberately no fallback to the API writer URL. Compose uses the file form with the fixed, restricted `chancela_search_projector` role. |
| `CHANCELA_SEARCH_PROJECTOR_CPUS`                                     | Compose CPU ceiling for the projector (default `1.5`).                                                                                                                                                                                         |
| `CHANCELA_SEARCH_PROJECTOR_MEMORY`                                   | Compose memory ceiling for the projector (default `1g`).                                                                                                                                                                                       |

Database selection and TLS use the same `CHANCELA_DATA_DIR`,
`CHANCELA_DB_BACKEND`, and `CHANCELA_PG_TLS_ROOT_CERT` contracts as the API.
The connection credential is intentionally different: the API uses
`DATABASE_URL_FILE`, while the projector fails closed unless its dedicated
`CHANCELA_SEARCH_DATABASE_URL_FILE` exists. A one-shot initializer runs only
after the API has migrated the schema, creates/reasserts the restricted role,
and verifies its exact column allowlist plus real denials against raw document
bytes, ledger/entity writes, authoritative control columns, and provider
credentials. The projector also remains pinned to
`CHANCELA_NODE_ROLE=follower` as defense in depth.

The PostgreSQL role can read exactly `settings.id` and `settings.json`; `id` is
required for singleton predicates and `json` contains the main `settings`
document plus the authoritative `backup-recovery-drill-receipts`,
`privacy-dpia-records`, `privacy-breach-playbooks`, and
`privacy-transfer-controls` documents. It has no `INSERT`, `UPDATE`, or `DELETE`
privilege on `settings`. When one of those database documents exists, it wins
over its legacy JSON fallback. A missing backup/privacy singleton may still
fall back to `backup-recovery-drills.json`, `privacy-dpias.json`,
`privacy-breach-playbooks.json`, or `privacy-transfer-controls.json` during an
upgrade; an existing fallback that cannot be read or decoded prevents candidate
publication instead of silently becoming an empty document.

SQLite keeps `settings.json`, `settings.pending-audit.json`, and the same legacy
backup/privacy files beside the database under `CHANCELA_DATA_DIR`. The API and
projector must therefore mount that complete root, not selected files. A
genuinely absent settings document selects defaults, but an unreadable or
malformed `settings.json`, or any existing pending-audit journal, makes the
external projector fail closed. The API remains available for operator repair
and the last completed search generation remains queryable but stale.

These topology/database variables remain deployment-owned; the bounded indexing
policy is edited through the dedicated `/v1/search/settings` slice and requires
`search.manage`, without granting access to unrelated instance settings.

`search.index_threads` is read before the projector constructs its Tokio
runtime. Saving a new value persists the setting, but it takes effect only
after the projector service restarts. The effective external minimum is two
runtime worker threads; the setting does not claim that one corpus build is
sharded across them. In embedded mode, `search.interval_seconds` is the periodic
full-reconciliation interval. In external mode it is only the cheap
control/settings polling cadence: a complete rebuild runs when the source
revision or explicit command changes, after the process first acquires its
projector lease, and once per UTC date. `search.queue_capacity` and
`search.batch_size` bound only the embedded in-process worker; the external
projector publishes one complete generation through a single atomic fenced CAS
and does not claim queue/batch sharding.

Query-only freshness is checkpoint-based, not the wall-clock age of an
otherwise current generation. The API requires the published checkpoint to
match the authoritative source/command checkpoint, requires a completed
generation in the current UTC date bucket, and requires a trusted active lease
owner with a heartbeat inside
`CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS`. A generation therefore remains fresh
while its inputs are unchanged, while a dead or fenced projector is still
reported promptly. Schema-v2 heartbeats are stored below
`<CHANCELA_SEARCH_RUNTIME_DIR>/search-projector-heartbeats/<lease_id>.json`.
The API and CLI healthcheck read the durable control row first and select only
that current lease's file. A rolling standby writes no heartbeat; a stale owner
can update only its retired lease file, so neither can replace the selected
active heartbeat or make an otherwise healthy query-only API appear stale.

### Connector egress allowlist: environment vs. Settings

The outbound host allowlist is the one boundary configurable from both places, so its
precedence is explicit:

- **Environment variable set** — it is a hard ceiling. The in-app list (Settings →
  Operações, `settings.manage` at Global) may only narrow it; an entry outside the ceiling
  is rejected with a `422`. This is the recommended posture for a hardened deployment.
- **Environment variable unset** — the in-app list is the sole egress boundary, and the UI
  says so.
- **Neither set** — network connectors fail closed, unchanged from before.

Entries saved in-app are validated more strictly than the variable (no wildcards, schemes,
ports or paths; no loopback, link-local/metadata, multicast or over-broad CIDRs), each
change is ledgered as `connector.allowlist.updated`, and changes apply without restarting
the API or the worker. See [Sync, backup, and connector worker](connectors-worker.md) for
the full rule and the security trade-off.

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
| `CHANCELA_CREDENTIAL_KEY` / `CHANCELA_CREDENTIAL_KEY_FILE` | Root key for the credential store. **Required** whenever no other source applies — see the table below. |
| `CHANCELA_CREDENTIAL_STRICT` | Fail-closed unless the resolved protection level is confidential. |

### Where the root key comes from

The store resolves a root key at the moment a credential is first saved, in this
order, and **refuses to save anything** if none applies — it never falls back to
storing a provider secret in plaintext.

| # | Source | Applies when | Protection level |
|---|---|---|---|
| 1 | OS-sealed envelope (Windows DPAPI) | The server runs on **Windows** with a data directory. Nothing to configure: a random root is generated and sealed to the current Windows user in `provider-credentials-root.json`. | confidential |
| 2 | Derived from the SQLCipher DB key | The SQLite store is encrypted (`sqlcipher` build + `CHANCELA_DB_KEY`/`_FILE`). | confidential |
| 3 | `CHANCELA_CREDENTIAL_KEY` / `_FILE` | Set by the operator. | confidential with an encrypted DB, otherwise obfuscation |

So in practice:

- **Windows (desktop app or `chancela-server`)** — works out of the box via DPAPI.
  The sealed root is bound to the Windows user account *and* machine: it does not
  survive copying the data directory to another host or user, so back the
  credentials up by re-entering them there.
- **Linux/macOS, Docker, and every Postgres deployment** — there is no OS-sealing
  provider, so you must supply source 2 or 3. Set
  `CHANCELA_CREDENTIAL_KEY_FILE` to a file containing a high-entropy secret:

    ```sh
    openssl rand -base64 48 > /run/secrets/credential_key
    chmod 600 /run/secrets/credential_key
    ```

  Prefer the `_FILE` form over `CHANCELA_CREDENTIAL_KEY`: an env var is visible to
  anything that can read `/proc/<pid>/environ` and tends to end up in shell
  history and process listings. Setting both is a fail-closed configuration error.

- **In-memory mode (no `CHANCELA_DATA_DIR` and no `chancela-data/`)** — provider
  credentials cannot be saved at all, because there is nowhere to persist them or
  to seal a root. No credential key will help; set `CHANCELA_DATA_DIR`. The server
  prints a warning at startup whenever credentials could not be stored.

Treat the root key like a master key: back it up out of band, rotate it
deliberately, never log or commit it. Losing it does not corrupt anything else —
the stored provider secrets simply become unreadable and must be re-entered. See
[`docs/security/hardened-docker.md`](security/hardened-docker.md#the-credential-root-key).

## Trust, signature, and integration variables

Trust sources and signing providers can be seeded by environment and refined in
Settings.

| Area | Variables |
|---|---|
| Trust lists (TSL / LOTL) | `CHANCELA_TSL_URL`, `CHANCELA_LOTL_URL`, `CHANCELA_TSL_TRUST_ANCHOR`, `CHANCELA_TSL_TRUST_ANCHOR_SHA256`, `CHANCELA_TSL_CACHE_MAX_STALE_HOURS` |
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
  Editable in the admin UI under **Assinaturas → Fontes TSL**, alongside the sources the anchors
  authenticate; the environment variables above remain an equivalent alternative. At runtime the
  settings anchors are **unioned with** the environment anchors (settings-first, environment as
  fallback) — on **every** trust path: the operator-triggered LOTL bootstrap
  (`POST /v1/trust/refresh`), the trusted-list policy consulted at **signing time**, and the QTST
  timestamp-trust report attached to a timestamped signature.

> **Trust surface.** A settings-provisioned anchor is a **trust root**: matching it is what makes a
> Trusted List authentic, and an authentic list is what reports a certificate as qualified. Whoever
> may write `signing.tsl_trust_anchor_certs` / `signing.tsl_trust_anchor_sha256` can therefore cause
> a list to authenticate. That write is gated on the narrow `signing.configure` permission (not
> plain `settings.manage`), though the migration that introduced `signing.configure` grants it to
> every existing `settings.manage` holder — so in an install predating custom roles the effective
> audience is unchanged. Fail-closed is preserved regardless: the union can only ever *add* anchors,
> and an install that provisions none in settings **or** environment trusts no list at all.

**Bootstrapping the first anchor.** With no anchor configured, nothing authenticates the EU List of
Trusted Lists either, so the anchor assistant (**Assinaturas → Fontes TSL**) proposes nothing. On an
explicit second request it will fetch that list and show the certificate the document itself carries,
as a starting point. Be exact about what that is: fetching over HTTPS authenticated the **server**,
not the list — whoever served the document also chose the certificate inside it, so a substituted
list arrives with its own matching certificate and its signature verifies against that. The value
becomes trustworthy only when a human compares its SHA-256 fingerprint with the one published in the
Official Journal of the European Union. This is ordinary bootstrap practice; it just has to be
confirmed that way. The assistant never pre-selects the candidate, never offers it without being
asked, and hands over only the fingerprint — never a pasteable PEM.

An anchor accepted that way is recorded in `signing.tsl_trust_anchor_self_asserted_sha256`, a list of
64-character sha256 hex fingerprints. It is an **annotation, not an anchor**: no trust path reads it,
it widens nothing, and an entry matching no configured anchor is inert. It exists so the distinction
survives the save — without it, an anchor taken from a document that vouched for itself would be
indistinguishable from one transcribed out of the Official Journal. The admin UI marks such anchors
in the anchor list and offers a control to clear the mark once the comparison has been made.

**Rotation:** because matching is by the exact signing certificate (equivalently its SHA-256
fingerprint), configure **multiple** anchors to span a key rollover. Add the incoming signing
certificate (or its fingerprint) alongside the outgoing one *before* the scheme switches keys;
both are trusted during the overlap, and the retired one can be removed after the cut-over. This
is the intended mechanism — there is no certificate-path build to an issuing CA, so the anchor
must be the actual publishing certificate(s).

### Outbound TLS intermediates (`signing.tls_intermediate_certs`)

**A different kind of trust from the anchors above, and the difference is not a nuance.** A trust
anchor is the certificate that **signed** a Trusted List. This setting concerns the certificate the
**web server hosting that file** presents at the TLS handshake. Different certificates, different
issuers, different property; neither can substitute for the other, and a certificate configured here
can never make an unauthentic list validate.

A TLS server is required to send every certificate in its chain except the root. Some do not. The
Portuguese Trusted List endpoint (`https://www.gns.gov.pt/media/TSLPT.xml`) presents its leaf alone
and omits the intermediate that issued it, so the fetch fails with:

```
signing_trusted_list_tls_chain_incomplete — invalid peer certificate: UnknownIssuer
```

**A browser or `curl` will load the same address successfully**, because they chase the missing
issuer through the certificate's Authority Information Access extension or reuse a cached copy.
`rustls`, which this product uses, deliberately implements neither and requires the server to send a
complete chain. The remote server is misconfigured; this setting is the workaround.

Provide the missing intermediate as one or more PEM certificate strings (or raw DER), in the admin UI
under **Assinaturas → Fontes TSL**, or directly in the settings document. Each entry is validated on
save as a real X.509 certificate — a stricter check than the anchor fields apply — and rejected with
`422` and the field path otherwise. Writing it is gated on the same `signing.configure` permission as
the anchors. It defaults to empty, in which case the outbound client is built exactly as it was
before the setting existed.

> **This is not a way to skip certificate verification, and no such option exists anywhere in this
> product.** A configured certificate joins the pool of candidate chain links; it is **never** added
> to the root store. The chain must still terminate at a root the operating system already trusts,
> the signatures must still verify, the hostname must still match the certificate, and validity dates
> still apply. An attacker gains nothing from a configured intermediate: exploiting one requires a
> leaf genuinely issued under it, which requires that intermediate's private key — and whoever holds
> that can already mint certificates every browser accepts. Configuring the public certificate of a
> CA that a public root already vouches for adds no authority the root had not already delegated.

### Skipping TLS verification for one source (`tls_skip_verification`)

The option of last resort, and the one to reach for only after the intermediates above have failed.
Per source, off by default, gated on `signing.configure`:

```json
{ "signing": { "tsl_sources": [ { "id": "pt-gns", "url": "https://…", "tls_skip_verification": true } ] } }
```

**What it costs, accurately.** A Trusted List's authenticity does **not** rest on TLS. It rests on
the list's own XML-DSig signature, verified against the trust anchors configured above. That check is
mandatory, has no off switch anywhere in this product, and is unaffected by this setting. An attacker
who intercepts the fetch and substitutes a **forged** list still fails it, and qualified signing still
refuses. TLS here is defence in depth on the transport, and this removes that second layer only.

The two residual risks are real and are worth stating plainly rather than leaving to be inferred:

- **Replay.** Someone on the network path can serve a **genuine but older** list. It authenticates
  perfectly — it is genuine — and a trust service the scheme operator has withdrawn since then still
  reads as granted on it. The `NextUpdate` staleness check narrows this window; it does not close it.
- **Denial of service.** They can block or corrupt the response at will.

**Scope.** Exactly the one source. Not the EU LOTL fetch, not an ad-hoc URL passed to
`POST /v1/trust/refresh`, not another configured source, and not any other outbound client in the
product — connectors, the registry, the CAE and law corpora and SMTP all keep full verification and
cannot reach the setting. **SSRF vetting and pinned-address resolution are unaffected**: a relaxed
source still cannot be pointed at a loopback, link-local, private or metadata address.

Refused on save unless the source is URL-backed with an `https` URL, because on a file-backed or
`http://` source the flag would be silently inert. And it is **not** a one-time confirmation on a
settings page: for as long as it is on, every trust surface reports `tsl_transport_not_verified`
beside the verdict, naming the source and host, so whoever reads a result months later sees how it
was obtained.

### The durable Trusted List cache

Every successful Trusted List fetch is stored under `tsl-cache/` in the data directory, and a later
fetch that fails falls back to it. Without that, a transient network fault — a container egress
rule, a proxy, a DNS blip — makes qualified signing impossible outright, even though the list
itself carries a `NextUpdate` and is designed by ETSI TS 119 612 to be used until it.

What is cached is the **raw list bytes and nothing else**: not the parsed list, not the signature
verdict, not the set of granted services. Every use of a cached copy re-runs the whole pipeline
against the *current* configuration — parse, XML-DSig verification, trust-anchor matching,
algorithm policy — so revoking an anchor or tightening `signing.tsl_legacy_algorithms` invalidates
the cache at its next use, with no invalidation step that could disagree with the checks
themselves.

Using a cached copy **inside** its `NextUpdate` is ordinary and unremarkable. Past it:

- the result is **marked**. `validation.cache_fallback` on `GET /v1/trust/status` and
  `GET /v1/trust/tsa` carries the stable code `tsl_served_from_stale_cache` and the reason the
  fetch failed, and the admin UI shows it beside the signature verdict. A Trusted List is how a
  withdrawn trust service *stops* being trusted, so an expired copy can still report a service the
  scheme operator has since withdrawn — that must never be silent.
- it is **bounded**. `CHANCELA_TSL_CACHE_MAX_STALE_HOURS` (default `168` — seven days) is how long
  past its own expiry a cached list may still be used. Beyond that the cached copy is refused and
  signing fails closed exactly as it would with no cache at all. Seven days covers a Friday-night
  outage found on Monday, which is the realistic worst case for a transient infrastructure fault;
  past a week the fault is a configuration problem to fix rather than one to wait out. Set `0` to
  refuse any use past `NextUpdate`.

Fail-closed is unchanged: **no cache and no fetch still refuses.** The cache adds resilience, never
authority.

The cache directory is included in `POST /v1/backup` and in the `chancela backup` archive, because
it is the material a signature's trust decision was taken from while the network was down. Keeping
it across a restore is safe in the other direction too — every entry is re-hashed, re-parsed and
re-verified on use, and one restored past its maximum age is refused rather than served.

## Multi-node variables

Used only by the cluster overlay (see [Deployment → Multi-node](deployment.md#multi-node-leaderfollower)):

| Variable | Purpose |
|---|---|
| `CHANCELA_NODE_ROLE` | `auto` (advisory-lock election), `leader`, or `follower`. |
| `CHANCELA_NODE_ADDRESS` / `CHANCELA_ADVERTISED_URL` | Per-node internal / externally-reachable URL for `307` write redirects. |
| `CHANCELA_CLUSTER_WRITE_MODE` | `redirect` or `proxy`. |
| `CHANCELA_LEADER_WATCHDOG_INTERVAL` / `CHANCELA_NODE_STALE_AFTER` / `CHANCELA_HEARTBEAT_INTERVAL` / `CHANCELA_PROMOTE_POLL_INTERVAL` / `CHANCELA_CHANGEFEED_POLL_INTERVAL` | Election/heartbeat/watchdog timing. |

## Secrets (Postgres profile)

The hardened `postgres` compose profile reads five file-based Docker secrets from
`docker/secrets/`. The real files are **gitignored** — only the `*.example`
templates are committed, so never commit a real secret.

| Secret file | Injected as | Purpose |
|---|---|---|
| `postgres_password` | `POSTGRES_PASSWORD_FILE` | Postgres superuser password. |
| `database_url` | `DATABASE_URL_FILE` | Full libpq URL **including the same password**; references the `postgres` service by name and is mounted into the API only. |
| `credential_key` | `CHANCELA_CREDENTIAL_KEY_FILE` | Provider-credential store root key (required on Postgres — there is no SQLCipher `DerivedFromDbKey` source). Mounted read-only into the API only; the projector cannot read it. |
| `search_database_password` | role initializer only | Independent password for the fixed `chancela_search_projector` PostgreSQL role. Never mounted into the projector. |
| `search_database_url` | `CHANCELA_SEARCH_DATABASE_URL_FILE` | URL containing the independent projector password. Mounted into the role verifier and projector only; it cannot authenticate as the API/schema owner. |

### Setting up the secret files

Copy each template, then fill it in with a strong value:

```sh
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
cp docker/secrets/search_database_password.example docker/secrets/search_database_password
cp docker/secrets/search_database_url.example      docker/secrets/search_database_url
```

Generate strong values, e.g.:

```sh
openssl rand -base64 32 > docker/secrets/postgres_password   # also paste into database_url
openssl rand -base64 48 > docker/secrets/credential_key
openssl rand -base64 32 > docker/secrets/search_database_password # also paste into search_database_url
```

The password inside `database_url` **must match** `postgres_password`, otherwise
the API cannot authenticate to Postgres. The independent password inside
`search_database_url` must likewise match `search_database_password`; using the
API password/role defeats the projector isolation contract. The templates use
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
| **Email** (`email`) | The outbound SMTP relay: host, port, encryption, sender identity, the write-only relay password, and a test send (see below). |
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

### Outbound email (SMTP)

The **Email** section configures the SMTP relay the application sends through.
It is reserved to administrators: every endpoint below requires `settings.manage`
at global scope — the same gate as `PUT /v1/settings` — which the **Owner** and
**Platform Administrator** roles hold and **Tenant Administrator** deliberately
does not.

**Scope, stated plainly:** configuring SMTP makes the relay usable and verifiable.
It does not by itself cause any feature to start sending mail — external-signer
invites and notifications are unchanged and still surface in-app.

| Setting | Notes |
|---|---|
| `email.enabled` | Master switch. Off by default. A half-filled configuration can be saved while `enabled` is false; turning it on requires `host` and `from_address`. |
| `email.host` / `email.port` | Relay hostname (also the name the TLS certificate must match) and port. Defaults to `587`. |
| `email.encryption` | `starttls` (default), `implicit_tls` (port 465), or `none`. |
| `email.username` | SMTP AUTH user. Leave empty for a relay that takes no credentials. |
| `email.from_address` / `email.from_name` | Envelope sender + `From:` header. |
| `email.helo_name` | Name announced in `EHLO`; defaults to the `from_address` domain. |
| `email.allow_insecure` | Explicit acknowledgement required to use `encryption: none`. |

**TLS is on by default and cannot be dropped silently.** In `starttls` mode a
relay that does not advertise `STARTTLS` is a hard failure, not a downgrade, and
the client refuses the upgrade if the server pipelines data after its `STARTTLS`
reply (STARTTLS response injection). Choosing `none` is rejected by the server
with a `422` unless `allow_insecure` is also `true`, so an unencrypted relay is
only ever reached deliberately.

**The password is never in `settings.json`.** It is written through
`PUT /v1/settings/email/password`, stored AEAD-encrypted in the same credential
store as the signing-provider secrets, and cleared with
`DELETE /v1/settings/email/password`. No endpoint returns it —
`GET /v1/settings/email/status` reports a `password_configured` boolean and
nothing else. Each change appends a ledger event (`email.password.updated` /
`email.password.cleared`) recording who and when, never the value.

**Test send.** `POST /v1/settings/email/test` with `{"to": "…"}` opens a real
session and reports the relay's real answer. A relay rejection is a `200` whose
body carries `ok: false` and a structured `failure` — the stage (`auth`,
`rcpt_to`, `starttls`, …), the kind, the SMTP code, the RFC 3463 enhanced status
code, and the server's own text — because `535 5.7.8 authentication failed` and
`554 5.7.1 relay access denied` need different fixes. HTTP errors are reserved
for genuine request problems (no permission, relay not configured, bad
recipient).
