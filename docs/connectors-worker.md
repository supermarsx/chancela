# Sync, backup, and connector worker

Chancela implements sync and backup as separate job purposes with independently
selected targets. A configuration cannot silently reuse an S3 backup bucket as
the active sync target: S3 is intentionally backup-only. This boundary follows
ARC-20 and keeps collaboration traffic, recovery retention, and forensic
continuity from becoming one indistinguishable data path.

The implementation is split into:

- `chancela-api`, which owns tenant-scoped target CRUD, repository/integration
  authorization, metadata-only audit events, server-owned artifact selection,
  and redacted operator status views;
- `chancela-connectors`, which contains protocol clients, capability reports,
  credential-reference handling, checksums, cancellation, and bounded retries;
- `chancela-worker`, which owns the durable queue, idempotency, retries,
  cancellation markers, receipts, recovery after interruption, and heartbeat;
- `docker/Dockerfile.worker`, the dedicated non-root worker image required by
  ARC-40.

## Connector matrix

| Target | Purpose | Implemented operations | Integrity / commit behavior | Automated assurance |
| --- | --- | --- | --- | --- |
| Local disk / NAS | sync or backup | upload, recursive parent creation | source and committed SHA-256; immutable destination; atomic rename | real filesystem integration tests, including idempotency, conflict, cancellation, and traversal rejection |
| Nextcloud / WebDAV | sync or backup | authenticated probe, `MKCOL`, streamed `PUT`, atomic `MOVE` | `OC-Checksum: SHA256`, length, temporary name, cleanup on failed move | local HTTP protocol test verifies auth, `PROPFIND`, `MKCOL`, checksum headers, body, and `MOVE` |
| OneDrive / SharePoint | sync or backup | drive probe, upload-session creation, sequential resumable chunks; direct empty-file upload | 10 MiB chunks, `Content-Range`, bounded retry; verifies returned size and SHA-256 when Graph supplies it | local HTTP protocol test covers resumable and empty uploads and remote evidence |
| Google Drive | sync or backup | about probe, search, folder creation, revisions, resumable and empty upload | 8 MiB sequential chunks, `Content-Range`, bounded retry; verifies returned size | local HTTP protocol test covers all listed operations |
| SFTP / SSH | sync or backup | password-authenticated upload, recursive parent creation, temporary file, rename, stat | mandatory SHA-256 host-key pin; Ed25519/ECDSA server keys only; committed-size check | compile plus constructor/security tests; live server credentials are operator assurance |
| Explicit FTPS | sync or backup | TLS-authenticated upload, recursive parent creation, temporary file, rename, stat | native CA trust, binary/private data mode, committed-size check; plain FTP is not implemented | compile plus constructor/security tests; live server credentials are operator assurance |
| SMB 2/3 | sync or backup | authenticated upload, recursive parent creation, streaming temporary file, rename, stat | encryption required unless the operator explicitly sets `allow_unencrypted`; committed-size check | compile plus constructor/security tests; live server credentials are operator assurance |
| S3-compatible | **backup only** | head/stat, bounded list, atomic local download, multipart upload, abort, idempotent replay | per-part CRC32, final size + metadata SHA-256 + provider checksum, version/ETag receipt | signed local S3 protocol test covers multipart, replay, stat, list, and verified download |

!!! warning "Live-provider assurance boundary"
    CI does not carry real SFTP, FTPS, SMB, Microsoft, Google, Nextcloud, or S3
    tenant credentials. The HTTP and S3 suites verify protocol construction
    against local providers; native clients receive compile and fail-closed
    configuration coverage. Before production use, run `probe` with the real
    account, certificate chain, network route, permissions, quotas, and server
    versions. A compile or mock pass is not a live-provider certification.

The protocol choices follow the providers' maintained interfaces:

- [Nextcloud WebDAV client APIs](https://docs.nextcloud.com/server/latest/developer_manual/client_apis/WebDAV/basic.html)
  and [RFC 4918](https://www.rfc-editor.org/rfc/rfc4918);
- [Microsoft Graph upload sessions](https://learn.microsoft.com/graph/api/driveitem-createuploadsession)
  and [large-file upload guidance](https://learn.microsoft.com/graph/sdks/large-file-upload);
- [Google Drive resumable uploads](https://developers.google.com/workspace/drive/api/guides/manage-uploads),
  [search](https://developers.google.com/workspace/drive/api/guides/search-files),
  [folders](https://developers.google.com/workspace/drive/api/guides/folder), and
  [revisions](https://developers.google.com/workspace/drive/api/guides/manage-revisions);
- [Amazon S3 multipart upload](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html)
  and [checksum guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html).

## Durable job lifecycle

Each job is immutable JSON keyed by the SHA-256 of a server-derived idempotency
key. Queue state is represented by atomic moves between `staged`, `pending`,
`running`, `completed`, `failed`, and `cancelled`. Status events and receipts
are immutable files. Cancellation and retry requests also use private staged
markers so the worker cannot observe an operator action before its audit event
commits.

The worker applies these rules:

1. The API accepts an act-document selector or the latest instance-backup
   selector, never a caller-supplied host path. It copies the selected artifact
   beneath its fixed `source_root`; backup copies are streamed.
2. Enqueue canonicalizes the source beneath `source_root`, rejects traversal or
   symlink escape, and records source length and SHA-256.
3. An API job is staged, a DAT-10 metadata-only ledger event is durably
   committed, and only then is the job atomically published to `pending`.
   Failed audit commits discard the stage and roll back newly materialized data.
4. A replay with the same idempotency key and equivalent job returns the
   existing job. A replay that changes any material field is a conflict.
5. Claiming atomically moves one job to `running` and records an ordered event.
6. The worker uses the immutable target snapshot stored with an API-created
   job, revalidates its URL/DNS policy, and rechecks source length and SHA-256.
7. Retryable provider failures use capped exponential backoff. The not-before
   event is durable before the job becomes claimable again.
8. Cancellation is a durable marker observed before claim and during transfer.
9. Success commits a receipt before the job enters `completed`.
10. On restart, a running job with a receipt reconciles to success, a cancelled
   job reconciles to cancelled, and any other running job is requeued.

The worker emits a durable heartbeat at least every ten seconds while transfers
run. The image healthcheck fails if no heartbeat is newer than 120 seconds.

## Run the dedicated image

The committed `worker` profile starts the API and worker together. They mount
the same `chancela-data` volume, while the example configuration uses separate
local sync and backup targets and contains no credentials:

```sh
docker compose -f docker/docker-compose.yml --profile worker up --build
```

The hardened equivalent is:

```sh
docker compose -f docker-compose.hardened.yml --profile worker up --build
```

Both use:

- config at `/etc/chancela-worker/config.json` (read-only);
- API-materialized source files under `/var/lib/chancela/worker/sources`;
- durable queue under `/var/lib/chancela/worker/queue`;
- separate default targets under `/var/lib/chancela/worker/targets/sync` and
  `/var/lib/chancela/worker/targets/backup`;
- connector secret files under `/run/chancela-connector-secrets` (read-only).

Set `CHANCELA_WORKER_CONFIG` to mount another host configuration. Do not edit
the example into a secret-bearing file and commit it.

## Authenticated operator API

All routes are fail-closed in the central route-classification table. A target
belongs to one tenant, has its own `Integration` scope, and owns a generated
`Repository` scope used by jobs. Cross-tenant target and job IDs return not
found rather than disclosing existence.

| Operation | Route | Required permission and scope |
| --- | --- | --- |
| list/create targets | `GET/POST /v1/tenants/{tenant}/connector-targets` | `SettingsRead` / `SettingsManage` on the tenant |
| read/update/archive | `GET/PATCH/DELETE /v1/tenants/{tenant}/connector-targets/{target}` | settings permission on the target `Integration` |
| live probe | `POST /v1/tenants/{tenant}/connector-targets/{target}/probe` | `SettingsRead` on the `Integration` |
| run | `POST /v1/tenants/{tenant}/connector-targets/{target}/run` | `DataExport` for sync or `DataBackup` for backup on the target `Repository`; act exports also require `ActRead` |
| list/read/cancel/retry jobs | `/v1/tenants/{tenant}/connector-jobs...` | purpose permission on the owning `Repository` |

Target create/update bodies accept connector configuration with credential
reference names only. Local filesystem targets are rejected by the API. A run
body has the following bounded shape:

```json
{
  "request_id": "018f6458-8d8c-7d20-a908-0242ac120002",
  "purpose": "sync",
  "artifact": {
    "kind": "act_document",
    "act_id": "4b3c2d00-0000-4000-8000-000000000003",
    "variant": "signed"
  },
  "destination": "acts/2026/act-42.pdf"
}
```

For whole-instance backups, use `{"kind":"latest_instance_backup"}` with
`purpose=backup`; this additionally requires global `DataBackup`. Target and
run bodies are capped at 64 KiB, destination paths at 2,048 bytes, job pages at
100 results, and the internal status scan at 500 current jobs. Responses expose
source SHA-256, size, provider evidence, and safe status detail. They never
expose the host source path, immutable target snapshot, secret value, or
idempotency key. Stable examples live in `contracts/connector-*.json`.

### Queue and inspect a job

Copy a source into the worker's durable volume, then enqueue a path relative to
`source_root`:

```sh
docker compose -f docker/docker-compose.yml cp archive.asice worker:/var/lib/chancela/worker/sources/archive.asice
docker compose -f docker/docker-compose.yml exec worker \
  /usr/local/bin/chancela-worker enqueue \
  --config /etc/chancela-worker/config.json \
  --data-dir /var/lib/chancela/worker/queue \
  --purpose backup \
  --source archive.asice \
  --destination 2026/archive.asice \
  --content-type application/vnd.etsi.asic-e+zip \
  --idempotency-key tenant-42-archive-2026-001
```

The command returns the deterministic job ID. Use it with `status` or `cancel`:

```sh
docker compose -f docker/docker-compose.yml exec worker \
  /usr/local/bin/chancela-worker status \
  --data-dir /var/lib/chancela/worker/queue --job-id JOB_SHA256

docker compose -f docker/docker-compose.yml exec worker \
  /usr/local/bin/chancela-worker cancel \
  --data-dir /var/lib/chancela/worker/queue --job-id JOB_SHA256
```

Probe configured targets without printing credentials:

```sh
docker compose -f docker/docker-compose.yml exec worker \
  /usr/local/bin/chancela-worker probe \
  --config /etc/chancela-worker/config.json \
  --data-dir /var/lib/chancela/worker/queue
```

## Configuration and credentials

Configuration contains credential **references**, never values. Every reference
must start with `CHANCELA_CONNECTOR_SECRET_` and contain only uppercase ASCII,
digits, and underscores. For example, the runtime resolver accepts either:

- `CHANCELA_CONNECTOR_SECRET_GRAPH_TOKEN` containing the value; or
- `CHANCELA_CONNECTOR_SECRET_GRAPH_TOKEN_FILE=/run/chancela-connector-secrets/graph_token`
  pointing to a UTF-8 secret file no larger than 64 KiB.

The `_FILE` form is preferred for containers. `CHANCELA_CONNECTOR_SECRETS_DIR`
is mandatory for file-backed values. The canonical file must remain beneath
that directory and neither the directory nor any path component may be a
symbolic link. Resolved values are zeroized and their debug representation is
always `[REDACTED]`.

A shortened multi-provider example follows. The selected sync and backup IDs
must exist and must be different when operational policy requires isolation:

```json
{
  "source_root": "/var/lib/chancela/worker/sources",
  "targets": {
    "purposes": {
      "sync": "nextcloud-sync",
      "backup": "s3-backup"
    },
    "targets": [
      {
        "kind": "web_dav",
        "id": "nextcloud-sync",
        "base_url": "https://cloud.example/remote.php/dav/files/operator",
        "auth": {
          "mode": "basic",
          "username": "operator",
          "password_ref": "CHANCELA_CONNECTOR_SECRET_NEXTCLOUD_APP_PASSWORD"
        },
        "timeout_seconds": 60,
        "allow_insecure_http": false
      },
      {
        "kind": "s3",
        "id": "s3-backup",
        "bucket": "chancela-archive",
        "prefix": "tenant-42",
        "region": "eu-west-1",
        "endpoint_url": null,
        "force_path_style": false,
        "access_key_ref": "CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY",
        "secret_key_ref": "CHANCELA_CONNECTOR_SECRET_S3_SECRET_KEY",
        "session_token_ref": null,
        "timeout_seconds": 60,
        "allow_insecure_http": false
      }
    ]
  },
  "poll_interval_ms": 1000,
  "max_parallel_jobs": 2,
  "max_job_attempts": 4,
  "retry_initial_ms": 1000,
  "retry_max_ms": 60000
}
```

Clear-text HTTP is rejected unless `allow_insecure_http` is explicitly enabled
for an operator-controlled test endpoint. Graph and Drive upload-session URLs
are separately parsed and subject to the same rule, preventing a provider
response from redirecting source bytes to an unsafe URL. HTTP redirects are
limited to three and must remain same-origin.

Every network connector is validated against an outbound host allowlist: a
comma-separated exact hostname/IP/CIDR list. Wildcards are rejected. The
configured host must have an exact host entry. DNS is resolved before connector
use and every non-public result (loopback, private, link-local,
metadata-service ranges, and similar) must also match an explicit IP or CIDR
entry. For example, a reviewed private Nextcloud deployment may use:

```text
CHANCELA_CONNECTOR_ALLOWED_HOSTS=cloud.example,10.42.8.15/32
```

### Two sources, one boundary

The allowlist has a deployment source and a runtime source:

| Source | Where | Who may change it |
|---|---|---|
| `CHANCELA_CONNECTOR_ALLOWED_HOSTS` | Deployment environment | Whoever controls the container/unit file; requires a redeploy |
| Connector egress allowlist | **Settings → Operações**, stored in the settings document and published to `<CHANCELA_DATA_DIR>/connector-allowed-hosts.json` | A holder of `settings.manage` at **Global** scope (Owner, Platform Administrator) |

**The rule is intersection, never union.** When the environment variable is set
it is a **ceiling**: every runtime entry must be covered by it, so an
administrator can only ever *narrow* what the deployment permits. Saving an
entry outside the ceiling is rejected with a `422` naming the variable. When the
environment variable is unset, the runtime allowlist is the sole boundary; with
neither configured, network connectors fail closed exactly as before. The UI
states which of these three cases is in force, and shows the ceiling itself.

Because the runtime allowlist is the path an attacker holding an admin session
would use, entries saved through it are validated more strictly than the
environment variable. Rejected outright, regardless of what the deployment would
permit: wildcards in any form; anything carrying a scheme, port, path, query, or
user information; `localhost` and the loopback ranges; the link-local range
`169.254.0.0/16` and `fe80::/10` (`169.254.169.254` is the cloud
instance-metadata endpoint, the highest-value SSRF destination in a hosted
deployment); multicast and the unspecified address; and CIDRs broader than `/16`
(IPv4) or `/32` (IPv6). At most 64 entries. Private RFC 1918 ranges remain
allowed — LAN SMB/FTPS backup targets are a supported deployment.

Every change appends a `connector.allowlist.updated` event to the append-only
ledger alongside the usual `settings.updated`, recording the actor, the previous
and new lists, what was added and removed, and whether a deployment ceiling was
in force. Changes take effect on the **next connector operation** in both the
API and the worker process — no restart of either is required.

**The security trade-off, stated plainly.** Before this, the egress boundary
could only be moved by someone with deployment access. Now an attacker who
obtains a Global `settings.manage` session can also narrow it, and — where no
environment ceiling is pinned — widen it to a host they control, subject to the
validation above. A hardened deployment should therefore continue to set
`CHANCELA_CONNECTOR_ALLOWED_HOSTS`, which reduces a compromised admin session to
choosing a subset of hosts the deployment already trusts.

Microsoft Graph and Google Drive upload-session URLs are independently checked
against the same policy before bytes are sent, so their session hosts must also
be allowlisted. DNS validation narrows SSRF exposure but does not pin the HTTP
socket to the resolved address; production DNS and egress controls remain part
of the deployment boundary. Redirects are limited to three same-origin hops.

For SFTP, configure an OpenSSH `SHA256:...` fingerprint and ensure the server
offers an Ed25519 or ECDSA host key. RSA server host keys and unpinned keys are
rejected. FTPS uses explicit TLS with the native trust store; plain FTP is not
available. SMB encryption is fail-closed unless `allow_unencrypted` is an
explicit, reviewed local-network exception.

## S3 integrity and ETag caveat

S3 uploads use `aws-sdk-s3` 1.138.0, multipart uploads with at most 10,000
parts, CRC32 confirmation for every part, and abort on cancellation or any
pre-completion error. Chancela stores source SHA-256 and idempotency metadata,
then requires final size, metadata SHA-256, and the provider checksum before
recording `RemoteConfirmed`.

An S3 ETag is retained as provider evidence, but it is **not treated as a
content hash**. AWS documents that multipart and encrypted-object ETags are not
the MD5 of the object. Restore downloads go to a new temporary file, verify the
stored SHA-256, `fsync`, and only then rename into a destination that must not
already exist.

## Google Drive path boundary

Google Drive upload metadata uses the final basename of `destination` and the
configured `parent_folder_id`. Slash-separated intermediate path components
are not auto-created. Use `create_folder`, select the resulting parent ID in a
target configuration, and then enqueue into that parent. This avoids silently
guessing folder identity in a system where names are not unique.
