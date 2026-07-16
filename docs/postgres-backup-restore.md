# PostgreSQL backup &amp; restore

This runbook covers backing up and restoring the self-hosted server edition when it
runs on the optional **PostgreSQL backend** (`CHANCELA_DB_BACKEND=postgres`). The
default SQLite/SQLCipher editions are covered by the hot-backup bundle and
`scripts/restore.{sh,ps1}` instead; see the deployment overview for those.

The durable record on Postgres is the same hash-chained ledger plus the domain
aggregate tables. The single trustworthy signal that a backup or a restore is
sound is that the **ledger chain re-verifies on boot**: the server prints
`chain verified` at startup and `GET /health` reports `"ledger_verified": true`.
Every procedure below ends on that check.

> Scope note: these procedures capture and restore the bytes of the database. They
> do not, by themselves, make any claim about the legal weight of the records they
> contain — only that the chain the application wrote is intact and re-verifiable.

## What to back up

- **The database.** All ledger events and aggregate/read-model tables live here.
- **The instance sidecars**, if any are kept outside the database (e.g. a `laws/`
  corpus or a `settings.json` mounted next to the server). Back these up with your
  normal file backup; they are not part of the SQL dump.
- **The store encryption / secrets configuration** needed to read provider
  credentials after a restore (the credential *records* are in the database, but
  the key that unseals them is supplied by your deployment). Store this separately
  and securely.

Encryption at rest for the database itself is a property of your Postgres
deployment (managed-service disk encryption, or a self-managed volume on an
encrypted filesystem), not of these scripts. Keep the dump archives on
encrypted-at-rest storage too — a `pg_dump` file is plaintext SQL/BLOBs.

## Prerequisites

- The PostgreSQL client tools `pg_dump` and `pg_restore` (package
  `postgresql-client`), matching or newer than the server's major version.
- `DATABASE_URL` — the same libpq connection string the server uses, e.g.
  `postgres://chancela:***@db.internal:5432/chancela`. TLS parameters
  (`sslmode=verify-full`, `sslrootcert=...`) are honored by `pg_dump`/`pg_restore`
  exactly as by the application.
- A password supplied **out of band**: prefer a `~/.pgpass` (Unix) /
  `%APPDATA%\postgresql\pgpass.conf` (Windows) entry, or `PGPASSWORD`, so the
  secret never lands in your shell history or the process list.

## Backup

Take a consistent logical dump with `scripts/pg-backup.{sh,ps1}`, which wraps
`pg_dump --format=custom`:

```sh
export DATABASE_URL=postgres://chancela:***@db.internal:5432/chancela
# password via ~/.pgpass or PGPASSWORD
bash scripts/pg-backup.sh ./backups
```

```powershell
$env:DATABASE_URL = 'postgres://chancela:***@db.internal:5432/chancela'
scripts\pg-backup.ps1 -OutDir .\backups
```

`pg_dump` runs its dump inside a single repeatable-read snapshot, so the archive is
a **consistent point-in-time image** even while the server keeps serving. Because
the ledger's append is atomic and single-writer, a snapshot never captures a
half-written event.

The result is a timestamped custom-format archive
(`chancela-pg-backup-<UTC>.dump`) that `pg_restore` can reload. Copy it to your
off-box, encrypted-at-rest backup location.

You can also drive this from a managed provider's own snapshot tooling instead of
`pg_dump`; the verification step (restore + `ledger_verified`) is what matters, not
the snapshot mechanism.

## Restore

Restore with `scripts/pg-restore.{sh,ps1}`, which wraps
`pg_restore --clean --if-exists` and then verifies the result:

```sh
export DATABASE_URL=postgres://chancela:***@db.internal:5432/chancela_restore
bash scripts/pg-restore.sh ./backups/chancela-pg-backup-20260715T120000Z.dump
```

```powershell
$env:DATABASE_URL = 'postgres://chancela:***@db.internal:5432/chancela_restore'
scripts\pg-restore.ps1 -DumpFile .\backups\chancela-pg-backup-20260715T120000Z.dump
```

The script:

1. **Refuses to run while a server is alive** at the probe URL (`GET /health`), so
   it never restores under an app that is holding the ledger's single-writer
   connection or serving from the database being replaced.
2. **Restores** the archive into the target `DATABASE_URL`
   (`pg_restore --clean --if-exists --no-owner --exit-on-error`). `--clean
   --if-exists` makes a re-restore over an existing database idempotent;
   `--exit-on-error` fails closed on the first problem.
3. **Verifies.** You start the server against the restored database; the script
   polls `GET /health` and asserts `"ledger_verified": true` — the same durable
   chain re-verification the SQLite restore relies on. A `false` (or absent)
   result exits non-zero: the restored database failed the integrity check and
   must not go into service.

To rehearse safely, point `DATABASE_URL` at a **throwaway** database (e.g.
`createdb chancela_restore_test`) and restore into that first. A backup you have
never restored is not a backup you can rely on; run the drill on a schedule.

### Restoring into a fresh database

For a clean recovery onto a new host, create an empty database and role, point
`DATABASE_URL` at it, and run the restore. The application re-creates and stamps
its own schema/`instance_id` on first boot only when the database is empty; a
restore reloads the captured schema and rows, so start the server afterward and let
it re-verify the chain rather than pre-initializing the database.

## Point-in-time recovery (PITR / WAL)

`pg_dump` gives you periodic, self-contained snapshots. It does **not** give you
continuous point-in-time recovery. If your recovery-point objective is tighter than
your dump interval, configure PostgreSQL PITR at the server/provider level —
continuous WAL archiving (`archive_command` / `archive_library`) plus a base
backup (`pg_basebackup`), or your managed provider's continuous-backup feature —
and recover with `recovery_target_time`. That is a database-administration concern
outside these scripts; the same post-recovery check applies: boot the app and
confirm `ledger_verified` is `true`.

## PostgreSQL TLS (`sslmode`)

The Postgres backend connects over a rustls-based TLS connector. The posture is
resolved from `CHANCELA_PG_SSLMODE` (highest precedence) or the `sslmode=`
parameter of `DATABASE_URL`, defaulting to `verify-full`:

| Mode | Encrypted | Server certificate verified | Use |
| --- | --- | --- | --- |
| `disable` | No | — | Rejected: plaintext database transport is not supported. |
| `prefer` | Maybe | No | Rejected: fallback to plaintext or an unauthenticated peer is not supported. |
| `require` | Yes | No | Rejected: encryption without server authentication is insufficient. |
| `verify-full` (default; `verify-ca` is hardened to this mode) | Yes | Yes — root CA + hostname | Required for compose, networked, and managed Postgres. |

Existing deployments using an insecure mode must provision a trusted server
certificate and CA before upgrading. The local compose profile does this with
its isolated `postgres-tls-init` service; managed deployments should mount the
provider's CA bundle.

Configuration:

- **Mode** — put `sslmode=` in `DATABASE_URL`
  (e.g. `postgres://…/chancela?sslmode=verify-full`) or set
  `CHANCELA_PG_SSLMODE=verify-full`. The environment variable wins over the URL.
- **Root CA for `verify-full`** — set `CHANCELA_PG_TLS_ROOT_CERT` to a PEM file of
  the trusted root certificate(s). When unset, the operating-system trust store is
  used. `verify-full` fails closed if no usable root CA is available rather than
  silently trusting nothing.

Notes:

- `pg_dump` / `pg_restore` read `sslmode` and `sslrootcert` from the same
  `DATABASE_URL` / libpq environment, so the backup and restore tooling verifies
  the server on the same terms as the application.
- Channel binding (SCRAM-SHA-256-**PLUS**) is not negotiated; authentication uses
  plain SCRAM-SHA-256 over the encrypted channel. TLS still fully encrypts the
  session and, under `verify-full`, authenticates the server.

## Verifying integrity

After any backup drill or restore, the acceptance check is always the same:

- The startup banner prints `Ledger  <N> events on disk - chain verified`.
- `GET /health` returns `"ledger_verified": true`.

If either says otherwise, treat the database as suspect: do not put it into
service, and investigate the chain failure before relying on it.
