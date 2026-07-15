#!/usr/bin/env bash
# Chancela PostgreSQL backup helper (POSIX / bash).
#
# For the self-hosted server edition running on the optional Postgres backend
# (CHANCELA_DB_BACKEND=postgres). Takes a transactionally-consistent logical dump
# of the whole database with `pg_dump` and writes it to a timestamped file, then
# prints how to verify it via a restore drill + GET /health ledger_verified.
#
# `pg_dump` runs its dump inside a single repeatable-read snapshot, so the archive
# is a consistent point-in-time image even while the server keeps serving (§4 the
# ledger's atomic append means the snapshot never captures a half-written event).
#
# Usage:
#   DATABASE_URL=postgres://chancela:...@host:5432/chancela \
#     bash scripts/pg-backup.sh [output-dir]
#   bash scripts/pg-backup.sh                 # writes into ./backups
#   bash scripts/pg-backup.sh /srv/backups    # a chosen directory
#
# Environment:
#   DATABASE_URL   libpq connection string / URI (required). The SAME value the
#                  server is started with. TLS parameters (sslmode=verify-full,
#                  sslrootcert=...) are honored by pg_dump exactly as by the app.
#   PGPASSWORD     password, OR (preferred) a ~/.pgpass / PGPASSFILE entry so the
#                  secret never appears in the process list or shell history.
#   PG_DUMP        override the pg_dump binary (e.g. a versioned path).
#
# Produces a PostgreSQL custom-format archive (`.dump`), restorable with
# scripts/pg-restore.sh (which wraps pg_restore).

set -euo pipefail

out_dir="${1:-./backups}"
pg_dump_bin="${PG_DUMP:-pg_dump}"

if [ -z "${DATABASE_URL:-}" ]; then
    printf 'DATABASE_URL is not set. Export the same libpq connection string the\n' >&2
    printf 'server uses, e.g.:\n' >&2
    printf '  export DATABASE_URL=postgres://chancela:***@host:5432/chancela\n' >&2
    exit 1
fi

if ! command -v "$pg_dump_bin" >/dev/null 2>&1; then
    printf 'Could not find `%s`. Install the PostgreSQL client tools (postgresql-client)\n' "$pg_dump_bin" >&2
    printf 'or set PG_DUMP to its full path.\n' >&2
    exit 1
fi

mkdir -p "$out_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_file="$out_dir/chancela-pg-backup-$stamp.dump"

printf 'Chancela PostgreSQL backup\n\n'
printf '  target    %s\n' "$out_file"
printf '  dumping   (consistent snapshot via pg_dump)\n\n'

# --format=custom       compressed, selective, restorable with pg_restore
# --no-owner/--no-acl   portable across roles (the app owns its own objects on restore)
# A non-zero pg_dump exit leaves no partial file trusted: remove it and fail.
if ! "$pg_dump_bin" \
        --format=custom \
        --no-owner \
        --no-privileges \
        --file="$out_file" \
        "$DATABASE_URL"; then
    printf '\npg_dump failed; removing the incomplete archive.\n' >&2
    rm -f "$out_file"
    exit 1
fi

size="$(wc -c < "$out_file" | tr -d ' ')"
printf 'Backup written:\n'
printf '  path   %s\n' "$out_file"
printf '  bytes  %s\n\n' "$size"

cat <<EOF
Next steps:
  1. Copy this archive to your off-box, encrypted-at-rest backup location.
  2. VERIFY it is restorable (do this regularly, not only in a real incident):
       - restore it into a THROWAWAY database + data dir with
           scripts/pg-restore.sh "$out_file"
         (see that script's help for the scratch-DATABASE_URL flow), then
       - start the server against the restored database and confirm the chain
         re-verified on boot: GET /health reports "ledger_verified": true
         (the startup banner also prints 'chain verified').
  A backup you have never restored is not a backup you can rely on.
EOF
exit 0
