#!/usr/bin/env bash
# Chancela PostgreSQL restore helper (POSIX / bash).
#
# Restores a scripts/pg-backup.sh archive (a pg_dump custom-format `.dump`) into a
# target database with `pg_restore`, SAFELY:
#   1. Refuses to run while a server is alive at the probe URL (GET /health), so it
#      never restores under an app that is holding the ledger's single-writer
#      connection (§4) or serving from the database being replaced.
#   2. Restores with pg_restore --clean --if-exists into the target DATABASE_URL.
#   3. Verifies the result: polls the app's /health after you start it against the
#      restored database and asserts "ledger_verified": true (the same durable
#      chain re-verification the SQLite restore relies on).
#
# Usage:
#   DATABASE_URL=postgres://chancela:...@host:5432/chancela \
#     bash scripts/pg-restore.sh <backup.dump> [base-url]
#   bash scripts/pg-restore.sh chancela-pg-backup-20260715T120000Z.dump
#   bash scripts/pg-restore.sh backup.dump http://127.0.0.1:8080
#
# Environment:
#   DATABASE_URL   libpq connection string for the TARGET database (required). To
#                  rehearse without risk, point it at a throwaway database, e.g.
#                  createdb chancela_restore_test first.
#   PGPASSWORD     password, OR a ~/.pgpass / PGPASSFILE entry (preferred).
#   PG_RESTORE     override the pg_restore binary.
#   VERIFY_TIMEOUT seconds to wait for /health after restore (default 180).
#
# Needs `pg_restore`; `curl` for the /health verification; `jq` optional (nicer
# output, otherwise a grep fallback is used).

set -euo pipefail

if [ "$#" -lt 1 ]; then
    printf 'Usage: DATABASE_URL=... bash scripts/pg-restore.sh <backup.dump> [base-url]\n' >&2
    exit 1
fi

dump_file="$1"
base_url="${2:-http://127.0.0.1:8080}"
pg_restore_bin="${PG_RESTORE:-pg_restore}"
verify_timeout="${VERIFY_TIMEOUT:-180}"

case "$base_url" in
    *://*) : ;;
    *)     base_url="http://$base_url" ;;
esac
base_url="${base_url%/}"

if [ -z "${DATABASE_URL:-}" ]; then
    printf 'DATABASE_URL is not set. Export the target libpq connection string.\n' >&2
    printf '  To rehearse safely, point it at a throwaway database first.\n' >&2
    exit 1
fi
if [ ! -f "$dump_file" ]; then
    printf 'Backup archive not found: %s\n' "$dump_file" >&2
    exit 1
fi
if ! command -v "$pg_restore_bin" >/dev/null 2>&1; then
    printf 'Could not find `%s` (install postgresql-client or set PG_RESTORE).\n' "$pg_restore_bin" >&2
    exit 1
fi

printf 'Chancela PostgreSQL restore\n\n'
printf '  archive   %s\n' "$dump_file"
printf '  target    (DATABASE_URL)\n'
printf '  probing   %s/health\n\n' "$base_url"

# 1. Refuse if a server is alive at the probe URL. A live app holds the writer
#    connection and would be serving stale reads from the database mid-restore.
if command -v curl >/dev/null 2>&1; then
    if code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$base_url/health" 2>/dev/null)" \
        && [ -n "$code" ] && [ "$code" != "000" ]; then
        printf 'A server is responding at %s (HTTP %s) - refusing to restore under a live app.\n' "$base_url" "$code"
        printf '  Stop chancela-server first, then re-run.\n'
        printf '  (If that URL is some OTHER service, pass the real base URL as the 2nd argument.)\n'
        exit 1
    fi
else
    printf 'warning: `curl` not found - skipping the "is the app running?" safety probe\n'
    printf '         AND the post-restore /health verification. Make SURE the server is\n'
    printf '         stopped before continuing, and verify ledger_verified by hand after.\n\n'
fi

# 2. Restore. --clean --if-exists drops the app's objects before recreating them so
#    a re-restore over an existing database is idempotent; --no-owner keeps it
#    portable across roles. --exit-on-error fails closed on the first problem.
printf 'Restoring with pg_restore (this drops + recreates the app objects) ...\n'
if ! "$pg_restore_bin" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        --exit-on-error \
        --dbname="$DATABASE_URL" \
        "$dump_file"; then
    printf '\npg_restore reported an error. The target database may be partially restored;\n' >&2
    printf 'do NOT start the app against it until you have re-run a clean restore.\n' >&2
    exit 1
fi
printf 'Restore complete.\n\n'

# 3. Verify. The durable proof is the ledger re-verifying on boot: start the app
#    against the restored database, then this polls /health for ledger_verified.
if ! command -v curl >/dev/null 2>&1; then
    printf 'Skipping automated verification (no curl). Start the server against the\n'
    printf 'restored database and confirm GET %s/health reports "ledger_verified": true.\n' "$base_url"
    exit 0
fi

printf 'Now start the server against the restored database, e.g.:\n'
printf '  CHANCELA_DB_BACKEND=postgres DATABASE_URL="$DATABASE_URL" cargo run -p chancela-server\n\n'
printf 'Waiting up to %ss for %s/health ...\n' "$verify_timeout" "$base_url"

deadline=$(( $(date +%s) + verify_timeout ))
body=''
while [ "$(date +%s)" -lt "$deadline" ]; do
    if body="$(curl -sS --max-time 5 "$base_url/health" 2>/dev/null)" && [ -n "$body" ]; then
        break
    fi
    body=''
    sleep 3
done

if [ -z "$body" ]; then
    printf '\nTimed out waiting for %s/health. Once the app is up, confirm by hand that\n' "$base_url"
    printf '  "ledger_verified": true\n'
    printf 'before trusting the restored database.\n'
    exit 2
fi

if command -v jq >/dev/null 2>&1; then
    verified="$(printf '%s' "$body" | jq -r '.ledger_verified // .persistence.ledger_verified // empty')"
else
    verified="$(printf '%s' "$body" | grep -o '"ledger_verified"[[:space:]]*:[[:space:]]*\(true\|false\)' | grep -o '\(true\|false\)' | head -n 1)"
fi

if [ "$verified" = "true" ]; then
    printf '\nOK: GET /health reports "ledger_verified": true - the restored chain re-verified.\n'
    exit 0
fi

printf '\nWARNING: /health did NOT report ledger_verified == true (got: %s).\n' "${verified:-<absent>}"
printf 'The restored database failed the durable integrity check. Investigate before\n'
printf 'relying on it; do not put it into service.\n'
exit 3
