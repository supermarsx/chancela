#!/usr/bin/env bash
# Chancela hot-backup helper (POSIX / bash).
#
# Calls `POST /v1/backup` on a RUNNING chancela-server and prints the returned
# manifest: the on-disk archive path, its size, the ledger length + boot-verify
# status, and the per-file SHA-256 digest table. The server takes the snapshot
# with SQLite `VACUUM INTO` (transactionally consistent, no downtime), so this is
# safe to run against a live instance.
#
# Usage:
#   bash scripts/backup.sh                    # default http://127.0.0.1:8080
#   bash scripts/backup.sh 127.0.0.1:9000     # a different host:port
#   bash scripts/backup.sh http://host:8080   # full base URL also works
#
# If the server is in-memory (no CHANCELA_DATA_DIR) it returns 422 and there is
# nothing to back up online; if it is unreachable this prints a clear message.
# Either way it points at the COLD-COPY alternative (stop the app, copy the data
# dir) documented in the README. Uses `curl`; `jq` (optional) gives a formatted
# table, otherwise the raw manifest JSON is shown.

set -euo pipefail

base_url="${1:-http://127.0.0.1:8080}"
# Accept a bare host:port (prepend http://) and trim a trailing slash.
case "$base_url" in
    *://*) : ;;
    *)     base_url="http://$base_url" ;;
esac
base_url="${base_url%/}"
backup_url="$base_url/v1/backup"

if ! command -v curl >/dev/null 2>&1; then
    printf 'This script needs `curl`, which was not found on PATH.\n' >&2
    exit 1
fi

cold_copy_hint() {
    cat <<'EOF'

Cold-copy alternative (works with the app stopped):
  1. Stop chancela-server / close the desktop app.
  2. Copy the whole data directory (the folder holding chancela.db,
     settings.json, users.json, cae-catalog.json and laws/) somewhere safe.
     Its location is the CHANCELA_DATA_DIR you started the server with,
     or the per-app data dir the desktop app logs at startup.
  Restore either kind of copy with scripts/restore.sh.
EOF
}

printf 'Chancela backup - POST %s\n\n' "$backup_url"

# Capture body and HTTP status together; a trailing line holds the status code.
# A curl transport failure (server down) leaves http_code empty.
http_code=''
body="$(curl -sS --max-time 300 -X POST -w '\n%{http_code}' "$backup_url" 2>/dev/null)" || true
if [ -n "$body" ]; then
    http_code="${body##*$'\n'}"
    body="${body%$'\n'*}"
fi

if [ -z "$http_code" ]; then
    printf 'Could not reach a chancela-server at %s.\n' "$base_url"
    printf '  Is the server running? Pass a base URL argument if it listens elsewhere.\n'
    cold_copy_hint
    exit 1
fi

# Extract a scalar JSON field from the (flat) manifest without requiring jq.
json_field() {
    printf '%s' "$body" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^,\"}]*\)\"\{0,1\}.*/\1/p" | head -n 1
}

if [ "$http_code" = "422" ]; then
    message="$(json_field error)"
    [ -n "$message" ] || message='backup requires on-disk persistence; set CHANCELA_DATA_DIR'
    printf 'The server is running IN-MEMORY, so there is nothing to back up online.\n'
    printf '  server said: %s\n' "$message"
    printf '  Start it with CHANCELA_DATA_DIR set to enable POST /v1/backup.\n'
    cold_copy_hint
    exit 2
fi

if [ "$http_code" != "200" ]; then
    printf 'The server rejected the backup (HTTP %s).\n' "$http_code"
    [ -n "$body" ] && printf '  server said: %s\n' "$body"
    cold_copy_hint
    exit 1
fi

# Success: render the manifest. Prefer a formatted table via jq; fall back to raw.
if command -v jq >/dev/null 2>&1; then
    printf '%s' "$body" | jq -r '
        "Backup written:",
        "  path            \(.path)",
        "  size            \(.bytes) bytes",
        "  created_at      \(.created_at)",
        "  app_version     \(.app_version)",
        "  schema_version  \(.store_schema_version)",
        "  ledger_length   \(.ledger_length)",
        "  ledger_verified \(.ledger_verified)",
        "",
        "Archived files:",
        (["  name","bytes","sha256"] | @tsv),
        (.files[] | ["  \(.name)", .bytes, .sha256] | @tsv)
    '
    verified="$(printf '%s' "$body" | jq -r '.ledger_verified')"
else
    printf 'Backup written (install `jq` for a formatted table):\n\n'
    printf '%s\n' "$body"
    verified="$(json_field ledger_verified)"
fi

if [ "$verified" != "true" ]; then
    printf '\nWARNING: the durable chain did NOT verify at backup time. The archive still\n'
    printf 'captures the current bytes, but investigate the integrity failure before relying\n'
    printf 'on it (see the server banner / GET /health ledger_verified).\n'
    exit 3
fi

printf '\nDone. Copy the archive above to your off-box backup location.\n'
exit 0
