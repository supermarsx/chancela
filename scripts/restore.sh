#!/usr/bin/env bash
# Chancela restore helper (POSIX / bash).
#
# Automates the documented manual restore (t30 §D6) SAFELY:
#   1. Refuses to run while a server is alive at the probe URL (GET /health), so
#      it never overwrites a data dir an app has open.
#   2. Renames any existing target data dir to "<dir>.pre-restore-<stamp>" so the
#      current state is never destroyed, only set aside.
#   3. Unpacks the named backup .zip (a scripts/backup.sh / POST /v1/backup
#      archive, or a cold copy zipped up) into a fresh target data dir.
#   4. Prints how to start against it and verify the chain (GET /health
#      ledger_verified).
#
# Usage:
#   bash scripts/restore.sh <backup.zip> <data-dir> [base-url]
#   bash scripts/restore.sh chancela-backup-20260707T120000Z.zip ./data
#   bash scripts/restore.sh backup.zip ./data 127.0.0.1:9000
#
# Unpacks with `unzip`, falling back to `python3 -m zipfile`; needs `curl` for the
# liveness probe.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    printf 'Usage: bash scripts/restore.sh <backup.zip> <data-dir> [base-url]\n' >&2
    exit 1
fi

backup_zip="$1"
data_dir="$2"
base_url="${3:-http://127.0.0.1:8080}"
case "$base_url" in
    *://*) : ;;
    *)     base_url="http://$base_url" ;;
esac
base_url="${base_url%/}"

if [ ! -f "$backup_zip" ]; then
    printf 'Backup archive not found: %s\n' "$backup_zip" >&2
    exit 1
fi

printf 'Chancela restore\n\n'
printf '  archive   %s\n' "$backup_zip"
printf '  data dir  %s\n' "$data_dir"
printf '  probing   %s/health\n\n' "$base_url"

# 1. Refuse if a server is alive at the probe URL. curl exits 0 with a numeric
#    HTTP code when something answered; a refused/timed-out connection exits
#    non-zero (the good case: nothing is listening).
if command -v curl >/dev/null 2>&1; then
    if code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$base_url/health" 2>/dev/null)" \
        && [ -n "$code" ] && [ "$code" != "000" ]; then
        printf 'A server is responding at %s (HTTP %s) - refusing to restore under a live app.\n' "$base_url" "$code"
        printf '  Stop chancela-server / close the desktop app first, then re-run.\n'
        printf '  (If that URL is some OTHER service, pass the real base URL as the 3rd argument.)\n'
        exit 1
    fi
else
    printf 'warning: `curl` not found - skipping the "is the app running?" safety probe.\n'
    printf '         Make SURE chancela-server / the desktop app is stopped before continuing.\n\n'
fi

# 2. Set aside any existing data dir (never destroy it).
if [ -e "$data_dir" ]; then
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    aside="${data_dir%/}.pre-restore-$stamp"
    printf 'Existing data dir found; moving it aside:\n'
    printf '  %s\n    -> %s\n' "$data_dir" "$aside"
    mv "$data_dir" "$aside"
fi

# 3. Unpack the archive into a fresh data dir. The archive holds chancela.db plus
#    the sidecars (settings.json/users.json/cae-catalog.json/laws/) and a
#    manifest.json at its root - exactly the data-dir layout.
mkdir -p "$data_dir"
printf '\nUnpacking archive into %s ...\n' "$data_dir"
if command -v unzip >/dev/null 2>&1; then
    unzip -o -q "$backup_zip" -d "$data_dir"
elif command -v python3 >/dev/null 2>&1; then
    python3 -m zipfile -e "$backup_zip" "$data_dir"
else
    printf 'Need `unzip` or `python3` to unpack the archive; neither was found.\n' >&2
    printf 'Install one, or extract %s into %s by hand.\n' "$backup_zip" "$data_dir" >&2
    exit 1
fi

if [ ! -f "$data_dir/chancela.db" ]; then
    printf '\nWARNING: the unpacked archive has no chancela.db at its root.\n'
    printf '  It may not be a Chancela backup, or it wrapped the files in a subfolder.\n'
    printf '  Inspect %s; the server needs chancela.db directly inside the data dir.\n' "$data_dir"
    exit 1
fi

cat <<EOF

Restore staged. Next steps:
  1. Start the server against the restored data dir, e.g.:
       CHANCELA_DATA_DIR="$data_dir" cargo run -p chancela-server
     (or point the desktop app at it the same way).
  2. Confirm the chain verified on boot:
       the startup banner shows 'Ledger  <N> events on disk - chain verified',
       and GET $base_url/health reports "ledger_verified": true.
  If anything looks wrong, your previous data dir is preserved next to it as
  the .pre-restore-<stamp> folder.
EOF
exit 0
