#!/usr/bin/env bash
# End-to-end Compose proof for the restricted PostgreSQL projector role.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="${CHANCELA_PROJECTOR_SMOKE_PROJECT:-chancela-projector-pg-smoke}"
HOST_PORT="${CHANCELA_PROJECTOR_SMOKE_PORT:-18082}"
export CHANCELA_HOST_PORT="$HOST_PORT"
export CHANCELA_POSTGRES_IMAGE="${CHANCELA_POSTGRES_IMAGE:-chancela-server:ci}"
export CHANCELA_SEARCH_PROJECTOR_IMAGE="${CHANCELA_SEARCH_PROJECTOR_IMAGE:-chancela-search-projector:ci}"
standby_id=""

COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  -f docker/docker-compose.yml
  --profile postgres
)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${COMPOSE[@]}" ps --all || true
    "${COMPOSE[@]}" logs --no-color --tail 120 search-projector-role-init || true
    "${COMPOSE[@]}" logs --no-color --tail 200 search-projector-postgres || true
    "${COMPOSE[@]}" logs --no-color --tail 80 server-postgres || true
    if [ -n "$standby_id" ]; then
      docker logs "$standby_id" || true
    fi
  fi
  if [ -n "$standby_id" ]; then
    docker rm -f "$standby_id" >/dev/null 2>&1 || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

read_durable_projector_lease() {
  "${COMPOSE[@]}" run --rm --no-deps \
    --entrypoint /bin/sh \
    search-projector-role-init -ec '
      projector_url="$(tr -d "\r\n" </run/projector-secrets/search_database_url)"
      export PGSSLROOTCERT="$CHANCELA_PG_TLS_ROOT_CERT"
      psql "$projector_url" -X --set=ON_ERROR_STOP=1 \
        --tuples-only --no-align --field-separator "|" \
        -c "SELECT lease_id, lease_owner FROM search_projection_control WHERE lease_id IS NOT NULL"
    '
}

read_runtime_heartbeat() {
  local runtime_volume="$1"
  local lease_id="$2"
  docker run --rm \
    --network none \
    --user 65532:65532 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "$runtime_volume:/runtime:ro" \
    --entrypoint /usr/bin/busybox \
    "$CHANCELA_POSTGRES_IMAGE" \
    cat "/runtime/search-projector-heartbeats/${lease_id}.json"
}

list_runtime_heartbeat_files() {
  local runtime_volume="$1"
  docker run --rm \
    --network none \
    --user 65532:65532 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "$runtime_volume:/runtime:ro" \
    --entrypoint /usr/bin/busybox \
    "$CHANCELA_POSTGRES_IMAGE" \
    sh -ec '
      directory=/runtime/search-projector-heartbeats
      test -d "$directory"
      found=0
      for file in "$directory"/*.json; do
        test -f "$file" || continue
        found=1
        /usr/bin/busybox basename "$file"
      done
      test "$found" -eq 1
    ' |
    sort
}

assert_selected_projector_heartbeat() {
  local label="$1"
  local expected_lease_id="$2"
  local expected_owner="$3"
  local status_json="$4"
  local heartbeat_json="$5"
  ASSERT_LABEL="$label" \
    EXPECTED_LEASE_ID="$expected_lease_id" \
    EXPECTED_OWNER="$expected_owner" \
    SEARCH_STATUS_BODY="$status_json" \
    SEARCH_HEARTBEAT_BODY="$heartbeat_json" \
    python3 - <<'PY'
import json
import os

label = os.environ["ASSERT_LABEL"]
expected_lease_id = os.environ["EXPECTED_LEASE_ID"]
expected_owner = os.environ["EXPECTED_OWNER"]
status = json.loads(os.environ["SEARCH_STATUS_BODY"])
heartbeat = json.loads(os.environ["SEARCH_HEARTBEAT_BODY"])
if status.get("stale") is not False:
    raise SystemExit(f"{label}: API reported the active projection stale: {status!r}")
if status.get("projector_heartbeat_fresh") is not True:
    raise SystemExit(f"{label}: API did not trust the canonical heartbeat: {status!r}")
if status.get("projector_lease_owner") != expected_owner:
    raise SystemExit(f"{label}: durable lease owner changed: {status!r}")
if status.get("projector_phase") != "idle":
    raise SystemExit(f"{label}: active projector did not remain idle: {status!r}")
if heartbeat.get("schema_version") != 2:
    raise SystemExit(f"{label}: selected heartbeat schema is not v2: {heartbeat!r}")
if heartbeat.get("lease_id") != expected_lease_id:
    raise SystemExit(f"{label}: selected heartbeat lease changed: {heartbeat!r}")
if heartbeat.get("owner") != expected_owner:
    raise SystemExit(f"{label}: selected heartbeat owner changed: {heartbeat!r}")
if heartbeat.get("phase") != "idle":
    raise SystemExit(f"{label}: selected heartbeat phase changed: {heartbeat!r}")
if heartbeat.get("last_error") not in (None, ""):
    raise SystemExit(f"{label}: selected heartbeat reported an error: {heartbeat!r}")
PY
}

wait_for_idle_projector() {
  local label="$1"
  local previous_lease_id="${2:-}"
  local previous_owner="${3:-}"
  local health=""
  local last_health=""
  local lease_row=""
  local last_lease_row=""
  local current_lease_id=""
  local current_owner=""
  for _ in {1..180}; do
    if health="$(
      "${COMPOSE[@]}" exec -T search-projector-postgres \
        /usr/local/bin/chancela-search-projector \
        healthcheck --runtime-dir /run/chancela-search 2>/dev/null
    )" && grep -q 'phase=Idle' <<<"$health"; then
      if [ -z "$previous_lease_id" ]; then
        printf '%s\n' "$health"
        return 0
      fi
      if lease_row="$(read_durable_projector_lease 2>/dev/null)"; then
        current_lease_id="${lease_row%%|*}"
        current_owner="${lease_row#*|}"
        if [ -n "$current_lease_id" ] &&
          [ "$current_owner" != "$lease_row" ] &&
          [ "$current_lease_id" != "$previous_lease_id" ] &&
          [ "$current_owner" != "$previous_owner" ]; then
          printf '%s\n' "$health"
          return 0
        fi
        last_lease_row="$lease_row"
      fi
    fi
    if [ -n "$health" ] && [ "$health" != "$last_health" ]; then
      printf '%s: %s\n' "$label" "$health" >&2
      last_health="$health"
    fi
    sleep 1
  done
  printf '%s\n' "$health" >&2
  if [ -n "$previous_lease_id" ]; then
    printf '%s: previous lease=%s|%s current lease=%s\n' \
      "$label" "$previous_lease_id" "$previous_owner" "$last_lease_row" >&2
  fi
  "${COMPOSE[@]}" logs --no-color --tail 200 search-projector-postgres >&2 || true
  echo "$label did not reach an idle published generation" >&2
  return 1
}

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --no-build

runtime_init_id="$("${COMPOSE[@]}" ps -aq search-runtime-init)"
if [ -z "$runtime_init_id" ]; then
  echo "search runtime ownership initializer container is missing" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.State.ExitCode}}' "$runtime_init_id")" != "0" ]; then
  echo "search runtime ownership initializer did not complete successfully" >&2
  exit 1
fi
"${COMPOSE[@]}" logs --no-color search-runtime-init |
  grep -q 'search runtime volume ready (65532:65532:700)'

base_url="http://127.0.0.1:${HOST_PORT}"
for _ in {1..120}; do
  if curl -fsS "$base_url/health" >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "$base_url/health" >/dev/null

role_init_id="$("${COMPOSE[@]}" ps -aq search-projector-role-init)"
if [ -z "$role_init_id" ]; then
  echo "restricted projector role initializer container is missing" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.State.ExitCode}}' "$role_init_id")" != "0" ]; then
  echo "restricted projector role initializer did not complete successfully" >&2
  exit 1
fi
"${COMPOSE[@]}" logs --no-color search-projector-role-init |
  grep -q 'exact ACL verified'

# Run the probes a second time in verification-only mode. These include actual
# denied UPDATEs on entities/events and an actual denied SELECT on
# provider_credentials, not only catalog introspection.
"${COMPOSE[@]}" run --rm --no-deps search-projector-role-init verify

password="Postgres-Projector-Smoke-2026!"
owner="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "{\"username\":\"projector.pg.smoke\",\"display_name\":\"Projector PG Smoke\",\"password\":\"$password\"}" \
    "$base_url/v1/users"
)"
user_id="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["id"])' <<<"$owner"
)"
session="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "{\"username\":\"projector.pg.smoke\",\"password\":\"$password\"}" \
    "$base_url/v1/session"
)"
session_token="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["token"])' <<<"$session"
)"

# Start from a known healthy generation, then stop the managed projector while
# authoritative singleton rows and deliberately malformed legacy fallbacks are
# prepared. The API must immediately report that the derived index is stale.
wait_for_idle_projector "initial PostgreSQL projector"
initial_lease_row="$(read_durable_projector_lease)"
initial_lease_id="${initial_lease_row%%|*}"
initial_lease_owner="${initial_lease_row#*|}"
if [ -z "$initial_lease_id" ] || [ "$initial_lease_owner" = "$initial_lease_row" ]; then
  printf '%s\n' "$initial_lease_row" >&2
  echo "initial PostgreSQL projector did not hold one durable lease" >&2
  exit 1
fi
"${COMPOSE[@]}" stop --timeout 20 search-projector-postgres

stale_status=""
for _ in {1..30}; do
  if stale_status="$(
    curl -fsS \
      -H "X-Chancela-Session: $session_token" \
      "$base_url/v1/search/status"
  )" && SEARCH_STATUS_BODY="$stale_status" python3 - <<'PY'
import json
import os

status = json.loads(os.environ["SEARCH_STATUS_BODY"])
if status.get("stale") is not True:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 1
done
SEARCH_STATUS_BODY="$stale_status" python3 - <<'PY'
import json
import os

status = json.loads(os.environ["SEARCH_STATUS_BODY"])
if status.get("stale") is not True:
    raise SystemExit(f"stopped PostgreSQL projector was not reported stale: {status!r}")
PY

entity="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    -H "X-Chancela-Session: $session_token" \
    --data '{"name":"ProjectorPgAclUnique2026, Lda","nipc":"503004642","seat":"Porto","kind":"SociedadePorQuotas"}' \
    "$base_url/v1/entities"
)"
entity_id="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["id"])' <<<"$entity"
)"

dpia="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    -H "X-Chancela-Session: $session_token" \
    --data '{
      "title":"ProjectorPgDpiaAuthoritative2026",
      "purpose":"Packaging authority smoke",
      "legal_basis":"Legal obligation",
      "data_categories":["corporate records"],
      "subprocessors":[],
      "risk_level":"medium",
      "status":"active"
    }' \
    "$base_url/v1/privacy/dpias"
)"
DPIA_BODY="$dpia" python3 - <<'PY'
import json
import os

record = json.loads(os.environ["DPIA_BODY"])
if record.get("title") != "ProjectorPgDpiaAuthoritative2026":
    raise SystemExit(f"unexpected DPIA response: {record!r}")
PY

backup="$(
  curl -fsS --max-time 120 \
    -H "Content-Type: application/json" \
    -H "X-Chancela-Session: $session_token" \
    --data '{}' \
    "$base_url/v1/backup"
)"
backup_path="$(
  python3 -c 'import json, sys; path=json.load(sys.stdin).get("path"); assert path; sys.stdout.write(path)' \
    <<<"$backup"
)"
drill_payload="$(
  BACKUP_PATH="$backup_path" python3 -c \
    'import json, os, sys; sys.stdout.write(json.dumps({"archive": os.environ["BACKUP_PATH"], "operator_notes": "PostgreSQL projector authority smoke"}))'
)"
drill="$(
  curl -fsS --max-time 120 \
    -H "Content-Type: application/json" \
    -H "X-Chancela-Session: $session_token" \
    --data "$drill_payload" \
    "$base_url/v1/backup/recovery-drills"
)"
DRILL_BODY="$drill" python3 - <<'PY'
import json
import os

receipt = json.loads(os.environ["DRILL_BODY"])
manifest = receipt.get("manifest") or {}
isolated = receipt.get("isolated_restore_verification") or {}
expected_isolated_error = "isolated snapshot verification evidence was not produced"

if (
    receipt.get("preflight_ok") is not True
    or receipt.get("preflight_ready") is not True
    or receipt.get("ledger_verified") is not True
    or manifest.get("schema") != "chancela-pg-logical-backup/v1"
    or manifest.get("ledger_verified") is not True
    or manifest.get("db_member_present") is not True
):
    raise SystemExit(f"PostgreSQL logical recovery preflight did not verify: {receipt!r}")

# PostgreSQL verifies its logical bundle in memory and has no SQLite database file
# to materialize as an isolated snapshot. The generic receipt currently records that
# absent SQLite-style evidence as a failed isolated-restore subcheck.
if (
    receipt.get("isolated_restore_verified") is not False
    or isolated.get("status") != "failed"
    or expected_isolated_error not in isolated.get("errors", [])
    or any(
        isolated.get(field) is not False
        for field in (
            "db_snapshot_materialized",
            "db_snapshot_opened",
            "state_loaded",
            "ledger_verified",
            "cleanup_verified",
        )
    )
):
    raise SystemExit(
        f"PostgreSQL receipt did not honestly record unavailable isolated-snapshot evidence: {receipt!r}"
    )
PY

# Prove both compatibility sidecars already have database-authoritative
# replacements before corrupting the files. The restricted projector role can
# read these rows but cannot repair or insert them.
authoritative_documents="$(
  "${COMPOSE[@]}" run --rm --no-deps \
    --entrypoint /bin/sh \
    search-projector-role-init -ec '
      export PGSSLROOTCERT="$CHANCELA_PG_TLS_ROOT_CERT"
      projector_url="$(tr -d "\r\n" </run/projector-secrets/search_database_url)"
      psql "$projector_url" -X --set=ON_ERROR_STOP=1 \
        --tuples-only --no-align \
        -c "SELECT count(*) FROM settings
              WHERE id IN ('\''privacy-dpia-records'\'', '\''backup-recovery-drill-receipts'\'')
                AND octet_length(json) > 2"
    '
)"
if [ "$(tr -d '[:space:]' <<<"$authoritative_documents")" != "2" ]; then
  printf '%s\n' "$authoritative_documents" >&2
  echo "PostgreSQL did not persist both projector-authoritative compatibility documents" >&2
  exit 1
fi

server_id="$("${COMPOSE[@]}" ps -q server-postgres)"
app_data_volume="$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/chancela"}}{{.Name}}{{end}}{{end}}' \
    "$server_id"
)"
if [ -z "$app_data_volume" ]; then
  echo "PostgreSQL API has no named /var/lib/chancela application-data mount" >&2
  exit 1
fi
docker run --rm \
  --network none \
  --user 65532:65532 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$app_data_volume:/data" \
  --entrypoint /usr/bin/busybox \
  "$CHANCELA_POSTGRES_IMAGE" \
  sh -ec '
    umask 077
    printf "%s\n" "{malformed" > /data/privacy-dpias.json
    printf "%s\n" "{malformed" > /data/backup-recovery-drills.json
  '

# The matching singleton rows now exist in `settings`. A successful rebuild
# proves they win over malformed legacy fallbacks on the read-only app-data
# mount; falling back to either file would fail before publication.
"${COMPOSE[@]}" start search-projector-postgres
wait_for_idle_projector \
  "database-authoritative PostgreSQL projector rebuild" \
  "$initial_lease_id" \
  "$initial_lease_owner"

# Exercise the original lifecycle failure path as the durable lease owner.
# A concurrent process is now a true standby and intentionally writes no
# heartbeat, so stop the healthy owner first; otherwise this probe would merely
# wait for the lease and time out without ever touching the invalid runtime.
# The candidate must unwind through a controlled ExitCode::FAILURE rather than
# dropping postgres runtime-bearing resources on a Tokio worker and aborting
# with 139/a nested-runtime panic.
lifecycle_lease_row="$(read_durable_projector_lease)"
lifecycle_lease_id="${lifecycle_lease_row%%|*}"
lifecycle_lease_owner="${lifecycle_lease_row#*|}"
if [ -z "$lifecycle_lease_id" ] || [ "$lifecycle_lease_owner" = "$lifecycle_lease_row" ]; then
  printf '%s\n' "$lifecycle_lease_row" >&2
  echo "database-authoritative PostgreSQL projector did not hold one durable lease" >&2
  exit 1
fi
"${COMPOSE[@]}" stop --timeout 20 search-projector-postgres
set +e
lifecycle_output="$(
  /usr/bin/timeout 45s "${COMPOSE[@]}" run --rm --no-deps \
    -e CHANCELA_SEARCH_RUNTIME_DIR=/var/lib/chancela/projector-invalid-runtime \
    search-projector-postgres \
    once 2>&1
)"
lifecycle_status=$?
set -e
if [ "$lifecycle_status" -ne 1 ]; then
  printf '%s\n' "$lifecycle_output" >&2
  echo "invalid-runtime lifecycle probe exited $lifecycle_status, expected controlled status 1" >&2
  exit 1
fi
if grep -Eqi \
  'Cannot start a runtime from within a runtime|panicked at|panic in a destructor|non-unwinding panic|aborted' \
  <<<"$lifecycle_output"; then
  printf '%s\n' "$lifecycle_output" >&2
  echo "invalid-runtime lifecycle probe exposed a nested-runtime/destructor panic" >&2
  exit 1
fi
if ! grep -Fqi \
  'heartbeat I/O failed for /var/lib/chancela/projector-invalid-runtime/search-projector-heartbeats' \
  <<<"$lifecycle_output"; then
  printf '%s\n' "$lifecycle_output" >&2
  echo "invalid-runtime lifecycle probe did not report the expected bounded heartbeat failure" >&2
  exit 1
fi
"${COMPOSE[@]}" start search-projector-postgres
wait_for_idle_projector \
  "post-lifecycle PostgreSQL projector" \
  "$lifecycle_lease_id" \
  "$lifecycle_lease_owner"
echo "PostgreSQL projector invalid-runtime lifecycle regression passed."

search_body=""
dpia_search_body=""
backup_alert_search_body=""
status_body=""
for _ in {1..120}; do
  if ! search_body="$(
    curl -fsS \
      -H "X-Chancela-Session: $session_token" \
      "$base_url/v1/search?q=ProjectorPgAclUnique2026&kind=entity&limit=10"
  )"; then
    sleep 1
    continue
  fi
  if ! SEARCH_BODY="$search_body" ENTITY_ID="$entity_id" python3 - <<'PY'
import json
import os

response = json.loads(os.environ["SEARCH_BODY"])
hits = response.get("page", {}).get("hits", [])
if not any(hit.get("entity_id") == os.environ["ENTITY_ID"] for hit in hits):
    raise SystemExit(1)
generation = response.get("index", {}).get("generation")
if not isinstance(generation, int) or generation <= 0:
    raise SystemExit(1)
PY
  then
    sleep 1
    continue
  fi
  if ! dpia_search_body="$(
    curl -fsS --get \
      -H "X-Chancela-Session: $session_token" \
      --data-urlencode "q=ProjectorPgDpiaAuthoritative2026" \
      --data-urlencode "kind=operational_action" \
      --data-urlencode "limit=10" \
      "$base_url/v1/search"
  )"; then
    sleep 1
    continue
  fi
  if ! DPIA_SEARCH_BODY="$dpia_search_body" python3 - <<'PY'
import json
import os

response = json.loads(os.environ["DPIA_SEARCH_BODY"])
hits = response.get("page", {}).get("hits", [])
if not any(
    hit.get("kind") == "operational_action"
    and "ProjectorPgDpiaAuthoritative2026" in (
        f'{hit.get("title", "")} {hit.get("snippet", "")}'
    )
    for hit in hits
):
    raise SystemExit(1)
PY
  then
    sleep 1
    continue
  fi
  if ! backup_alert_search_body="$(
    curl -fsS --get \
      -H "X-Chancela-Session: $session_token" \
      --data-urlencode "q=Local backup recovery drill freshness" \
      --data-urlencode "kind=operational_action" \
      --data-urlencode "limit=10" \
      "$base_url/v1/search"
  )"; then
    sleep 1
    continue
  fi
  if ! BACKUP_ALERT_SEARCH_BODY="$backup_alert_search_body" python3 - <<'PY'
import json
import os

response = json.loads(os.environ["BACKUP_ALERT_SEARCH_BODY"])
hits = response.get("page", {}).get("hits", [])
if not any(
    hit.get("kind") == "operational_action"
    and "Local backup recovery drill freshness" in (
        f'{hit.get("title", "")} {hit.get("snippet", "")}'
    )
    for hit in hits
):
    raise SystemExit(1)
PY
  then
    sleep 1
    continue
  fi
  if ! status_body="$(
    curl -fsS \
      -H "X-Chancela-Session: $session_token" \
      "$base_url/v1/search/status"
  )"; then
    sleep 1
    continue
  fi
  if ! SEARCH_STATUS_BODY="$status_body" python3 - <<'PY'
import datetime as dt
import json
import os
import re

status = json.loads(os.environ["SEARCH_STATUS_BODY"])
if status.get("stale") is not False:
    raise SystemExit(1)
if status.get("projector_heartbeat_fresh") is not True:
    raise SystemExit(1)
if not status.get("projector_lease_owner"):
    raise SystemExit(1)
if status.get("projector_phase") != "idle":
    raise SystemExit(1)
source_revision = status.get("projector_source_revision")
published_revision = status.get("projector_published_source_revision")
if not isinstance(source_revision, int) or source_revision != published_revision:
    raise SystemExit(1)
completed = status.get("last_completed_at")
if not isinstance(completed, str):
    raise SystemExit(1)
rfc3339 = re.fullmatch(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
    completed,
)
if rfc3339 is None:
    raise SystemExit(1)
fraction = rfc3339.group(2)
normalized = (
    rfc3339.group(1)
    + (f".{fraction[:6].ljust(6, '0')}" if fraction else "")
    + ("+00:00" if rfc3339.group(3) == "Z" else rfc3339.group(3))
)
completed_date = (
    dt.datetime.fromisoformat(normalized).astimezone(dt.timezone.utc).date()
)
if completed_date != dt.datetime.now(dt.timezone.utc).date():
    raise SystemExit(1)
PY
  then
    sleep 1
    continue
  fi

  # Rolling deployment / accidental-overlap regression. Schema-v2 heartbeats
  # are scoped by canonical durable lease UUID. Select exactly the current
  # lease's file; a standby must create no heartbeat file at all and must not
  # change the active lease, selected heartbeat, or API freshness.
  expected_owner="$(
    SEARCH_STATUS_BODY="$status_body" python3 -c \
      'import json, os, sys; owner=json.loads(os.environ["SEARCH_STATUS_BODY"]).get("projector_lease_owner"); assert owner; sys.stdout.write(owner)'
  )"
  projector_id="$("${COMPOSE[@]}" ps -q search-projector-postgres)"
  runtime_volume="$(
    docker inspect --format \
      '{{range .Mounts}}{{if eq .Destination "/run/chancela-search"}}{{.Name}}{{end}}{{end}}' \
      "$projector_id"
  )"
  if [ -z "$runtime_volume" ]; then
    echo "primary PostgreSQL projector has no named heartbeat runtime mount" >&2
    exit 1
  fi
  lease_row="$(read_durable_projector_lease)"
  active_lease_id="${lease_row%%|*}"
  durable_owner="${lease_row#*|}"
  if [ -z "$active_lease_id" ] || [ "$durable_owner" = "$lease_row" ]; then
    printf '%s\n' "$lease_row" >&2
    echo "restricted role did not return one durable projector lease" >&2
    exit 1
  fi
  ACTIVE_LEASE_ID="$active_lease_id" python3 - <<'PY'
import os
import uuid

raw = os.environ["ACTIVE_LEASE_ID"]
parsed = uuid.UUID(raw)
if str(parsed) != raw:
    raise SystemExit(f"durable projector lease_id is not a canonical UUID: {raw!r}")
PY
  if [ "$durable_owner" != "$expected_owner" ]; then
    printf 'API owner=%s\ndurable owner=%s\n' "$expected_owner" "$durable_owner" >&2
    echo "API and restricted-role durable lease owners disagree" >&2
    exit 1
  fi
  heartbeat_files_before="$(list_runtime_heartbeat_files "$runtime_volume")"
  heartbeat_before="$(read_runtime_heartbeat "$runtime_volume" "$active_lease_id")"
  assert_selected_projector_heartbeat \
    "before standby overlap" \
    "$active_lease_id" \
    "$expected_owner" \
    "$status_body" \
    "$heartbeat_before"

  standby_name="${PROJECT}-search-projector-standby"
  "${COMPOSE[@]}" run -d --no-deps \
    --name "$standby_name" \
    -e CHANCELA_SEARCH_INSTANCE_ID=overlap-smoke \
    -e CHANCELA_SEARCH_HEARTBEAT_SECONDS=2 \
    -e CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS=6 \
    search-projector-postgres >/dev/null
  standby_id="$(docker inspect --format '{{.Id}}' "$standby_name")"

  for probe in {1..8}; do
    sleep 1
    if [ "$(docker inspect --format '{{.State.Running}}' "$standby_id")" != "true" ]; then
      docker logs "$standby_id" >&2 || true
      echo "overlap projector exited before completing standby probe $probe" >&2
      exit 1
    fi
    overlap_status="$(
      curl -fsS \
        -H "X-Chancela-Session: $session_token" \
        "$base_url/v1/search/status"
    )"
    overlap_heartbeat_files="$(list_runtime_heartbeat_files "$runtime_volume")"
    if [ "$overlap_heartbeat_files" != "$heartbeat_files_before" ]; then
      printf 'before:\n%s\nduring:\n%s\n' \
        "$heartbeat_files_before" "$overlap_heartbeat_files" >&2
      echo "standby overlap changed the lease-scoped heartbeat file set" >&2
      exit 1
    fi
    overlap_heartbeat="$(read_runtime_heartbeat "$runtime_volume" "$active_lease_id")"
    assert_selected_projector_heartbeat \
      "standby overlap probe $probe" \
      "$active_lease_id" \
      "$expected_owner" \
      "$overlap_status" \
      "$overlap_heartbeat"
  done

  docker stop --time 20 "$standby_id" >/dev/null
  standby_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$standby_id")"
  standby_logs="$(docker logs "$standby_id" 2>&1)"
  if [ "$standby_exit_code" != "0" ]; then
    printf '%s\n' "$standby_logs" >&2
    echo "overlap projector stopped with exit code $standby_exit_code, expected 0" >&2
    exit 1
  fi
  if grep -Eqi \
    'Cannot start a runtime from within a runtime|panicked at|panic in a destructor|non-unwinding panic|aborted' \
    <<<"$standby_logs"; then
    printf '%s\n' "$standby_logs" >&2
    echo "overlap projector logs contain a runtime/destructor panic" >&2
    exit 1
  fi
  docker rm "$standby_id" >/dev/null
  standby_id=""

  for probe in {1..3}; do
    after_overlap_status="$(
      curl -fsS \
        -H "X-Chancela-Session: $session_token" \
        "$base_url/v1/search/status"
    )"
    after_overlap_heartbeat_files="$(list_runtime_heartbeat_files "$runtime_volume")"
    if [ "$after_overlap_heartbeat_files" != "$heartbeat_files_before" ]; then
      printf 'before:\n%s\nafter:\n%s\n' \
        "$heartbeat_files_before" "$after_overlap_heartbeat_files" >&2
      echo "standby shutdown changed the lease-scoped heartbeat file set" >&2
      exit 1
    fi
    after_overlap_heartbeat="$(read_runtime_heartbeat "$runtime_volume" "$active_lease_id")"
    assert_selected_projector_heartbeat \
      "after standby shutdown probe $probe" \
      "$active_lease_id" \
      "$expected_owner" \
      "$after_overlap_status" \
      "$after_overlap_heartbeat"
    sleep 1
  done
  "${COMPOSE[@]}" exec -T search-projector-postgres \
    /usr/local/bin/chancela-search-projector \
    healthcheck --runtime-dir /run/chancela-search
  lease_row_after="$(read_durable_projector_lease)"
  if [ "$lease_row_after" != "$lease_row" ]; then
    printf 'before=%s\nafter=%s\n' "$lease_row" "$lease_row_after" >&2
    echo "durable projector lease changed across standby overlap" >&2
    exit 1
  fi
  echo "PostgreSQL projector rolling-overlap lease-scoped heartbeat regression passed."

  projector_logs="$("${COMPOSE[@]}" logs --no-color search-projector-postgres)"
  if grep -Eqi \
    'Cannot start a runtime from within a runtime|panicked at|panic in a destructor|non-unwinding panic|aborted' \
    <<<"$projector_logs"; then
    printf '%s\n' "$projector_logs" >&2
    echo "primary PostgreSQL projector logs contain a runtime/destructor panic" >&2
    exit 1
  fi
  printf '%s\n' "$search_body"
  printf '%s\n' "$dpia_search_body"
  printf '%s\n' "$backup_alert_search_body"
  printf '%s\n' "$status_body"
  echo "restricted PostgreSQL projector DB-authoritative singleton, publication/query/freshness, and clean-log smoke passed."

  projector_id="$("${COMPOSE[@]}" ps -q search-projector-postgres)"
  if [ -z "$projector_id" ]; then
    echo "primary PostgreSQL projector container disappeared before graceful-stop probe" >&2
    exit 1
  fi
  "${COMPOSE[@]}" stop --timeout 20 search-projector-postgres
  projector_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$projector_id")"
  if [ "$projector_exit_code" != "0" ]; then
    "${COMPOSE[@]}" logs --no-color search-projector-postgres >&2 || true
    echo "primary PostgreSQL projector stopped with exit code $projector_exit_code, expected 0" >&2
    exit 1
  fi
  projector_logs="$(docker logs "$projector_id" 2>&1)"
  if grep -Eqi \
    'Cannot start a runtime from within a runtime|panicked at|panic in a destructor|non-unwinding panic|aborted' \
    <<<"$projector_logs"; then
    printf '%s\n' "$projector_logs" >&2
    echo "gracefully stopped PostgreSQL projector logs contain a runtime/destructor panic" >&2
    exit 1
  fi
  echo "restricted PostgreSQL projector graceful-stop smoke passed."
  exit 0
done

printf '%s\n' "last entity search response:" "$search_body" >&2
printf '%s\n' "last search status response:" "$status_body" >&2
"${COMPOSE[@]}" logs --no-color --tail 200 search-projector-postgres >&2 || true
echo "restricted PostgreSQL projector did not publish/query the seeded entity" >&2
exit 1
