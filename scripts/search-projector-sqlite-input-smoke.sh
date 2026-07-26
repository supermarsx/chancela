#!/usr/bin/env bash
# Live SQLite proof for projector input visibility and fail-closed lifecycle.
set -euo pipefail

PROJECT="${CHANCELA_PROJECTOR_SQLITE_SMOKE_PROJECT:-chancela-projector-sqlite-input-smoke}"
HOST_PORT="${CHANCELA_PROJECTOR_SQLITE_SMOKE_PORT:-0}"
export CHANCELA_HOST_PORT="$HOST_PORT"
export CHANCELA_SERVER_IMAGE="${CHANCELA_SERVER_IMAGE:-chancela-server:ci}"
export CHANCELA_SEARCH_PROJECTOR_IMAGE="${CHANCELA_SEARCH_PROJECTOR_IMAGE:-chancela-search-projector:ci}"
# Keep stale-heartbeat probes bounded without permitting healthcheck flapping.
export CHANCELA_SEARCH_HEARTBEAT_SECONDS="${CHANCELA_SEARCH_HEARTBEAT_SECONDS:-2}"
export CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS="${CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS:-6}"

COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  -f docker/docker-compose.yml
  --profile single-node
)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${COMPOSE[@]}" ps --all || true
    "${COMPOSE[@]}" logs --no-color || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

reject_runtime_panic() {
  label="$1"
  output="$2"
  if grep -Eqi \
    'Cannot start a runtime from within a runtime|panicked at|panic in a destructor|non-unwinding panic|aborted' \
    <<<"$output"; then
    printf '%s\n' "$output" >&2
    echo "$label exposed a runtime/destructor panic" >&2
    exit 1
  fi
}

expect_once_failure() {
  label="$1"
  expected_pattern="$2"
  set +e
  output="$("${COMPOSE[@]}" run --rm --no-deps search-projector-sqlite once 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 1 ]; then
    printf '%s\n' "$output" >&2
    echo "$label exited $status, expected controlled status 1" >&2
    exit 1
  fi
  reject_runtime_panic "$label" "$output"
  if ! grep -Eqi "$expected_pattern" <<<"$output"; then
    printf '%s\n' "$output" >&2
    echo "$label did not report its bounded input error" >&2
    exit 1
  fi
  echo "$label failed closed with controlled status 1."
}

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --no-build

mapped="$("${COMPOSE[@]}" port server-sqlite 8080)"
base_url="http://${mapped}"
for _ in {1..120}; do
  if curl -fsS "$base_url/health" >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "$base_url/health" >/dev/null

password="Sqlite-Projector-Input-Smoke-2026!"
owner="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "{\"username\":\"projector.sqlite.smoke\",\"display_name\":\"Projector SQLite Smoke\",\"password\":\"$password\"}" \
    "$base_url/v1/users"
)"
user_id="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["id"])' <<<"$owner"
)"
session="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    --data "{\"username\":\"projector.sqlite.smoke\",\"password\":\"$password\"}" \
    "$base_url/v1/session"
)"
session_token="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["token"])' <<<"$session"
)"
entity="$(
  curl -fsS \
    -H "Content-Type: application/json" \
    -H "X-Chancela-Session: $session_token" \
    --data '{"name":"ProjectorSqliteInputUnique2026, Lda","nipc":"503004642","seat":"Braga","kind":"SociedadePorQuotas"}' \
    "$base_url/v1/entities"
)"
entity_id="$(
  python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["id"])' <<<"$entity"
)"

for _ in {1..120}; do
  if "${COMPOSE[@]}" exec -T search-projector-sqlite \
    /usr/local/bin/chancela-search-projector \
    healthcheck --runtime-dir /var/lib/chancela/search-projector \
    >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${COMPOSE[@]}" exec -T search-projector-sqlite \
  /usr/local/bin/chancela-search-projector \
  healthcheck --runtime-dir /var/lib/chancela/search-projector

for _ in {1..120}; do
  if search_body="$(
    curl -fsS \
      -H "X-Chancela-Session: $session_token" \
      "$base_url/v1/search?q=ProjectorSqliteInputUnique2026&kind=entity&limit=10"
  )" && SEARCH_BODY="$search_body" ENTITY_ID="$entity_id" python3 - <<'PY'
import json
import os

response = json.loads(os.environ["SEARCH_BODY"])
hits = response.get("page", {}).get("hits", [])
if not any(hit.get("entity_id") == os.environ["ENTITY_ID"] for hit in hits):
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 1
done
SEARCH_BODY="$search_body" ENTITY_ID="$entity_id" python3 - <<'PY'
import json
import os

response = json.loads(os.environ["SEARCH_BODY"])
hits = response.get("page", {}).get("hits", [])
if not any(hit.get("entity_id") == os.environ["ENTITY_ID"] for hit in hits):
    raise SystemExit("SQLite projector did not publish the seeded entity")
PY

server_id="$("${COMPOSE[@]}" ps -q server-sqlite)"
data_volume="$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/chancela"}}{{.Name}}{{end}}{{end}}' \
    "$server_id"
)"
if [ -z "$data_volume" ]; then
  echo "SQLite API has no named /var/lib/chancela data mount" >&2
  exit 1
fi

volume_write() {
  docker run --rm \
    --network none \
    --user 65532:65532 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "$data_volume:/data" \
    --entrypoint /usr/bin/busybox \
    "$CHANCELA_SERVER_IMAGE" \
    sh -ec "$1"
}

"${COMPOSE[@]}" stop --timeout 20 search-projector-sqlite
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
    raise SystemExit(f"stopped SQLite projector was not reported stale: {status!r}")
PY

stale_health_output=""
stale_health_status=0
for _ in {1..30}; do
  set +e
  stale_health_output="$(
    "${COMPOSE[@]}" run --rm --no-deps search-projector-sqlite \
      healthcheck --runtime-dir /var/lib/chancela/search-projector \
      --max-age-seconds "$CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS" 2>&1
  )"
  stale_health_status=$?
  set -e
  if [ "$stale_health_status" -ne 0 ]; then
    break
  fi
  sleep 1
done
if [ "$stale_health_status" -eq 0 ]; then
  printf '%s\n' "$stale_health_output" >&2
  echo "stopped SQLite projector heartbeat unexpectedly remained healthy" >&2
  exit 1
fi
reject_runtime_panic "stale SQLite heartbeat probe" "$stale_health_output"
echo "stopped SQLite projector reports stale through API and heartbeat healthcheck."

volume_write '
  /usr/bin/busybox test ! -e /data/settings.pending-audit.json
  umask 077
  echo "{}" > /data/settings.pending-audit.json
'
expect_once_failure \
  "pending SQLite settings-journal probe" \
  'settings audit journal|pending-audit'
volume_write '/usr/bin/busybox rm -f /data/settings.pending-audit.json'

volume_write '
  /usr/bin/busybox test ! -e /data/settings.json.smoke-backup
  if /usr/bin/busybox test -e /data/settings.json; then
    /usr/bin/busybox mv /data/settings.json /data/settings.json.smoke-backup
  fi
  umask 077
  echo "{}" > /data/settings.json
  /usr/bin/busybox chmod 000 /data/settings.json
'
expect_once_failure \
  "unreadable SQLite settings probe" \
  'settings\.json|permission denied|Permission denied'
volume_write '
  /usr/bin/busybox rm -f /data/settings.json
  if /usr/bin/busybox test -e /data/settings.json.smoke-backup; then
    /usr/bin/busybox mv /data/settings.json.smoke-backup /data/settings.json
  fi
'

"${COMPOSE[@]}" start search-projector-sqlite
for _ in {1..120}; do
  if "${COMPOSE[@]}" exec -T search-projector-sqlite \
    /usr/local/bin/chancela-search-projector \
    healthcheck --runtime-dir /var/lib/chancela/search-projector \
    >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${COMPOSE[@]}" exec -T search-projector-sqlite \
  /usr/local/bin/chancela-search-projector \
  healthcheck --runtime-dir /var/lib/chancela/search-projector

for _ in {1..120}; do
  if final_status="$(
    curl -fsS \
      -H "X-Chancela-Session: $session_token" \
      "$base_url/v1/search/status"
  )" && SEARCH_STATUS_BODY="$final_status" python3 - <<'PY'
import json
import os

status = json.loads(os.environ["SEARCH_STATUS_BODY"])
if status.get("stale") is not False:
    raise SystemExit(1)
if status.get("projector_heartbeat_fresh") is not True:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 1
done
SEARCH_STATUS_BODY="$final_status" python3 - <<'PY'
import json
import os

status = json.loads(os.environ["SEARCH_STATUS_BODY"])
if status.get("stale") is not False or status.get("projector_heartbeat_fresh") is not True:
    raise SystemExit(f"recovered SQLite projector did not become fresh: {status!r}")
PY

projector_logs="$("${COMPOSE[@]}" logs --no-color search-projector-sqlite)"
reject_runtime_panic "recovered SQLite projector" "$projector_logs"
echo "SQLite projector journal/unreadable-input recovery and clean-log smoke passed."
