#!/usr/bin/env bash
# Focused live proof for the hardened PostgreSQL Compose wiring. The exhaustive
# projector/ACL behavior remains in search-projector-postgres-smoke.sh; this
# lane proves the hardened-only secret, network, runtime, and restart contracts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="${CHANCELA_HARDENED_SMOKE_PROJECT:-chancela-hardened-pg-smoke}"
HOST_PORT="${CHANCELA_HARDENED_SMOKE_PORT:-18083}"
SERVER_IMAGE="${CHANCELA_POSTGRES_IMAGE:-chancela-server:ci}"
PROJECTOR_IMAGE="${CHANCELA_SEARCH_PROJECTOR_IMAGE:-chancela-search-projector:ci}"
SECRET_PROBE_IMAGE="${CHANCELA_SECRET_PROBE_IMAGE:-alpine/openssl:3.5.7@sha256:3da6a24cdaa2f2ac8ef4defb322249fae6159983104653a9e5312f5b75dac7af}"
TEMP_ROOT="$(mktemp -d)"
SECRETS_DIR="$TEMP_ROOT/secrets"
OVERRIDE_FILE="$TEMP_ROOT/compose.override.yml"
DOCKER_SECRETS_DIR="$SECRETS_DIR"
DOCKER_OVERRIDE_FILE="$OVERRIDE_FILE"

if command -v cygpath >/dev/null 2>&1; then
  DOCKER_SECRETS_DIR="$(cygpath -m "$SECRETS_DIR")"
  DOCKER_OVERRIDE_FILE="$(cygpath -m "$OVERRIDE_FILE")"
  # The Docker Desktop daemon needs container paths verbatim. MSYS otherwise
  # rewrites `/usr/local/bin/...` in `compose exec` into a Windows host path.
  export MSYS_NO_PATHCONV=1
fi

mkdir -p "$SECRETS_DIR"
api_password="$(openssl rand -hex 24)"
projector_password="$(openssl rand -hex 24)"
credential_key="$(openssl rand -hex 32)"
printf '%s' "$api_password" >"$SECRETS_DIR/postgres_password"
printf 'postgres://chancela:%s@postgres:5432/chancela?sslmode=verify-full' \
  "$api_password" >"$SECRETS_DIR/database_url"
printf '%s' "$credential_key" >"$SECRETS_DIR/credential_key"
printf '%s' "$projector_password" >"$SECRETS_DIR/search_database_password"
printf 'postgres://chancela_search_projector:%s@postgres:5432/chancela?sslmode=verify-full' \
  "$projector_password" >"$SECRETS_DIR/search_database_url"
chmod 0600 "$SECRETS_DIR"/*

cat >"$OVERRIDE_FILE" <<EOF
services:
  server-postgres:
    image: ${SERVER_IMAGE}
    pull_policy: never
  search-projector-postgres:
    image: ${PROJECTOR_IMAGE}
    pull_policy: never
secrets:
  postgres_password:
    file: ${DOCKER_SECRETS_DIR}/postgres_password
  database_url:
    file: ${DOCKER_SECRETS_DIR}/database_url
  credential_key:
    file: ${DOCKER_SECRETS_DIR}/credential_key
  search_database_password:
    file: ${DOCKER_SECRETS_DIR}/search_database_password
  search_database_url:
    file: ${DOCKER_SECRETS_DIR}/search_database_url
EOF

export CHANCELA_HOST_PORT="$HOST_PORT"
export CHANCELA_POSTGRES_IMAGE="$SERVER_IMAGE"
export CHANCELA_SEARCH_PROJECTOR_IMAGE="$PROJECTOR_IMAGE"
export CHANCELA_PROJECTOR_DEDICATED_DATABASE=true
export CHANCELA_HARDENED_SECRETS_DIR="$DOCKER_SECRETS_DIR"

COMPOSE=(
  docker compose
  --project-name "$PROJECT"
  -f docker-compose.hardened.yml
  -f "$DOCKER_OVERRIDE_FILE"
  --profile postgres
)

if [ "${1:-}" = "--config-check" ]; then
  "${COMPOSE[@]}" config --quiet
  rm -rf "$TEMP_ROOT"
  echo "hardened PostgreSQL smoke Compose override rendered successfully."
  exit 0
fi

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    "${COMPOSE[@]}" ps --all || true
    "${COMPOSE[@]}" logs --no-color || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TEMP_ROOT"
  exit "$status"
}
trap cleanup EXIT

wait_for_api() {
  for _ in {1..120}; do
    if curl -fsS "http://127.0.0.1:${HOST_PORT}/health" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "hardened PostgreSQL API did not become healthy" >&2
  return 1
}

wait_for_projector() {
  for _ in {1..120}; do
    if "${COMPOSE[@]}" exec -T search-projector-postgres \
      /usr/local/bin/chancela-search-projector \
      healthcheck --runtime-dir /run/chancela-search \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "hardened PostgreSQL projector did not become healthy" >&2
  return 1
}

assert_completed() {
  service="$1"
  container_id="$("${COMPOSE[@]}" ps -aq "$service")"
  test -n "$container_id"
  test "$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" = "0"
}

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up -d --no-build

wait_for_api
wait_for_projector
echo "hardened PostgreSQL API and projector are healthy."
assert_completed file-secrets-permissions-init
assert_completed secrets-preflight
assert_completed search-runtime-init
assert_completed search-projector-role-init
echo "secret permission handoff and one-shot initializers completed."
"${COMPOSE[@]}" run --rm --no-deps search-projector-role-init verify
echo "restricted projector role verification completed."

case "$(uname -s)" in
  Linux)
    host_uid="$(id -u)"
    for name in \
      postgres_password \
      database_url \
      credential_key \
      search_database_password \
      search_database_url
    do
      test "$(stat -c '%u:%g:%a' "$SECRETS_DIR/$name")" = "$host_uid:65532:640"
    done
    echo "file-secret host owner/group/mode handoff verified."
    ;;
  *)
    echo "POSIX host inode mapping check skipped on $(uname -s)."
    ;;
esac

# An unrelated identity with no capabilities receives no secret bytes even if
# it is explicitly handed this otherwise-private test directory. This runs on
# Docker Desktop too; only the native-host inode assertion above is Linux-only.
docker run --rm \
  --network none \
  --read-only \
  --user 65534:65534 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 16 \
  --mount "type=bind,src=${DOCKER_SECRETS_DIR},dst=/smoke-secrets,readonly" \
  --entrypoint /bin/sh \
  "$SECRET_PROBE_IMAGE" \
  -eu -c '
    for name in \
      postgres_password \
      database_url \
      credential_key \
      search_database_password \
      search_database_url
    do
      if head -c 1 "/smoke-secrets/$name" >/dev/null 2>&1; then
        echo "unrelated uid unexpectedly read $name" >&2
        exit 1
      fi
    done
  '
echo "file-secret consumer access and unrelated-identity denial verified."

server_id="$("${COMPOSE[@]}" ps -q server-postgres)"
projector_id="$("${COMPOSE[@]}" ps -q search-projector-postgres)"
postgres_id="$("${COMPOSE[@]}" ps -q postgres)"
SERVER_INSPECT="$(docker inspect "$server_id")" \
PROJECTOR_INSPECT="$(docker inspect "$projector_id")" \
POSTGRES_INSPECT="$(docker inspect "$postgres_id")" \
PROJECT_NAME="$PROJECT" \
  python3 - <<'PY'
import json
import os

server = json.loads(os.environ["SERVER_INSPECT"])[0]
projector = json.loads(os.environ["PROJECTOR_INSPECT"])[0]
postgres = json.loads(os.environ["POSTGRES_INSPECT"])[0]
project = os.environ["PROJECT_NAME"].replace("-", "")

def fail(message):
    raise SystemExit(message)

for label, container in (("server", server), ("projector", projector)):
    host = container["HostConfig"]
    if host.get("ReadonlyRootfs") is not True:
        fail(f"{label} root filesystem is not read-only")
    if "ALL" not in (host.get("CapDrop") or []):
        fail(f"{label} does not drop all capabilities")
    if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
        fail(f"{label} lacks no-new-privileges")

server_networks = set(server["NetworkSettings"]["Networks"])
projector_networks = set(projector["NetworkSettings"]["Networks"])
postgres_networks = set(postgres["NetworkSettings"]["Networks"])
if len(server_networks) != 2 or not any(name.endswith("_edge") for name in server_networks):
    fail(f"server networks are not edge+backend: {sorted(server_networks)}")
if len(projector_networks) != 1 or not next(iter(projector_networks)).endswith("_backend"):
    fail(f"projector is not backend-only: {sorted(projector_networks)}")
if len(postgres_networks) != 1 or not next(iter(postgres_networks)).endswith("_backend"):
    fail(f"postgres is not backend-only: {sorted(postgres_networks)}")

for label, container, expected in (
    ("server", server, {"database_url", "credential_key"}),
    ("projector", projector, {"search_database_url"}),
):
    mounted = {
        mount["Destination"].split("/")[-1]
        for mount in container.get("Mounts", [])
        if mount["Destination"].startswith("/run/secrets/")
        and mount.get("RW") is False
    }
    if mounted != expected:
        fail(f"{label} read-only secret mounts differ: {sorted(mounted)}")
PY
echo "runtime hardening, network isolation, and secret exposure verified."

"${COMPOSE[@]}" stop --timeout 20 search-projector-postgres server-postgres
"${COMPOSE[@]}" start server-postgres
wait_for_api
"${COMPOSE[@]}" start search-projector-postgres
wait_for_projector

echo "hardened PostgreSQL secret/network/runtime/restart smoke passed."
