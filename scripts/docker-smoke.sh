#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/docker-smoke.sh [--compose-profile | --config-check] [image]

Runs the Docker health/persistence smoke against image.
With --compose-profile, starts the single-node Compose profile and also
inspects the Compose-created server-sqlite container for the expected runtime
hardening posture.
With --config-check, only validates that every Compose profile
(single-node, worker, postgres) renders a valid config via
`docker compose config --quiet`, and that each backend profile combined with
the additive `worker` profile still selects exactly ONE app service — no image
is built or started. This is the lightweight gate for the postgres profile and
does not prove live Postgres runtime behavior.
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
compose_file="$repo_root/docker/docker-compose.yml"

if [ "${1:-}" = "--config-check" ]; then
  status=0
  for profile in single-node worker postgres; do
    if docker compose -f "$compose_file" --profile "$profile" config --quiet; then
      echo "compose config OK: --profile $profile"
    else
      echo "compose config FAILED: --profile $profile" >&2
      status=1
    fi
  done

  # The backend axis (single-node | postgres) and the sidecar axis (worker) must
  # compose. Two app services in one rendering means two containers publishing
  # ${CHANCELA_HOST_PORT:-8080}, and the second one dies on `up`.
  for backend in single-node postgres; do
    services="$(docker compose -f "$compose_file" \
      --profile "$backend" --profile worker config --services | sort)"
    app_count="$(printf '%s\n' "$services" | grep -c '^server-' || true)"
    if [ "$app_count" -eq 1 ] && printf '%s\n' "$services" | grep -qx worker; then
      echo "compose config OK: --profile $backend --profile worker (1 app service + worker)"
    else
      echo "compose config FAILED: --profile $backend --profile worker" >&2
      echo "  expected exactly 1 server-* service plus worker, got: $(echo $services)" >&2
      status=1
    fi
  done
  exit "$status"
fi

image="${1:-chancela-server:local}"
compose_profile=false
if [ "${1:-}" = "--compose-profile" ]; then
  compose_profile=true
  image="${2:-chancela-server:local}"
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

data_dir="$(mktemp -d)"
container=""
project="chancela-smoke-$(date +%s)-$$"

assert_compose_hardening() {
  local service="${1:?service required}"
  local cid
  cid="$(docker compose -f "$compose_file" --profile single-node -p "$project" ps -q "$service")"
  if [ -z "$cid" ]; then
    echo "compose service $service did not produce a container" >&2
    exit 1
  fi

  DOCKER_INSPECT_JSON="$(docker inspect "$cid")" \
  CHANCELA_SMOKE_SERVICE="$service" \
  python3 - <<'PY'
import json
import os

service = os.environ["CHANCELA_SMOKE_SERVICE"]
inspect_data = json.loads(os.environ["DOCKER_INSPECT_JSON"])
container = inspect_data[0]
host = container.get("HostConfig") or {}
config = container.get("Config") or {}
mounts = container.get("Mounts") or []

failures = []
if host.get("ReadonlyRootfs") is not True:
    failures.append("read-only rootfs")

if "ALL" not in (host.get("CapDrop") or []):
    failures.append("cap_drop ALL")

if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
    failures.append("no-new-privileges")

user = str(config.get("User") or "").strip()
user_parts = user.split(":") if user else []
if not user_parts or user_parts[0] in {"0", "root"}:
    failures.append("non-root user")
elif len(user_parts) > 1 and user_parts[1] in {"0", "root"}:
    failures.append("non-root group")

tmpfs = host.get("Tmpfs") or {}
if isinstance(tmpfs, dict):
    has_tmpfs = "/tmp" in tmpfs
else:
    has_tmpfs = any(str(entry).split(":", 1)[0] == "/tmp" for entry in tmpfs)
if not has_tmpfs:
    failures.append("/tmp tmpfs")

has_persistent_data = any(
    mount.get("Destination") == "/var/lib/chancela"
    and mount.get("Type") in {"volume", "bind"}
    for mount in mounts
)
if not has_persistent_data:
    failures.append("/var/lib/chancela persistent data mount")

if failures:
    raise SystemExit(
        f"compose hardening smoke failed for {service}: missing {failures}"
    )

print(
    "compose hardening smoke passed for "
    f"{service}: read-only rootfs, cap_drop ALL, no-new-privileges, "
    f"user {user}, /tmp tmpfs, /var/lib/chancela persistent mount"
)
PY
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$compose_profile" = true ]; then
    docker compose -f "$compose_file" --profile single-node -p "$project" logs server-sqlite || true
  elif [ "$status" -ne 0 ] && [ -n "$container" ]; then
    docker logs "$container" || true
  fi
  if [ "$compose_profile" = true ]; then
    CHANCELA_SERVER_IMAGE="$image" CHANCELA_HOST_PORT=0 \
      docker compose -f "$compose_file" --profile single-node -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  if [ "$compose_profile" != true ] && [ -n "$container" ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  rm -rf "$data_dir"
}
trap cleanup EXIT

chmod 777 "$data_dir"

if [ "$compose_profile" = true ]; then
  CHANCELA_SERVER_IMAGE="$image" CHANCELA_HOST_PORT=0 \
    docker compose -f "$compose_file" --profile single-node -p "$project" up -d --no-build server-sqlite
  container="$(docker compose -f "$compose_file" --profile single-node -p "$project" ps -q server-sqlite)"
  assert_compose_hardening server-sqlite
  mapped="$(docker compose -f "$compose_file" --profile single-node -p "$project" port server-sqlite 8080)"
else
  container="$(docker run -d \
    -p 127.0.0.1::8080 \
    -e CHANCELA_DATA_DIR=/data \
    -v "$data_dir:/data" \
    "$image")"

  mapped="$(docker port "$container" 8080/tcp)"
fi
health_url="http://${mapped}/health"
body=""

for _ in $(seq 1 60); do
  if body="$(curl -fsS "$health_url")"; then
    break
  fi
  sleep 1
done

if [ -z "$body" ]; then
  echo "server did not become healthy at $health_url" >&2
  exit 1
fi

printf '%s\n' "$body"
HEALTH_BODY="$body" python3 - <<'PY'
import json
import os

health = json.loads(os.environ["HEALTH_BODY"])
checks = {
    "status": health.get("status") == "ok",
    "persistent": health.get("persistent") is True,
    "ledger_verified": health.get("ledger_verified") is True,
    "store_schema_version": isinstance(health.get("store_schema_version"), int),
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit(f"health smoke failed {failed}: {health!r}")
PY
