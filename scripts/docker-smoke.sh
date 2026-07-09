#!/usr/bin/env bash
set -euo pipefail

image="${1:-chancela-server:local}"
data_dir="$(mktemp -d)"
container=""

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ -n "$container" ]; then
    docker logs "$container" || true
  fi
  if [ -n "$container" ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  rm -rf "$data_dir"
}
trap cleanup EXIT

chmod 777 "$data_dir"

container="$(docker run -d \
  -p 127.0.0.1::8080 \
  -e CHANCELA_DATA_DIR=/data \
  -v "$data_dir:/data" \
  "$image")"

mapped="$(docker port "$container" 8080/tcp)"
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
