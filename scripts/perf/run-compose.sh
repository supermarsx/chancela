#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROFILE="${1:-pr-smoke}"
OUTPUT="${2:-$ROOT/.perf-work/$PROFILE}"
SLO="${3:-}"
CRYPTO_CONFIG="${4:-}"
PROFILE_FILE="$ROOT/scripts/perf/profiles/$PROFILE.json"
DATASET_DIR="$OUTPUT/dataset"
REPORT_DIR="$OUTPUT/report"
LOG_DIR="$OUTPUT/logs"
mkdir -p "$DATASET_DIR" "$REPORT_DIR" "$LOG_DIR"

if [ ! -f "$PROFILE_FILE" ]; then
  echo "unknown performance profile: $PROFILE" >&2
  exit 2
fi

COMPOSE=(
  docker compose
  -f docker/docker-compose.yml
  -f docker/docker-compose.cluster.yml
  -f scripts/perf/docker-compose.perf.yml
  --profile postgres
  --profile cluster
  --profile performance
)

cleanup() {
  rc=$?
  "${COMPOSE[@]}" logs --no-color > "$LOG_DIR/compose.log" 2>&1 || true
  if [ "${CHANCELA_PERF_KEEP:-0}" != "1" ]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

python scripts/perf/harness.py generate \
  --profile "$PROFILE_FILE" \
  --output-dir "$DATASET_DIR" > "$LOG_DIR/generate.json"
python scripts/perf/harness.py validate \
  --dataset-dir "$DATASET_DIR" > "$LOG_DIR/validate.json"

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build --scale chancela-cluster="${CHANCELA_CLUSTER_REPLICAS:-3}" \
  postgres redis chancela-cluster perf-gateway

ready=0
for _ in $(seq 1 120); do
  if curl --fail --silent --show-error http://127.0.0.1:"${CHANCELA_PERF_HOST_PORT:-18081}"/health \
      > "$LOG_DIR/gateway-health.json"; then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "performance topology did not become ready" >&2
  exit 1
fi

args=(
  python scripts/perf/harness.py run
  --profile "$PROFILE_FILE"
  --dataset-dir "$DATASET_DIR"
  --report-dir "$REPORT_DIR"
  --base-url "http://127.0.0.1:${CHANCELA_PERF_HOST_PORT:-18081}"
)
if [ -n "$SLO" ]; then
  args+=(--slo "$SLO")
fi
if [ -n "$CRYPTO_CONFIG" ]; then
  args+=(--cryptographic-config "$CRYPTO_CONFIG")
fi
"${args[@]}" 2>&1 | tee "$LOG_DIR/harness.log"
