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
REPLICAS="${CHANCELA_CLUSTER_REPLICAS:-3}"
PERF_PROJECT="${CHANCELA_PERF_PROJECT_NAME:-chancela-perf}"
TOPOLOGY_INITIAL="$REPORT_DIR/topology-initial.json"
TOPOLOGY_FINAL="$REPORT_DIR/topology-final.json"
DURATION_BUDGET="$REPORT_DIR/duration-budget.json"
WORKFLOW_TIMEOUT_SECONDS="${CHANCELA_PERF_JOB_TIMEOUT_SECONDS:-21600}"
SEARCH_READY_TIMEOUT_SECONDS="${CHANCELA_PERF_SEARCH_READY_TIMEOUT_SECONDS:-900}"
mkdir -p "$DATASET_DIR" "$REPORT_DIR" "$LOG_DIR"

if ! [[ "$REPLICAS" =~ ^[0-9]+$ ]] || (( REPLICAS < 1 || REPLICAS > 9 )); then
  echo "CHANCELA_CLUSTER_REPLICAS must be an integer between 1 and 9" >&2
  exit 2
fi
if ! [[ "$PERF_PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "CHANCELA_PERF_PROJECT_NAME must be a lowercase Compose project name" >&2
  exit 2
fi

if [ ! -f "$PROFILE_FILE" ]; then
  echo "unknown performance profile: $PROFILE" >&2
  exit 2
fi

COMPOSE=(
  docker compose
  --project-name "$PERF_PROJECT"
  -f docker/docker-compose.yml
  -f docker/docker-compose.cluster.yml
  -f scripts/perf/docker-compose.perf.yml
  --profile postgres
  --profile cluster
  --profile performance
)
TOPOLOGY_ARGS=(
  python scripts/perf/topology.py
  --project-name "$PERF_PROJECT"
  --compose-file docker/docker-compose.yml
  --compose-file docker/docker-compose.cluster.yml
  --compose-file scripts/perf/docker-compose.perf.yml
  --profile postgres
  --profile cluster
  --profile performance
  --expected-replicas "$REPLICAS"
)

cleanup() {
  rc=$?
  if [ ! -s "$TOPOLOGY_FINAL" ]; then
    "${TOPOLOGY_ARGS[@]}" --allow-degraded --output "$TOPOLOGY_FINAL" \
      > "$LOG_DIR/topology-final.log" 2>&1 || true
  fi
  "${COMPOSE[@]}" logs --no-color > "$LOG_DIR/compose.log" 2>&1 || true
  if [ "${CHANCELA_PERF_KEEP:-0}" != "1" ]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

budget_args=(
  python scripts/perf/harness.py budget
  --profile "$PROFILE_FILE"
  --output "$DURATION_BUDGET"
  --workflow-timeout-seconds "$WORKFLOW_TIMEOUT_SECONDS"
  --search-readiness-timeout-seconds "$SEARCH_READY_TIMEOUT_SECONDS"
)
if [ -n "$CRYPTO_CONFIG" ]; then
  budget_args+=(--cryptographic-config "$CRYPTO_CONFIG")
fi
"${budget_args[@]}" > "$LOG_DIR/duration-budget.json"

python scripts/perf/harness.py generate \
  --profile "$PROFILE_FILE" \
  --output-dir "$DATASET_DIR" > "$LOG_DIR/generate.json"
python scripts/perf/harness.py validate \
  --dataset-dir "$DATASET_DIR" > "$LOG_DIR/validate.json"

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build --scale chancela-cluster="$REPLICAS" \
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
"${TOPOLOGY_ARGS[@]}" --output "$TOPOLOGY_INITIAL" \
  > "$LOG_DIR/topology-initial.log"

args=(
  python scripts/perf/harness.py run
  --profile "$PROFILE_FILE"
  --dataset-dir "$DATASET_DIR"
  --report-dir "$REPORT_DIR"
  --base-url "http://127.0.0.1:${CHANCELA_PERF_HOST_PORT:-18081}"
  --topology-evidence "$TOPOLOGY_INITIAL"
  --final-topology-evidence "$TOPOLOGY_FINAL"
  --duration-budget-evidence "$DURATION_BUDGET"
  --search-readiness-timeout-seconds "$SEARCH_READY_TIMEOUT_SECONDS"
)
if [ -n "$SLO" ]; then
  args+=(--slo "$SLO")
fi
if [ -n "$CRYPTO_CONFIG" ]; then
  args+=(--cryptographic-config "$CRYPTO_CONFIG")
fi
"${args[@]}" 2>&1 | tee "$LOG_DIR/harness.log"
