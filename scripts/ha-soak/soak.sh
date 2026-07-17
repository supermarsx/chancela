#!/usr/bin/env bash
# wp28 HA multi-node soak — host orchestrator.
#
# Brings up a 3-node `chancela-cluster` + Postgres + Redis via compose, then runs the in-network
# load+chaos driver (scripts/ha-soak/loader.py) as a container attached to the compose network with
# the docker socket mounted. Streams the driver's output (which ends with a JSON summary and a
# PASS/FAIL correctness verdict), then tears the cluster down.
#
# Usage:
#   scripts/ha-soak/soak.sh [DURATION_SECONDS] [REPLICAS]
# Env:
#   SOAK_KEEP=1   leave the cluster up after the run (skip teardown)
#   SOAK_WRITERS  writer-thread count inside the driver (default 6)
#
# Requires: docker + compose v2, the `chancela-server:postgres` image already built, and the
# docker/secrets/{postgres_password,database_url,credential_key} files present.
set -euo pipefail

DURATION="${1:-1800}"
REPLICAS="${2:-3}"
PROJECT="chancela"
NET="${PROJECT}_default"
PG="chancela-postgres-1"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# Run from the repo root and use RELATIVE compose paths. Git Bash mangles absolute POSIX paths passed
# to the Windows docker.exe (a leading /f/... becomes F:\f\...); relative paths sidestep that. The one
# path that must survive verbatim — the docker socket — uses the // prefix trick in `docker run` below.
cd "$ROOT"
COMPOSE=(docker compose
  -f docker/docker-compose.yml
  -f docker/docker-compose.cluster.yml
  -f scripts/ha-soak/docker-compose.soak.yml
  --profile postgres --profile cluster)

IMAGE="${CHANCELA_POSTGRES_IMAGE:-chancela-server:postgres}"

log(){ echo "[soak.sh] $*"; }

log "duration=${DURATION}s replicas=${REPLICAS}"

# --- 1. build / ensure the chancela-server:postgres image ------------------------------------
# The `chancela-cluster` service carries both a `build:` stanza and `image: chancela-server:postgres`,
# so `compose build` produces the correctly-tagged image (sqlcipher+postgres+redis features). Build
# when the image is missing, or unconditionally when SOAK_REBUILD=1.
if [ "${SOAK_REBUILD:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "building image ${IMAGE} (SOAK_REBUILD=${SOAK_REBUILD:-0})..."
  "${COMPOSE[@]}" build chancela-cluster
else
  log "image ${IMAGE} already present (set SOAK_REBUILD=1 to force a rebuild)"
fi

# --- 2. clean any prior cluster + volumes so each run starts from an empty durable ledger -----
log "cleaning any prior cluster + volumes..."
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true

# --- 3. bring the cluster up ------------------------------------------------------------------
log "bringing up cluster (postgres + redis + ${REPLICAS}x chancela-cluster)..."
"${COMPOSE[@]}" up -d --scale "chancela-cluster=${REPLICAS}" postgres redis chancela-cluster

log "waiting for ${REPLICAS} replicas to be running..."
for _ in $(seq 1 60); do
  running=$(docker ps --filter "name=chancela-chancela-cluster" --filter "status=running" --format '{{.Names}}' | wc -l | tr -d ' ')
  [ "$running" = "$REPLICAS" ] && break
  sleep 2
done
NODES=$(docker ps --filter "name=chancela-chancela-cluster" --format '{{.Names}}' | sort | paste -sd, -)
log "app nodes: $NODES"
if [ -z "$NODES" ]; then log "FATAL: no app nodes running"; docker ps -a --filter name=chancela-chancela-cluster; exit 1; fi

# Quick boot sanity: if a node already exited, dump its log and bail (surfaces boot bugs fast).
for n in $(echo "$NODES" | tr ',' ' '); do
  state=$(docker inspect -f '{{.State.Status}}' "$n")
  if [ "$state" != "running" ]; then log "FATAL: $n is $state"; docker logs "$n" 2>&1 | tail -30; exit 1; fi
done

RESULT="$ROOT/.orchestration/logs/wp28-soak-result.txt"
DRIVER_LOG="$ROOT/.orchestration/logs/wp28-soak-driver.out"
mkdir -p "$ROOT/.orchestration/logs"

log "launching in-network load+chaos driver (duration ${DURATION}s)..."
set +e
docker run -i --rm \
  --name chancela-soak-driver \
  --network "$NET" \
  -e "SOAK_WRITERS=${SOAK_WRITERS:-6}" \
  -v //var/run/docker.sock:/var/run/docker.sock \
  python:3.12-alpine \
  sh -c "apk add --no-cache docker-cli >/dev/null 2>&1 && python - --nodes '$NODES' --postgres-container '$PG' --duration '$DURATION'" \
  < "$HERE/loader.py" 2>&1 | tee "$DRIVER_LOG"
DRIVER_RC=${PIPESTATUS[0]}
set -e
log "driver exited rc=$DRIVER_RC"

# --- machine-readable result file -------------------------------------------------------------
{
  echo "wp28 HA multi-node soak result"
  echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "duration_requested_s: ${DURATION}"
  echo "replicas: ${REPLICAS}"
  echo "nodes: ${NODES}"
  echo "driver_exit_code: ${DRIVER_RC}"
  if [ "$DRIVER_RC" = "0" ]; then echo "VERDICT: PASS"; else echo "VERDICT: FAIL"; fi
  echo "---- driver verdict lines ----"
  grep -E "LEDGER_DIVERGENCE|CORRECTNESS|\"correctness_pass\"|\"ledger_divergence\"" "$DRIVER_LOG" || true
  echo "---- driver JSON summary ----"
  # everything from the SOAK SUMMARY banner to end (the metrics + per-node convergence)
  awk '/==== SOAK SUMMARY ====/{f=1;next} f' "$DRIVER_LOG" | sed '/==== LEDGER_DIVERGENCE/,$d'
} > "$RESULT" 2>/dev/null || true
log "wrote result to $RESULT"

if [ "${SOAK_KEEP:-0}" = "1" ]; then
  log "SOAK_KEEP=1 → leaving cluster up"
else
  log "tearing down..."
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
fi
exit $DRIVER_RC
