#!/usr/bin/env bash
# Chancela dev runner (POSIX / bash).
#
# Runs `cargo run -p chancela-server` and `npm run dev --workspace apps/web`
# concurrently with prefixed, interleaved output. Ctrl+C — or either child
# exiting — tears both down cleanly so no orphan processes survive.
#
# Invoked via `npm run dev` (or `bash scripts/dev.sh` directly).

set -euo pipefail

pids=()
shutting_down=0

# Signal a process and all of its descendants. `npm` spawns the Vite node
# process (and cargo the server binary) as children, so signalling only the
# launcher would orphan them. pgrep -P walks the tree on Linux/macOS; where it
# is unavailable the direct kill of the launcher is still applied.
kill_tree() {
    local sig="$1" pid="$2" child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        kill_tree "$sig" "$child"
    done
    kill "$sig" "$pid" 2>/dev/null || true
}

shutdown() {
    if [ "$shutting_down" -ne 0 ]; then
        return 0
    fi
    shutting_down=1
    trap - INT TERM
    for pid in "${pids[@]:-}"; do
        [ -n "$pid" ] || continue
        kill_tree -TERM "$pid"
    done
    # Give children a moment to exit on the TERM, then hard-kill stragglers.
    sleep 1
    for pid in "${pids[@]:-}"; do
        [ -n "$pid" ] || continue
        kill_tree -KILL "$pid"
    done
}

# Start a child, routing its stdout+stderr through a per-line [label] prefix.
# Process substitution keeps $! pointing at the real command (not the prefixer),
# so we can signal it directly on teardown.
start_labeled() {
    local label="$1"
    shift
    "$@" > >(while IFS= read -r line; do printf '[%s] %s\n' "$label" "$line"; done) 2>&1 &
    pids+=("$!")
}

printf 'Chancela dev - starting server + web (Ctrl+C to stop)\n\n'

trap 'shutdown; exit 130' INT
trap 'shutdown; exit 143' TERM

start_labeled server cargo run -p chancela-server
start_labeled web npm run dev --workspace apps/web

# Poll until any child exits, then tear the rest down with its exit code.
while :; do
    for pid in "${pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            code=0
            wait "$pid" 2>/dev/null || code=$?
            printf '\n[dev] a process exited (code %s) - shutting down the other process.\n' "$code"
            shutdown
            exit "$code"
        fi
    done
    sleep 1
done
