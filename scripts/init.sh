#!/usr/bin/env bash
# Chancela one-shot developer bootstrap (POSIX / bash).
#
# Verifies the required toolchain is present (cargo, rustup, node, npm),
# reports the detected versions, enforces Node >= 20, installs the npm
# workspace dependencies, and prints the next steps. It never mutates the
# Rust toolchain (no rustup install/update) — it only reports what is there.
#
# Invoked via `npm run init` (or `bash scripts/init.sh` directly).

set -euo pipefail

MIN_NODE_MAJOR=20

# Print the trimmed first line of a tool's output, or nothing if the tool is
# missing or fails. Never errors out — a missing tool is an expected outcome.
tool_version() {
    local out
    if ! out=$("$@" 2>/dev/null); then
        return 0
    fi
    printf '%s\n' "$out" | head -n 1
}

printf 'Chancela - environment check\n\n'

missing=0
for tool in cargo rustup node npm; do
    version=$(tool_version "$tool" --version)
    if [ -n "$version" ]; then
        printf '  ok    %-7s %s\n' "$tool" "$version"
    else
        printf '  MISS  %-7s not found on PATH\n' "$tool"
        missing=1
    fi
done

# Node engine gate (mirrors package.json "engines": { "node": ">=20" }).
node_version=$(tool_version node --version)
if [ -n "$node_version" ]; then
    node_major=$(printf '%s' "$node_version" | sed -E 's/^[^0-9]*([0-9]+).*/\1/')
    if [ -n "$node_major" ] && [ "$node_major" -lt "$MIN_NODE_MAJOR" ]; then
        printf '\nNode %s is too old - Chancela requires Node >= %s.\n' "$node_version" "$MIN_NODE_MAJOR" >&2
        missing=1
    fi
fi

if [ "$missing" -ne 0 ]; then
    printf "\nInstall the missing tools, then re-run 'npm run init'.\n" >&2
    printf '  Rust (cargo + rustup): https://rustup.rs\n' >&2
    printf '  Node.js (node + npm):  https://nodejs.org  (>= 20)\n' >&2
    exit 1
fi

printf '\nInstalling web workspace dependencies (npm install)...\n\n'
npm install

printf '\nSetup complete. Next steps:\n'
printf '  npm run dev      # run the API server + web dev server together\n'
printf '  npm run test     # cargo + vitest test suites\n'
printf '  npm run build    # release build of server and web bundle\n'
printf '  npm run package  # assemble a distributable tarball\n'
