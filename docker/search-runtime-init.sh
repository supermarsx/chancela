#!/bin/sh
# Prepare the dedicated Postgres projector heartbeat volume for the non-root
# runtime. This service has no network and only the CHOWN capability.
set -eu

runtime_dir="${CHANCELA_SEARCH_RUNTIME_DIR:-/runtime}"
runtime_uid="${CHANCELA_SEARCH_RUNTIME_UID:-65532}"
runtime_gid="${CHANCELA_SEARCH_RUNTIME_GID:-65532}"

if [ ! -d "$runtime_dir" ]; then
  echo "ERROR: search runtime volume is not mounted at $runtime_dir" >&2
  exit 1
fi

# Reacquire ownership first so chmod does not require FOWNER on repeat runs,
# then hand the directory back to the projector's fixed non-root identity.
chown 0:0 "$runtime_dir"
chmod 0700 "$runtime_dir"
chown "$runtime_uid:$runtime_gid" "$runtime_dir"

actual="$(stat -c '%u:%g:%a' "$runtime_dir")"
expected="$runtime_uid:$runtime_gid:700"
if [ "$actual" != "$expected" ]; then
  echo "ERROR: search runtime volume posture is $actual, expected $expected" >&2
  exit 1
fi

echo "search runtime volume ready ($expected)."
