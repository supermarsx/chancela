#!/bin/sh
# Prepare file-backed Compose secrets for the non-root application identity.
#
# Docker Compose implements file sources as bind mounts, so it cannot remap
# uid/gid/mode the way Swarm secrets can. Preserve the operator as file owner,
# grant read access only to the application group, and never make a secret
# world-readable.
set -eu

secrets_dir="${CHANCELA_FILE_SECRETS_DIR:-/host-secrets}"
runtime_gid="${CHANCELA_RUNTIME_GID:-65532}"

case "$runtime_gid" in
  "" | *[!0-9]*)
    echo "ERROR: CHANCELA_RUNTIME_GID must be a numeric gid." >&2
    exit 1
    ;;
esac

for name in \
  postgres_password \
  database_url \
  credential_key \
  search_database_password \
  search_database_url
do
  path="$secrets_dir/$name"
  if [ -L "$path" ] || [ ! -f "$path" ] || [ ! -s "$path" ]; then
    echo "ERROR: $path must be a nonempty regular file, not a link." >&2
    exit 1
  fi
  chgrp "$runtime_gid" "$path"
  chmod 0640 "$path"
  if [ "$(stat -c '%g:%a' "$path")" != "$runtime_gid:640" ]; then
    echo "ERROR: failed to restrict $path to its owner and gid $runtime_gid." >&2
    exit 1
  fi
done

echo "file-backed secrets prepared for owner + gid $runtime_gid (0640)."
