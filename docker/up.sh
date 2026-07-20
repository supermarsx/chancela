#!/bin/sh
# One-command bring-up of the `postgres` deployment profile.
#
#   sh docker/up.sh -d            # generate missing secrets, then up -d
#   sh docker/up.sh -d --build
#
# It exists because the correct incantation has two non-obvious parts that a
# fresh clone gets wrong:
#
#  1. The profile's three docker secrets are gitignored, so they do not exist
#     yet. Compose only WARNS about a missing secret file and hands the path to
#     the daemon anyway, which fails the container with an opaque
#     "bind source path does not exist" -- or silently creates a directory
#     there. Generation has to happen on the host BEFORE compose runs: compose
#     creates every container, validating every bind mount, before starting the
#     first one, so no init container can run early enough.
#  2. `--profile postgres` needs the explicit `-f docker/docker-compose.yml`
#     form. The auto-loaded override files make `server` unconditional, and
#     with the profile's `chancela` service that is two containers publishing
#     ${CHANCELA_HOST_PORT:-8080}; the second dies with "port is already
#     allocated".
#
# The secret generation is create-if-absent only -- re-running this script
# never rotates a password (see docker/preflight-secrets.sh for why that
# matters).
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

sh "$here/preflight-secrets.sh" --generate

exec docker compose -f "$here/docker-compose.yml" --profile postgres up "$@"
