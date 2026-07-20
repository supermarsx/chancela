#!/bin/sh
# One-command bring-up of the `postgres` deployment profile.
#
#   sh docker/up.sh -d            # up -d, with the correct -f/--profile form
#   sh docker/up.sh -d --build
#
# It exists for one non-obvious reason: `--profile postgres` needs the explicit
# `-f docker/docker-compose.yml` form. The auto-loaded override files make
# `server` unconditional, and together with the profile's `chancela` service
# that is two containers publishing ${CHANCELA_HOST_PORT:-8080}; the second dies
# with "port is already allocated".
#
# It no longer generates anything. The profile's three secrets are created
# inside the stack by the `secrets-init` service, which fills the
# `chancela-secrets` volume before postgres or the app start -- so the plain
# compose command below works on a fresh clone with no host-side step:
#
#   docker compose -f docker/docker-compose.yml --profile postgres up -d
#
# Operators who would rather own the values themselves still can: put them in
# docker/secrets/ (by hand, or with `sh docker/preflight-secrets.sh --generate`)
# and secrets-init adopts those instead of generating. Either way the values are
# create-if-absent -- nothing here ever rotates a password.
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

exec docker compose -f "$here/docker-compose.yml" --profile postgres up "$@"
