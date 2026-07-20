#!/bin/sh
# Host-side preflight for the `postgres` compose profile.
#
# The profile's three docker secrets are gitignored, so a fresh checkout has
# only the committed *.example templates. Without this check the first symptom
# is a daemon-level mount error naming a path the operator has never seen:
#
#   Error response from daemon: invalid mount config for type "bind":
#   bind source path does not exist: .../docker/secrets/postgres_password
#
# Worse, some daemons silently create a DIRECTORY at the missing path instead
# of failing. Postgres then reads POSTGRES_PASSWORD_FILE as a directory, and a
# later `cp ...example docker/secrets/postgres_password` nests the file inside
# it rather than fixing anything -- so this script rejects that state too.
#
# Run it before `docker compose --profile postgres up`; it is a plain host
# script (not a compose service) because compose creates every container --
# and therefore validates every bind mount -- before it starts the first one,
# so no init container can run early enough to pre-empt the failure.
set -eu

secrets_dir="$(CDPATH='' cd -- "$(dirname -- "$0")/secrets" && pwd)"
missing=0

for name in postgres_password database_url credential_key; do
  path="$secrets_dir/$name"
  if [ -d "$path" ]; then
    echo "ERROR: $path is a DIRECTORY (left behind by an earlier failed run)." >&2
    echo "       Remove it first:  rm -rf docker/secrets/$name" >&2
    missing=1
  elif [ ! -f "$path" ]; then
    echo "ERROR: missing secret file docker/secrets/$name" >&2
    echo "       Create it:  cp docker/secrets/$name.example docker/secrets/$name" >&2
    missing=1
  elif [ ! -s "$path" ]; then
    echo "ERROR: docker/secrets/$name is empty." >&2
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'EOF'

The `postgres` profile reads three file-based docker secrets from
docker/secrets/. They are gitignored on purpose -- only the *.example
templates are committed. Fill each one in after copying it:

  postgres_password  a long random password
  database_url       a libpq URL containing THAT SAME password
  credential_key     a high-entropy key, e.g. openssl rand -base64 48

See docker/secrets/README.md and docs/deployment.md.
EOF
  exit 1
fi

echo "docker/secrets: postgres_password, database_url, credential_key all present."
