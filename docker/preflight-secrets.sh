#!/bin/sh
# Host-side secret management for the `postgres` compose profile -- OPTIONAL.
#
# The profile no longer needs this. The three secrets live in the
# `chancela-secrets` named volume, which the `secrets-init` compose service
# fills before postgres or the app start, so a fresh clone works with a plain
#
#   docker compose --profile postgres up -d
#
# This script remains for operators who would rather own the values on the host
# (to back them up, to reuse an existing database, or to rotate deliberately).
# Anything it writes into docker/secrets/ is ADOPTED by secrets-init -- copied
# into the volume instead of generating -- as long as the volume does not
# already hold that secret. Once the volume has a value, the volume wins; the
# host file is then ignored, and the script says so.
#
# It also still rejects the debris state where an earlier failed run left a
# DIRECTORY at docker/secrets/<name>, because a later
# `cp ...example docker/secrets/<name>` nests the file inside it rather than
# fixing anything.
#
# Usage:
#   sh docker/preflight-secrets.sh              # check only (exit 1 if unusable)
#   sh docker/preflight-secrets.sh --generate   # create the MISSING ones, then check
#
# --generate is strictly create-if-absent. It never rewrites, rotates or
# overwrites an existing secret file, because all three are write-once in
# practice:
#
#   postgres_password  baked into the `chancela-pgdata` volume the first time
#                      Postgres initialises; POSTGRES_PASSWORD_FILE is ignored
#                      on every later start. A new value would leave the app
#                      unable to authenticate against its own database.
#   database_url       embeds that same password inline, so it is generated
#                      from the same value in the same step (see below).
#   credential_key     encrypts stored provider credentials; a new value makes
#                      every already-stored credential undecryptable.
set -eu

generate=0
for arg in "$@"; do
  case "$arg" in
    --generate) generate=1 ;;
    -h | --help)
      cat <<'EOF'
Usage:
  sh docker/preflight-secrets.sh              # check only (exit 1 if unusable)
  sh docker/preflight-secrets.sh --generate   # create the MISSING ones, then check

--generate is strictly create-if-absent: it never rewrites, rotates or
overwrites an existing secret file.
EOF
      exit 0
      ;;
    *)
      echo "preflight-secrets.sh: unknown option '$arg' (expected --generate)" >&2
      exit 2
      ;;
  esac
done

secrets_dir="$(CDPATH='' cd -- "$(dirname -- "$0")/secrets" && pwd)"

# Write $2 to the file $1 with NO trailing newline and mode 0600.
#
# The newline matters: `database_url` is read verbatim by the app and
# `postgres_password` is passed to libpq by the healthcheck, so a stray "\n"
# is the classic invisible authentication failure. (Both consumers happen to
# trim today, but the file is the contract; keep it exact.)
#
# The mode is set before the content is written, so the value is never briefly
# world-readable. chmod is a no-op on a Windows/NTFS checkout -- Git for
# Windows and Docker Desktop report 0644 regardless -- so on Windows the
# directory ACL is the only protection. That is a development-host concern;
# the Linux deployments this profile targets honour it.
write_secret() {
  # rand_secret runs inside a command substitution, so its `exit 1` ends only
  # that subshell -- without this guard a missing openssl would silently write
  # an EMPTY secret, which is the one outcome worse than writing none.
  if [ -z "$2" ]; then
    echo "ERROR: refusing to write an empty secret to $1" >&2
    exit 1
  fi
  # Subshell so the tightened umask does not leak into the rest of the script.
  # Creating the file under umask 077 means it is never even briefly readable
  # by anyone else; the explicit chmod covers a pre-existing-inode edge case.
  (
    umask 077
    : >"$1"
    chmod 600 "$1" 2>/dev/null || true
    printf '%s' "$2" >"$1"
  )
}

# Cryptographically random, URL-safe, unpadded base64 of $1 bytes.
#
# URL-safe matters because the password is embedded in `database_url`'s
# userinfo, where standard base64's "/" and "+" are invalid or ambiguous and
# would otherwise need percent-encoding in one file but not the other. The
# alphabet here (A-Za-z0-9-_) is unreserved in a URI, so the same literal
# string is correct in both files. Never $RANDOM: it is a 15-bit LCG.
rand_secret() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    raw="$(openssl rand -base64 "$bytes")"
  elif [ -r /dev/urandom ] && command -v base64 >/dev/null 2>&1; then
    raw="$(dd if=/dev/urandom bs="$bytes" count=1 2>/dev/null | base64)"
  else
    echo "ERROR: need openssl or /dev/urandom + base64 to generate secrets." >&2
    echo "       Install openssl, or create docker/secrets/* by hand." >&2
    exit 1
  fi
  printf '%s' "$raw" | tr -d '\n=' | tr '+/' '-_'
}

# Echo the value $1 has in a compose .env file (docker/.env, then the repo-root
# .env -- the two project directories compose can be invoked from), else $2.
env_default() {
  for envfile in "$(dirname -- "$secrets_dir")/.env" "$(dirname -- "$secrets_dir")/../.env"; do
    [ -f "$envfile" ] || continue
    val="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$envfile" | tail -n 1)"
    val="${val%\"}"
    val="${val#\"}"
    if [ -n "$val" ]; then
      printf '%s' "$val"
      return 0
    fi
  done
  printf '%s' "$2"
}

# Refuse to invent a password when a database that was initialised with the
# OLD one still exists. This is the one failure mode worse than the missing
# file: Postgres would keep the baked-in password, the app would present the
# new one, and the stack would look corrupted rather than misconfigured.
assert_no_pgdata_volume() {
  command -v docker >/dev/null 2>&1 || return 0
  for vol in chancela_chancela-pgdata chancela-pgdata; do
    docker volume inspect "$vol" >/dev/null 2>&1 || continue
    cat >&2 <<EOF
ERROR: docker/secrets/postgres_password is missing, but the Postgres data
       volume '$vol' already exists.

       POSTGRES_PASSWORD_FILE is read ONLY when Postgres initialises its data
       directory, so that volume already has a password baked in. Generating a
       new one here would produce a database the app cannot authenticate
       against. Refusing.

       Either restore the original secret files from your backup, or -- if the
       data is expendable -- discard the database and start clean:

         docker compose --profile postgres down -v
         sh docker/preflight-secrets.sh --generate
EOF
    exit 1
  done
}

if [ "$generate" -eq 1 ]; then
  pw_path="$secrets_dir/postgres_password"
  url_path="$secrets_dir/database_url"
  key_path="$secrets_dir/credential_key"

  # postgres_password + database_url are ONE unit: the URL carries the same
  # password inline (postgres://chancela:<pw>@postgres:5432/...), so a
  # half-generated pair is a guaranteed authentication failure. Deriving the
  # URL from whatever password is on disk -- freshly generated or pre-existing
  # -- keeps them consistent by construction.
  if [ ! -e "$pw_path" ]; then
    if [ -e "$url_path" ]; then
      cat >&2 <<'EOF'
ERROR: docker/secrets/database_url exists but docker/secrets/postgres_password
       does not. The URL embeds the password, so the password is recoverable
       only from that URL -- generating a new one would desynchronise the pair.

       Copy the password out of database_url (the part between ':' and '@')
       into docker/secrets/postgres_password, then re-run this script.
EOF
      exit 1
    fi
    assert_no_pgdata_volume
    write_secret "$pw_path" "$(rand_secret 36)"
    echo "generated docker/secrets/postgres_password (288-bit, mode 0600)"
  fi

  if [ ! -e "$url_path" ] && [ -f "$pw_path" ]; then
    pw="$(cat "$pw_path")"
    # The database and role names must match what the postgres service will
    # create. Compose takes them from the environment OR from a .env file next
    # to the compose file, which a plain shell does not see -- so read that too,
    # otherwise a .env override silently produces a URL pointing at a database
    # that does not exist.
    db="${CHANCELA_PG_DB:-$(env_default CHANCELA_PG_DB chancela)}"
    user="${CHANCELA_PG_USER:-$(env_default CHANCELA_PG_USER chancela)}"
    # Host/port/sslmode mirror the template and the compose service; only the
    # password comes from the file, so the two secrets cannot drift.
    write_secret "$url_path" \
      "postgres://$user:$pw@postgres:5432/$db?sslmode=verify-full"
    echo "generated docker/secrets/database_url (from postgres_password, mode 0600)"
  fi

  if [ ! -e "$key_path" ]; then
    write_secret "$key_path" "$(rand_secret 48)"
    echo "generated docker/secrets/credential_key (384-bit, mode 0600)"
  fi
fi

missing=0

# Absent host files are no longer a failure: they are the normal state once
# secrets-init has populated the volume. Only say so when the volume really
# exists, so a genuine "nothing anywhere" still reaches the error path below.
volume_holds_secrets() {
  command -v docker >/dev/null 2>&1 || return 1
  for vol in chancela_chancela-secrets chancela-secrets; do
    docker volume inspect "$vol" >/dev/null 2>&1 && return 0
  done
  return 1
}

host_files=0
for name in postgres_password database_url credential_key; do
  [ -e "$secrets_dir/$name" ] && host_files=1
done

if [ "$host_files" -eq 0 ] && volume_holds_secrets; then
  echo "docker/secrets is empty and the chancela-secrets volume exists:"
  echo "the three secrets are managed inside the stack by secrets-init. Nothing to do."
  exit 0
fi

for name in postgres_password database_url credential_key; do
  path="$secrets_dir/$name"
  if [ -d "$path" ]; then
    echo "ERROR: $path is a DIRECTORY (left behind by an earlier failed run)." >&2
    echo "       Remove it first:  rm -rf docker/secrets/$name" >&2
    missing=1
  elif [ ! -f "$path" ]; then
    echo "ERROR: missing secret file docker/secrets/$name" >&2
    echo "       Either let the stack create it (just run 'up' -- secrets-init" >&2
    echo "       does), or generate it here:  sh docker/preflight-secrets.sh --generate" >&2
    missing=1
  elif [ ! -s "$path" ]; then
    echo "ERROR: docker/secrets/$name is empty." >&2
    missing=1
  elif grep -q 'CHANGE_ME' "$path" 2>/dev/null; then
    # A warning, not an error: a stack started from the placeholder does work,
    # and failing here would strand an operator mid-deploy. It is still a real
    # finding -- the value is public, it is in this repository.
    echo "WARNING: docker/secrets/$name still contains the CHANGE_ME placeholder" >&2
    echo "         from the *.example template. Replace it before exposing this" >&2
    echo "         deployment (see docker/secrets/README.md)." >&2
  fi
done

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'EOF'

Some of docker/secrets/ is populated and some is not. That half-state is the
one this script cannot resolve for you, because the three values are related:

  postgres_password  a long random password
  database_url       a libpq URL containing THAT SAME password
  credential_key     a high-entropy key, e.g. openssl rand -base64 48

Either complete the set here, consistently and only once:

  sh docker/preflight-secrets.sh --generate

or empty docker/secrets/ entirely and let the stack manage them:

  docker compose --profile postgres up -d

See docker/secrets/README.md and docs/deployment.md.
EOF
  exit 1
fi

echo "docker/secrets: postgres_password, database_url, credential_key all present."
