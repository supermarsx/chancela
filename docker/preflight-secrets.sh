#!/bin/sh
# Host-side secret management for the `postgres` compose profile -- OPTIONAL.
#
# The profile no longer needs this. Runtime secrets live in named volumes,
# which the `secrets-init` compose service
# fills before postgres or the app start, so a fresh clone needs only the
# explicit acknowledgement that the local Compose database is dedicated:
#
#   CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
#     docker compose --profile postgres up -d
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
# overwrites an existing secret file. The API/Postgres pair and credential key
# are write-once in practice:
#
#   postgres_password  baked into the `chancela-pgdata` volume the first time
#                      Postgres initialises; POSTGRES_PASSWORD_FILE is ignored
#                      on every later start. A new value would leave the app
#                      unable to authenticate against its own database.
#   database_url       embeds that same password inline, so it is generated
#                      from the same value in the same step (see below).
#   credential_key     encrypts stored provider credentials; a new value makes
#                      every already-stored credential undecryptable.
#   search_database_password/search_database_url
#                      authenticate a separate least-privilege projector role.
#                      The URL is derived from this independent password.
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

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
default_secrets_dir="$script_dir/secrets"
secrets_dir="${CHANCELA_HOST_SECRETS_DIR:-$default_secrets_dir}"
probe_image="${CHANCELA_VOLUME_PROBE_IMAGE:-alpine/openssl:3.5.7@sha256:3da6a24cdaa2f2ac8ef4defb322249fae6159983104653a9e5312f5b75dac7af}"
docker_bin="${CHANCELA_DOCKER_BIN:-docker}"
db_password_min_length=32
active_publish_dir=""
active_publish_file=""
mkdir -p "$secrets_dir"

cleanup_publication() {
  if [ -n "$active_publish_file" ]; then
    rm -f "$active_publish_file"
  fi
  if [ -n "$active_publish_dir" ]; then
    rmdir "$active_publish_dir" 2>/dev/null || true
  fi
  active_publish_file=""
  active_publish_dir=""
}
trap 'cleanup_publication' EXIT
trap 'cleanup_publication; exit 130' HUP INT TERM

read_secret() {
  tr -d '\r\n' 2>/dev/null <"$1"
}

fail_unreadable_secret() {
  path="$1"
  label="$2"
  echo "ERROR: $label at $path cannot be read by uid $(id -u)." >&2
  echo "       Fix the secret file owner and mode; refusing to infer content errors." >&2
  exit 1
}

reject_unsafe_existing_secret() {
  path="$1"
  label="$2"
  if [ -L "$path" ]; then
    echo "ERROR: $label at $path is a symbolic link; secret links are forbidden." >&2
    exit 1
  fi
  if [ -d "$path" ]; then
    echo "ERROR: $label at $path is a directory, expected a secret file." >&2
    exit 1
  fi
  [ -e "$path" ] || return 0
  if [ ! -f "$path" ] || [ ! -s "$path" ]; then
    echo "ERROR: $label at $path is missing usable secret content." >&2
    exit 1
  fi
  if grep -qi 'change_me' "$path" 2>/dev/null; then
    echo "ERROR: $label at $path contains a public CHANGE_ME placeholder (case-insensitive)." >&2
    echo "       Generate a real value before starting any deployment." >&2
    exit 1
  fi
  if ! raw_bytes="$(wc -c 2>/dev/null <"$path")"; then
    fail_unreadable_secret "$path" "$label"
  fi
  raw_bytes="$(printf '%s' "$raw_bytes" | tr -d '[:space:]')"
  if ! clean_value="$(read_secret "$path")"; then
    fail_unreadable_secret "$path" "$label"
  fi
  clean_bytes="$(printf '%s' "$clean_value" | wc -c | tr -d '[:space:]')"
  if [ "$raw_bytes" != "$clean_bytes" ]; then
    echo "ERROR: $label at $path contains a CR or LF; secret files must be exact single values." >&2
    exit 1
  fi
}

validate_db_password_value() {
  password_value="$1"
  password_label="$2"
  if [ "${#password_value}" -lt "$db_password_min_length" ]; then
    echo "ERROR: $password_label must contain at least $db_password_min_length characters." >&2
    exit 1
  fi
  case "$password_value" in
    *[!A-Za-z0-9._~-]*)
      echo "ERROR: $password_label contains characters outside the URI-unreserved set." >&2
      echo "       Allowed: A-Z a-z 0-9 period underscore tilde hyphen." >&2
      exit 1
      ;;
  esac
}

validate_db_password_file() {
  password_file="$1"
  password_label="$2"
  [ -e "$password_file" ] || return 0
  reject_unsafe_existing_secret "$password_file" "$password_label"
  validate_db_password_value "$(read_secret "$password_file")" "$password_label"
}

validate_pair() {
  pair_password_path="$1"
  pair_url_path="$2"
  pair_expected_prefix="$3"
  pair_expected_suffix="$4"
  pair_label="$5"
  [ -s "$pair_password_path" ] || return 0
  [ -s "$pair_url_path" ] || return 0

  pair_password="$(read_secret "$pair_password_path")"
  pair_actual_url="$(read_secret "$pair_url_path")"
  pair_expected_url="${pair_expected_prefix}${pair_password}${pair_expected_suffix}"
  if [ "$pair_actual_url" != "$pair_expected_url" ]; then
    echo "ERROR: $pair_label password/URL pair does not match this local Compose profile." >&2
    echo "       These helpers intentionally accept only postgres:5432 with verify-full." >&2
    echo "       Refusing without printing either credential." >&2
    exit 1
  fi
}

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
publish_secret() {
  destination="$1"
  secret_value="$2"
  # rand_secret runs inside a command substitution, so its `exit 1` ends only
  # that subshell -- without this guard a missing openssl would silently write
  # an EMPTY secret, which is the one outcome worse than writing none.
  if [ -z "$secret_value" ]; then
    echo "ERROR: refusing to publish an empty secret to $destination" >&2
    exit 1
  fi
  destination_dir="${destination%/*}"
  destination_name="${destination##*/}"
  active_publish_dir="$(
    umask 077
    mktemp -d "$destination_dir/.chancela-${destination_name}.publish.XXXXXX"
  )"
  if [ -z "$active_publish_dir" ] || [ ! -d "$active_publish_dir" ]; then
    echo "ERROR: cannot create private publication staging directory for $destination_name." >&2
    exit 1
  fi
  active_publish_file="$active_publish_dir/value"
  (
    umask 077
    printf '%s' "$secret_value" >"$active_publish_file"
  )
  chmod 0600 "$active_publish_file" 2>/dev/null || true

  # A same-filesystem hard link is an atomic create-if-absent publication:
  # unlike mv/cp/redirection it can never replace an inode that appeared after
  # validation. If another initializer won the race, accept only the exact same
  # regular non-link value.
  if ln "$active_publish_file" "$destination" 2>/dev/null; then
    cleanup_publication
    return 0
  fi
  cleanup_publication
  reject_unsafe_existing_secret "$destination" "$destination_name"
  if [ "$(read_secret "$destination")" != "$secret_value" ]; then
    echo "ERROR: $destination_name appeared concurrently with a different value; refusing." >&2
    exit 1
  fi
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
  printf '%s' "$raw" | tr -d '\r\n=' | tr '+/' '-_'
}

# Echo the value $1 has in a compose .env file (docker/.env, then the repo-root
# .env -- the two project directories compose can be invoked from), else $2.
env_default() {
  for envfile in \
    "$(dirname -- "$default_secrets_dir")/.env" \
    "$(dirname -- "$default_secrets_dir")/../.env"
  do
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
  command -v "$docker_bin" >/dev/null 2>&1 || return 0
  for vol in $(discover_labeled_volumes chancela-pgdata); do
    volume_contains_pg_version "$vol" || continue
    cat >&2 <<EOF
ERROR: docker/secrets/postgres_password is missing, but an existing local
       Compose database volume '$vol' contains a nonempty PG_VERSION marker.

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

discover_labeled_volumes() {
  compose_volume_key="$1"
  command -v "$docker_bin" >/dev/null 2>&1 || return 0
  "$docker_bin" volume ls \
    --filter "label=com.docker.compose.volume=$compose_volume_key" \
    --format '{{.Name}}' 2>/dev/null
}

volume_project_label() {
  "$docker_bin" volume inspect \
    --format '{{ index .Labels "com.docker.compose.project" }}' \
    "$1" 2>/dev/null
}

volume_for_project_key() {
  project_label="$1"
  compose_volume_key="$2"
  "$docker_bin" volume ls \
    --filter "label=com.docker.compose.project=$project_label" \
    --filter "label=com.docker.compose.volume=$compose_volume_key" \
    --format '{{.Name}}' 2>/dev/null | sed -n '1p'
}

volume_contains_exact_file() {
  volume_name="$1"
  relative_path="$2"
  [ -n "$volume_name" ] || return 1
  "$docker_bin" run --rm --network none --read-only \
    --mount "type=volume,src=$volume_name,dst=/probe,readonly" \
    --entrypoint /bin/sh "$probe_image" -eu -c \
    'candidate="/probe/$1"; [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -s "$candidate" ]' \
    sh "$relative_path" >/dev/null 2>&1
}

volume_contains_pg_version() {
  volume_name="$1"
  "$docker_bin" run --rm --network none --read-only \
    --mount "type=volume,src=$volume_name,dst=/probe,readonly" \
    --entrypoint /bin/sh "$probe_image" -eu -c \
    'find /probe -maxdepth 4 -type f -name PG_VERSION -size +0 -print -quit | grep -q .' \
    >/dev/null 2>&1
}

project_split_secrets_complete() {
  project_label="$1"
  for mapping in \
    "chancela-postgres-password:postgres_password" \
    "chancela-database-url:database_url" \
    "chancela-credential-key:credential_key" \
    "chancela-search-password:search_database_password" \
    "chancela-search-secrets:search_database_url"
  do
    compose_volume_key="${mapping%%:*}"
    relative_path="${mapping#*:}"
    candidate_volume="$(volume_for_project_key "$project_label" "$compose_volume_key")"
    volume_contains_exact_file "$candidate_volume" "$relative_path" || return 1
  done
}

project_legacy_secrets_complete() {
  project_label="$1"
  legacy_volume="$(volume_for_project_key "$project_label" chancela-secrets)"
  [ -n "$legacy_volume" ] || return 1
  for relative_path in \
    postgres_password \
    database_url \
    credential_key \
    search_database_password \
    search_database_url
  do
    volume_contains_exact_file "$legacy_volume" "$relative_path" || return 1
  done
}

if [ "$generate" -eq 1 ]; then
  pw_path="$secrets_dir/postgres_password"
  url_path="$secrets_dir/database_url"
  key_path="$secrets_dir/credential_key"
  search_pw_path="$secrets_dir/search_database_password"
  search_url_path="$secrets_dir/search_database_url"

  # Refuse public placeholders, empty files, and directory debris before writing
  # any missing peer or unrelated secret.
  for name in postgres_password database_url credential_key search_database_password search_database_url; do
    reject_unsafe_existing_secret "$secrets_dir/$name" "docker/secrets/$name"
  done
  validate_db_password_file "$pw_path" "docker/secrets/postgres_password"
  validate_db_password_file "$search_pw_path" "docker/secrets/search_database_password"

  existing_db="${CHANCELA_PG_DB:-$(env_default CHANCELA_PG_DB chancela)}"
  existing_user="${CHANCELA_PG_USER:-$(env_default CHANCELA_PG_USER chancela)}"
  validate_pair \
    "$pw_path" \
    "$url_path" \
    "postgres://$existing_user:" \
    "@postgres:5432/$existing_db?sslmode=verify-full" \
    "API/Postgres"
  validate_pair \
    "$search_pw_path" \
    "$search_url_path" \
    "postgres://chancela_search_projector:" \
    "@postgres:5432/$existing_db?sslmode=verify-full" \
    "search projector"

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
    publish_secret "$pw_path" "$(rand_secret 36)"
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
    publish_secret "$url_path" \
      "postgres://$user:$pw@postgres:5432/$db?sslmode=verify-full"
    echo "generated docker/secrets/database_url (from postgres_password, mode 0600)"
  fi

  if [ ! -e "$key_path" ]; then
    publish_secret "$key_path" "$(rand_secret 48)"
    echo "generated docker/secrets/credential_key (384-bit, mode 0600)"
  fi

  if [ ! -e "$search_pw_path" ]; then
    if [ -e "$search_url_path" ]; then
      cat >&2 <<'EOF'
ERROR: docker/secrets/search_database_url exists but
       docker/secrets/search_database_password does not. Refusing to invent a
       password that cannot match the existing URL.

       Restore the password used by that URL, or remove both projector secret
       files and re-run this script with --generate.
EOF
      exit 1
    fi
    publish_secret "$search_pw_path" "$(rand_secret 36)"
    echo "generated docker/secrets/search_database_password (288-bit, mode 0600)"
  fi

  if [ ! -e "$search_url_path" ] && [ -f "$search_pw_path" ]; then
    search_pw="$(cat "$search_pw_path")"
    search_db="${CHANCELA_PG_DB:-$(env_default CHANCELA_PG_DB chancela)}"
    publish_secret "$search_url_path" \
      "postgres://chancela_search_projector:$search_pw@postgres:5432/$search_db?sslmode=verify-full"
    echo "generated docker/secrets/search_database_url (from search_database_password, mode 0600)"
  fi
fi

missing=0

# Absent host files are no longer a failure: they are the normal state once
# secrets-init has populated the volume. Only say so when the volume really
# exists, so a genuine "nothing anywhere" still reaches the error path below.
volume_holds_secrets() {
  command -v "$docker_bin" >/dev/null 2>&1 || return 1
  projects="$(
    for compose_volume_key in \
      chancela-postgres-password \
      chancela-database-url \
      chancela-credential-key \
      chancela-search-password \
      chancela-search-secrets \
      chancela-secrets
    do
      for candidate_volume in $(discover_labeled_volumes "$compose_volume_key"); do
        volume_project_label "$candidate_volume"
      done
    done | sed '/^$/d'
  )"
  for project_label in $projects; do
    if project_split_secrets_complete "$project_label" \
      || project_legacy_secrets_complete "$project_label"; then
      echo "found complete nonempty managed secrets for Compose project '$project_label'"
      return 0
    fi
  done
  return 1
}

host_files=0
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  [ -e "$secrets_dir/$name" ] && host_files=1
done

if [ "$host_files" -eq 0 ] && volume_holds_secrets; then
  echo "docker/secrets is empty and a labeled Compose project has a complete"
  echo "five-file managed secret set. secrets-init owns it; nothing to do."
  exit 0
fi

for name in postgres_password database_url credential_key search_database_password search_database_url; do
  path="$secrets_dir/$name"
  if [ -L "$path" ]; then
    echo "ERROR: $path is a symbolic link; secret links are forbidden." >&2
    missing=1
  elif [ -d "$path" ]; then
    echo "ERROR: $path is a DIRECTORY (left behind by an earlier failed run)." >&2
    echo "       Remove it first:  rm -rf docker/secrets/$name" >&2
    missing=1
  elif [ ! -f "$path" ]; then
    echo "ERROR: missing secret file docker/secrets/$name" >&2
    echo "       Either let the normal stack create it (just run 'up' --" >&2
    echo "       secrets-init does), or generate it here:" >&2
    echo "         sh docker/preflight-secrets.sh --generate" >&2
    missing=1
  elif [ ! -s "$path" ]; then
    echo "ERROR: docker/secrets/$name is empty." >&2
    missing=1
  elif grep -qi 'change_me' "$path" 2>/dev/null; then
    echo "ERROR: docker/secrets/$name contains a public CHANGE_ME placeholder (case-insensitive)." >&2
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'EOF'

Some of docker/secrets/ is populated and some is not. That half-state is the
one this script cannot resolve for you, because both database credential pairs
must remain internally consistent:

  postgres_password          a long random password
  database_url               a libpq URL containing THAT SAME password
  credential_key             a high-entropy key, e.g. openssl rand -base64 48
  search_database_password   an independent projector-role password
  search_database_url        a URL containing THAT projector password

Either complete the set here, consistently and only once:

  sh docker/preflight-secrets.sh --generate

or empty docker/secrets/ entirely and let the stack manage them:

  CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
    docker compose --profile postgres up -d

See docker/secrets/README.md and docs/deployment.md.
EOF
  exit 1
fi

db="${CHANCELA_PG_DB:-$(env_default CHANCELA_PG_DB chancela)}"
user="${CHANCELA_PG_USER:-$(env_default CHANCELA_PG_USER chancela)}"
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  reject_unsafe_existing_secret "$secrets_dir/$name" "docker/secrets/$name"
done
validate_db_password_file \
  "$secrets_dir/postgres_password" \
  "docker/secrets/postgres_password"
validate_db_password_file \
  "$secrets_dir/search_database_password" \
  "docker/secrets/search_database_password"
validate_pair \
  "$secrets_dir/postgres_password" \
  "$secrets_dir/database_url" \
  "postgres://$user:" \
  "@postgres:5432/$db?sslmode=verify-full" \
  "API/Postgres"
validate_pair \
  "$secrets_dir/search_database_password" \
  "$secrets_dir/search_database_url" \
  "postgres://chancela_search_projector:" \
  "@postgres:5432/$db?sslmode=verify-full" \
  "search projector"

chmod 0600 \
  "$secrets_dir/postgres_password" \
  "$secrets_dir/database_url" \
  "$secrets_dir/credential_key" \
  "$secrets_dir/search_database_password" \
  "$secrets_dir/search_database_url" \
  2>/dev/null || true
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  reject_unsafe_existing_secret "$secrets_dir/$name" "docker/secrets/$name"
done

echo "docker/secrets: API, signing, and restricted projector secrets all present."
