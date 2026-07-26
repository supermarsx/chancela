#!/bin/sh
# Populate per-secret named volumes for the normal `postgres` Compose profile.
#
# Each destination volume contains exactly one secret and is mounted only into
# the services that consume that secret. The former `chancela-secrets` combined
# volume is mounted read-only at /legacy-secrets solely as a migration source;
# no long-running service receives it.
set -eu

legacy_dir="${CHANCELA_LEGACY_SECRETS_DIR:-/legacy-secrets}"
postgres_password_dir="${CHANCELA_POSTGRES_PASSWORD_DIR:-/postgres-password}"
database_url_dir="${CHANCELA_DATABASE_URL_DIR:-/database-url}"
credential_key_dir="${CHANCELA_CREDENTIAL_KEY_DIR:-/credential-key}"
search_password_dir="${CHANCELA_SEARCH_PASSWORD_DIR:-/search-password}"
search_url_dir="${CHANCELA_SEARCH_URL_DIR:-/search-url}"
host_dir="${CHANCELA_HOST_SECRETS_DIR:-/host-secrets}"
pgdata_probe="${CHANCELA_PGDATA_PROBE:-/probe/pgdata}"
appdata_probe="${CHANCELA_APPDATA_PROBE:-/probe/app-data}"
cluster_data_probe="${CHANCELA_CLUSTER_DATA_PROBE:-/probe/cluster-data}"
# The Compose service intentionally leaves this at root:root. The override
# exists only for unprivileged host-side fixture execution.
secret_owner="${CHANCELA_SECRET_VOLUME_OWNER:-0:0}"
db_password_min_length=32
active_publish_dir=""
active_publish_file=""
case "$secret_owner" in
  *[!0-9:]* | :* | *: | *:*:*)
    echo "ERROR: CHANCELA_SECRET_VOLUME_OWNER must be a numeric uid:gid pair." >&2
    exit 1
    ;;
esac

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

pg_db="${CHANCELA_PG_DB:-chancela}"
pg_user="${CHANCELA_PG_USER:-chancela}"

pw_path="$postgres_password_dir/postgres_password"
url_path="$database_url_dir/database_url"
key_path="$credential_key_dir/credential_key"
search_pw_path="$search_password_dir/search_database_password"
search_url_path="$search_url_dir/search_database_url"

for directory in \
  "$postgres_password_dir" \
  "$database_url_dir" \
  "$credential_key_dir" \
  "$search_password_dir" \
  "$search_url_dir"
do
  mkdir -p "$directory"
done

read_secret() {
  tr -d '\r\n' <"$1"
}

reject_unsafe_candidate() {
  path="$1"
  label="$2"
  if [ -L "$path" ]; then
    echo "ERROR: $label at $path is a symbolic link; secret links are forbidden." >&2
    exit 1
  fi
  [ -e "$path" ] || return 0
  if [ -d "$path" ]; then
    echo "ERROR: $label at $path is a directory, expected a secret file." >&2
    exit 1
  fi
  if [ ! -f "$path" ] || [ ! -s "$path" ]; then
    echo "ERROR: $label at $path is empty or not a regular file." >&2
    exit 1
  fi
  if grep -qi 'change_me' "$path" 2>/dev/null; then
    echo "ERROR: $label at $path contains a public CHANGE_ME placeholder (case-insensitive)." >&2
    exit 1
  fi
  raw_bytes="$(wc -c <"$path" | tr -d '[:space:]')"
  clean_bytes="$(read_secret "$path" | wc -c | tr -d '[:space:]')"
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

validate_db_password_file_if_present() {
  password_path="$1"
  password_label="$2"
  [ -e "$password_path" ] || return 0
  reject_unsafe_candidate "$password_path" "$password_label"
  validate_db_password_value "$(read_secret "$password_path")" "$password_label"
}

validate_pair_values() {
  password="$1"
  actual_url="$2"
  expected_prefix="$3"
  expected_suffix="$4"
  label="$5"
  expected_url="${expected_prefix}${password}${expected_suffix}"
  if [ "$actual_url" != "$expected_url" ]; then
    echo "ERROR: $label password/URL pair does not match this local Compose profile." >&2
    echo "       These helpers intentionally accept only postgres:5432 with verify-full." >&2
    echo "       Refusing without printing either credential." >&2
    exit 1
  fi
}

validate_pair_files_if_complete() {
  password_path="$1"
  candidate_url_path="$2"
  expected_prefix="$3"
  expected_suffix="$4"
  label="$5"
  [ -s "$password_path" ] || return 0
  [ -s "$candidate_url_path" ] || return 0
  validate_pair_values \
    "$(read_secret "$password_path")" \
    "$(read_secret "$candidate_url_path")" \
    "$expected_prefix" \
    "$expected_suffix" \
    "$label"
}

choose_value() {
  for candidate in "$@"; do
    if [ -s "$candidate" ]; then
      read_secret "$candidate"
      return 0
    fi
  done
  return 1
}

# Cryptographically random, URL-safe, unpadded base64 of $1 bytes.
rand_secret() {
  raw="$(openssl rand -base64 "$1")"
  printf '%s' "$raw" | tr -d '\r\n=' | tr '+/' '-_'
}

# Values are protected by per-secret volume attachment, not a shared Unix UID.
# Mode 0444 lets the two intentional consumers of postgres_password/database_url
# use different UIDs while no unrelated container receives those volumes.
publish_secret() {
  destination="$1"
  value="$2"
  if [ -z "$value" ]; then
    echo "ERROR: refusing to write an empty secret to $destination" >&2
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
    printf '%s' "$value" >"$active_publish_file"
  )
  chown "$secret_owner" "$active_publish_file"
  chmod 0444 "$active_publish_file"

  if ln "$active_publish_file" "$destination" 2>/dev/null; then
    cleanup_publication
    return 0
  fi
  cleanup_publication
  reject_unsafe_candidate "$destination" "$destination_name"
  if [ "$(read_secret "$destination")" != "$value" ]; then
    echo "ERROR: $destination_name appeared concurrently with a different value; refusing." >&2
    exit 1
  fi
}

installation_exists() {
  if [ -n "$(find "$pgdata_probe" -maxdepth 4 -name PG_VERSION -type f 2>/dev/null | head -n 1)" ]; then
    return 0
  fi
  if [ -s "$appdata_probe/provider-credentials.enc.json" ]; then
    return 0
  fi
  if [ -s "$cluster_data_probe/provider-credentials.enc.json" ]; then
    return 0
  fi
  return 1
}

refuse_existing_installation() {
  cat >&2 <<EOF
ERROR: the '$1' secret is absent from its split volume, the legacy
       chancela-secrets volume, and docker/secrets/, but this deployment already
       has state that only that secret can unlock.

       Restore the original secret and rerun Compose. If the data is expendable,
       remove the deployment volumes together with the state using:

         docker compose --profile postgres down -v
EOF
  exit 1
}

# Validate every possible source before persisting anything. A stale ignored
# host file must not let a public placeholder linger unnoticed.
for directory in \
  "$postgres_password_dir" \
  "$database_url_dir" \
  "$credential_key_dir" \
  "$search_password_dir" \
  "$search_url_dir" \
  "$legacy_dir" \
  "$host_dir"
do
  for name in postgres_password database_url credential_key search_database_password search_database_url; do
    reject_unsafe_candidate "$directory/$name" "$name"
  done
  validate_db_password_file_if_present \
    "$directory/postgres_password" \
    "postgres_password"
  validate_db_password_file_if_present \
    "$directory/search_database_password" \
    "search_database_password"
done

api_prefix="postgres://$pg_user:"
api_suffix="@postgres:5432/$pg_db?sslmode=verify-full"
search_prefix="postgres://chancela_search_projector:"
search_suffix="@postgres:5432/$pg_db?sslmode=verify-full"

validate_pair_files_if_complete \
  "$legacy_dir/postgres_password" \
  "$legacy_dir/database_url" \
  "$api_prefix" \
  "$api_suffix" \
  "legacy API/Postgres"
validate_pair_files_if_complete \
  "$host_dir/postgres_password" \
  "$host_dir/database_url" \
  "$api_prefix" \
  "$api_suffix" \
  "host API/Postgres"
validate_pair_files_if_complete \
  "$host_dir/search_database_password" \
  "$host_dir/search_database_url" \
  "$search_prefix" \
  "$search_suffix" \
  "host search projector"
validate_pair_files_if_complete \
  "$pw_path" \
  "$url_path" \
  "$api_prefix" \
  "$api_suffix" \
  "split-volume API/Postgres"
validate_pair_files_if_complete \
  "$search_pw_path" \
  "$search_url_path" \
  "$search_prefix" \
  "$search_suffix" \
  "split-volume search projector"

pg_password=""
if ! pg_password="$(
  choose_value \
    "$pw_path" \
    "$legacy_dir/postgres_password" \
    "$host_dir/postgres_password"
)"; then
  installation_exists && refuse_existing_installation postgres_password
  pg_password="$(rand_secret 36)"
  echo "generated postgres_password (288-bit)"
fi
validate_db_password_value "$pg_password" "selected postgres_password"

database_url=""
if ! database_url="$(
  choose_value \
    "$url_path" \
    "$legacy_dir/database_url" \
    "$host_dir/database_url"
)"; then
  database_url="${api_prefix}${pg_password}${api_suffix}"
  echo "generated database_url from postgres_password"
fi
validate_pair_values "$pg_password" "$database_url" "$api_prefix" "$api_suffix" "API/Postgres"

credential_key=""
if ! credential_key="$(
  choose_value \
    "$key_path" \
    "$legacy_dir/credential_key" \
    "$host_dir/credential_key"
)"; then
  installation_exists && refuse_existing_installation credential_key
  credential_key="$(rand_secret 48)"
  echo "generated credential_key (384-bit)"
fi

search_password=""
if ! search_password="$(
  choose_value \
    "$search_pw_path" \
    "$legacy_dir/search_database_password" \
    "$host_dir/search_database_password"
)"; then
  if [ -s "$search_url_path" ] \
    || [ -s "$legacy_dir/search_database_url" ] \
    || [ -s "$host_dir/search_database_url" ]; then
    echo "ERROR: search_database_url exists without its password; refusing to invent a mismatch." >&2
    exit 1
  fi
  search_password="$(rand_secret 36)"
  echo "generated search_database_password (288-bit)"
fi
validate_db_password_value "$search_password" "selected search_database_password"

search_database_url=""
if ! search_database_url="$(
  choose_value \
    "$search_url_path" \
    "$legacy_dir/search_database_url" \
    "$host_dir/search_database_url"
)"; then
  search_database_url="${search_prefix}${search_password}${search_suffix}"
  echo "generated search_database_url from search_database_password"
fi
validate_pair_values \
  "$search_password" \
  "$search_database_url" \
  "$search_prefix" \
  "$search_suffix" \
  "search projector"

# Strict create-if-absent publication. A same-filesystem hard link publishes
# each fully prepared inode atomically and cannot overwrite a concurrent value.
[ -s "$pw_path" ] || publish_secret "$pw_path" "$pg_password"
[ -s "$url_path" ] || publish_secret "$url_path" "$database_url"
[ -s "$key_path" ] || publish_secret "$key_path" "$credential_key"
[ -s "$search_pw_path" ] || publish_secret "$search_pw_path" "$search_password"
[ -s "$search_url_path" ] || publish_secret "$search_url_path" "$search_database_url"

# Re-read every destination after publication. This closes the validation/use
# gap and proves that a concurrent initializer published the exact same values
# rather than a mismatched half-pair.
for destination in "$pw_path" "$url_path" "$key_path" "$search_pw_path" "$search_url_path"; do
  reject_unsafe_candidate "$destination" "${destination##*/}"
done
validate_db_password_file_if_present "$pw_path" "published postgres_password"
validate_db_password_file_if_present "$search_pw_path" "published search_database_password"
if [ "$(read_secret "$pw_path")" != "$pg_password" ] \
  || [ "$(read_secret "$url_path")" != "$database_url" ] \
  || [ "$(read_secret "$key_path")" != "$credential_key" ] \
  || [ "$(read_secret "$search_pw_path")" != "$search_password" ] \
  || [ "$(read_secret "$search_url_path")" != "$search_database_url" ]; then
  echo "ERROR: a split secret changed during atomic publication; refusing." >&2
  exit 1
fi
validate_pair_values \
  "$(read_secret "$pw_path")" \
  "$(read_secret "$url_path")" \
  "$api_prefix" \
  "$api_suffix" \
  "published API/Postgres"
validate_pair_values \
  "$(read_secret "$search_pw_path")" \
  "$(read_secret "$search_url_path")" \
  "$search_prefix" \
  "$search_suffix" \
  "published search projector"

for directory in \
  "$postgres_password_dir" \
  "$database_url_dir" \
  "$credential_key_dir" \
  "$search_password_dir" \
  "$search_url_dir"
do
  chown "$secret_owner" "$directory"
  chmod 0755 "$directory"
done
chown "$secret_owner" "$pw_path" "$url_path" "$key_path" "$search_pw_path" "$search_url_path"
chmod 0444 "$pw_path" "$url_path" "$key_path" "$search_pw_path" "$search_url_path"
for destination in "$pw_path" "$url_path" "$key_path" "$search_pw_path" "$search_url_path"; do
  reject_unsafe_candidate "$destination" "${destination##*/}"
done

echo "split secret volumes ready; legacy combined volume is migration-only."
