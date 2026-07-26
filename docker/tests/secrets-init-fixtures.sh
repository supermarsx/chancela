#!/bin/sh
# Regression fixtures for split-volume initialization and legacy migration.
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
secrets_init="$repo_root/docker/secrets-init.sh"
fixture_root="${TMPDIR:-/tmp}/chancela-secrets-init-$$"
legacy_api_password='LegacyApiPassword_0123456789abcdefXYZ'
legacy_search_password='LegacySearchPassword_0123456789abcXYZ'
host_api_password='HostApiPassword_0123456789abcdefXYZ12'
host_search_password='HostSearchPassword_0123456789abcdefXYZ'

cleanup() {
  rm -rf "$fixture_root"
}
trap cleanup EXIT HUP INT TERM

prepare_case() {
  case_root="$1"
  for directory in legacy host postgres-password database-url credential-key search-password search-url pgdata appdata cluster-data; do
    mkdir -p "$case_root/$directory"
  done
}

run_init() {
  case_root="$1"
  CHANCELA_LEGACY_SECRETS_DIR="$case_root/legacy" \
  CHANCELA_POSTGRES_PASSWORD_DIR="$case_root/postgres-password" \
  CHANCELA_DATABASE_URL_DIR="$case_root/database-url" \
  CHANCELA_CREDENTIAL_KEY_DIR="$case_root/credential-key" \
  CHANCELA_SEARCH_PASSWORD_DIR="$case_root/search-password" \
  CHANCELA_SEARCH_URL_DIR="$case_root/search-url" \
  CHANCELA_HOST_SECRETS_DIR="$case_root/host" \
  CHANCELA_PGDATA_PROBE="$case_root/pgdata" \
  CHANCELA_APPDATA_PROBE="$case_root/appdata" \
  CHANCELA_CLUSTER_DATA_PROBE="$case_root/cluster-data" \
  CHANCELA_SECRET_VOLUME_OWNER="$(id -u):$(id -g)" \
    sh "$secrets_init"
}

write_pair_set() {
  target="$1"
  api_password="$2"
  search_password="$3"
  printf '%s' "$api_password" >"$target/postgres_password"
  printf 'postgres://chancela:%s@postgres:5432/chancela?sslmode=verify-full' \
    "$api_password" >"$target/database_url"
  printf '%s' 'fixture-credential-key' >"$target/credential_key"
  printf '%s' "$search_password" >"$target/search_database_password"
  printf 'postgres://chancela_search_projector:%s@postgres:5432/chancela?sslmode=verify-full' \
    "$search_password" >"$target/search_database_url"
}

assert_equal_files() {
  left="$1"
  right="$2"
  label="$3"
  if ! cmp -s "$left" "$right"; then
    echo "FAIL: $label differs" >&2
    exit 1
  fi
}

assert_mode_if_supported() {
  path="$1"
  expected="$2"
  case "$(uname -s)" in
    CYGWIN* | MINGW* | MSYS*)
      return 0
      ;;
  esac
  actual="$(stat -c '%a' "$path")"
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: $path has mode $actual, expected $expected" >&2
    exit 1
  fi
}

destination_path() {
  case "$2" in
    postgres_password) printf '%s/postgres-password/postgres_password' "$1" ;;
    database_url) printf '%s/database-url/database_url' "$1" ;;
    credential_key) printf '%s/credential-key/credential_key' "$1" ;;
    search_database_password) printf '%s/search-password/search_database_password' "$1" ;;
    search_database_url) printf '%s/search-url/search_database_url' "$1" ;;
  esac
}

legacy_case="$fixture_root/legacy"
prepare_case "$legacy_case"
write_pair_set "$legacy_case/legacy" "$legacy_api_password" "$legacy_search_password"
run_init "$legacy_case" >/dev/null
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  destination="$(destination_path "$legacy_case" "$name")"
  assert_equal_files "$legacy_case/legacy/$name" "$destination" "legacy $name migration"
  assert_mode_if_supported "$destination" 444
done
for directory in postgres-password database-url credential-key search-password search-url; do
  assert_mode_if_supported "$legacy_case/$directory" 755
done

host_case="$fixture_root/host"
prepare_case "$host_case"
write_pair_set "$host_case/host" "$host_api_password" "$host_search_password"
run_init "$host_case" >/dev/null
assert_equal_files \
  "$host_case/host/search_database_url" \
  "$host_case/search-url/search_database_url" \
  "host projector URL adoption"

# Every split destination, not only the projector URL, is authoritative after
# the first successful run.
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  cp "$(destination_path "$host_case" "$name")" "$fixture_root/original-$name"
done
write_pair_set \
  "$host_case/host" \
  'ReplacementApiPassword_0123456789abcdefXYZ' \
  'ReplacementSearchPassword_0123456789abcXYZ'
run_init "$host_case" >/dev/null
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  assert_equal_files \
    "$fixture_root/original-$name" \
    "$(destination_path "$host_case" "$name")" \
    "create-if-absent $name"
done

placeholder_case="$fixture_root/placeholder"
prepare_case "$placeholder_case"
write_pair_set "$placeholder_case/host" "$host_api_password" "$host_search_password"
printf '%s' 'cHaNgE_mE' >"$placeholder_case/host/credential_key"
if run_init "$placeholder_case" >/dev/null 2>&1; then
  echo "FAIL: case-insensitive placeholder input should have failed" >&2
  exit 1
fi
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  if [ -e "$(destination_path "$placeholder_case" "$name")" ]; then
    echo "FAIL: placeholder rejection persisted a destination secret" >&2
    exit 1
  fi
done

empty_case="$fixture_root/empty"
prepare_case "$empty_case"
write_pair_set "$empty_case/host" "$host_api_password" "$host_search_password"
: >"$empty_case/host/credential_key"
if run_init "$empty_case" >/dev/null 2>&1; then
  echo "FAIL: empty source secret should have failed" >&2
  exit 1
fi

mismatch_case="$fixture_root/mismatch"
prepare_case "$mismatch_case"
write_pair_set "$mismatch_case/host" "$host_api_password" "$host_search_password"
printf '%s' \
  'postgres://chancela_search_projector:wrong@postgres:5432/chancela?sslmode=verify-full' \
  >"$mismatch_case/host/search_database_url"
if run_init "$mismatch_case" >/dev/null 2>&1; then
  echo "FAIL: mismatched projector pair should have failed" >&2
  exit 1
fi

source_symlink="$fixture_root/source-symlink"
prepare_case "$source_symlink"
write_pair_set "$source_symlink/host" "$host_api_password" "$host_search_password"
rm -f "$source_symlink/host/credential_key"
ln -s "$host_case/host/credential_key" "$source_symlink/host/credential_key"
if run_init "$source_symlink" >/dev/null 2>&1; then
  echo "FAIL: source symlink should have failed" >&2
  exit 1
fi

destination_symlink="$fixture_root/destination-symlink"
prepare_case "$destination_symlink"
write_pair_set "$destination_symlink/host" "$host_api_password" "$host_search_password"
ln -s "$destination_symlink/not-a-secret" \
  "$destination_symlink/postgres-password/postgres_password"
if run_init "$destination_symlink" >/dev/null 2>&1; then
  echo "FAIL: destination symlink should have failed" >&2
  exit 1
fi

# A stale staging directory left by an interrupted process cannot be treated as
# a secret and does not block a later mktemp-backed atomic publication.
recovery="$fixture_root/recovery"
prepare_case "$recovery"
write_pair_set "$recovery/host" "$host_api_password" "$host_search_password"
mkdir -p "$recovery/postgres-password/.chancela-postgres_password.publish.999999"
run_init "$recovery" >/dev/null

# Concurrent initializers using the same operator-managed set must converge on
# exactly the same five published inodes without clobbering.
race="$fixture_root/race"
prepare_case "$race"
write_pair_set "$race/host" "$host_api_password" "$host_search_password"
run_init "$race" >/dev/null 2>&1 &
first_pid=$!
run_init "$race" >/dev/null 2>&1 &
second_pid=$!
first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
if [ "$first_status" -ne 0 ] && [ "$second_status" -ne 0 ]; then
  echo "FAIL: both racing split-volume initializers failed" >&2
  exit 1
fi
run_init "$race" >/dev/null
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  assert_equal_files \
    "$race/host/$name" \
    "$(destination_path "$race" "$name")" \
    "race-safe $name"
done

# Cluster application state is an equally authoritative credential-key probe.
# Refuse regeneration before publishing any other destination secret.
cluster_state="$fixture_root/cluster-state"
prepare_case "$cluster_state"
write_pair_set "$cluster_state/host" "$host_api_password" "$host_search_password"
rm -f "$cluster_state/host/credential_key"
printf '%s' 'existing-encrypted-provider-state' \
  >"$cluster_state/cluster-data/provider-credentials.enc.json"
if run_init "$cluster_state" >/dev/null 2>&1; then
  echo "FAIL: existing cluster credential state should block key generation" >&2
  exit 1
fi
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  if [ -e "$(destination_path "$cluster_state" "$name")" ]; then
    echo "FAIL: cluster-state refusal persisted $name" >&2
    exit 1
  fi
done

echo "split secret initialization fixtures passed"
