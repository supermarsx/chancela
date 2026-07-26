#!/bin/sh
# Focused regression fixtures for host preflight validation and publication.
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
preflight="$repo_root/docker/preflight-secrets.sh"
fixture_root="${TMPDIR:-/tmp}/chancela-preflight-secrets-$$"
api_password='FixtureApiPassword_0123456789abcdefXYZ'
search_password='FixtureSearchPassword_0123456789abcXYZ'

cleanup() {
  rm -rf "$fixture_root"
}
trap cleanup EXIT HUP INT TERM

make_valid_fixture() {
  target="$1"
  mkdir -p "$target"
  printf '%s' "$api_password" >"$target/postgres_password"
  printf 'postgres://chancela:%s@postgres:5432/chancela?sslmode=verify-full' \
    "$api_password" >"$target/database_url"
  printf '%s' 'fixture-credential-key' >"$target/credential_key"
  printf '%s' "$search_password" >"$target/search_database_password"
  printf 'postgres://chancela_search_projector:%s@postgres:5432/chancela?sslmode=verify-full' \
    "$search_password" >"$target/search_database_url"
}

expect_pass() {
  label="$1"
  target="$2"
  if ! CHANCELA_HOST_SECRETS_DIR="$target" sh "$preflight" >/dev/null 2>&1; then
    echo "FAIL: $label should have passed" >&2
    exit 1
  fi
}

expect_fail() {
  label="$1"
  target="$2"
  if CHANCELA_HOST_SECRETS_DIR="$target" sh "$preflight" >/dev/null 2>&1; then
    echo "FAIL: $label should have failed" >&2
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

valid="$fixture_root/valid"
make_valid_fixture "$valid"
expect_pass "matching non-placeholder pairs" "$valid"

placeholder="$fixture_root/placeholder"
make_valid_fixture "$placeholder"
printf '%s' 'cHaNgE_mE' >"$placeholder/credential_key"
expect_fail "case-insensitive public placeholder" "$placeholder"

mismatch="$fixture_root/mismatch"
make_valid_fixture "$mismatch"
printf '%s' \
  'postgres://chancela_search_projector:not-the-password@postgres:5432/chancela?sslmode=verify-full' \
  >"$mismatch/search_database_url"
expect_fail "mismatched password and URL" "$mismatch"

short_password="$fixture_root/short-password"
make_valid_fixture "$short_password"
printf '%s' 'too-short' >"$short_password/postgres_password"
printf '%s' \
  'postgres://chancela:too-short@postgres:5432/chancela?sslmode=verify-full' \
  >"$short_password/database_url"
expect_fail "short database password" "$short_password"

unsafe_password="$fixture_root/unsafe-password"
make_valid_fixture "$unsafe_password"
unsafe_value='FixturePasswordWithPercent_0123456789%'
printf '%s' "$unsafe_value" >"$unsafe_password/postgres_password"
printf 'postgres://chancela:%s@postgres:5432/chancela?sslmode=verify-full' \
  "$unsafe_value" >"$unsafe_password/database_url"
expect_fail "non-URI-safe database password" "$unsafe_password"

newline="$fixture_root/newline"
make_valid_fixture "$newline"
printf '\r\n' >>"$newline/credential_key"
expect_fail "secret with CRLF" "$newline"

symlink="$fixture_root/symlink"
make_valid_fixture "$symlink"
rm -f "$symlink/credential_key"
ln -s "$valid/credential_key" "$symlink/credential_key"
expect_fail "symbolic-link secret" "$symlink"

generated="$fixture_root/generated"
mkdir -p "$generated"
printf '%s' "$api_password" >"$generated/postgres_password"
printf '%s' "$search_password" >"$generated/search_database_password"
CHANCELA_HOST_SECRETS_DIR="$generated" sh "$preflight" --generate >/dev/null
expect_pass "generated missing URL/key files" "$generated"
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  cp "$generated/$name" "$fixture_root/generated-$name.snapshot"
  assert_mode_if_supported "$generated/$name" 600
done
CHANCELA_HOST_SECRETS_DIR="$generated" sh "$preflight" --generate >/dev/null
for name in postgres_password database_url credential_key search_database_password search_database_url; do
  if ! cmp -s "$generated/$name" "$fixture_root/generated-$name.snapshot"; then
    echo "FAIL: --generate overwrote existing $name" >&2
    exit 1
  fi
done

# A stale staging directory from an interrupted process must not block mktemp
# recovery, and it must never be mistaken for a published secret.
recovery="$fixture_root/recovery"
mkdir -p "$recovery/.chancela-database_url.publish.999999"
printf '%s' "$api_password" >"$recovery/postgres_password"
printf '%s' "$search_password" >"$recovery/search_database_password"
CHANCELA_HOST_SECRETS_DIR="$recovery" sh "$preflight" --generate >/dev/null
expect_pass "interrupted-publication recovery" "$recovery"

# Two initializers with the same fixed passwords may race on generated peers.
# At least one must complete and the final five-file set must validate.
race="$fixture_root/race"
mkdir -p "$race"
printf '%s' "$api_password" >"$race/postgres_password"
printf '%s' "$search_password" >"$race/search_database_password"
CHANCELA_HOST_SECRETS_DIR="$race" sh "$preflight" --generate >/dev/null 2>&1 &
first_pid=$!
CHANCELA_HOST_SECRETS_DIR="$race" sh "$preflight" --generate >/dev/null 2>&1 &
second_pid=$!
first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
if [ "$first_status" -ne 0 ] && [ "$second_status" -ne 0 ]; then
  echo "FAIL: both racing preflight publishers failed" >&2
  exit 1
fi
expect_pass "race-safe final secret set" "$race"

# Mock Docker to prove discovery uses Compose labels, custom project names, and
# exact nonempty content probes rather than volume existence.
mock_docker="$fixture_root/mock-docker"
mock_log="$fixture_root/mock-docker.log"
cat >"$mock_docker" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$MOCK_DOCKER_LOG"
case "${1:-}:${2:-}" in
  volume:ls)
    key=""
    for argument in "$@"; do
      case "$argument" in
        label=com.docker.compose.volume=*)
          key="${argument##*=}"
          ;;
      esac
    done
    [ -n "$key" ] && printf '%s_%s\n' "$MOCK_PROJECT" "$key"
    ;;
  volume:inspect)
    printf '%s\n' "$MOCK_PROJECT"
    ;;
  run:*)
    case "$*" in
      *PG_VERSION*)
        [ "$MOCK_VOLUME_STATE" = "pgdata-present" ]
        ;;
      *)
        last=""
        for argument in "$@"; do
          last="$argument"
        done
        if [ "$MOCK_VOLUME_STATE" = "complete" ]; then
          exit 0
        fi
        if [ "$MOCK_VOLUME_STATE" = "incomplete" ] \
          && [ "$last" != "credential_key" ]; then
          exit 0
        fi
        exit 1
        ;;
    esac
    ;;
esac
MOCK
chmod 0700 "$mock_docker"

managed="$fixture_root/managed"
mkdir -p "$managed"
MOCK_DOCKER_LOG="$mock_log" \
MOCK_PROJECT='custom-audit-project' \
MOCK_VOLUME_STATE=complete \
CHANCELA_DOCKER_BIN="$mock_docker" \
CHANCELA_HOST_SECRETS_DIR="$managed" \
  sh "$preflight" >/dev/null
if ! grep -q 'label=com.docker.compose.project=custom-audit-project' "$mock_log"; then
  echo "FAIL: custom Compose project label was not used for secret discovery" >&2
  exit 1
fi

incomplete="$fixture_root/incomplete-managed"
mkdir -p "$incomplete"
if MOCK_DOCKER_LOG="$mock_log" \
  MOCK_PROJECT='custom-audit-project' \
  MOCK_VOLUME_STATE=incomplete \
  CHANCELA_DOCKER_BIN="$mock_docker" \
  CHANCELA_HOST_SECRETS_DIR="$incomplete" \
    sh "$preflight" >/dev/null 2>&1; then
  echo "FAIL: existing but incomplete labeled volumes should not pass" >&2
  exit 1
fi

pgdata_present="$fixture_root/pgdata-present"
mkdir -p "$pgdata_present"
if MOCK_DOCKER_LOG="$mock_log" \
  MOCK_PROJECT='custom-audit-project' \
  MOCK_VOLUME_STATE=pgdata-present \
  CHANCELA_DOCKER_BIN="$mock_docker" \
  CHANCELA_HOST_SECRETS_DIR="$pgdata_present" \
    sh "$preflight" --generate >/dev/null 2>&1; then
  echo "FAIL: nonempty PG_VERSION in a custom-project volume should block generation" >&2
  exit 1
fi
if [ -e "$pgdata_present/postgres_password" ]; then
  echo "FAIL: pgdata refusal persisted a password" >&2
  exit 1
fi

pgdata_empty="$fixture_root/pgdata-empty"
mkdir -p "$pgdata_empty"
MOCK_DOCKER_LOG="$mock_log" \
MOCK_PROJECT='custom-audit-project' \
MOCK_VOLUME_STATE=pgdata-empty \
CHANCELA_DOCKER_BIN="$mock_docker" \
CHANCELA_HOST_SECRETS_DIR="$pgdata_empty" \
  sh "$preflight" --generate >/dev/null
expect_pass "empty labeled pgdata permits generation" "$pgdata_empty"

echo "preflight secret fixtures passed"
