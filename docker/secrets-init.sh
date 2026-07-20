#!/bin/sh
# Populate the `chancela-secrets` named volume for the `postgres` profile.
#
# Runs as a one-shot compose service before postgres and the app start, exactly
# like postgres-tls-init: `depends_on: { condition: service_completed_successfully }`.
# That is possible only because the three secrets live in a NAMED VOLUME rather
# than in host bind mounts -- compose creates named volumes on its own, whereas
# a bind mount to a file that does not exist yet is validated (and mangled into
# a directory) before any container can run.
#
# Three inputs, in priority order, per secret:
#
#   1. the volume already holds it   -> keep it, untouched. Never rotate.
#   2. docker/secrets/<name> exists  -> adopt it (bind-mounted read-only at
#                                       $host_dir). This is the migration path
#                                       for installations created by
#                                       preflight-secrets.sh, and the escape
#                                       hatch for operators who manage their own.
#   3. neither                       -> generate.
#
# All three secrets are write-once in practice, so step 1 is not an
# optimisation, it is the safety property:
#
#   postgres_password  baked into chancela-pgdata the first time Postgres
#                      initialises; POSTGRES_PASSWORD_FILE is ignored on every
#                      later start. A new value locks the app out of its own
#                      database and looks like corruption.
#   database_url       embeds that same password inline, so it is NEVER
#                      generated independently -- always derived from whatever
#                      postgres_password holds, in the same run.
#   credential_key     decrypts the stored provider credentials; a new value
#                      makes every stored credential undecryptable.
set -eu

secrets_dir="${CHANCELA_SECRETS_DIR:-/secrets}"
host_dir="${CHANCELA_HOST_SECRETS_DIR:-/host-secrets}"
pgdata_probe="${CHANCELA_PGDATA_PROBE:-/probe/pgdata}"
appdata_probe="${CHANCELA_APPDATA_PROBE:-/probe/app-data}"

# postgres:*-alpine runs the server as uid/gid 70; our app image runs as 65532.
# Each secret is owned by, and readable ONLY by, the one process that needs it.
pg_uid="${CHANCELA_PG_SERVER_UID:-70}"
pg_gid="${CHANCELA_PG_SERVER_GID:-70}"
app_uid="${CHANCELA_APP_UID:-65532}"
app_gid="${CHANCELA_APP_GID:-65532}"

pg_db="${CHANCELA_PG_DB:-chancela}"
pg_user="${CHANCELA_PG_USER:-chancela}"

pw_path="$secrets_dir/postgres_password"
url_path="$secrets_dir/database_url"
key_path="$secrets_dir/credential_key"

mkdir -p "$secrets_dir"

# Cryptographically random, URL-safe, unpadded base64 of $1 bytes.
#
# URL-safe matters because the password is embedded in database_url's userinfo,
# where standard base64's "/" and "+" would need percent-encoding in one file
# but not the other -- which is exactly how the two drift apart. The alphabet
# here (A-Za-z0-9-_) is unreserved in a URI, so the same literal string is
# correct in both files.
rand_secret() {
  raw="$(openssl rand -base64 "$1")"
  printf '%s' "$raw" | tr -d '\n=' | tr '+/' '-_'
}

# Write $2 to $1 with no trailing newline, owned by $3:$4, mode 0400.
#
# umask 077 in a subshell so the file is never even briefly readable by anyone
# else, and so the tightened umask does not leak into the rest of the script.
write_secret() {
  if [ -z "$2" ]; then
    echo "ERROR: refusing to write an empty secret to $1" >&2
    exit 1
  fi
  (
    umask 077
    : >"$1"
    printf '%s' "$2" >"$1"
  )
  chown "$3:$4" "$1"
  chmod 0400 "$1"
}

# Read a single-line secret with surrounding newlines (and Windows CRs) removed.
# A secret file containing a newline is always a mistake -- it is the classic
# invisible authentication failure -- so strip rather than propagate.
read_secret() {
  tr -d '\r\n' <"$1"
}

# Copy docker/secrets/<name> into the volume if the volume does not have it.
# Returns 0 if the secret is present afterwards, 1 if it is still absent.
adopt_from_host() {
  name="$1"
  dest="$secrets_dir/$name"
  src="$host_dir/$name"

  [ -s "$dest" ] && return 0

  if [ -d "$src" ]; then
    echo "WARNING: $host_dir/$name is a DIRECTORY (debris from an older failed" >&2
    echo "         run); ignoring it. Remove docker/secrets/$name on the host." >&2
    return 1
  fi
  [ -f "$src" ] || return 1
  [ -s "$src" ] || {
    echo "WARNING: docker/secrets/$name is empty; ignoring it." >&2
    return 1
  }

  value="$(read_secret "$src")"
  write_secret "$dest" "$value" "$2" "$3"
  echo "adopted $name from docker/secrets/$name"
  if grep -q 'CHANGE_ME' "$dest" 2>/dev/null; then
    echo "WARNING: $name still contains the CHANGE_ME placeholder from the" >&2
    echo "         committed *.example template. It is public in the repo." >&2
  fi
  return 0
}

# True when this stack already holds state that one of the secrets is the only
# key to. Generating a fresh secret on top of that is strictly worse than
# stopping: Postgres keeps the password baked into its data directory, and the
# credential store cannot be decrypted with a new key.
#
# Both volumes are mounted read-only here purely to answer this question.
installation_exists() {
  # Postgres has initialised its data directory (PG18 nests PGDATA one level
  # below the volume root, hence the depth).
  if [ -n "$(find "$pgdata_probe" -maxdepth 4 -name PG_VERSION -type f 2>/dev/null | head -n 1)" ]; then
    return 0
  fi
  # SQLite-era credential sidecar in the app data volume.
  if [ -s "$appdata_probe/provider-credentials.enc.json" ]; then
    return 0
  fi
  return 1
}

refuse_existing_installation() {
  cat >&2 <<EOF
ERROR: the '$1' secret is absent from the chancela-secrets volume and from
       docker/secrets/, but this deployment already has state that only that
       secret can unlock (an initialised chancela-pgdata and/or an existing
       provider-credential store).

       Generating a new value here would produce a stack that fails
       authentication -- or a credential store nobody can decrypt -- which
       looks like corruption rather than misconfiguration. Refusing.

       Either restore the secret (drop the original file into docker/secrets/,
       it is adopted on the next 'up'), or -- if the data is expendable --
       discard the state and start clean:

         docker compose --profile postgres down -v
EOF
  exit 1
}

# --- postgres_password + database_url are ONE unit ------------------------
#
# The URL carries the same password inline, so a half-generated pair is a
# guaranteed authentication failure. The URL is always built from whatever
# postgres_password holds on disk in this same run -- freshly generated or
# pre-existing -- so consistency is by construction, not by convention.

adopt_from_host postgres_password "$pg_uid" "$pg_gid" || true
adopt_from_host database_url "$app_uid" "$app_gid" || true

if [ ! -s "$pw_path" ]; then
  if [ -s "$url_path" ]; then
    cat >&2 <<'EOF'
ERROR: database_url is present but postgres_password is not. The URL embeds the
       password, so the password is recoverable only from that URL -- generating
       a new one would desynchronise the pair. Refusing.

       Copy the password out of database_url (between ':' and '@') into
       docker/secrets/postgres_password and run 'up' again.
EOF
    exit 1
  fi
  installation_exists && refuse_existing_installation postgres_password
  write_secret "$pw_path" "$(rand_secret 36)" "$pg_uid" "$pg_gid"
  echo "generated postgres_password (288-bit)"
fi

if [ ! -s "$url_path" ]; then
  write_secret "$url_path" \
    "postgres://$pg_user:$(read_secret "$pw_path")@postgres:5432/$pg_db?sslmode=verify-full" \
    "$app_uid" "$app_gid"
  echo "generated database_url (derived from postgres_password)"
fi

# --- credential_key -------------------------------------------------------

adopt_from_host credential_key "$app_uid" "$app_gid" || true

if [ ! -s "$key_path" ]; then
  installation_exists && refuse_existing_installation credential_key
  write_secret "$key_path" "$(rand_secret 48)" "$app_uid" "$app_gid"
  echo "generated credential_key (384-bit)"
fi

# Re-assert ownership and mode on every run: a volume restored from a backup,
# or written by an older revision of this script, may not have them.
chmod 0755 "$secrets_dir"
chown "$pg_uid:$pg_gid" "$pw_path"
chown "$app_uid:$app_gid" "$url_path" "$key_path"
chmod 0400 "$pw_path" "$url_path" "$key_path"

# Anything still on the host that the volume already had is deliberately NOT
# re-read: the volume is authoritative once populated (see the header).
for name in postgres_password database_url credential_key; do
  if [ -s "$host_dir/$name" ] && ! cmp -s "$host_dir/$name" "$secrets_dir/$name"; then
    echo "NOTE: docker/secrets/$name differs from the value already in the" >&2
    echo "      chancela-secrets volume; the VOLUME wins. Delete the volume" >&2
    echo "      (down -v) to re-adopt the host file." >&2
  fi
done

echo "chancela-secrets: postgres_password, database_url, credential_key ready."
