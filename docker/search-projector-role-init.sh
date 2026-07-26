#!/bin/sh
# Provision and verify the deliberately narrow PostgreSQL role used by the
# socketless full-search projector. The API/schema owner must run first.
set -eu

admin_url_file="${CHANCELA_DATABASE_URL_FILE:-/run/database-url/database_url}"
admin_password_file="${CHANCELA_POSTGRES_PASSWORD_FILE:-/run/postgres-password/postgres_password}"
projector_url_file="${CHANCELA_SEARCH_DATABASE_URL_FILE:-/run/search-url/search_database_url}"
projector_password_file="${CHANCELA_SEARCH_DATABASE_PASSWORD_FILE:-/run/search-password/search_database_password}"
tls_root_cert="${CHANCELA_PG_TLS_ROOT_CERT:-/run/chancela-postgres-tls/ca.crt}"
pg_db="${CHANCELA_PG_DB:-chancela}"
pg_user="${CHANCELA_PG_USER:-chancela}"
dedicated_database_ack="${CHANCELA_PROJECTOR_DEDICATED_DATABASE:-}"
db_password_min_length=32
mode="${1:-apply}"

case "$mode" in
  apply | verify) ;;
  *)
    echo "usage: search-projector-role-init.sh [apply|verify]" >&2
    exit 2
    ;;
esac

case "$dedicated_database_ack" in
  true)
    ;;
  *)
    cat >&2 <<'EOF'
ERROR: the restricted projector role requires database-global PUBLIC ACL
       revocations. Set CHANCELA_PROJECTOR_DEDICATED_DATABASE=true only after
       confirming that this PostgreSQL database is dedicated to Chancela.
EOF
    exit 1
    ;;
esac

read_secret() {
  path="$1"
  label="$2"
  if [ -L "$path" ]; then
    echo "ERROR: $label at $path is a symbolic link; secret links are forbidden" >&2
    exit 1
  fi
  if [ ! -f "$path" ] || [ ! -s "$path" ]; then
    echo "ERROR: missing or empty $label at $path" >&2
    exit 1
  fi
  secret_value="$(tr -d '\r\n' <"$path")"
  raw_bytes="$(wc -c <"$path" | tr -d '[:space:]')"
  clean_bytes="$(printf '%s' "$secret_value" | wc -c | tr -d '[:space:]')"
  if [ "$raw_bytes" != "$clean_bytes" ]; then
    echo "ERROR: $label contains a CR or LF; secret files must be exact single values" >&2
    exit 1
  fi
  printf '%s' "$secret_value"
}

validate_db_password() {
  password_value="$1"
  password_label="$2"
  if [ "${#password_value}" -lt "$db_password_min_length" ]; then
    echo "ERROR: $password_label must contain at least $db_password_min_length characters" >&2
    exit 1
  fi
  case "$password_value" in
    *[!A-Za-z0-9._~-]*)
      echo "ERROR: $password_label contains characters outside the URI-unreserved set" >&2
      exit 1
      ;;
  esac
}

admin_url="$(read_secret "$admin_url_file" "API database URL")"
admin_password="$(read_secret "$admin_password_file" "Postgres owner password")"
projector_url="$(read_secret "$projector_url_file" "search-projector database URL")"
projector_password="$(read_secret "$projector_password_file" "search-projector database password")"

for secret_label in \
  "API database URL:$admin_url" \
  "Postgres owner password:$admin_password" \
  "search-projector database URL:$projector_url" \
  "search-projector database password:$projector_password"
do
  label="${secret_label%%:*}"
  value="${secret_label#*:}"
  lowercase_value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$lowercase_value" in
    *change_me*)
      echo "ERROR: $label contains the public CHANGE_ME placeholder" >&2
      exit 1
      ;;
  esac
done
validate_db_password "$admin_password" "Postgres owner password"
validate_db_password "$projector_password" "search-projector database password"

expected_admin_url="postgres://$pg_user:$admin_password@postgres:5432/$pg_db?sslmode=verify-full"
expected_projector_url="postgres://chancela_search_projector:$projector_password@postgres:5432/$pg_db?sslmode=verify-full"
if [ "$admin_url" != "$expected_admin_url" ]; then
  echo "ERROR: API database URL does not match its password or this local Compose profile" >&2
  exit 1
fi
if [ "$projector_url" != "$expected_projector_url" ]; then
  echo "ERROR: search-projector database URL does not match its password or this local Compose profile" >&2
  exit 1
fi

escape_pgpass() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/:/\\:/g'
}

pgpass_file="/tmp/chancela-projector-role-init.pgpass"
(
  umask 077
  {
    printf 'postgres:5432:%s:%s:%s\n' \
      "$pg_db" "$pg_user" "$(escape_pgpass "$admin_password")"
    printf 'postgres:5432:%s:%s:%s\n' \
      "$pg_db" "chancela_search_projector" "$(escape_pgpass "$projector_password")"
  } >"$pgpass_file"
)
export PGPASSFILE="$pgpass_file"

# Password-free connection strings keep both database passwords out of argv and
# the process environment. libpq obtains them from the 0600 tmpfs passfile.
admin_conninfo="postgres://$pg_user@postgres:5432/$pg_db?sslmode=verify-full"
projector_conninfo="postgres://chancela_search_projector@postgres:5432/$pg_db?sslmode=verify-full"
acl_probe_created=0

drop_acl_probe() {
  psql "$admin_conninfo" -X --set=ON_ERROR_STOP=1 \
    -c 'DROP FUNCTION IF EXISTS public.chancela_projector_acl_probe()' \
    >/dev/null 2>&1
}

cleanup_role_init() {
  if [ "$acl_probe_created" -eq 1 ]; then
    if drop_acl_probe; then
      acl_probe_created=0
    else
      echo "WARNING: could not remove the transient projector ACL probe" >&2
    fi
  fi
  rm -f "$pgpass_file" /tmp/search-projector-acl-denial.log
}
trap 'cleanup_role_init' EXIT
trap 'cleanup_role_init; exit 130' HUP INT TERM

unset admin_url admin_password projector_url projector_password expected_admin_url expected_projector_url

# libpq otherwise searches the current uid's home directory for root.crt. The
# Compose profiles mount the private deployment CA at this explicit path.
export PGSSLROOTCERT="$tls_root_cert"
export CHANCELA_SEARCH_DATABASE_PASSWORD_FILE="$projector_password_file"

if [ "$mode" = "apply" ]; then
  # Recover cleanly if an earlier interrupted initializer left its reserved,
  # side-effect-free ACL probe behind.
  drop_acl_probe
  acl_probe_created=1
  # Keep the password out of argv and the process environment: psql reads the
  # fixed secret file into a quoted variable inside the client.
  psql "$admin_conninfo" -X --set=ON_ERROR_STOP=1 <<'SQL'
\set projector_password `cat "$CHANCELA_SEARCH_DATABASE_PASSWORD_FILE"`

BEGIN;

SELECT
  'CREATE ROLE chancela_search_projector LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (
  SELECT 1 FROM pg_roles WHERE rolname = 'chancela_search_projector'
)
\gexec

-- Reassert the role posture and password on every deployment. Password
-- rotation is therefore an explicit secret-file change followed by this
-- one-shot initializer, never an implicit application migration.
ALTER ROLE chancela_search_projector
  WITH LOGIN PASSWORD :'projector_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  VALID UNTIL 'infinity'
  -- A rolling deployment can temporarily overlap active and standby projector
  -- processes. Each process uses the bounded r2d2 default (10) plus one
  -- follower writer connection, so 32 covers the 22-connection process overlap
  -- and deployment/health probes without making the role unbounded.
  CONNECTION LIMIT 32;

-- Refuse a pre-existing role that owns database objects. Ownership bypasses
-- GRANT/REVOKE and would make the allowlist below cosmetic.
DO $guard$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_database database
    JOIN pg_roles role ON role.oid = database.datdba
    WHERE role.rolname = 'chancela_search_projector'
  ) OR EXISTS (
    SELECT 1
    FROM pg_namespace namespace
    JOIN pg_roles role ON role.oid = namespace.nspowner
    WHERE role.rolname = 'chancela_search_projector'
  ) OR EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_roles role ON role.oid = relation.relowner
    WHERE role.rolname = 'chancela_search_projector'
  ) OR EXISTS (
    SELECT 1
    FROM pg_proc routine
    JOIN pg_roles role ON role.oid = routine.proowner
    WHERE role.rolname = 'chancela_search_projector'
  ) OR EXISTS (
    SELECT 1
    FROM pg_type object_type
    JOIN pg_roles role ON role.oid = object_type.typowner
    WHERE role.rolname = 'chancela_search_projector'
  ) OR EXISTS (
    SELECT 1
    FROM pg_shdepend dependency
    JOIN pg_roles role ON role.oid = dependency.refobjid
    JOIN pg_database database ON database.datname = current_database()
    WHERE role.rolname = 'chancela_search_projector'
      AND dependency.refclassid = 'pg_authid'::regclass
      AND dependency.deptype = 'o'
      AND dependency.dbid IN (0, database.oid)
  ) THEN
    RAISE EXCEPTION
      'refusing projector role that owns database, schema, relation, routine, or type objects';
  END IF;
END
$guard$;

-- Remove both directions of role membership before rebuilding the ACL. Being
-- a member of another role inherits capability; having members exposes this
-- role's grants to additional principals.
SELECT format(
  'REVOKE %I FROM chancela_search_projector',
  parent_role.rolname
)
FROM pg_auth_members membership
JOIN pg_roles parent_role ON parent_role.oid = membership.roleid
JOIN pg_roles member_role ON member_role.oid = membership.member
WHERE member_role.rolname = 'chancela_search_projector'
\gexec
SELECT format(
  'REVOKE chancela_search_projector FROM %I',
  member_role.rolname
)
FROM pg_auth_members membership
JOIN pg_roles projector_role ON projector_role.oid = membership.roleid
JOIN pg_roles member_role ON member_role.oid = membership.member
WHERE projector_role.rolname = 'chancela_search_projector'
\gexec

SELECT format(
  'REVOKE ALL PRIVILEGES ON DATABASE %I FROM chancela_search_projector',
  current_database()
)
\gexec
-- These are database-global changes. The shell requires the explicit
-- CHANCELA_PROJECTOR_DEDICATED_DATABASE=true acknowledgement before reaching
-- this transaction, because applying them to a shared database is unsafe.
SELECT format(
  'REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC',
  current_database()
)
\gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM chancela_search_projector;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM chancela_search_projector;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM chancela_search_projector;
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM chancela_search_projector;
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
  current_user
)
\gexec

SELECT format(
  'GRANT CONNECT ON DATABASE %I TO chancela_search_projector',
  current_database()
)
\gexec
GRANT USAGE ON SCHEMA public TO chancela_search_projector;

-- Authoritative corpus inputs, granted column-by-column to match the exact
-- projector queries. Authentication, tenant/pairing/signing/provider tables
-- are absent, as are retained PDF/import bytes and generated spec/layout text.
GRANT SELECT (json)
  ON TABLE entities, books, acts, group_template_libraries,
    group_template_library_revisions
  TO chancela_search_projector;
GRANT SELECT (entity_id, json)
  ON TABLE registry_extracts
  TO chancela_search_projector;
GRANT SELECT (
  id, act_id, agenda_number, deliberation_index, title, detail, due_date,
  assignee, assignee_display, status, created_at, created_by, completed_at,
  completed_by
) ON TABLE follow_ups TO chancela_search_projector;
GRANT SELECT (
  seq, id, actor, justification, timestamp, scope, kind, payload_digest,
  prev_hash, hash, links
) ON TABLE events TO chancela_search_projector;
GRANT SELECT (key, value)
  ON TABLE meta
  TO chancela_search_projector;
-- `settings.id` is required by the fixed singleton predicates; `json` carries
-- the main settings document plus the authoritative backup-recovery and
-- privacy-control singleton documents. No settings write privilege is granted.
GRANT SELECT (id, json)
  ON TABLE settings, user_templates
  TO chancela_search_projector;
GRANT SELECT (id, act_id, template_id, pdf_digest, profile, created_at)
  ON TABLE documents
  TO chancela_search_projector;
GRANT SELECT (
  document_id, idempotency_key, act_id, template_id, actor, dispatched_at,
  channel, reference, evidence_reference, imported_document_id,
  recipients_json, operator_note, recorded_at
) ON TABLE generated_document_dispatch_evidence TO chancela_search_projector;
GRANT SELECT (
  id, act_id, filename, declared_content_type, detected_content_type, sha256,
  size_bytes, imported_at, imported_by, operator_review_status,
  operator_reviewed_at, operator_reviewed_by, operator_review_note,
  operator_acknowledged_guardrail_ids_json, technical_validation_report_json
) ON TABLE imported_documents TO chancela_search_projector;
GRANT SELECT (
  id, imported_document_id, review_status, reviewed_at, reviewed_by,
  review_note, acknowledged_guardrail_ids_json
) ON TABLE imported_document_review_history TO chancela_search_projector;
GRANT SELECT (
  import_id, entity_ref, entity_name, entity_nipc, book_ref, date_from,
  date_to, page_count, page_from, page_to, original_number_from,
  original_number_to, sha256, size_bytes, content_type, source_filename,
  notes, imported_at, imported_by, ocr_status
) ON TABLE paper_book_imports TO chancela_search_projector;
GRANT SELECT (
  draft_id, import_id, extracted_text, text_digest, page_spans_json,
  confidence, engine_name, engine_version, created_at, created_by,
  review_status, reviewed_at, reviewed_by, review_note, superseded_by
) ON TABLE paper_book_ocr_drafts TO chancela_search_projector;

-- Derived projection state. The API creates/migrates these tables and the
-- singleton control row before this initializer runs.
GRANT SELECT (
  id, source_revision, fence_token, published_source_revision,
  published_fence_token, published_command_generation, command,
  command_generation, lease_id, lease_owner, lease_heartbeat_at,
  lease_expires_at_unix_ms, updated_at
) ON TABLE search_projection_control TO chancela_search_projector;
GRANT UPDATE (
  published_source_revision, published_fence_token,
  published_command_generation, command, lease_id, lease_owner,
  lease_heartbeat_at, lease_expires_at_unix_ms, updated_at
) ON TABLE search_projection_control TO chancela_search_projector;
GRANT SELECT (id, json), INSERT (id, json), UPDATE (json), DELETE
  ON TABLE search_documents
  TO chancela_search_projector;
GRANT SELECT (id, json), INSERT (id, json), UPDATE (json)
  ON TABLE search_index_state
  TO chancela_search_projector;

-- A side-effect-free live routine probe is removed by the shell on every exit.
-- It exists during the effective-ACL checks solely to prove PUBLIC/projector
-- routine EXECUTE remains denied.
CREATE OR REPLACE FUNCTION public.chancela_projector_acl_probe()
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS 'SELECT 1';
REVOKE EXECUTE ON FUNCTION public.chancela_projector_acl_probe() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.chancela_projector_acl_probe()
  FROM chancela_search_projector;

-- Assert the effective global and role posture while every change is still
-- transactional. Any failed assertion aborts the transaction, so a deployment
-- never commits a partially tightened database.
DO $precommit_acl$
DECLARE
  projector_oid oid;
  public_schema_oid oid;
  database_oid oid;
BEGIN
  SELECT oid INTO STRICT projector_oid
  FROM pg_roles
  WHERE rolname = 'chancela_search_projector';
  SELECT oid INTO STRICT public_schema_oid
  FROM pg_namespace
  WHERE nspname = 'public';
  SELECT oid INTO STRICT database_oid
  FROM pg_database
  WHERE datname = current_database();

  IF NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE oid = projector_oid
      AND rolcanlogin
      AND NOT rolsuper
      AND NOT rolinherit
      AND NOT rolcreaterole
      AND NOT rolcreatedb
      AND NOT rolreplication
      AND NOT rolbypassrls
      AND rolconnlimit = 32
      AND (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz)
  ) THEN
    RAISE EXCEPTION 'projector role flags are not exact';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_auth_members
    WHERE roleid = projector_oid OR member = projector_oid
  ) THEN
    RAISE EXCEPTION 'projector role retains a role membership';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_database WHERE datdba = projector_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_namespace WHERE nspowner = projector_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_class WHERE relowner = projector_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_proc WHERE proowner = projector_oid
  ) OR EXISTS (
    SELECT 1 FROM pg_type WHERE typowner = projector_oid
  ) OR EXISTS (
    SELECT 1
    FROM pg_shdepend dependency
    WHERE dependency.refclassid = 'pg_authid'::regclass
      AND dependency.refobjid = projector_oid
      AND dependency.deptype = 'o'
      AND dependency.dbid IN (0, database_oid)
  ) THEN
    RAISE EXCEPTION 'projector role owns a database object';
  END IF;

  IF NOT has_database_privilege(
    'chancela_search_projector', current_database(), 'CONNECT'
  ) OR has_database_privilege(
    'chancela_search_projector', current_database(), 'CREATE'
  ) OR has_database_privilege(
    'chancela_search_projector', current_database(), 'TEMPORARY'
  ) OR NOT has_schema_privilege(
    'chancela_search_projector', 'public', 'USAGE'
  ) OR has_schema_privilege(
    'chancela_search_projector', 'public', 'CREATE'
  ) THEN
    RAISE EXCEPTION 'projector database/schema ACL is not exact';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_database database
    CROSS JOIN LATERAL aclexplode(
      COALESCE(database.datacl, acldefault('d', database.datdba))
    ) acl
    WHERE database.oid = database_oid
      AND acl.grantee = 0
      AND acl.privilege_type IN ('CONNECT', 'CREATE', 'TEMPORARY')
  ) THEN
    RAISE EXCEPTION 'PUBLIC retains a database capability';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_namespace namespace
    CROSS JOIN LATERAL aclexplode(
      COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
    ) acl
    WHERE namespace.oid = public_schema_oid
      AND acl.grantee = 0
      AND acl.privilege_type = 'CREATE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC retains CREATE on schema public';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_proc routine
    WHERE routine.pronamespace = public_schema_oid
      AND has_function_privilege(
        'chancela_search_projector', routine.oid, 'EXECUTE'
      )
  ) THEN
    RAISE EXCEPTION 'projector can execute a public-schema routine';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_proc routine
    CROSS JOIN LATERAL aclexplode(
      COALESCE(routine.proacl, acldefault('f', routine.proowner))
    ) acl
    WHERE routine.pronamespace = public_schema_oid
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC can execute a public-schema routine';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_default_acl
    WHERE defaclrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND defaclnamespace = 0
      AND defaclobjtype = 'f'
  ) OR EXISTS (
    SELECT 1
    FROM pg_default_acl default_acl
    CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) acl
    WHERE default_acl.defaclrole = (
      SELECT oid FROM pg_roles WHERE rolname = current_user
    )
      AND default_acl.defaclnamespace = 0
      AND default_acl.defaclobjtype = 'f'
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC default routine EXECUTE is not revoked';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN (
      VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES'),
        ('TRIGGER'), ('TRUNCATE')
    ) AS forbidden(privilege)
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(
        'chancela_search_projector', relation.oid, forbidden.privilege
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND relation.relname <> 'search_documents'
      AND has_table_privilege(
        'chancela_search_projector', relation.oid, 'DELETE'
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_class sequence
    JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
    CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS forbidden(privilege)
    WHERE namespace.nspname = 'public'
      AND sequence.relkind = 'S'
      AND has_sequence_privilege(
        'chancela_search_projector', sequence.oid, forbidden.privilege
      )
  ) THEN
    RAISE EXCEPTION 'projector retains a forbidden broad object privilege';
  END IF;
END
$precommit_acl$;

COMMIT;
SQL
fi

actual_role="$(
  psql "$projector_conninfo" -X -A -t --set=ON_ERROR_STOP=1 \
    -c 'SELECT current_user'
)"
if [ "$actual_role" != "chancela_search_projector" ]; then
  echo "ERROR: projector URL authenticated as '$actual_role', expected 'chancela_search_projector'" >&2
  exit 1
fi

# Verify the complete positive allowlist, then prove that no other public table
# is readable and no source table is writable. This catches URL drift and grant
# regressions before the projector process starts.
acl_ok="$(
  psql "$projector_conninfo" -X -A -t --set=ON_ERROR_STOP=1 <<'SQL'
WITH
allowed_select(table_name, column_name) AS (
  VALUES
    ('entities', 'json'),
    ('books', 'json'),
    ('acts', 'json'),
    ('registry_extracts', 'entity_id'),
    ('registry_extracts', 'json'),
    ('follow_ups', 'id'),
    ('follow_ups', 'act_id'),
    ('follow_ups', 'agenda_number'),
    ('follow_ups', 'deliberation_index'),
    ('follow_ups', 'title'),
    ('follow_ups', 'detail'),
    ('follow_ups', 'due_date'),
    ('follow_ups', 'assignee'),
    ('follow_ups', 'assignee_display'),
    ('follow_ups', 'status'),
    ('follow_ups', 'created_at'),
    ('follow_ups', 'created_by'),
    ('follow_ups', 'completed_at'),
    ('follow_ups', 'completed_by'),
    ('group_template_libraries', 'json'),
    ('group_template_library_revisions', 'json'),
    ('events', 'seq'),
    ('events', 'id'),
    ('events', 'actor'),
    ('events', 'justification'),
    ('events', 'timestamp'),
    ('events', 'scope'),
    ('events', 'kind'),
    ('events', 'payload_digest'),
    ('events', 'prev_hash'),
    ('events', 'hash'),
    ('events', 'links'),
    ('meta', 'key'),
    ('meta', 'value'),
    ('settings', 'id'),
    ('settings', 'json'),
    ('user_templates', 'id'),
    ('user_templates', 'json'),
    ('documents', 'id'),
    ('documents', 'act_id'),
    ('documents', 'template_id'),
    ('documents', 'pdf_digest'),
    ('documents', 'profile'),
    ('documents', 'created_at'),
    ('generated_document_dispatch_evidence', 'document_id'),
    ('generated_document_dispatch_evidence', 'idempotency_key'),
    ('generated_document_dispatch_evidence', 'act_id'),
    ('generated_document_dispatch_evidence', 'template_id'),
    ('generated_document_dispatch_evidence', 'actor'),
    ('generated_document_dispatch_evidence', 'dispatched_at'),
    ('generated_document_dispatch_evidence', 'channel'),
    ('generated_document_dispatch_evidence', 'reference'),
    ('generated_document_dispatch_evidence', 'evidence_reference'),
    ('generated_document_dispatch_evidence', 'imported_document_id'),
    ('generated_document_dispatch_evidence', 'recipients_json'),
    ('generated_document_dispatch_evidence', 'operator_note'),
    ('generated_document_dispatch_evidence', 'recorded_at'),
    ('imported_documents', 'id'),
    ('imported_documents', 'act_id'),
    ('imported_documents', 'filename'),
    ('imported_documents', 'declared_content_type'),
    ('imported_documents', 'detected_content_type'),
    ('imported_documents', 'sha256'),
    ('imported_documents', 'size_bytes'),
    ('imported_documents', 'imported_at'),
    ('imported_documents', 'imported_by'),
    ('imported_documents', 'operator_review_status'),
    ('imported_documents', 'operator_reviewed_at'),
    ('imported_documents', 'operator_reviewed_by'),
    ('imported_documents', 'operator_review_note'),
    ('imported_documents', 'operator_acknowledged_guardrail_ids_json'),
    ('imported_documents', 'technical_validation_report_json'),
    ('imported_document_review_history', 'id'),
    ('imported_document_review_history', 'imported_document_id'),
    ('imported_document_review_history', 'review_status'),
    ('imported_document_review_history', 'reviewed_at'),
    ('imported_document_review_history', 'reviewed_by'),
    ('imported_document_review_history', 'review_note'),
    ('imported_document_review_history', 'acknowledged_guardrail_ids_json'),
    ('paper_book_imports', 'import_id'),
    ('paper_book_imports', 'entity_ref'),
    ('paper_book_imports', 'entity_name'),
    ('paper_book_imports', 'entity_nipc'),
    ('paper_book_imports', 'book_ref'),
    ('paper_book_imports', 'date_from'),
    ('paper_book_imports', 'date_to'),
    ('paper_book_imports', 'page_count'),
    ('paper_book_imports', 'page_from'),
    ('paper_book_imports', 'page_to'),
    ('paper_book_imports', 'original_number_from'),
    ('paper_book_imports', 'original_number_to'),
    ('paper_book_imports', 'sha256'),
    ('paper_book_imports', 'size_bytes'),
    ('paper_book_imports', 'content_type'),
    ('paper_book_imports', 'source_filename'),
    ('paper_book_imports', 'notes'),
    ('paper_book_imports', 'imported_at'),
    ('paper_book_imports', 'imported_by'),
    ('paper_book_imports', 'ocr_status'),
    ('paper_book_ocr_drafts', 'draft_id'),
    ('paper_book_ocr_drafts', 'import_id'),
    ('paper_book_ocr_drafts', 'extracted_text'),
    ('paper_book_ocr_drafts', 'text_digest'),
    ('paper_book_ocr_drafts', 'page_spans_json'),
    ('paper_book_ocr_drafts', 'confidence'),
    ('paper_book_ocr_drafts', 'engine_name'),
    ('paper_book_ocr_drafts', 'engine_version'),
    ('paper_book_ocr_drafts', 'created_at'),
    ('paper_book_ocr_drafts', 'created_by'),
    ('paper_book_ocr_drafts', 'review_status'),
    ('paper_book_ocr_drafts', 'reviewed_at'),
    ('paper_book_ocr_drafts', 'reviewed_by'),
    ('paper_book_ocr_drafts', 'review_note'),
    ('paper_book_ocr_drafts', 'superseded_by'),
    ('search_projection_control', 'id'),
    ('search_projection_control', 'source_revision'),
    ('search_projection_control', 'fence_token'),
    ('search_projection_control', 'published_source_revision'),
    ('search_projection_control', 'published_fence_token'),
    ('search_projection_control', 'published_command_generation'),
    ('search_projection_control', 'command'),
    ('search_projection_control', 'command_generation'),
    ('search_projection_control', 'lease_id'),
    ('search_projection_control', 'lease_owner'),
    ('search_projection_control', 'lease_heartbeat_at'),
    ('search_projection_control', 'lease_expires_at_unix_ms'),
    ('search_projection_control', 'updated_at'),
    ('search_documents', 'id'),
    ('search_documents', 'json'),
    ('search_index_state', 'id'),
    ('search_index_state', 'json')
),
allowed_insert(table_name, column_name) AS (
  VALUES
    ('search_documents', 'id'),
    ('search_documents', 'json'),
    ('search_index_state', 'id'),
    ('search_index_state', 'json')
),
allowed_update(table_name, column_name) AS (
  VALUES
    ('search_projection_control', 'published_source_revision'),
    ('search_projection_control', 'published_fence_token'),
    ('search_projection_control', 'published_command_generation'),
    ('search_projection_control', 'command'),
    ('search_projection_control', 'lease_id'),
    ('search_projection_control', 'lease_owner'),
    ('search_projection_control', 'lease_heartbeat_at'),
    ('search_projection_control', 'lease_expires_at_unix_ms'),
    ('search_projection_control', 'updated_at'),
    ('search_documents', 'json'),
    ('search_index_state', 'json')
),
forbidden_table_privilege(privilege) AS (
  VALUES
    ('TRUNCATE'),
    ('TRIGGER')
)
SELECT
  (
    SELECT
      rolcanlogin
      AND NOT rolsuper
      AND NOT rolinherit
      AND NOT rolcreaterole
      AND NOT rolcreatedb
      AND NOT rolreplication
      AND NOT rolbypassrls
      AND rolconnlimit = 32
      AND (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz)
    FROM pg_roles
    WHERE rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles role
      ON role.oid = membership.roleid OR role.oid = membership.member
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_database database
    JOIN pg_roles role ON role.oid = database.datdba
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_namespace namespace
    JOIN pg_roles role ON role.oid = namespace.nspowner
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_class relation
    JOIN pg_roles role ON role.oid = relation.relowner
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_proc routine
    JOIN pg_roles role ON role.oid = routine.proowner
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_type object_type
    JOIN pg_roles role ON role.oid = object_type.typowner
    WHERE role.rolname = current_user
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_shdepend dependency
    JOIN pg_roles role ON role.oid = dependency.refobjid
    JOIN pg_database database ON database.datname = current_database()
    WHERE role.rolname = current_user
      AND dependency.refclassid = 'pg_authid'::regclass
      AND dependency.deptype = 'o'
      AND dependency.dbid IN (0, database.oid)
  )
  AND has_database_privilege(current_user, current_database(), 'CONNECT')
  AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
  AND NOT has_database_privilege(current_user, current_database(), 'TEMPORARY')
  AND has_schema_privilege(current_user, 'public', 'USAGE')
  AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
  AND NOT EXISTS (
    SELECT 1
    FROM pg_database database
    CROSS JOIN LATERAL aclexplode(
      COALESCE(database.datacl, acldefault('d', database.datdba))
    ) acl
    WHERE database.datname = current_database()
      AND acl.grantee = 0
      AND acl.privilege_type IN ('CONNECT', 'CREATE', 'TEMPORARY')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_namespace namespace
    CROSS JOIN LATERAL aclexplode(
      COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
    ) acl
    WHERE namespace.nspname = 'public'
      AND acl.grantee = 0
      AND acl.privilege_type = 'CREATE'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_proc routine
    JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
    WHERE namespace.nspname = 'public'
      AND has_function_privilege(current_user, routine.oid, 'EXECUTE')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_proc routine
    JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
    CROSS JOIN LATERAL aclexplode(
      COALESCE(routine.proacl, acldefault('f', routine.proowner))
    ) acl
    WHERE namespace.nspname = 'public'
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  )
  AND EXISTS (
    SELECT 1
    FROM pg_default_acl default_acl
    JOIN pg_database database
      ON database.datname = current_database()
      AND database.datdba = default_acl.defaclrole
    WHERE default_acl.defaclnamespace = 0
      AND default_acl.defaclobjtype = 'f'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_default_acl default_acl
    JOIN pg_database database
      ON database.datname = current_database()
      AND database.datdba = default_acl.defaclrole
    CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) acl
    WHERE default_acl.defaclnamespace = 0
      AND default_acl.defaclobjtype = 'f'
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM allowed_select allowed
    WHERE NOT has_column_privilege(
      current_user,
      format('public.%I', allowed.table_name),
      allowed.column_name,
      'SELECT'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns column_catalog
    WHERE column_catalog.table_schema = 'public'
      AND has_column_privilege(
        current_user,
        format('public.%I', column_catalog.table_name),
        column_catalog.column_name,
        'SELECT'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_select allowed
        WHERE allowed.table_name = column_catalog.table_name
          AND allowed.column_name = column_catalog.column_name
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_any_column_privilege(current_user, relation.oid, 'SELECT')
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_select allowed
        WHERE allowed.table_name = relation.relname
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM allowed_insert allowed
    WHERE NOT has_column_privilege(
      current_user,
      format('public.%I', allowed.table_name),
      allowed.column_name,
      'INSERT'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns column_catalog
    WHERE column_catalog.table_schema = 'public'
      AND has_column_privilege(
        current_user,
        format('public.%I', column_catalog.table_name),
        column_catalog.column_name,
        'INSERT'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_insert allowed
        WHERE allowed.table_name = column_catalog.table_name
          AND allowed.column_name = column_catalog.column_name
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_any_column_privilege(current_user, relation.oid, 'INSERT')
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_insert allowed
        WHERE allowed.table_name = relation.relname
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM allowed_update allowed
    WHERE NOT has_column_privilege(
      current_user,
      format('public.%I', allowed.table_name),
      allowed.column_name,
      'UPDATE'
    )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns column_catalog
    WHERE column_catalog.table_schema = 'public'
      AND has_column_privilege(
        current_user,
        format('public.%I', column_catalog.table_name),
        column_catalog.column_name,
        'UPDATE'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_update allowed
        WHERE allowed.table_name = column_catalog.table_name
          AND allowed.column_name = column_catalog.column_name
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_any_column_privilege(current_user, relation.oid, 'UPDATE')
      AND NOT EXISTS (
        SELECT 1
        FROM allowed_update allowed
        WHERE allowed.table_name = relation.relname
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_any_column_privilege(current_user, relation.oid, 'REFERENCES')
  )
  AND NOT has_table_privilege(current_user, 'search_projection_control', 'SELECT')
  AND NOT has_table_privilege(current_user, 'search_projection_control', 'UPDATE')
  AND NOT has_table_privilege(current_user, 'search_projection_control', 'INSERT')
  AND NOT has_table_privilege(current_user, 'search_projection_control', 'DELETE')
  AND NOT has_table_privilege(current_user, 'search_documents', 'SELECT')
  AND NOT has_table_privilege(current_user, 'search_documents', 'INSERT')
  AND NOT has_table_privilege(current_user, 'search_documents', 'UPDATE')
  AND has_table_privilege(current_user, 'search_documents', 'DELETE')
  AND NOT has_table_privilege(current_user, 'search_index_state', 'SELECT')
  AND NOT has_table_privilege(current_user, 'search_index_state', 'INSERT')
  AND NOT has_table_privilege(current_user, 'search_index_state', 'UPDATE')
  AND NOT has_table_privilege(current_user, 'search_index_state', 'DELETE')
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN forbidden_table_privilege
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(
        current_user,
        relation.oid,
        forbidden_table_privilege.privilege
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND relation.relname <> 'search_documents'
      AND has_table_privilege(current_user, relation.oid, 'DELETE')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE')) AS broad(privilege)
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(
        current_user,
        relation.oid,
        broad.privilege
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class sequence
    JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
    CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS wanted(privilege)
    WHERE namespace.nspname = 'public'
      AND sequence.relkind = 'S'
      AND has_sequence_privilege(current_user, sequence.oid, wanted.privilege)
  );
SQL
)"
if [ "$acl_ok" != "t" ]; then
  echo "ERROR: search-projector PostgreSQL ACL verification failed" >&2
  exit 1
fi

expect_denied() {
  label="$1"
  statement="$2"
  if psql "$projector_conninfo" -X --set=ON_ERROR_STOP=1 \
    -c "$statement" >/tmp/search-projector-acl-denial.log 2>&1; then
    echo "ERROR: restricted projector role unexpectedly performed $label" >&2
    exit 1
  fi
  if ! grep -qi 'permission denied' /tmp/search-projector-acl-denial.log; then
    echo "ERROR: $label failed for an unexpected reason:" >&2
    sed -n '1,20p' /tmp/search-projector-acl-denial.log >&2
    exit 1
  fi
}

expect_denied "entity UPDATE" "UPDATE entities SET id = id WHERE FALSE"
expect_denied "temporary table CREATE" \
  "CREATE TEMPORARY TABLE projector_forbidden_temp (id integer)"
expect_denied "database schema CREATE" \
  "CREATE SCHEMA projector_forbidden_schema"
if [ "$acl_probe_created" -eq 1 ]; then
  expect_denied "public routine EXECUTE" \
    "SELECT public.chancela_projector_acl_probe()"
fi
expect_denied "ledger-event UPDATE" "UPDATE events SET seq = seq WHERE FALSE"
expect_denied "provider-credential SELECT" "SELECT 1 FROM provider_credentials LIMIT 1"
expect_denied "generated-document PDF bytes SELECT" \
  "SELECT pdf_bytes FROM documents LIMIT 1"
expect_denied "generated-document template spec SELECT" \
  "SELECT template_spec_json FROM documents LIMIT 1"
expect_denied "generated-document resolved layout SELECT" \
  "SELECT document_layout_json FROM documents LIMIT 1"
expect_denied "imported-document retained bytes SELECT" \
  "SELECT bytes FROM imported_documents LIMIT 1"
expect_denied "paper-book retained bytes SELECT" \
  "SELECT bytes FROM paper_book_imports LIMIT 1"
expect_denied "settings singleton UPDATE" \
  "UPDATE settings SET json = json WHERE id = 'settings'"
expect_denied "settings singleton INSERT" \
  "INSERT INTO settings (id, json) VALUES ('projector-forbidden', '{}')"
expect_denied "settings singleton DELETE" \
  "DELETE FROM settings WHERE id = 'settings'"
expect_denied "projector-control source revision UPDATE" \
  "UPDATE search_projection_control SET source_revision = source_revision WHERE id = 'main'"
expect_denied "projector-control fence token UPDATE" \
  "UPDATE search_projection_control SET fence_token = fence_token WHERE id = 'main'"
expect_denied "projector-control command generation UPDATE" \
  "UPDATE search_projection_control SET command_generation = command_generation WHERE id = 'main'"
expect_denied "projector-control id UPDATE" \
  "UPDATE search_projection_control SET id = id WHERE id = 'main'"

# Remove the side-effect-free probe while the owner passfile is still present.
if [ "$acl_probe_created" -eq 1 ]; then
  drop_acl_probe
  acl_probe_created=0
fi

echo "search-projector PostgreSQL role and exact ACL verified."
