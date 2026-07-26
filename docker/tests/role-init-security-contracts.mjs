#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const scriptPath = resolve(repoRoot, "docker/search-projector-role-init.sh");
const source = readFileSync(scriptPath, "utf8");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function requireText(text, message) {
  assert(source.includes(text), message);
}

requireText(
  'dedicated_database_ack="${CHANCELA_PROJECTOR_DEDICATED_DATABASE:-}"',
  "dedicated-database acknowledgement gate is missing",
);
requireText(
  "'REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC'",
  "database-global PUBLIC revoke is incomplete",
);
requireText(
  "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
  "PUBLIC schema CREATE revoke is missing",
);
requireText(
  "REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC;",
  "existing PUBLIC routine EXECUTE revoke is missing",
);
requireText(
  "ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
  "global owner default routine revoke is missing",
);
assert(
  !source.includes(
    "IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC",
  ),
  "schema-scoped default revoke cannot cancel PostgreSQL's global default",
);
for (const flag of [
  "NOSUPERUSER",
  "NOCREATEDB",
  "NOCREATEROLE",
  "NOINHERIT",
  "NOREPLICATION",
  "NOBYPASSRLS",
  "CONNECTION LIMIT 32",
  "VALID UNTIL 'infinity'",
]) {
  requireText(flag, `role posture omits ${flag}`);
}
for (const ownershipCatalog of [
  "pg_database",
  "pg_namespace",
  "pg_class",
  "pg_proc",
  "pg_type",
]) {
  requireText(ownershipCatalog, `ownership assertion omits ${ownershipCatalog}`);
}
requireText(
  "WHERE roleid = projector_oid OR member = projector_oid",
  "bidirectional membership assertion is missing",
);
requireText(
  "'chancela_search_projector', current_database(), 'CREATE'",
  "effective database CREATE denial assertion is missing",
);
requireText(
  "projector can execute a public-schema routine",
  "effective public-routine assertion is missing",
);
requireText(
  'expect_denied "database schema CREATE"',
  "live CREATE SCHEMA denial is missing",
);
requireText(
  'expect_denied "public routine EXECUTE"',
  "live routine EXECUTE denial is missing",
);
requireText("export PGPASSFILE=", "PGPASSFILE authentication is missing");
assert(
  source.includes(
    'admin_conninfo="postgres://$pg_user@postgres:5432/$pg_db?sslmode=verify-full"',
  ) &&
    source.includes(
      'projector_conninfo="postgres://chancela_search_projector@postgres:5432/$pg_db?sslmode=verify-full"',
    ),
  "psql connection arguments must remain password-free",
);

const begin = source.indexOf("BEGIN;");
const precommit = source.indexOf("DO $precommit_acl$");
const commit = source.indexOf("COMMIT;", precommit);
assert(
  begin >= 0 && precommit > begin && commit > precommit,
  "owner-side ACL assertions must execute before COMMIT",
);

const refusal = spawnSync("sh", [scriptPath], {
  cwd: repoRoot,
  encoding: "utf8",
  env: {
    ...process.env,
    CHANCELA_PROJECTOR_DEDICATED_DATABASE: "",
  },
});
assert(
  refusal.status !== 0 &&
    refusal.stderr.includes(
      "Set CHANCELA_PROJECTOR_DEDICATED_DATABASE=true",
    ),
  "initializer did not fail closed without dedicated-database acknowledgement",
);

console.log("Role initializer security contracts passed");
