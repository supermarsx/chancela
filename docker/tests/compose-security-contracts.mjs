#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));

function composeJson(files, profiles) {
  const args = ["compose"];
  for (const file of files) args.push("-f", file);
  for (const profile of profiles) args.push("--profile", profile);
  args.push("config", "--format", "json");
  return JSON.parse(
    execFileSync("docker", args, {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    }),
  );
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function keys(value) {
  return Object.keys(value ?? {}).sort();
}

function sameMembers(actual, expected, message) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  assert(JSON.stringify(left) === JSON.stringify(right), `${message}: ${left}`);
}

function volumeSources(service) {
  return (service?.volumes ?? [])
    .filter((volume) => volume.type === "volume")
    .map((volume) => volume.source);
}

function secretTargets(service) {
  return (service?.secrets ?? []).map((secret) => secret.source ?? secret);
}

const normalPg = composeJson(["docker/docker-compose.yml"], ["postgres"]);
const normalSqlite = composeJson(
  ["docker/docker-compose.yml"],
  ["single-node"],
);
const cluster = composeJson(
  ["docker/docker-compose.yml", "docker/docker-compose.cluster.yml"],
  ["postgres", "cluster"],
);
const hardenedPg = composeJson(["docker-compose.hardened.yml"], ["postgres"]);
const hardenedSqlite = composeJson(
  ["docker-compose.hardened.yml"],
  ["single-node"],
);

assert(
  normalSqlite.services["search-projector-sqlite"].network_mode === "none",
  "normal SQLite projector must have no network namespace",
);
assert(
  hardenedSqlite.services["search-projector-sqlite"].network_mode === "none",
  "hardened SQLite projector must have no network namespace",
);
for (const [label, config, apiName, projectorName] of [
  ["normal SQLite", normalSqlite, "server-sqlite", "search-projector-sqlite"],
  [
    "hardened SQLite",
    hardenedSqlite,
    "server-sqlite",
    "search-projector-sqlite",
  ],
  [
    "normal PostgreSQL",
    normalPg,
    "server-postgres",
    "search-projector-postgres",
  ],
  [
    "hardened PostgreSQL",
    hardenedPg,
    "server-postgres",
    "search-projector-postgres",
  ],
  [
    "cluster PostgreSQL",
    cluster,
    "chancela-cluster",
    "search-projector-postgres",
  ],
]) {
  const apiEnvironment = config.services[apiName].environment;
  const projectorEnvironment = config.services[projectorName].environment;
  assert(
    apiEnvironment.CHANCELA_SEARCH_HEARTBEAT_SECONDS ===
      projectorEnvironment.CHANCELA_SEARCH_HEARTBEAT_SECONDS,
    `${label} API and projector heartbeat intervals must match`,
  );
  assert(
    apiEnvironment.CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS ===
      projectorEnvironment.CHANCELA_SEARCH_HEALTH_MAX_AGE_SECONDS,
    `${label} API and projector health-age limits must match`,
  );
}
assert(normalPg.networks.backend.internal, "normal backend must be internal");
assert(
  hardenedPg.networks.backend.internal,
  "hardened backend must be internal",
);

for (const serviceName of [
  "postgres",
  "redis",
  "search-projector-role-init",
  "search-projector-postgres",
]) {
  sameMembers(
    keys(normalPg.services[serviceName].networks),
    ["backend"],
    `${serviceName} must be backend-only`,
  );
  assert(
    normalPg.services[serviceName].network_mode !== "none",
    `${serviceName} unexpectedly lost required backend networking`,
  );
}
sameMembers(
  keys(normalPg.services["server-postgres"].networks),
  ["backend", "default"],
  "normal Postgres API network attachment",
);
sameMembers(
  keys(cluster.services["chancela-cluster"].networks),
  ["backend", "default"],
  "cluster API network attachment",
);
sameMembers(
  keys(hardenedPg.services["server-postgres"].networks),
  ["backend", "edge"],
  "hardened Postgres API network attachment",
);
for (const serviceName of [
  "postgres",
  "redis",
  "search-projector-role-init",
  "search-projector-postgres",
]) {
  sameMembers(
    keys(hardenedPg.services[serviceName].networks),
    ["backend"],
    `hardened ${serviceName} must be backend-only`,
  );
}

const normalAllowedConsumers = new Map([
  [
    "chancela-postgres-password",
    ["postgres", "search-projector-role-init", "secrets-init"],
  ],
  [
    "chancela-database-url",
    ["search-projector-role-init", "secrets-init", "server-postgres"],
  ],
  ["chancela-credential-key", ["secrets-init", "server-postgres"]],
  ["chancela-search-password", ["search-projector-role-init", "secrets-init"]],
  [
    "chancela-search-secrets",
    ["search-projector-postgres", "search-projector-role-init", "secrets-init"],
  ],
  ["chancela-secrets", ["secrets-init"]],
]);
for (const [volume, expectedConsumers] of normalAllowedConsumers) {
  const actualConsumers = Object.entries(normalPg.services)
    .filter(([, service]) => volumeSources(service).includes(volume))
    .map(([name]) => name);
  sameMembers(actualConsumers, expectedConsumers, `${volume} consumers`);
}

const clusterProbe = cluster.services["secrets-init"].volumes.find(
  (volume) => volume.target === "/probe/cluster-data",
);
assert(
  clusterProbe?.source === "chancela-cluster-data" &&
    clusterProbe.read_only === true,
  "cluster initializer must probe chancela-cluster-data read-only",
);
assert(
  cluster.services["secrets-init"].environment.CHANCELA_CLUSTER_DATA_PROBE ===
    "/probe/cluster-data",
  "cluster probe path environment is missing",
);

assert(
  Object.hasOwn(
    normalPg.services["search-projector-role-init"].environment,
    "CHANCELA_PROJECTOR_DEDICATED_DATABASE",
  ),
  "normal role initializer lacks dedicated-database acknowledgement",
);
assert(
  Object.hasOwn(
    hardenedPg.services["search-projector-role-init"].environment,
    "CHANCELA_PROJECTOR_DEDICATED_DATABASE",
  ),
  "hardened role initializer lacks dedicated-database acknowledgement",
);

const hardenedExpectedSecrets = new Map([
  ["postgres", ["postgres_password"]],
  ["server-postgres", ["credential_key", "database_url"]],
  [
    "search-projector-role-init",
    [
      "database_url",
      "postgres_password",
      "search_database_password",
      "search_database_url",
    ],
  ],
  ["search-projector-postgres", ["search_database_url"]],
  [
    "secrets-preflight",
    [
      "credential_key",
      "database_url",
      "postgres_password",
      "search_database_password",
      "search_database_url",
    ],
  ],
]);
for (const [serviceName, expectedSecrets] of hardenedExpectedSecrets) {
  sameMembers(
    secretTargets(hardenedPg.services[serviceName]),
    expectedSecrets,
    `hardened ${serviceName} secret exposure`,
  );
}

const standardSource = readFileSync(
  resolve(repoRoot, "docker/docker-compose.yml"),
  "utf8",
);
const hardenedSource = readFileSync(
  resolve(repoRoot, "docker-compose.hardened.yml"),
  "utf8",
);
assert(
  standardSource.includes("CHANCELA_PROJECTOR_DEDICATED_DATABASE=true"),
  "standard startup instructions omit the dedicated-database acknowledgement",
);
assert(
  hardenedSource.includes("CHANCELA_PROJECTOR_DEDICATED_DATABASE=true"),
  "hardened startup instructions omit the dedicated-database acknowledgement",
);

console.log("Compose security contracts passed");
