import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const digestPattern = /@sha256:[0-9a-f]{64}$/u;
const requiredNodeEngine = ">=24.15.0";
const requiredNpmEngine = ">=12.0.1";
const requiredPackageManager = "npm@12.0.1";
const npmActivation = "npm install --global npm@12.0.1";
const requiredRustVersion = "1.97";

const read = (relativePath) =>
  readFileSync(join(repoRoot, relativePath), "utf8").replaceAll("\r\n", "\n");

for (const relativePath of ["package.json", "apps/desktop/package.json"]) {
  const manifest = JSON.parse(read(relativePath));
  assert.equal(
    manifest.packageManager,
    requiredPackageManager,
    `${relativePath} must pin ${requiredPackageManager}`,
  );
  assert.equal(
    manifest.engines?.node,
    requiredNodeEngine,
    `${relativePath} must require Node ${requiredNodeEngine}`,
  );
  assert.equal(
    manifest.engines?.npm,
    requiredNpmEngine,
    `${relativePath} must require npm ${requiredNpmEngine}`,
  );
}

const rootCargo = read("Cargo.toml");
assert.match(
  rootCargo,
  /^rust-version = "1\.97"$/mu,
  `Cargo.toml must declare rust-version ${requiredRustVersion}`,
);
const desktopCargo = read("apps/desktop/src-tauri/Cargo.toml");
assert.match(
  desktopCargo,
  /^rust-version = "1\.97"$/mu,
  `apps/desktop/src-tauri/Cargo.toml must declare rust-version ${requiredRustVersion}`,
);
assert.match(
  read("rust-toolchain.toml"),
  /^channel = "1\.97\.0"$/mu,
  "rust-toolchain.toml must pin Rust 1.97.0",
);
const connectorsManifest = read("crates/chancela-connectors/Cargo.toml");
assert.match(
  connectorsManifest,
  /^aws-sdk-s3 = \{ version = "=1\.138\.0", default-features = false, features = \["default-https-client", "http-1x", "rt-tokio"\] \}$/mu,
  "connector must pin AWS SDK S3 1.138.0 with only the modern HTTP 1.x HTTPS client",
);
assert.match(
  connectorsManifest,
  /^russh = \{ version = "0\.62\.2", default-features = false, features = \["ring"\] \}$/mu,
  "connector must not reactivate russh's unused RSA feature",
);
const dependencyPolicy = read("docs/dependency-management.md");
for (const marker of [
  "RUSTSEC-2023-0071",
  "rsa` 0.9.10",
  "2026-08-31",
  "cargo-audit-raw.json",
]) {
  assert.ok(
    dependencyPolicy.includes(marker),
    `dependency policy is missing ${marker}`,
  );
}
const cargoAuditPolicy = read("scripts/check-cargo-audit-policy.mjs");
for (const marker of [
  'advisoryId: "RUSTSEC-2023-0071"',
  'package: "rsa"',
  'version: "0.9.10"',
  'reviewBy: "2026-08-31"',
]) {
  assert.ok(cargoAuditPolicy.includes(marker), `cargo audit policy is missing ${marker}`);
}

const ciWorkflow = read(".github/workflows/ci.yml");
for (const marker of [
  "https://software.verapdf.org/rel/1.30/verapdf-greenfield-1.30.2-installer.zip",
  "6cc6341cb1af644044054b81f00a6590a7918abb18f762243de115258bcad838",
  "--flavour 2u",
  "--flavour ua1",
]) {
  assert.ok(ciWorkflow.includes(marker), `external PDF validation gate is missing ${marker}`);
}

function dockerExternalRefs(relativePath) {
  const body = read(relativePath);
  const fromMatches = [...body.matchAll(/^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/gimu)];
  const stages = new Set(fromMatches.map((match) => match[2]).filter(Boolean));
  const refs = fromMatches.map((match) => match[1]);

  for (const match of body.matchAll(/^COPY\s+--from=(\S+)\s+/gimu)) {
    if (!stages.has(match[1])) refs.push(match[1]);
  }

  for (const ref of refs) {
    assert.match(ref, digestPattern, `${relativePath} external image is not digest-pinned: ${ref}`);
  }
  return refs.sort();
}

const standardDockerRefs = dockerExternalRefs("docker/Dockerfile.server");
const hardenedDockerRefs = dockerExternalRefs("Dockerfile.hardened");
dockerExternalRefs("docker/Dockerfile.worker");
assert.deepEqual(
  standardDockerRefs,
  hardenedDockerRefs,
  "standard and hardened Dockerfiles must use the same immutable build/runtime inputs",
);

function composeServiceImage(relativePath, service) {
  const lines = read(relativePath).split("\n");
  const start = lines.findIndex((line) => line === `  ${service}:`);
  assert.notEqual(start, -1, `${relativePath} has no service ${service}`);
  let image;
  for (const line of lines.slice(start + 1)) {
    if (/^  \S[^:]*:\s*$/u.test(line)) break;
    const match = /^    image:\s+([^#]+?)\s*$/u.exec(line);
    if (match) {
      image = match[1].trim();
      break;
    }
  }
  assert.ok(image, `${relativePath} has no image for service ${service}`);
  assert.match(
    image,
    digestPattern,
    `${relativePath} service ${service} image is not digest-pinned: ${image}`,
  );
  return image;
}

for (const service of ["postgres-tls-init", "postgres", "redis"]) {
  const standard = composeServiceImage("docker/docker-compose.yml", service);
  const hardened = composeServiceImage("docker-compose.hardened.yml", service);
  assert.equal(
    standard,
    hardened,
    `standard and hardened Compose ${service} images must resolve to the same immutable ref`,
  );
}

const workflowsDir = join(repoRoot, ".github", "workflows");
for (const name of readdirSync(workflowsDir).filter((entry) => /\.ya?ml$/iu.test(entry))) {
  const relativePath = `.github/workflows/${name}`;
  const body = read(relativePath);
  for (const match of body.matchAll(/^\s*uses:\s*([^@\s]+)@([^\s#]+)(?:\s+#\s*(.+))?\s*$/gmu)) {
    const [line, action, ref, versionComment] = match;
    if (action.startsWith("./")) continue;
    assert.match(
      ref,
      /^[0-9a-f]{40}$/u,
      `${relativePath} action is not pinned to a full commit SHA: ${line.trim()}`,
    );
    assert.ok(
      versionComment?.trim(),
      `${relativePath} immutable action ref is missing its adjacent version comment: ${line.trim()}`,
    );
  }

  const jobStarts = [...body.matchAll(/^  ([a-zA-Z0-9_-]+):\s*$/gmu)];
  for (const [index, match] of jobStarts.entries()) {
    const jobName = match[1];
    const start = match.index;
    const end = jobStarts[index + 1]?.index ?? body.length;
    const job = body.slice(start, end);
    const npmCommands = [
      ...job.matchAll(/^\s*(?:run:\s*)?(?:npm|npx)\s+.*$/gmu),
    ].filter((command) => !command[0].includes(npmActivation));
    if (npmCommands.length === 0) continue;

    const setup = job.indexOf("actions/setup-node@");
    const activation = job.indexOf(npmActivation);
    const firstCommand = npmCommands[0].index;
    assert.notEqual(
      setup,
      -1,
      `${relativePath} job ${jobName} uses npm without actions/setup-node`,
    );
    assert.notEqual(
      activation,
      -1,
      `${relativePath} job ${jobName} does not activate exact npm 12.0.1`,
    );
    assert.ok(
      setup < activation && activation < firstCommand,
      `${relativePath} job ${jobName} must activate npm 12.0.1 after setup-node and before npm commands`,
    );
  }
}

console.log("supply-chain pin policy OK");
