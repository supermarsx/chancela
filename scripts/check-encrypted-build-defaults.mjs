#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  throw new Error(message);
}

function readText(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function script(packageJson, name, label) {
  const command = packageJson.scripts?.[name];
  if (typeof command !== "string" || command.trim() === "") {
    fail(`${label}: missing non-empty script ${name}`);
  }
  return command;
}

function assertContains(value, needle, label) {
  if (!value.includes(needle)) {
    fail(`${label}: expected to contain ${JSON.stringify(needle)}`);
  }
}

function assertNotContains(value, needle, label) {
  if (value.includes(needle)) {
    fail(`${label}: must not contain ${JSON.stringify(needle)}`);
  }
}

function assertRegex(value, regex, label) {
  if (!regex.test(value)) {
    fail(`${label}: expected to match ${regex}`);
  }
}

function checkRootReleaseBuild() {
  const pkg = readJson("package.json");
  const buildRust = script(pkg, "build:rust", "root package.json");
  assertContains(buildRust, "cargo build --workspace --release --locked", "root build:rust");
  assertContains(buildRust, "--features", "root build:rust");
  assertContains(buildRust, "chancela-server/sqlcipher", "root build:rust");
  assertContains(buildRust, "chancela-cli/sqlcipher", "root build:rust");

  const dev = script(pkg, "dev", "root package.json");
  assertNotContains(dev, "sqlcipher", "root dev script");
}

function checkDockerBuild() {
  const dockerfile = readText("docker/Dockerfile.server");
  assertContains(dockerfile, "perl", "Dockerfile SQLCipher vendored OpenSSL dependency");
  assertRegex(
    dockerfile,
    /cargo build --release -p chancela-server --locked --features chancela-server\/sqlcipher/,
    "Dockerfile server build",
  );
}

function checkDesktopBuild() {
  const pkg = readJson("apps/desktop/package.json");
  const build = script(pkg, "build", "desktop package.json");
  const noBundle = script(pkg, "build:no-bundle", "desktop package.json");
  assertContains(build, "tauri build", "desktop build");
  assertContains(build, "--features sqlcipher", "desktop build");
  assertContains(noBundle, "tauri build --no-bundle", "desktop build:no-bundle");
  assertContains(noBundle, "--features sqlcipher", "desktop build:no-bundle");

  const dev = script(pkg, "dev", "desktop package.json");
  const devPlaintext = script(pkg, "dev:plaintext", "desktop package.json");
  const devSqlcipher = script(pkg, "dev:sqlcipher", "desktop package.json");
  assertContains(dev, "npm run dev:plaintext", "desktop dev script");
  assertContains(
    devPlaintext,
    "CHANCELA_DESKTOP_ALLOW_PLAINTEXT_DB",
    "desktop dev:plaintext script",
  );
  assertContains(devPlaintext, "tauri", "desktop dev:plaintext script");
  assertContains(devPlaintext, "dev", "desktop dev:plaintext script");
  assertNotContains(devPlaintext, "sqlcipher", "desktop dev:plaintext script");
  assertContains(devSqlcipher, "tauri dev", "desktop dev:sqlcipher script");
  assertContains(devSqlcipher, "--features sqlcipher", "desktop dev:sqlcipher script");
  assertNotContains(
    script(pkg, "test:rust", "desktop package.json"),
    "sqlcipher",
    "desktop Rust test script",
  );
}

function checkCiWiring() {
  const ci = readText(".github/workflows/ci.yml");
  assertContains(ci, "npm run check:encrypted-build-defaults", "CI metadata encrypted-build gate");
  assertContains(ci, "Install native Perl for SQLCipher vendored OpenSSL", "CI Windows SQLCipher deps");
  assertContains(ci, "npm run build:no-bundle", "CI desktop build script");

  const release = readText(".github/workflows/release.yml");
  assertContains(release, "npm run package", "release package build");
  assertContains(
    release,
    "Install native Perl for SQLCipher vendored OpenSSL",
    "release Windows SQLCipher deps",
  );
}

try {
  checkRootReleaseBuild();
  checkDockerBuild();
  checkDesktopBuild();
  checkCiWiring();
  console.log("encrypted build defaults OK");
} catch (error) {
  console.error(`[encrypted-build-defaults] ${error.message}`);
  process.exit(1);
}
