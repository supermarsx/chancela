#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const gitShaPattern = /^[a-fA-F0-9]{40}$/;

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const options = {
    dist: path.join(repoRoot, "dist"),
    fixture: false,
    skipDist: false,
    allowEmptyDist: false,
    requireCleanSource: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dist") {
      const value = argv[++i];
      if (!value || value.startsWith("--")) fail("Missing value for --dist");
      options.dist = path.resolve(value);
    } else if (arg === "--fixture") {
      options.fixture = true;
    } else if (arg === "--skip-dist") {
      options.skipDist = true;
    } else if (arg === "--allow-empty-dist") {
      options.allowEmptyDist = true;
    } else if (arg === "--require-clean-source") {
      options.requireCleanSource = true;
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      fail(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

function printUsage() {
  console.log(`Usage: node scripts/check-package-artifacts.mjs [options]

Validates existing Chancela package outputs in dist/.

Options:
  --dist <dir>          Package output directory to inspect (default: dist)
  --fixture             Also validate a generated temporary package fixture
  --skip-dist           Validate only the fixture output
  --allow-empty-dist    Do not fail when --dist contains no package artifacts
  --require-clean-source
                        Require manifest.sourceProvenance.sourceTreeState to be clean
`);
}

function safePackagePath(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty relative path`);
  }
  if (value.includes("\0")) fail(`${label} contains a NUL byte: ${value}`);
  if (value.includes("\\")) fail(`${label} uses backslashes: ${value}`);
  if (value.startsWith("/") || value.startsWith("//")) {
    fail(`${label} is absolute: ${value}`);
  }
  if (/^[A-Za-z]:(?:\/|$)/.test(value)) {
    fail(`${label} uses a Windows drive path: ${value}`);
  }

  const parts = value.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    fail(`${label} contains an empty/current/traversal segment: ${value}`);
  }
  return value;
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    fail(`Invalid JSON in ${filePath}: ${error.message}`);
  }
}

function runGit(args) {
  const result = spawnSync("git", ["-C", repoRoot, ...args], { encoding: "utf8" });
  if (result.status !== 0) return null;
  return result.stdout.trim();
}

function currentHeadCommit() {
  const commit = runGit(["rev-parse", "HEAD"]);
  return gitShaPattern.test(commit ?? "") ? commit.toLowerCase() : null;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function expectFail(fn, expectedSubstring) {
  try {
    fn();
  } catch (error) {
    if (!error.message.includes(expectedSubstring)) {
      fail(`Expected failure containing "${expectedSubstring}", got "${error.message}"`);
    }
    return;
  }
  fail(`Expected failure containing "${expectedSubstring}"`);
}

function walkFiles(root) {
  if (!fs.existsSync(root)) return [];

  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) return walkFiles(fullPath);
    if (entry.isFile()) return [fullPath];
    fail(`Unsupported non-file package member: ${fullPath}`);
  });
}

function relativePackagePath(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join("/");
}

function assertExplicitReleaseIntegrity(manifest, label) {
  const integrity = manifest.releaseIntegrity;
  if (!integrity || typeof integrity !== "object" || Array.isArray(integrity)) {
    fail(`${label}: manifest.releaseIntegrity is required`);
  }

  const codeSigning = integrity.codeSigning;
  if (!codeSigning || typeof codeSigning !== "object" || Array.isArray(codeSigning)) {
    fail(`${label}: manifest.releaseIntegrity.codeSigning is required`);
  }
  if (!["unsigned", "signed"].includes(codeSigning.status)) {
    fail(`${label}: codeSigning.status must be "unsigned" or "signed"`);
  }
  if (codeSigning.status === "unsigned" && typeof codeSigning.reason !== "string") {
    fail(`${label}: unsigned codeSigning status must include a reason`);
  }
  if (codeSigning.status === "signed" && typeof codeSigning.signer !== "string") {
    fail(`${label}: signed codeSigning status must include a signer`);
  }

  const notarization = integrity.notarization;
  if (!notarization || typeof notarization !== "object" || Array.isArray(notarization)) {
    fail(`${label}: manifest.releaseIntegrity.notarization is required`);
  }
  if (!["not_applicable", "not_notarized", "notarized"].includes(notarization.status)) {
    fail(`${label}: notarization.status must be explicit`);
  }
  if (notarization.status !== "notarized" && typeof notarization.reason !== "string") {
    fail(`${label}: non-notarized status must include a reason`);
  }
  if (notarization.status === "notarized" && typeof notarization.evidence !== "string") {
    fail(`${label}: notarized status must include evidence`);
  }
}

function assertSourceProvenance(manifest, label, { requireCleanSource = false } = {}) {
  if (!isRecord(manifest.sourceProvenance)) {
    fail(`${label}: manifest.sourceProvenance is required`);
  }

  const provenance = manifest.sourceProvenance;
  if (!gitShaPattern.test(provenance.commitSha ?? "")) {
    fail(`${label}: manifest.sourceProvenance.commitSha must be a 40-character Git commit SHA`);
  }
  if (manifest.gitCommit !== provenance.commitSha) {
    fail(`${label}: manifest.gitCommit must mirror manifest.sourceProvenance.commitSha`);
  }
  const sourceTreeState = provenance.sourceTreeState;
  if (!["clean", "dirty", "unknown"].includes(sourceTreeState)) {
    fail(`${label}: manifest.sourceProvenance.sourceTreeState must be clean, dirty, or unknown`);
  }
  if (requireCleanSource && sourceTreeState !== "clean") {
    fail(
      `${label}: manifest.sourceProvenance.sourceTreeState must be clean when --require-clean-source is set; got ${sourceTreeState}`,
    );
  }
  if (provenance.buildMode !== "release") {
    fail(`${label}: manifest.sourceProvenance.buildMode must be release`);
  }

  const headCommit = currentHeadCommit();
  if (headCommit && provenance.commitSha.toLowerCase() !== headCommit) {
    fail(
      `${label}: manifest.sourceProvenance.commitSha ${provenance.commitSha} does not match current HEAD ${headCommit}`,
    );
  }
}

function assertManifest(packageRoot, label, options = {}) {
  const manifestPath = path.join(packageRoot, "manifest.json");
  if (!fs.existsSync(manifestPath)) fail(`${label}: missing manifest.json`);

  const manifest = readJson(manifestPath);
  assertExplicitReleaseIntegrity(manifest, label);
  assertSourceProvenance(manifest, label, options);

  if (!Array.isArray(manifest.included) || manifest.included.length === 0) {
    fail(`${label}: manifest.included must be a non-empty array`);
  }
  if (!manifest.checksums || manifest.checksums.algorithm !== "SHA-256") {
    fail(`${label}: manifest.checksums.algorithm must be SHA-256`);
  }
  if (!Array.isArray(manifest.checksums.files)) {
    fail(`${label}: manifest.checksums.files must be an array`);
  }

  const actualIncluded = new Set(
    walkFiles(packageRoot)
      .map((filePath) => relativePackagePath(packageRoot, filePath))
      .filter((relativePath) => !["manifest.json", "SHA256SUMS"].includes(relativePath))
      .sort(),
  );

  const manifestPaths = new Set();
  for (const [index, entry] of manifest.included.entries()) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      fail(`${label}: manifest.included[${index}] must be an object`);
    }
    const relativePath = safePackagePath(entry.path, `${label}: manifest.included[${index}].path`);
    if (manifestPaths.has(relativePath)) fail(`${label}: duplicate manifest path ${relativePath}`);
    manifestPaths.add(relativePath);

    const filePath = path.join(packageRoot, ...relativePath.split("/"));
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      fail(`${label}: manifest entry missing from package: ${relativePath}`);
    }
    if (entry.size !== fs.statSync(filePath).size) {
      fail(`${label}: manifest size mismatch for ${relativePath}`);
    }
    const digest = sha256(filePath);
    if (entry.sha256 !== digest) {
      fail(`${label}: manifest SHA-256 mismatch for ${relativePath}`);
    }
  }

  const actualList = [...actualIncluded].join("\n");
  const manifestList = [...manifestPaths].sort().join("\n");
  if (actualList !== manifestList) {
    fail(`${label}: manifest.included does not match package files`);
  }

  const checksumPaths = new Map();
  for (const [index, entry] of manifest.checksums.files.entries()) {
    const relativePath = safePackagePath(entry?.path, `${label}: manifest.checksums.files[${index}].path`);
    if (checksumPaths.has(relativePath)) {
      fail(`${label}: duplicate manifest.checksums.files path ${relativePath}`);
    }
    checksumPaths.set(relativePath, entry.sha256);
  }
  if ([...checksumPaths.keys()].sort().join("\n") !== [...manifestPaths].sort().join("\n")) {
    fail(`${label}: manifest.checksums.files does not match included paths`);
  }
  if (
    [...manifestPaths].some(
      (relativePath) =>
        checksumPaths.get(relativePath) !== sha256(path.join(packageRoot, ...relativePath.split("/"))),
    )
  ) {
    fail(`${label}: manifest.checksums.files does not mirror included file digests`);
  }
}

function parseSha256Sums(contents, label) {
  const entries = new Map();
  for (const [index, rawLine] of contents.split(/\r?\n/).entries()) {
    const line = rawLine.trimEnd();
    if (line.length === 0) continue;
    const match = line.match(/^([a-fA-F0-9]{64}) {2}\*?(.+)$/);
    if (!match) fail(`${label}: invalid SHA256SUMS line ${index + 1}`);

    const digest = match[1].toLowerCase();
    const relativePath = safePackagePath(match[2], `${label}: SHA256SUMS line ${index + 1}`);
    if (entries.has(relativePath)) fail(`${label}: duplicate SHA256SUMS path ${relativePath}`);
    entries.set(relativePath, digest);
  }
  return entries;
}

function assertSha256Sums(packageRoot, label) {
  const sumsPath = path.join(packageRoot, "SHA256SUMS");
  if (!fs.existsSync(sumsPath)) fail(`${label}: missing SHA256SUMS`);

  const entries = parseSha256Sums(fs.readFileSync(sumsPath, "utf8"), label);
  const expectedPaths = walkFiles(packageRoot)
    .map((filePath) => relativePackagePath(packageRoot, filePath))
    .filter((relativePath) => relativePath !== "SHA256SUMS")
    .sort();

  const entryPaths = [...entries.keys()].sort();
  if (expectedPaths.join("\n") !== entryPaths.join("\n")) {
    fail(`${label}: SHA256SUMS entries do not match package files`);
  }

  for (const [relativePath, expectedDigest] of entries) {
    const filePath = path.join(packageRoot, ...relativePath.split("/"));
    const actualDigest = sha256(filePath);
    if (actualDigest !== expectedDigest) {
      fail(`${label}: SHA256SUMS digest mismatch for ${relativePath}`);
    }
  }
}

function assertPackageDirectory(packageRoot, label, options = {}) {
  if (!fs.existsSync(packageRoot) || !fs.statSync(packageRoot).isDirectory()) {
    fail(`${label}: package directory not found`);
  }
  assertManifest(packageRoot, label, options);
  assertSha256Sums(packageRoot, label);
}

function runTar(args, label) {
  const result = spawnSync("tar", args, { encoding: "utf8" });
  if (result.status !== 0) {
    fail(`${label}: tar failed with exit ${result.status}: ${(result.stderr || result.stdout).trim()}`);
  }
  return result.stdout;
}

function assertArchiveMembers(archivePath, label) {
  const listing = runTar(["-tzf", archivePath], label)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (listing.length === 0) fail(`${label}: archive has no members`);

  const topLevels = new Set();
  for (const member of listing) {
    const normalized = member.endsWith("/") ? member.slice(0, -1) : member;
    safePackagePath(normalized, `${label}: archive member`);
    topLevels.add(normalized.split("/")[0]);
  }

  if (topLevels.size !== 1) {
    fail(`${label}: archive must contain exactly one top-level directory`);
  }

  return [...topLevels][0];
}

function assertArchive(archivePath, options = {}) {
  const label = path.relative(repoRoot, archivePath) || archivePath;
  const topLevel = assertArchiveMembers(archivePath, label);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chancela-package-"));
  try {
    runTar(["-xzf", archivePath, "-C", tmpDir], label);
    assertPackageDirectory(path.join(tmpDir, topLevel), `${label}:${topLevel}`, options);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function findPackageOutputs(distDir) {
  if (!fs.existsSync(distDir)) return { archives: [], directories: [] };

  const entries = fs.readdirSync(distDir, { withFileTypes: true });
  const archives = entries
    .filter((entry) => entry.isFile() && /^chancela-.+\.tar\.gz$/.test(entry.name))
    .map((entry) => path.join(distDir, entry.name))
    .sort();
  const directories = entries
    .filter((entry) => entry.isDirectory() && /^chancela-.+/.test(entry.name))
    .map((entry) => path.join(distDir, entry.name))
    .filter((dir) => fs.existsSync(path.join(dir, "manifest.json")))
    .sort();

  return { archives, directories };
}

function validateDist(distDir, { allowEmptyDist, requireCleanSource = false }) {
  const { archives, directories } = findPackageOutputs(distDir);
  if (archives.length === 0 && directories.length === 0) {
    if (allowEmptyDist) {
      console.log(`No package artifacts found in ${distDir}; skipped dist validation.`);
      return 0;
    }
    fail(`No package artifacts found in ${distDir}; run npm run package first.`);
  }

  const validationOptions = { requireCleanSource };
  for (const archivePath of archives) assertArchive(archivePath, validationOptions);
  for (const directoryPath of directories) {
    assertPackageDirectory(
      directoryPath,
      path.relative(repoRoot, directoryPath) || directoryPath,
      validationOptions,
    );
  }

  console.log(`Validated ${archives.length} archive(s) and ${directories.length} package director${directories.length === 1 ? "y" : "ies"} in ${distDir}.`);
  return archives.length + directories.length;
}

function fileKind(relativePath) {
  const name = path.posix.basename(relativePath);
  if (["chancela-server", "chancela-server.exe", "chancela", "chancela.exe"].includes(name)) {
    return "binary";
  }
  if (relativePath.startsWith("web/")) return "asset";
  if (relativePath.startsWith("scripts/")) return "script";
  if (["readme.md", "license.md"].includes(name)) return "document";
  return "asset";
}

function writePackageChecksums(packageRoot) {
  const sums = walkFiles(packageRoot)
    .map((filePath) => ({ filePath, relativePath: relativePackagePath(packageRoot, filePath) }))
    .filter(({ relativePath }) => relativePath !== "SHA256SUMS")
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath))
    .map(({ filePath, relativePath }) => `${sha256(filePath)}  *${relativePath}`)
    .join("\n");
  fs.writeFileSync(path.join(packageRoot, "SHA256SUMS"), `${sums}\n`);
}

function writeManifestAndChecksums(packageRoot, manifest) {
  fs.writeFileSync(path.join(packageRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writePackageChecksums(packageRoot);
}

function writeFixturePackage(distDir, { sourceTreeState = "dirty" } = {}) {
  const stem = "chancela-0.0.0-fixture-x64";
  const packageRoot = path.join(distDir, stem);
  fs.mkdirSync(path.join(packageRoot, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(packageRoot, "chancela-server"), "fixture server\n");
  fs.writeFileSync(path.join(packageRoot, "scripts", "backup.sh"), "#!/usr/bin/env bash\n");

  const included = walkFiles(packageRoot)
    .map((filePath) => ({ filePath, relativePath: relativePackagePath(packageRoot, filePath) }))
    .filter(({ relativePath }) => !["manifest.json", "SHA256SUMS"].includes(relativePath))
    .sort((a, b) => a.relativePath.localeCompare(b.relativePath))
    .map(({ filePath, relativePath }) => ({
      path: relativePath,
      kind: fileKind(relativePath),
      size: fs.statSync(filePath).size,
      sha256: sha256(filePath),
    }));

  const commitSha = currentHeadCommit() ?? "0".repeat(40);
  const manifest = {
    version: "0.0.0",
    platform: "fixture",
    arch: "x64",
    gitCommit: commitSha,
    generatedAt: "2026-01-01T00:00:00.000Z",
    sourceProvenance: {
      commitSha,
      sourceTreeState,
      buildMode: "release",
    },
    releaseIntegrity: {
      codeSigning: {
        status: "unsigned",
        reason: "Fixture package is intentionally unsigned.",
      },
      notarization: {
        status: "not_applicable",
        reason: "Fixture package is not a macOS release artifact.",
      },
    },
    included,
    checksums: {
      algorithm: "SHA-256",
      files: included,
    },
  };

  writeManifestAndChecksums(packageRoot, manifest);

  runTar(["-czf", `${stem}.tar.gz`, stem], `fixture:${stem}`);
  return packageRoot;
}

function validateFixture({ requireCleanSource = false } = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chancela-package-fixture-"));
  try {
    const distDir = path.join(tmpDir, "dist");
    fs.mkdirSync(distDir);
    const previousCwd = process.cwd();
    process.chdir(distDir);
    try {
      const packageRoot = writeFixturePackage(distDir, {
        sourceTreeState: requireCleanSource ? "clean" : "dirty",
      });
      validateDist(distDir, { allowEmptyDist: false, requireCleanSource });

      const headCommit = currentHeadCommit();
      const manifestPath = path.join(packageRoot, "manifest.json");
      const baseManifest = readJson(manifestPath);
      for (const sourceTreeState of ["dirty", "unknown"]) {
        const manifest = structuredClone(baseManifest);
        manifest.sourceProvenance.sourceTreeState = sourceTreeState;
        writeManifestAndChecksums(packageRoot, manifest);

        assertPackageDirectory(packageRoot, `fixture:${sourceTreeState}-source-dev`, {
          requireCleanSource: false,
        });
        expectFail(
          () =>
            assertPackageDirectory(packageRoot, `fixture:${sourceTreeState}-source-required`, {
              requireCleanSource: true,
            }),
          "sourceTreeState must be clean when --require-clean-source is set",
        );
      }
      writeManifestAndChecksums(packageRoot, baseManifest);

      if (headCommit) {
        const manifest = readJson(manifestPath);
        const mismatchedCommit =
          headCommit === "f".repeat(40) ? "e".repeat(40) : "f".repeat(40);
        manifest.gitCommit = mismatchedCommit;
        manifest.sourceProvenance.commitSha = mismatchedCommit;
        writeManifestAndChecksums(packageRoot, manifest);
        expectFail(
          () =>
            assertPackageDirectory(packageRoot, "fixture:mismatched-head", {
              requireCleanSource,
            }),
          "does not match current HEAD",
        );
      }
    } finally {
      process.chdir(previousCwd);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

try {
  const options = parseArgs(process.argv.slice(2));
  if (options.fixture) validateFixture(options);
  if (!options.skipDist) validateDist(options.dist, options);
} catch (error) {
  console.error(`[package-integrity] ${error.message}`);
  process.exit(1);
}
