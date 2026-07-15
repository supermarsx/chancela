#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const waiverId = "ci.coverage.thresholds.non_web_unit";
const debtMarker =
  "browser/desktop/Docker/live-provider coverage thresholds remain explicit waiver debt outside the apps/web Vitest/V8 unit-test lane";
const failures = [];

const manifest = readJson("docs/ci-assurance-waivers.json");
const waivers = manifest?.waivers;

if (manifest?.schema_version !== 1) {
  fail("docs/ci-assurance-waivers.json: schema_version must be 1");
}

if (!Array.isArray(waivers)) {
  fail("docs/ci-assurance-waivers.json: waivers must be an array");
} else {
  const matching = waivers.filter((waiver) => waiver?.id === waiverId);
  if (matching.length !== 1) {
    fail(
      `docs/ci-assurance-waivers.json: expected exactly one ${waiverId} waiver`,
    );
  } else {
    checkWaiver(matching[0]);
  }
}

checkPackageScript();
checkCiWorkflow();
checkSpecCoverageCheckpointPaths();
checkRecentLandedStaticMap();
checkBackedCaveats();

if (failures.length > 0) {
  console.error("[ci-assurance-waivers] failed");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `[ci-assurance-waivers] OK: ${waiverId} is explicit, reviewed, wired into CI, and backed by no-claim caveats`,
);

function checkWaiver(waiver) {
  requireString(waiver, "status");
  requireString(waiver, "owner");
  requireString(waiver, "scope");
  requireString(waiver, "review_cadence");
  requireString(waiver, "next_review_due");
  requireString(waiver, "no_claim");

  if (waiver.status !== "accepted_debt") {
    fail(`${waiverId}: status must remain accepted_debt`);
  }

  if (!/^\d{4}-\d{2}-\d{2}$/u.test(String(waiver.next_review_due ?? ""))) {
    fail(`${waiverId}: next_review_due must be YYYY-MM-DD`);
  }

  if (!Array.isArray(waiver.review_scope) || waiver.review_scope.length < 4) {
    fail(`${waiverId}: review_scope must list the affected non-web-unit lanes`);
  }

  const reviewScope = normalize(
    Array.isArray(waiver.review_scope) ? waiver.review_scope.join(" ") : "",
  );
  for (const required of ["browser", "desktop", "docker", "live-provider"]) {
    if (!reviewScope.includes(required)) {
      fail(`${waiverId}: review_scope missing ${required}`);
    }
  }

  const scope = normalize(String(waiver.scope ?? ""));
  for (const required of [
    "coverage thresholds",
    "browser",
    "desktop",
    "docker",
    "live-provider",
    "apps/web",
    "vitest/v8",
  ]) {
    if (!scope.includes(required)) {
      fail(`${waiverId}: scope missing ${required}`);
    }
  }

  const noClaim = normalize(String(waiver.no_claim ?? ""));
  for (const required of [
    "does not claim",
    "browser",
    "desktop",
    "docker",
    "live-provider",
    "release readiness",
    "production readiness",
    "partial count",
  ]) {
    if (!noClaim.includes(required)) {
      fail(`${waiverId}: no_claim missing ${required}`);
    }
  }
}

function checkPackageScript() {
  const packageJson = readJson("package.json");
  const script = packageJson?.scripts?.["check:ci-assurance-waivers"];
  if (
    typeof script !== "string" ||
    !script.includes("scripts/check-ci-assurance-waivers.mjs")
  ) {
    fail(
      "package.json: missing check:ci-assurance-waivers script pointing at scripts/check-ci-assurance-waivers.mjs",
    );
  }
}

function checkCiWorkflow() {
  const workflow = readText(".github/workflows/ci.yml");
  if (!containsMarker(workflow, "npm run check:ci-assurance-waivers")) {
    fail(
      ".github/workflows/ci.yml: metadata lane must run npm run check:ci-assurance-waivers",
    );
  }
  if (!containsMarker(workflow, waiverId) || !containsMarker(workflow, debtMarker)) {
    fail(
      ".github/workflows/ci.yml: missing non-web-unit coverage waiver caveat marker",
    );
  }
}

function checkSpecCoverageCheckpointPaths() {
  const checker = readText("scripts/check-spec-coverage.mjs");
  const requiredPaths = [
    ".github/workflows/ci.yml",
    "apps/web/vite.config.ts",
    "docs/ci-assurance-waivers.json",
    "package.json",
    "scripts/check-ci-assurance-waivers.mjs",
  ];

  for (const requiredPath of requiredPaths) {
    if (!checker.includes(`"${requiredPath}"`)) {
      fail(
        `scripts/check-spec-coverage.mjs: checkpointPaths missing ${requiredPath}`,
      );
    }
  }
}

function checkRecentLandedStaticMap() {
  const checkpoint = readText("scripts/checkpoint-recent-landed.mjs");
  for (const marker of [
    "CI assurance waiver static gate",
    "docs/ci-assurance-waivers.json",
    "scripts/check-ci-assurance-waivers.mjs",
    waiverId,
  ]) {
    if (!containsMarker(checkpoint, marker)) {
      fail(`scripts/checkpoint-recent-landed.mjs: missing marker ${marker}`);
    }
  }
}

function checkBackedCaveats() {
  const caveats = [
    {
      file: "SPEC-COVERAGE.md",
      markers: [waiverId, debtMarker, "does not reduce PARTIAL=11"],
    },
    {
      file: "docs/CI-E2E-HARDENING-PLAN.md",
      markers: [waiverId, debtMarker, "does not add those thresholds"],
    },
    {
      file: "docs/CI-CHECKPOINTS.md",
      markers: [waiverId, debtMarker, "no-claim static debt accounting only"],
    },
    {
      file: ".github/workflows/ci.yml",
      markers: [waiverId, debtMarker],
    },
    {
      file: "apps/web/vite.config.ts",
      markers: [waiverId, debtMarker],
    },
  ];

  for (const caveat of caveats) {
    const source = readText(caveat.file);
    for (const marker of caveat.markers) {
      if (!containsMarker(source, marker)) {
        fail(`${caveat.file}: missing caveat marker ${marker}`);
      }
    }
  }
}

function requireString(object, field) {
  if (typeof object?.[field] !== "string" || object[field].trim() === "") {
    fail(`${waiverId}: ${field} must be a non-empty string`);
  }
}

function containsMarker(source, marker) {
  return normalize(source).includes(normalize(marker));
}

function normalize(value) {
  return String(value)
    .replace(/`/g, "")
    .replace(/^\s*(?:#|\/\/)\s?/gm, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function readText(relativePath) {
  try {
    return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
  } catch (error) {
    fail(`${relativePath}: ${error.message}`);
    return "";
  }
}

function readJson(relativePath) {
  const source = readText(relativePath);
  if (source.length === 0) return null;

  try {
    return JSON.parse(source.replace(/^\uFEFF/, ""));
  } catch (error) {
    fail(`${relativePath}: invalid JSON: ${error.message}`);
    return null;
  }
}

function fail(message) {
  failures.push(message);
}
