#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const seams = [
  {
    label: "CMD SCMD live network test",
    file: "crates/chancela-cmd/tests/network.rs",
    packageName: "chancela-cmd",
    feature: "network-tests",
    boundaryPatterns: [
      /real AMA preprod credentials/i,
      /ApplicationId/,
      /CHANCELA_CMD_TEST_PHONE/,
    ],
  },
  {
    label: "CSC QTSP live network test",
    file: "crates/chancela-csc/tests/network.rs",
    packageName: "chancela-csc",
    feature: "network-tests",
    boundaryPatterns: [
      /real per-provider CSC sandbox account \+ credentials/i,
      /CHANCELA_CSC_<PROVIDER>_\*/,
      /CHANCELA_CSC_TEST_BASE_URL/,
    ],
  },
  {
    label: "TSA live timestamp test",
    file: "crates/chancela-tsa/tests/live_tsa.rs",
    packageName: "chancela-tsa",
    feature: "network-tests",
    boundaryPatterns: [
      /reachable RFC 3161 TSA/i,
      /CHANCELA_TSA_URL/,
      /network access/i,
    ],
  },
  {
    label: "smartcard real hardware test",
    file: "crates/chancela-smartcard/tests/hardware.rs",
    packageName: "chancela-smartcard",
    feature: "hardware-tests",
    boundaryPatterns: [
      /card reader/i,
      /Autentica..o\.gov middleware/i,
      /Cart.o\s+de\s+Cidad.o/i,
    ],
  },
];

const failures = [];

for (const seam of seams) {
  checkSeam(seam);
}

checkPackageScript();
checkCiMetadataLane();
checkCiNoRunCompileGates();
checkDocsNote();

if (failures.length > 0) {
  console.error("[live-provider-assurance] failed");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(
  `[live-provider-assurance] OK: ${seams.length} live-provider seams are gated, ignored, documented, and compiled in CI with --no-run`,
);

function checkSeam(seam) {
  const source = readText(seam.file);
  if (source === null) return;
  const prose = normalizeProse(source);

  if (!hasTopLevelFeatureGate(source, seam.feature)) {
    fail(
      `${seam.file}: missing top-level #![cfg(feature = "${seam.feature}")] gate`,
    );
  }

  if (!/^\s*#\s*\[\s*ignore\b/m.test(source)) {
    fail(`${seam.file}: missing #[ignore] marker on live-provider test(s)`);
  }

  if (
    !/--\s+--ignored/.test(prose) &&
    !/explicitly requested/i.test(prose) &&
    !/invoked explicitly/i.test(prose)
  ) {
    fail(
      `${seam.file}: missing manual ignored-test invocation or equivalent explicit-run copy`,
    );
  }

  if (!/never run(?:s)? in CI/i.test(prose)) {
    fail(`${seam.file}: missing no-CI boundary copy`);
  }

  if (!prose.includes(`--features ${seam.feature}`)) {
    fail(
      `${seam.file}: missing manual command copy for --features ${seam.feature}`,
    );
  }

  if (!source.includes("#[ignore]")) {
    fail(`${seam.file}: missing documentation copy naming #[ignore]`);
  }

  for (const pattern of seam.boundaryPatterns) {
    if (!pattern.test(prose)) {
      fail(`${seam.file}: missing boundary marker ${pattern}`);
    }
  }
}

function hasTopLevelFeatureGate(source, feature) {
  const gate = new RegExp(
    `^\\s*#!\\s*\\[\\s*cfg\\s*\\(\\s*feature\\s*=\\s*"${escapeRegExp(
      feature,
    )}"\\s*\\)\\s*\\]\\s*$`,
  );
  const lines = source.replace(/^\uFEFF/, "").split(/\r?\n/);

  for (const line of lines.slice(0, 40)) {
    if (gate.test(line)) return true;

    const trimmed = line.trim();
    if (
      trimmed === "" ||
      trimmed.startsWith("//!") ||
      trimmed.startsWith("#![allow") ||
      trimmed.startsWith("#![deny") ||
      trimmed.startsWith("#![warn") ||
      trimmed.startsWith("#![forbid")
    ) {
      continue;
    }

    return false;
  }

  return false;
}

function checkPackageScript() {
  const packageJson = readJson("package.json");
  if (!packageJson) return;

  const script = packageJson.scripts?.["check:live-provider-assurance"];
  if (
    typeof script !== "string" ||
    !script.includes("scripts/check-live-provider-assurance.mjs")
  ) {
    fail(
      "package.json: missing check:live-provider-assurance script pointing at scripts/check-live-provider-assurance.mjs",
    );
  }
}

function checkCiMetadataLane() {
  const workflow = readText(".github/workflows/ci.yml");
  if (workflow === null) return;

  if (!/npm\s+run\s+check:live-provider-assurance/.test(workflow)) {
    fail(
      ".github/workflows/ci.yml: metadata lane must run npm run check:live-provider-assurance",
    );
  }
}

function checkCiNoRunCompileGates() {
  const workflow = readText(".github/workflows/ci.yml");
  if (workflow === null) return;

  const logicalLines = workflow
    .replace(/\\\r?\n\s*/g, " ")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  for (const seam of seams) {
    const match = logicalLines.find((line) =>
      cargoNoRunLineMatches(line, seam.packageName, seam.feature),
    );
    if (!match) {
      fail(
        `.github/workflows/ci.yml: missing no-run compile gate for ${seam.packageName} with --features ${seam.feature}`,
      );
    }
  }
}

function cargoNoRunLineMatches(line, packageName, feature) {
  if (!/\bcargo\s+test\b/.test(line)) return false;
  return (
    hasArg(line, "-p") &&
    line.includes(packageName) &&
    line.includes("--features") &&
    line.includes(feature) &&
    line.includes("--no-run")
  );
}

function hasArg(line, arg) {
  return line.split(/\s+/).includes(arg);
}

function checkDocsNote() {
  const docs = readText("docs/CI-CHECKPOINTS.md");
  if (docs === null) return;
  const prose = normalizeProse(docs);

  const required = [
    "npm run check:live-provider-assurance",
    "static/compile-time assurance only",
    "does not prove live provider validity or authority approval",
  ];

  for (const marker of required) {
    if (!prose.includes(marker)) {
      fail(
        `docs/CI-CHECKPOINTS.md: missing live-provider assurance note marker "${marker}"`,
      );
    }
  }
}

function normalizeProse(source) {
  return source
    .replace(/^\s*\/\/[!/]\s?/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}

function readText(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  try {
    return fs.readFileSync(absolutePath, "utf8");
  } catch (error) {
    fail(`${relativePath}: ${error.message}`);
    return null;
  }
}

function readJson(relativePath) {
  const source = readText(relativePath);
  if (source === null) return null;

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

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
