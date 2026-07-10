import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const staticOnly = process.argv.includes("--static");

const checks = [
  {
    name: "static checkpoint map",
    command: [
      process.execPath,
      ["--check", "scripts/checkpoint-recent-landed.mjs"],
    ],
    before: assertCheckpointMap,
  },
  {
    name: "API paper import tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--test", "paper_import", "--locked"],
    ],
  },
  {
    name: "API archive package and DocTimeStamp evidence tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--test", "archive_package", "--locked"],
    ],
  },
  {
    name: "API local PKCS#12 signing tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "local_pkcs12_signing",
        "--locked",
      ],
    ],
  },
  {
    name: "API bounded retention execution tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "privacy",
        "--locked",
        "retention_",
      ],
    ],
  },
  {
    name: "TSL XML-DSig hardening tests",
    command: ["cargo", ["test", "-p", "chancela-tsl", "--locked"]],
  },
  {
    name: "web contracts/dashboard/signing/i18n matrix",
    command: npmCommand([
      "run",
      "test",
      "--workspace",
      "apps/web",
      "--",
      "src/contracts/contracts.test.ts",
      "src/features/dashboard/DashboardPage.test.tsx",
      "src/features/signing/SigningPanel.test.tsx",
      "src/i18n/i18n.test.ts",
    ]),
  },
  {
    name: "validator corpus manifest",
    command: npmCommand(["run", "test:validator-corpus"]),
  },
  {
    name: "desktop Cargo.lock locked check",
    command: [
      "cargo",
      [
        "metadata",
        "--manifest-path",
        "apps/desktop/src-tauri/Cargo.toml",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
      ],
    ],
  },
];

for (const check of checks) {
  console.log(`\n==> ${check.name}`);
  check.before?.();

  const [bin, args] = check.command;
  const result = spawnSync(bin, args, {
    cwd: repoRoot,
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }

  if (staticOnly) {
    console.log("\nrecent landed checkpoint static map OK");
    process.exit(0);
  }
}

function npmCommand(args) {
  return [process.execPath, [npmCliPath(), ...args]];
}

function npmCliPath() {
  const envCli = process.env.npm_execpath;
  if (envCli && isNpmCli(envCli) && existsSync(envCli)) {
    return envCli;
  }

  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules/npm/bin/npm-cli.js"),
    join(dirname(nodeDir), "lib/node_modules/npm/bin/npm-cli.js"),
  ];
  const npmCli = candidates.find((candidate) => existsSync(candidate));
  assert.ok(
    npmCli,
    `npm CLI not found; checked npm_execpath and ${candidates.join(", ")}`,
  );
  return npmCli;
}

function isNpmCli(path) {
  return path.replaceAll("\\", "/").endsWith("/npm-cli.js");
}

console.log("\nrecent landed checkpoint OK");

function assertCheckpointMap() {
  assertFileContains(
    "crates/chancela-api/tests/paper_import.rs",
    "valid_paper_book_import_validation_returns_non_canonical_dry_run_report",
    "paper import test fixture coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_reports_embedded_doc_timestamp_evidence_without_b_lta_claim",
    "archive package DocTimeStamp evidence coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/local_pkcs12_signing.rs",
    "local_pkcs12_signs_as_advanced_technical_evidence_only",
    "local PKCS#12 signing API regression coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_records_bounded_archive_and_idempotent_repeat",
    "bounded retention execution regression coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_rejects_tampered_signature_value",
    "TSL XML-DSig tamper regression coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "dashboard.json",
    "web dashboard contract fixture coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "DashboardPage",
    "dashboard unit coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "SigningPanel — local PKCS#12 software certificate",
    "web local PKCS#12 signing coverage",
  );
  assertFileContains(
    "apps/web/src/i18n/i18n.test.ts",
    "catalog completeness matrix",
    "i18n catalog matrix coverage",
  );
  assertFileContains(
    "apps/web/e2e/notification-popup-hardening.spec.ts",
    "closes on outside click",
    "notification popup outside-click browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/notification-popup-hardening.spec.ts",
    "zIndex",
    "notification popup z-index browser coverage",
  );
  assertFileExists(
    "docs/fixtures/validator-corpus/manifest.json",
    "validator corpus manifest",
  );
  assertFileContains(
    "docs/fixtures/validator-corpus/manifest.json",
    "future-doctimestamp",
    "DocTimeStamp validator corpus case",
  );
  assertFileExists(
    "apps/desktop/src-tauri/Cargo.lock",
    "desktop Cargo lockfile",
  );
  assertFileContains(
    "apps/desktop/package.json",
    "--locked",
    "desktop package locked Cargo test script",
  );
}

function assertFileExists(relativePath, label) {
  const path = join(repoRoot, relativePath);
  assert.ok(existsSync(path), `${label} missing at ${relativePath}`);
}

function assertFileContains(relativePath, needle, label) {
  assertFileExists(relativePath, label);
  const body = readFileSync(join(repoRoot, relativePath), "utf8");
  assert.ok(
    body.includes(needle),
    `${label} missing expected marker ${needle}`,
  );
}
