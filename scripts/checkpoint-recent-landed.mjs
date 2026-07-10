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
    name: "API data key operation tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--test", "data_key_ops", "--locked"],
    ],
  },
  {
    name: "CLI database encryption key-env tests",
    command: ["cargo", ["test", "-p", "chancela-cli", "--locked"]],
  },
  {
    name: "API official signature import guardrail acknowledgement test",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "official_signature_import",
        "--locked",
        "official_import_requires_guardrail_acknowledgement_without_artifact_or_event",
      ],
    ],
  },
  {
    name: "TSL XML-DSig hardening tests",
    command: ["cargo", ["test", "-p", "chancela-tsl", "--locked"]],
  },
  {
    name: "MCP resources and prompts tests",
    command: ["cargo", ["test", "-p", "chancela-mcp", "--locked"]],
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
      "src/features/documents/ActDocumentPanel.test.tsx",
      "src/features/notifications/NotificationBell.test.tsx",
      "src/features/notifications/NotificationsPage.test.tsx",
      "src/features/recovery/GestaoDadosSection.test.tsx",
      "src/features/signing/SigningPanel.test.tsx",
      "src/features/templates/TemplatesCatalogPage.test.tsx",
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
    "crates/chancela-api/tests/paper_import.rs",
    "paper_book_import_validation_allows_preflight_only_with_explicit_evidence",
    "paper import canonical preflight regression coverage",
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
    "crates/chancela-api/tests/data_key_ops.rs",
    "preflight_reports_empty_and_missing_replacement_key_without_leaking_keys",
    "data key rotation preflight request validation coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/official_signature_import.rs",
    "official_import_requires_guardrail_acknowledgement_without_artifact_or_event",
    "official signature import guardrail acknowledgement regression coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "key_rotation_preflight_request_debug_redacts_key_material",
    "data key rotation preflight secret-redaction coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_rejects_tampered_signature_value",
    "TSL XML-DSig tamper regression coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_spec_09_coverage_returns_boundaries_without_http_or_secret",
    "MCP spec coverage resource regression coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "prompts_get_returns_compliance_pack_gap_review_without_http_or_secret",
    "MCP compliance prompt regression coverage",
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
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "Secções do painel",
    "dashboard subtab unit coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "keeps terminal imported-document review disabled until guardrails are acknowledged",
    "imported-document guardrail acknowledgement UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "renders popup notification controls as icon-only actions with tooltip labels",
    "notification bell icon-only action coverage",
  );
  assertFileContains(
    "apps/web/src/ui/SubNav.test.tsx",
    "can render an icon-only item with an accessible name and tooltip",
    "subnav icon-only tooltip coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationsPage.test.tsx",
    "expectIconOnlyFilter",
    "notifications page icon-only filter coverage",
  );
  assertFileContains(
    "crates/chancela-cli/tests/cli.rs",
    "db_key_env_fails_closed_without_sqlcipher_and_does_not_create_plaintext_db",
    "CLI database key env fail-closed coverage",
  );
  assertFileContains(
    "crates/chancela-cli/tests/cli.rs",
    "ambiguous_db_key_sources_are_rejected_before_store_open",
    "CLI database key ambiguity coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "runs a secret-clearing data key rotation preflight and renders only returned evidence",
    "web data key rotation preflight coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "clears key rotation secrets after a failed preflight request",
    "web data key rotation failed-request secret clearing coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "SigningPanel — local PKCS#12 software certificate",
    "web local PKCS#12 signing coverage",
  );
  assertFileContains(
    "apps/web/src/features/templates/TemplatesCatalogPage.test.tsx",
    "renders pending law references and searches by citation or article text",
    "web template law-reference coverage",
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
  assertFileContains(
    "apps/web/e2e/imported-document-review.spec.ts",
    "dashboard import-review notification routes to review, can be dismissed, and keeps PDF export canonical",
    "imported document review notification browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/imported-document-review.spec.ts",
    "downloadedPaths).toEqual([ACT_PDF_PATH])",
    "imported document review canonical PDF export coverage",
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
