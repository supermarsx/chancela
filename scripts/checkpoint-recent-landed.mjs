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
    name: "API document bundle evidence tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--locked", "document_bundle"],
    ],
  },
  {
    name: "API external-validator report metadata tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--locked",
        "external_validator_report_metadata",
      ],
    ],
  },
  {
    name: "live provider assurance static gate",
    command: npmCommand(["run", "check:live-provider-assurance"]),
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
    name: "API multi-signature renewal planning tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "multi_signature_local_renewal_plan",
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
    name: "API privacy breach playbook evidence tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "privacy",
        "--locked",
        "breach_playbooks_allow_settings_manage_persist_and_audit",
      ],
    ],
  },
  {
    name: "API privacy transfer control evidence tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "privacy",
        "--locked",
        "transfer_controls_allow_user_manage_validate_persist_and_audit",
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
    name: "template catalog metadata tests",
    command: ["cargo", ["test", "-p", "chancela-templates", "--locked"]],
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
    name: "API trust catalog lookup tests",
    command: ["cargo", ["test", "-p", "chancela-api", "trust", "--locked"]],
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
      "src/api/client.test.ts",
      "src/contracts/contracts.test.ts",
      "src/features/books/books.test.tsx",
      "src/features/dashboard/DashboardPage.test.tsx",
      "src/features/documents/ActDocumentPanel.test.tsx",
      "src/features/entities/entities.test.tsx",
      "src/features/ferramentas/ferramentas.test.tsx",
      "src/features/ferramentas/trust.test.tsx",
      "src/features/notifications/NotificationBell.test.tsx",
      "src/features/notifications/NotificationsPage.test.tsx",
      "src/features/recovery/GestaoDadosSection.test.tsx",
      "src/features/signing/SigningPanel.test.tsx",
      "src/features/templates/TemplatesCatalogPage.test.tsx",
      "src/i18n/i18n.test.ts",
      "src/ui/SubNav.test.tsx",
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
    "crates/chancela-api/tests/paper_import.rs",
    "paper_book_import_ocr_run_configured_command_stores_unreviewed_non_authoritative_draft",
    "paper import local OCR run success coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/paper_import.rs",
    "paper_book_import_ocr_run_missing_config_returns_422_without_mutation",
    "paper import local OCR missing-config refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/books/paper-import/{id}/ocr/run",
    "paper import local OCR run route",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "PAPER_BOOK_OCR_COMMAND_ENV",
    "paper import local OCR command configuration",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_reports_embedded_doc_timestamp_evidence_without_b_lta_claim",
    "archive package DocTimeStamp evidence coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "archive_timestamp_append_api_persists_caller_supplied_local_technical_evidence",
    "caller-supplied archive timestamp append API coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "archive_timestamp_append_rejects_stale_token_without_digest_change_or_event",
    "caller-supplied archive timestamp stale-token refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/acts/{id}/signature/archive-timestamp/append",
    "caller-supplied archive timestamp append route",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub async fn append_archive_timestamp",
    "caller-supplied archive timestamp append handler",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_indexes_matching_external_validator_metadata_only",
    "archive package runtime external-validator metadata coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "document_bundle_indexes_matching_external_validator_metadata",
    "document bundle runtime external-validator metadata coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "paragraph_flow_emits_real_unicode_spaces",
    "PDF paragraph inter-word space mapping coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "wrapped_key_value_values_emit_real_unicode_spaces",
    "PDF wrapped key-value inter-word space mapping coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_report_records_space_emission_without_pdfua_claim",
    "PDF accessibility space evidence without PDF/UA claim coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct HeadingHierarchyReport",
    "PDF accessibility heading hierarchy blocker report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct RoleMapCoverageReport",
    "PDF accessibility role-map blocker report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct TableSemanticsReport",
    "PDF accessibility table-semantics blocker report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct NonTextContentReport",
    "PDF accessibility non-text content blocker report",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_heading_hierarchy_reports_skipped_and_unsupported_levels",
    "PDF accessibility heading blocker decomposition coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_role_map_and_table_semantics_are_reported",
    "PDF accessibility role-map and table blocker decomposition coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_explicit_alt_text_decorative_model_clears_local_blockers_without_pdfua_claim",
    "PDF accessibility local blocker clearing without PDF/UA claim coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_non_text_accounting_reports_missing_and_invalid_entries",
    "PDF accessibility non-text blocker decomposition coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "pdf_ua_is_not_claimed_with_minimal_tagging",
    "PDF/UA non-certification marker coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "create_external_validator_report_metadata",
    "external-validator report metadata capture API",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "metadata_list_response",
    "external-validator report metadata list API",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "download_external_validator_report_metadata",
    "external-validator raw metadata download API",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "raw_metadata_for_identity",
    "external-validator raw metadata identity disambiguation helper",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/external-validator-reports/{case_id}/{validator_family}",
    "external-validator raw metadata download route",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    "external_validator_report_download_route_is_classified_as_gated",
    "external-validator raw metadata download authz classification coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "EXTERNAL_VALIDATOR_REPORT_METADATA_DIR",
    "external-validator durable metadata sidecar directory",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "load_external_validator_report_metadata",
    "external-validator metadata sidecar reload helper",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "persist_external_validator_report_metadata",
    "external-validator metadata sidecar persistence helper",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "malformed_count",
    "external-validator malformed metadata counting",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_api_accepts_and_lists_redacted_summary",
    "API external-validator metadata capture/list regression coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_persists_and_reloads_from_data_dir",
    "API external-validator metadata data-dir reload coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "api-durable/eu-dss",
    "API external-validator metadata persisted raw download coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_malformed_sidecars_are_counted_not_trusted",
    "API external-validator malformed sidecar coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "api-malformed/eu-dss",
    "API external-validator malformed sidecar download refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_duplicate_identity_is_not_downloadable",
    "API external-validator duplicate identity download refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_download_allows_settings_read",
    "API external-validator settings.read download coverage",
  );
  assertFileContains(
    "package.json",
    "check:live-provider-assurance",
    "live-provider assurance package script",
  );
  assertFileContains(
    "scripts/check-live-provider-assurance.mjs",
    "checkCiNoRunCompileGates",
    "live-provider assurance CI compile-gate checker",
  );
  assertFileContains(
    ".github/workflows/ci.yml",
    "npm run check:live-provider-assurance",
    "live-provider assurance CI gate",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "provider validity or authority approval",
    "live-provider assurance conservative boundary copy",
  );
  assertFileContains(
    "crates/chancela-api/tests/local_pkcs12_signing.rs",
    "local_pkcs12_signs_as_advanced_technical_evidence_only",
    "local PKCS#12 signing API regression coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/pdf_signature_validation.rs",
    "pdf_signature_validation_reports_multi_signature_local_renewal_plan",
    "PDF signature validation multi-signature renewal-plan coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "signature_evidence_status_reports_multi_signature_local_renewal_plan",
    "signature status multi-signature renewal-plan coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "multi_signature_local_renewal_plan",
    "signature status multi-signature renewal-plan field",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_records_bounded_archive_and_idempotent_repeat",
    "bounded retention execution regression coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "evidence_receipts",
    "privacy evidence receipt persistence coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "authority_notified: false",
    "breach receipt false notification flag",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "data_transfer_executed: false",
    "transfer receipt false execution flag",
  );
  assertFileContains(
    "contracts/privacy.breach-playbooks.json",
    "\"authority_notified\": false",
    "breach playbook receipt contract fixture",
  );
  assertFileContains(
    "contracts/privacy.transfer-controls.json",
    "\"data_transfer_executed\": false",
    "transfer control receipt contract fixture",
  );
  assertFileContains(
    "crates/chancela-api/tests/data_key_ops.rs",
    "preflight_reports_empty_and_missing_replacement_key_without_leaking_keys",
    "data key rotation preflight request validation coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/data_key_ops.rs",
    "execution_refuses_plaintext_store_without_leaking_key_or_migrating",
    "data key rotation execution refusal coverage",
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
    "crates/chancela-api/src/data_status.rs",
    "key_rotation_execute_request_debug_redacts_key_material",
    "data key rotation execution secret-redaction coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_metadata_validation_reports_stage_channel_and_authored_metadata_drift",
    "template stage/channel metadata drift coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_rejects_tampered_signature_value",
    "TSL XML-DSig tamper regression coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/src/record.rs",
    "lookup_matches_complete_certificate_fingerprint_and_ski_only",
    "TSL record identifier lookup regression coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/src/record.rs",
    "lookup_reports_no_match_without_inferring_and_unknown_for_partial_hex",
    "TSL record lookup conservative unknown coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "structured_identifier_filters_match_complete_material_only",
    "API trust identifier filter regression coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    'id="trust-identifier-filter"',
    "web TSL identifier lookup control",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    'id="tsa-identifier-filter"',
    "web TSA identifier lookup control",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "passes identifier lookups to the TSL catalog endpoint and renders matching services",
    "web TSL identifier lookup coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "passes identifier lookups to TSA search and shows the empty state for no matches",
    "web TSA identifier lookup coverage",
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
    "crates/chancela-mcp/src/server.rs",
    "prompts_get_returns_paper_book_ocr_canonical_review_without_http_or_secret",
    "MCP paper-book OCR prompt regression coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "paper_book_ocr_canonical_review",
    "MCP paper-book OCR prompt catalog marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "dashboard.json",
    "web dashboard contract fixture coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "paper-book.ocr-draft.json",
    "paper-book OCR draft contract fixture coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "paper-book.ocr-run.json",
    "paper-book OCR run contract fixture coverage",
  );
  assertFileExists(
    "contracts/paper-book.ocr-run.json",
    "paper-book OCR run contract fixture",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "uses the data key rotation execution endpoint and sends only the replacement key",
    "web client data key execution endpoint coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "runPaperBookImportOcr",
    "web client paper-book OCR run API",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "listExternalValidatorReports",
    "web client external-validator metadata list API",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "uploadExternalValidatorReport",
    "web client external-validator metadata upload API",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "lists external-validator report metadata without raw report bytes",
    "web client external-validator metadata list coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "uploads external-validator report JSON as raw selected text",
    "web client external-validator raw JSON upload coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "creates and reviews OCR drafts as auxiliary non-canonical metadata only",
    "paper-book OCR draft UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "runs local OCR for a preserved import and exposes the auxiliary non-canonical draft",
    "paper-book local OCR run UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "surfaces missing local OCR configuration without creating an auxiliary draft",
    "paper-book local OCR missing-config UI coverage",
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
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "renders the full archive affordance as a tooltip-backed icon link",
    "dashboard archive icon-only action coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "expectIconOnlyActionLink",
    "dashboard work-queue icon-only action helper coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "dashboard-workqueue__action",
    "dashboard work-queue icon-only action implementation marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "keeps terminal imported-document review disabled until guardrails are acknowledged",
    "imported-document guardrail acknowledgement UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "surfaces the backend entity chronology and Mermaid graph source",
    "entity chronology graph UI coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/chronology.rs",
    "pub graph: ChronologyGraphBundle",
    "API entity chronology structured graph response field",
  );
  assertFileContains(
    "crates/chancela-registry/tests/chronology.rs",
    "chronology_shareholders_graph_has_deterministic_nodes_edges_and_provenance",
    "registry chronology shareholders structured graph coverage",
  );
  assertFileContains(
    "crates/chancela-registry/tests/chronology.rs",
    "chronology_organs_graph_has_deterministic_nodes_edges_and_provenance",
    "registry chronology organs structured graph coverage",
  );
  assertFileContains(
    "crates/chancela-registry/tests/chronology.rs",
    "chronology_relationships_graph_is_an_honest_empty_stub_without_corporate_relationships",
    "registry chronology relationships structured graph coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/EntityChronologyPanel.tsx",
    "entities.chronology.boundary",
    "localized entity chronology boundary copy",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "copies the technical JSON report after validation returns a report body",
    "PDF validator report copy coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "saves the technical JSON report as a browser-save/download Blob",
    "PDF validator report save coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "ExternalValidatorReportsPanel",
    "Ferramentas external-validator metadata panel",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "downloadSummary",
    "Ferramentas external-validator metadata summary save action",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "Ferramentas — external-validator reports panel",
    "Ferramentas external-validator metadata panel coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "downloads a client-generated metadata summary, not raw report bytes",
    "Ferramentas external-validator metadata summary-save coverage",
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
    "apps/web/src/ui/SubNav.test.tsx",
    "exposes only usable scroll arrows for the current overflow edge",
    "subnav overflow-arrow tooltip coverage",
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
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "executes a guarded data key rekey only after a ready preflight and clears secrets",
    "web data key rotation execution coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "SigningPanel — local PKCS#12 software certificate",
    "web local PKCS#12 signing coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "shows the available multi-signature local renewal plan as technical evidence only",
    "web multi-signature renewal-plan evidence coverage",
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
    "apps/web/src/i18n/locales/pt-PT.ts",
    "externalValidatorReports.downloadSummary",
    "i18n external-validator metadata panel keys",
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
  assertFileContains(
    "apps/web/e2e/data-key-rotation-execution.spec.ts",
    "data key rotation preflight reveals guarded execution and submits only the replacement key",
    "data key rotation execution browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/data-key-rotation-execution.spec.ts",
    "not.toHaveProperty('current_key')",
    "data key rotation browser secret-minimization coverage",
  );
  assertFileContains(
    "apps/web/e2e/chronology-and-pdf-validator.spec.ts",
    "entity detail loads route-stubbed chronology rows and exposes copyable Mermaid source",
    "entity chronology browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/chronology-and-pdf-validator.spec.ts",
    "PDF validator shows technical JSON actions after a report body and downloads/copies it",
    "PDF validator JSON copy/download browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/chronology-and-pdf-validator.spec.ts",
    "PDF validator fail-closed refusals do not expose technical JSON actions",
    "PDF validator fail-closed browser coverage",
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
