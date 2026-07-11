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
    name: "API external signer invite tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "external_signer_invites",
        "--locked",
      ],
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
    name: "archive local DGLAB interchange API/scaffold tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-archive",
        "--locked",
        "local_dglab_interchange",
      ],
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
    name: "API dashboard reminder policy tests",
    command: ["cargo", ["test", "-p", "chancela-api", "--locked", "reminder_"]],
  },
  {
    name: "API dashboard guest event redaction test",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--locked",
        "dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed",
      ],
    ],
  },
  {
    name: "API generated document durable by-id download test",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--locked",
        "on_demand_generate_persists_a_chosen_document_and_emits_the_event",
      ],
    ],
  },
  {
    name: "API generated document in-memory by-id download test",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--locked",
        "in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata",
      ],
    ],
  },
  {
    name: "Server condominium absent-owner generated communication persistence test",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-server",
        "--test",
        "e2e_act_document_persistence",
        "--locked",
        "condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata",
      ],
    ],
  },
  {
    name: "API retained-export cleanup dry-run tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--locked", "data_cleanup_"],
    ],
  },
  {
    name: "API structured platform log forwarding tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--locked", "platform_logs_forwarded"],
    ],
  },
  {
    name: "API local ASiC inspection endpoint tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "asic_signature_validation",
        "--locked",
      ],
    ],
  },
  {
    name: "signing ASiC decompression-bound tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-signing",
        "--test",
        "roundtrip",
        "--locked",
        "asic_",
      ],
    ],
  },
  {
    name: "authz platform log write seed tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-authz",
        "--locked",
        "platform_log_write_is_seeded_only_to_owner_and_platform_admin",
      ],
    ],
  },
  {
    name: "API backup recovery drill receipt tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--test",
        "backup_recovery_drill",
        "--locked",
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
      "src/api/settingsDefaults.test.ts",
      "src/contracts/contracts.test.ts",
      "src/features/books/books.test.tsx",
      "src/features/dashboard/DashboardPage.test.tsx",
      "src/features/documents/ActDocumentPanel.test.tsx",
      "src/features/entities/entities.test.tsx",
      "src/features/ferramentas/ExternalSigningWorkflowsPage.test.tsx",
      "src/features/ferramentas/ferramentas.test.tsx",
      "src/features/ferramentas/trust.test.tsx",
      "src/features/notifications/NotificationBell.test.tsx",
      "src/features/notifications/NotificationsPage.test.tsx",
      "src/features/recovery/GestaoDadosSection.test.tsx",
      "src/features/recovery/LivrosIntegridadeSection.test.tsx",
      "src/features/settings/SettingsPage.test.tsx",
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
    "crates/chancela-api/tests/paper_import.rs",
    "paper_book_ocr_conversion_dossier_requires_accepted_matching_draft_and_is_metadata_only",
    "paper import accepted OCR conversion dossier metadata-only coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/paper_import.rs",
    "duplicate is idempotent",
    "paper import OCR conversion dossier idempotent duplicate coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/paper_import.rs",
    "dossier list must not include raw OCR text",
    "paper import OCR conversion dossier raw-text redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/books/paper-import/{id}/ocr-drafts/{draft_id}/conversion-dossier",
    "paper import accepted OCR conversion dossier route",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/books/paper-import/{id}/conversion-dossiers",
    "paper import OCR conversion dossier list route",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "create_paper_book_ocr_conversion_dossier",
    "paper import accepted OCR conversion dossier handler",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "PAPER_BOOK_OCR_CONVERSION_DOSSIER_NOTICE",
    "paper import accepted OCR conversion dossier boundary notice",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    '"source_extracted_text_in_response": false',
    "paper import OCR conversion dossier response excludes raw OCR text marker",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    '"source_extracted_text_in_ledger_event": false',
    "paper import OCR conversion dossier ledger excludes raw OCR text marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "creates a metadata-only conversion dossier for an accepted OCR draft on operator action",
    "web paper-book conversion dossier operator-action coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "renders an existing conversion dossier without encouraging duplicate creation",
    "web paper-book conversion dossier existing-dossier coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "does not expose conversion dossier creation for non-accepted OCR drafts",
    "web paper-book conversion dossier accepted-draft gate coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "raw OCR text from a malformed dossier response must stay hidden",
    "web paper-book conversion dossier raw OCR hiding coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "calls.some((call) => call.url.endsWith('/conversion-dossier') && call.method === 'POST')",
    "web paper-book conversion dossier no automatic POST coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "document|signature|seal|archive",
    "web paper-book conversion dossier no document/signature/seal/archive calls coverage",
  );
  assertFileContains(
    "apps/web/e2e/paper-book-import-ocr.spec.ts",
    "paper-book import preserves non-canonical package and OCR review stays auxiliary",
    "paper-book OCR review browser workflow coverage",
  );
  assertFileContains(
    "apps/web/e2e/paper-book-import-ocr.spec.ts",
    "Confirmo que este rascunho OCR é auxiliar",
    "paper-book OCR draft auxiliary acknowledgement browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/paper-book-import-ocr.spec.ts",
    "operator-configured local OCR command",
    "paper-book OCR missing-command browser refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signer_invites.rs",
    "linked_invite_for_second_sequential_slot_conflicts_without_token",
    "external signer linked invite sequential blocker coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signer_invites.rs",
    "linked_invite_for_first_sequential_slot_succeeds_and_initiates_slot",
    "external signer linked invite first sequential initiation coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signer_invites.rs",
    "linked_invite_for_parallel_second_slot_succeeds",
    "external signer linked invite parallel initiation coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signer_invites.rs",
    "public_lookup_for_linked_invite_redacts_secrets_and_legal_claim_fields",
    "external signer linked invite public redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signer_invites.rs",
    "public_accept_updates_tracking_and_audit_without_signature_completion",
    "external signer invite response tracking-only coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub external_envelope_id: Option<Uuid>",
    "external signer invite optional envelope id request marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub external_slot_id: Option<Uuid>",
    "external signer invite optional slot id request marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "external_envelope_id and external_slot_id must be supplied together",
    "external signer invite linked id pair validation marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "prepare_envelope_slot_for_external_invite",
    "external signer invite linked slot preparation marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "commit_envelope_slot_for_external_invite",
    "external signer invite linked slot commit marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub external_envelope: Option<ExternalSignerInviteEnvelopeView>",
    "external signer invite response envelope metadata marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "creates and lists external signing envelopes and sends linked invite fields",
    "web external signing envelope client coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "external_envelope_id: 'env-1'",
    "web external signing linked invite envelope id payload marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "external_slot_id: 'slot-1'",
    "web external signing linked invite slot id payload marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "lists external-signing envelopes, slots, and the backend no-legal notice",
    "web SigningPanel envelope list/no-legal notice coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "creates an external-signing envelope with order policy and signer slots",
    "web SigningPanel workflow-only envelope creation coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "creates an invite linked to a selected envelope slot",
    "web SigningPanel linked-slot invite coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "expect(bodies[0]).not.toHaveProperty('external_envelope_id');",
    "web SigningPanel tracking-only invite payload marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "shows a safe sequential-order conflict without leaking token material",
    "web SigningPanel safe sequential conflict coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "expect(screen.queryByText(/cxi_should_not_render/)).toBeNull();",
    "web SigningPanel conflict token redaction marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "await waitFor(() => expect(screen.queryByText('Slot ainda não disponível')).toBeNull());",
    "web SigningPanel conflict clears after slot change marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "signing.envelopes.completion.summary",
    "web SigningPanel envelope completion summary marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "slotIdentityRequirements(slot, t)",
    "web SigningPanel envelope identity requirement marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalSigningWorkflowsPage.tsx",
    "if (workflow === 'external_envelope') return t('signing.invites.workflow.externalEnvelope');",
    "web Ferramentas external envelope workflow label marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalSigningWorkflowsPage.test.tsx",
    "expect(screen.getByText('Fluxo com envelope')).toBeTruthy();",
    "web Ferramentas external envelope localized row coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalSigningWorkflowsPage.test.tsx",
    "expect(screen.queryByText('external_envelope')).toBeNull();",
    "web Ferramentas raw workflow label redaction coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalSigningWorkflowsPage.test.tsx",
    "expect(JSON.parse(String(lookup?.init?.body))).toEqual({ token: unsafeLookingToken });",
    "web Ferramentas token lookup body-only coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "written_resolution_evidence_status: WrittenResolutionEvidenceStatusView::from_summary",
    "written-resolution evidence compliance status API marker",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "patch_act_written_resolution_evidence_round_trips_and_persists",
    "written-resolution evidence patch persistence coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "compliance_reports_written_resolution_evidence_status_only",
    "written-resolution evidence compliance status coverage",
  );
  assertFileContains(
    "crates/chancela-core/src/seal.rs",
    "written_resolution_evidence_binds_into_the_seal_digest_when_present",
    "written-resolution evidence seal digest binding coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_reports_embedded_doc_timestamp_evidence_without_b_lta_claim",
    "archive package DocTimeStamp evidence coverage",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "pub struct LocalDglabInterchangeManifest",
    "archive local DGLAB interchange manifest struct marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "chancela-local-dglab-interchange-manifest/v1",
    "archive local DGLAB interchange schema marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "pub fn build_local_dglab_interchange_manifest",
    "archive local DGLAB interchange builder marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "pub fn validate_local_dglab_interchange_manifest",
    "archive local DGLAB interchange validator marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "let files = local_dglab_file_entries(&source.files);",
    "archive local DGLAB interchange source-manifest file projection marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "local_dglab_interchange.files must be sorted by package path",
    "archive local DGLAB interchange sorted-file validation marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "local_dglab_interchange.files must match source manifest files",
    "archive local DGLAB interchange source validation marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "official_dglab_interchange: false",
    "archive local DGLAB official interchange false marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "external_dglab_approval_obtained: false",
    "archive local DGLAB approval false marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "legal_archive_certified: false",
    "archive local DGLAB legal archive false marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "destructive_disposal_performed: false",
    "archive local DGLAB destructive disposal false marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "local_dglab_interchange_manifest_generation_is_deterministic",
    "archive local DGLAB deterministic generation coverage",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "local_dglab_interchange_validator_rejects_any_true_claim_flag",
    "archive local DGLAB true claim flag refusal coverage",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "local_dglab_interchange_validator_rejects_mismatches_unsafe_paths_and_blanks",
    "archive local DGLAB mismatch unsafe path blank refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/books/{id}/archive/local-dglab-interchange-manifest",
    "API local DGLAB interchange manifest route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "pub async fn get_book_local_dglab_interchange_manifest",
    "API local DGLAB interchange manifest handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "`GET /v1/books/{id}/archive/local-dglab-interchange-manifest`",
    "API local DGLAB interchange read-only endpoint doc marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "Permission::BookExport",
    "API local DGLAB interchange book.export permission marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    "local_dglab_interchange_manifest_route_is_classified_as_gated",
    "API local DGLAB interchange route classification coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local_dglab_interchange_manifest_requires_book_export_permission",
    "API local DGLAB interchange permission coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local_dglab_interchange_manifest_is_deterministic_read_only_and_not_packaged",
    "API local DGLAB interchange deterministic read-only coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local DGLAB manifest endpoint must not append ledger events",
    "API local DGLAB interchange no-ledger coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local DGLAB manifest endpoint must not create persisted package or manifest files",
    "API local DGLAB interchange no-persisted-files coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local DGLAB manifest endpoint must not persist returned manifest bytes",
    "API local DGLAB interchange no-persisted-bytes coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "local DGLAB manifest must not be a ZIP member",
    "API local DGLAB interchange no-ZIP-member coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "getBookLocalDglabInterchangeManifest",
    "web API client local DGLAB manifest download marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "useDownloadBookLocalDglabInterchangeManifest",
    "web API hook local DGLAB manifest download marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "localDglabInterchangeManifestFilename",
    "BookDetail local DGLAB manifest JSON filename marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "LOCAL_DGLAB_MANIFEST_CONTENT_TYPE = 'application/json'",
    "BookDetail local DGLAB manifest JSON content-type marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "downloads the local DGLAB interchange manifest as local metadata-only JSON",
    "BookDetail local DGLAB manifest JSON download coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "url: '/v1/books/book-1/archive/local-dglab-interchange-manifest'",
    "BookDetail local DGLAB manifest GET coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "expect(saved.filename.endsWith('.zip')).toBe(false);",
    "BookDetail local DGLAB manifest no-ZIP download coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "expect(savedJson.official_dglab_interchange).toBe(false);",
    "BookDetail local DGLAB manifest official-export false coverage",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "pub enum AsicProfileShape",
    "ASiC structural profile-shape diagnostic type",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "pub struct AsicManifestDiagnostic",
    "ASiC manifest diagnostic type",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "pub struct AsicSignatureDiagnostic",
    "ASiC signature diagnostic type",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "pub enum AsicDiagnosticBlockerId",
    "ASiC stable blocker-id type",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "legal validity, or production compliance",
    "ASiC structural diagnostics conservative boundary copy",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_e_profile_report_exposes_manifest_blocker_ids_without_relaxing_extraction",
    "ASiC diagnostic blocker coverage without relaxed extraction",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_e_manifest_references_missing_signature",
    "ASiC missing referenced signature blocker coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_e_manifest_digest_mismatch",
    "ASiC manifest digest mismatch blocker coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/signature/asic/inspect",
    "API ASiC inspection route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    "read-only technical ASiC/CAdES inspection",
    "API ASiC inspection route-classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "Local technical ASiC/CAdES inspection for arbitrary ASiC ZIP containers",
    "API ASiC inspection technical scope marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "runs local CAdES validation only for the bounded ASiC-S/CAdES and ASiC-E/CAdES shapes",
    "API ASiC inspection bounded CAdES-only marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "call signing providers, mutate archives, or claim legal/qualified-signature validity",
    "API ASiC inspection no-XAdES/live-trust marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    'alias = "asic_base64"',
    "API ASiC inspection base64 request alias marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "declared_sha256: Option<String>",
    "API ASiC inspection declared sha256 marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "declared_size_bytes: Option<usize>",
    "API ASiC inspection declared size marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "pub member_paths: AsicMemberPathsReport",
    "API ASiC inspection member paths response marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "pub manifest_diagnostics: Vec<AsicManifestDiagnosticReport>",
    "API ASiC inspection manifest diagnostics marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "pub signature_diagnostics: Vec<AsicSignatureDiagnosticReport>",
    "API ASiC inspection signature diagnostics marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "pub cades: Option<AsicCadesValidationReport>",
    "API ASiC inspection optional CAdES report marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "xades_validation_performed: false",
    "API ASiC inspection XAdES validation false marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "production_asic_compliance_claimed: false",
    "API ASiC inspection production compliance false marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "eidas_legal_effect_claimed: false",
    "API ASiC inspection eIDAS legal-effect false marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_bounded_s_cades_returns_valid_local_result",
    "API ASiC inspection bounded ASiC-S/CAdES coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_bounded_e_cades_two_payloads_validates_manifest",
    "API ASiC inspection bounded ASiC-E/CAdES coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_xades_s_and_e_are_structured_unsupported",
    "API ASiC inspection XAdES unsupported coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_profile_blockers_remain_structured",
    "API ASiC inspection structured blockers coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_blocks_oversized_uncompressed_zip_member",
    "API ASiC inspection decompressed member cap coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_bad_inputs_fail_with_validation_errors",
    "API ASiC inspection bad-input/fixity coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_response_claim_boundaries_stay_false",
    "API ASiC inspection no-claim boundary coverage",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "struct ZipSizeBudget",
    "ASiC ZIP actual decompression budget marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "fn inspect_actual_consumed",
    "ASiC ZIP actual decompressed-size accounting marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "account_zip_member_for_inspection",
    "ASiC ZIP unsupported/XAdES/CAdES member accounting marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic.rs",
    "ASiC ZIP members decompressed to",
    "ASiC ZIP aggregate actual decompressed-size message marker",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_zip_total_actual_uncompressed_size_limit_blocks_underdeclared_inflation",
    "ASiC ZIP underdeclared aggregate inflation coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_profile_inspection_blocks_underdeclared_oversized_cades_signature",
    "ASiC ZIP underdeclared CAdES signature size coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "asic_profile_inspection_accounts_underdeclared_unsupported_meta_inf_members",
    "ASiC ZIP underdeclared unsupported META-INF accounting coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/roundtrip.rs",
    "unsupported META-INF",
    "ASiC ZIP unsupported META-INF blocker coverage",
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
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_embeds_matching_external_validator_raw_report_attachment",
    "archive package runtime external-validator raw report attachment coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "raw_report_path_pattern",
    "archive package external-validator raw report path pattern coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "document_bundle_indexes_matching_external_validator_metadata",
    "document bundle runtime external-validator metadata coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_accepts_verified_raw_report_attachment",
    "API external-validator raw report attachment acceptance coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_report_metadata_api_rejects_raw_report_digest_mismatch",
    "API external-validator raw report digest mismatch refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "!created.to_string().contains(\"content_base64\")",
    "API external-validator raw report create response byte redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "!listed.to_string().contains(\"content_base64\")",
    "API external-validator raw report list response byte redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/roles.rs",
    "Read-only drift diagnostics for an editable seeded role",
    "API seeded role drift read-only diagnostic marker",
  );
  assertFileContains(
    "crates/chancela-api/src/roles.rs",
    "pub seeded_role_drift: Option<SeededRoleDriftView>",
    "API seeded role drift response field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/roles.rs",
    "customized_seeded_platform_admin_reports_missing_defaults_without_granting_them",
    "API seeded role drift no-auto-grant coverage",
  );
  assertFileContains(
    "apps/web/src/features/rbac/FuncoesSection.tsx",
    "drift.requires_manual_review",
    "web RBAC seeded role drift manual-review marker",
  );
  assertFileContains(
    "apps/web/src/features/rbac/rbac.test.tsx",
    "shows seeded role drift as a manual-review status",
    "web RBAC seeded role drift coverage marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "pub readability_caveats: ReadabilityCaveatMetadata",
    "archive readability caveat manifest field marker",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "readability_caveats_default_when_missing_from_v1_manifest",
    "archive readability caveat old-v1 conservative default coverage",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "readability_caveats_reject_unknown_manifest_fields",
    "archive readability caveat unknown-field refusal coverage",
  );
  assertFileContains(
    "crates/chancela-archive/src/lib.rs",
    "zk_removes_gdpr_obligations",
    "archive ZK/GDPR caveat false-claim marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "FamilyChannelMismatch",
    "template family/channel mismatch issue marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "is_existing_authored_channel_compatibility",
    "template family/channel compatibility carve-out marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "expected family/channel incompatibility issue",
    "template family/channel mismatch coverage marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "service_type",
    "MCP trust catalog structured service-type filter marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "list_external_validator_reports",
    "MCP external-validator report summary tool marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "assert_eq!(tool.input_schema, closed_empty_schema())",
    "MCP external-validator closed no-arg schema marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "external_validator_catalog_exposes_no_raw_report_route_or_payload_field",
    "MCP external-validator no raw-report exposure coverage",
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
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct StructureDepthReport",
    "PDF accessibility structural-depth report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "complete_for_local_profile",
    "PDF accessibility bounded topology completeness marker",
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
    "accessibility_explicit_alt_text_decorative_model_keeps_limited_structure_blocker",
    "PDF accessibility bounded structure blocker retention coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_non_text_accounting_reports_missing_and_invalid_entries",
    "PDF accessibility non-text blocker decomposition coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_page_breaks_do_not_require_decorative_accounting",
    "PDF accessibility page breaks decorative-accounting coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "\\\"version\\\":7",
    "PDF accessibility report JSON v7 coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "\\\"structure_depth\\\":{",
    "PDF accessibility JSON structural-depth marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "assert_eq!(report.structure_depth.max_depth, 4);",
    "PDF accessibility structural max-depth coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "selfcheck_rejects_invalid_table_topology",
    "PDF accessibility bounded topology self-check coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/selfcheck.rs",
    "verify_local_structure_topology",
    "PDF accessibility bounded topology self-check marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "PdfUaBlocker::LimitedTaggedStructure",
    "PDF accessibility LimitedTaggedStructure blocker marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "writer_owned_decorative_artifacts_accounted_for",
    "PDF accessibility writer-owned decorative artifact accounting marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "layout:header-rule",
    "PDF accessibility header-rule decorative target coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "vote-table-{position}-rule",
    "PDF accessibility vote-table rule decorative target coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "block:{index}:rule",
    "PDF accessibility explicit-rule decorative target coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "signature-line:{slot_index}",
    "PDF accessibility signature-line decorative target coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "fn known_decorative_targets(doc: &DocumentModel) -> Vec<String>",
    "PDF accessibility known decorative target boundary",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "New caller-owned non-text block variants must update this accounting",
    "PDF accessibility exhaustive DocumentBlock accounting marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "accessibility_non_text_accounting_covers_current_block_variants",
    "PDF accessibility current DocumentBlock variant accounting coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "pdf_ua_is_not_claimed_with_minimal_tagging",
    "PDF/UA non-certification marker coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    '("ChancelaKeyValue", "Table")',
    "PDF key-value table role-map target marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    '("ChancelaVoteTable", "Table")',
    "PDF vote table role-map target marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/layout.rs",
    "StructureRole::KeyValueTable => \"Table\"",
    "PDF key-value table structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/layout.rs",
    "StructureRole::TableHeaderCell => \"TH\"",
    "PDF table header cell structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/layout.rs",
    "StructureRole::TableDataCell => \"TD\"",
    "PDF table data cell structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/pdfa.rs",
    "layout::StructureRole::TableRow => \"TR\"",
    "PDF structure tree table row role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "\\\"key_value_tables_have_table_semantics\\\":true",
    "PDF accessibility table semantics complete JSON marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    "\\\"pdf_ua_blockers\\\":[\\\"limited_tagged_structure\\\"]",
    "PDF accessibility reduced bounded blocker list marker",
  );
  assertFileDoesNotContain(
    "crates/chancela-doc/src/tests.rs",
    "\\\"pdf_ua_blockers\\\":[\\\"no_alt_text_model\\\",\\\"limited_tagged_structure\\\"]",
    "PDF accessibility default fixture no-alt blocker removal marker",
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
    "attachment_for_identity",
    "external-validator report identity disambiguation helper",
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
    "EXTERNAL_VALIDATOR_RAW_REPORT_MAX_BYTES",
    "external-validator raw report upload size bound",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "EXTERNAL_VALIDATOR_REPORT_UPLOAD_MAX_BYTES",
    "external-validator metadata-plus-raw upload size bound",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "parse_declared_raw_report",
    "external-validator declared raw report parser",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "decoded.len() as u64 != size_bytes || sha256_hex(&decoded) != sha256",
    "external-validator raw report fixity enforcement",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "EXTERNAL_VALIDATOR_RAW_REPORT_ARCHIVE_PATH_PATTERN",
    "external-validator raw report archive path pattern",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface ExternalValidatorRawReportSummary",
    "web external-validator raw report summary contract",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface ExternalValidatorRawReportUpload",
    "web external-validator raw report upload contract",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "raw_report?: ExternalValidatorRawReportUpload",
    "web external-validator optional raw report upload body marker",
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
    "crates/chancela-api/src/external_validator_evidence.rs",
    "download_external_validator_raw_report_bytes",
    "external-validator raw report byte download API",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "raw_report_download_filename",
    "external-validator raw report attachment filename helper",
  );
  assertFileContains(
    "crates/chancela-api/src/external_validator_evidence.rs",
    "attachment; filename=\\\"{filename}\\\"",
    "external-validator raw report attachment disposition marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report",
    "external-validator raw report byte download route",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_raw_report_downloads_retained_bytes_after_reload",
    "API external-validator raw report retained byte download coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_raw_report_download_requires_settings_read",
    "API external-validator raw report settings.read gate coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_raw_report_manifest_only_returns_404",
    "API external-validator raw report manifest-only 404 coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "external_validator_raw_report_download_fail_closed_cases",
    "API external-validator raw report unsafe/malformed/duplicate fail-closed coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create response must not expose embedded raw report bytes",
    "API external-validator create response raw byte redaction marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "list response must not expose embedded raw report bytes",
    "API external-validator list response raw byte redaction marker",
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
    "docs/CI-CHECKPOINTS.md",
    "MCP resource/prompt coverage including workflow provenance review\nguidance and draft-vs-signed comparison review guidance",
    "CI checkpoints MCP review-aids lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "dashboard guest recent-events redaction",
    "CI checkpoints dashboard guest recent-events redaction lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated-document by-id\ndownload route plus condominium absent-owner communication auto-generation",
    "CI checkpoints generated-document by-id route lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "raw-report byte download API",
    "CI checkpoints external-validator raw-report byte lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "imported-document review receipt UI",
    "CI checkpoints imported-document receipt lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "trust identifier-match explanations",
    "CI checkpoints trust identifier-match lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "release clean-source\nprovenance gating",
    "CI checkpoints release clean-source lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "seeded role drift diagnostics",
    "CI checkpoints seeded role drift lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "archive readability/ZK caveat\nmetadata",
    "CI checkpoints archive readability caveat lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "template family/channel rule guards",
    "CI checkpoints template family/channel lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "MCP trust-catalog filter\ndiscoverability",
    "CI checkpoints MCP trust catalog filter lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "MCP draft-vs-signed comparison review prompt/resource/no-call/no-claim\nmarkers",
    "CI checkpoints static MCP draft-signed comparison marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "dashboard guest `recent_events: []` redaction and no-permission-grant\nmarkers",
    "CI checkpoints static dashboard guest redaction marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated-document by-id route, `act.read` gate, durable/in-memory,\ncanonical Ata preservation, absent-owner communication auto-generation, and\npending dispatch evidence markers",
    "CI checkpoints static generated-document by-id marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata",
    "CI checkpoints absent-owner communication server command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "including raw metadata and raw-report\n  byte downloads",
    "CI checkpoints external-validator raw metadata/raw-report command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "the settings.read raw metadata and raw-report\nbyte download",
    "CI checkpoints static raw-report byte marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "imported-document review receipt markers for pending/reviewed states",
    "CI checkpoints static imported-document receipt marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "trust identifier-match explanation/copy-safe hash and\nSKI markers",
    "CI checkpoints static trust identifier-match marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retained-export cleanup dry-run planning",
    "CI checkpoints retained-export dry-run lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retention duplicate review-only request guards, queued-review status surfacing,\nand prior bounded execution projection",
    "CI checkpoints retention duplicate-review lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retention due-candidate duplicate-review, queued-status, prior-execution\nprojection, and projected-row duplicate-action suppression UI markers",
    "CI checkpoints retention prior projection static marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "Template catalog metadata/semantic lint",
    "CI checkpoints template semantic lint command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "all-family standalone agenda-item templates",
    "CI checkpoints agenda-item template lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "read-only local DGLAB interchange\nmanifest API and BookDetail JSON-download markers",
    "CI checkpoints local DGLAB API/BookDetail lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "101-template\ncensus",
    "CI checkpoints 101-template census marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "CSC delegation/revocation template IDs/rendering markers",
    "CI checkpoints CSC delegation/revocation marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "authenticated\nRBAC-denied/rejected/malformed/suppressed sanitized audit markers",
    "CI checkpoints platform forwarded failure audit marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "BookDetail JSON-save markers",
    "CI checkpoints local DGLAB BookDetail JSON marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "no-ZIP-member/no-ledger\nmarkers plus BookDetail JSON-save markers",
    "CI checkpoints local DGLAB no-ZIP/no-ledger marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "template legal effect, DRE\nverification",
    "CI checkpoints template legal no-claim marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "official DGLAB export,\ngovernment filing",
    "CI checkpoints local DGLAB no-official-export marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "metadata lane keeps release-trust, SBOM package-linkage, and package provenance",
    "CI checkpoints release-trust metadata lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "Docker job stays no-push/local-load with `local-ci`",
    "CI checkpoints release-trust Docker local-ci marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "package integrity, emits `releaseTrust.mode = unsigned-dev`",
    "CI checkpoints release workflow unsigned-dev marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "Production package validation now requires\n`--manifest`",
    "CI checkpoints release production manifest-required marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "static workflow assurance only; switch those checks to `production` only when",
    "CI checkpoints release workflow static-only boundary marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    "function guardCiMetadataWorkflow(ciText)",
    "release trust self-test CI metadata workflow guard marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/ci.yml jobs.metadata must run SBOM package linkage self-test",
    "release trust self-test SBOM linkage metadata marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    "releaseTrust.imagePublication.status",
    "release trust self-test Docker nested publication status marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/ci.yml jobs.docker must validate Docker trust metadata in local-ci mode",
    "release trust self-test Docker local-ci validation marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/release.yml jobs.package must emit releaseTrust.mode = unsigned-dev",
    "release trust self-test release unsigned-dev workflow marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/release.yml jobs.package must mark package attestation not_attested",
    "release trust self-test release not_attested workflow marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/release.yml jobs.package must check the SBOM with --package linkage",
    "release trust self-test release SBOM linkage marker",
  );
  assertFileContains(
    "scripts/check-package-artifacts.mjs",
    "--require-clean-source",
    "package artifact clean-source flag marker",
  );
  assertFileContains(
    "scripts/check-package-artifacts.mjs",
    "sourceTreeState must be clean when --require-clean-source is set",
    "package artifact clean-source dirty/unknown refusal marker",
  );
  assertFileContains(
    ".github/workflows/release.yml",
    "npm run test:package-integrity -- --require-clean-source",
    "release workflow package integrity clean-source marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    ".github/workflows/release.yml jobs.package must run package artifact integrity checks with --require-clean-source",
    "release trust self-test clean-source workflow marker",
  );
  assertFileContains(
    "docs/CI-RELEASE-HARDENING.md",
    "`--require-clean-source` rejects `dirty` and\n  `unknown` source tree states",
    "CI release hardening clean-source fixture marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    'if ((mode === "production" || expectedMode === "production") && !manifest)',
    "release trust production package manifest-required guard marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    "Production package validation requires --manifest",
    "release trust production package manifest-required error marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    "productionWithoutManifest.releaseTrust.mode = \"production\";",
    "release trust self-test package-mode production manifest-required marker",
  );
  assertFileContains(
    "scripts/check-release-trust.mjs",
    "expectedProductionWithoutManifest",
    "release trust self-test expected-mode production manifest-required marker",
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
    "status_scope: \"declared_capacity_evidence_only\".to_owned()",
    "declared signer-capacity evidence scope marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "verification_status: \"not_checked_by_scap\".to_owned()",
    "declared signer-capacity non-SCAP marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/cmd_signing.rs",
    "cmd_signing_round_trip_produces_a_validating_signed_pdf",
    "CMD declared signer-capacity evidence coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/local_pkcs12_signing.rs",
    "local_pkcs12_signs_as_advanced_technical_evidence_only",
    "local PKCS#12 declared signer-capacity evidence coverage",
  );
  assertFileContains(
    "crates/chancela-store/tests/store.rs",
    "declared_capacity_evidence_only",
    "store declared signer-capacity evidence persistence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "multi_signature_local_renewal_plan",
    "signature status multi-signature renewal-plan field",
  );
  assertFileContains(
    "crates/chancela-pades/src/dss.rs",
    "pub vri_tu_keys: Vec<Vec<u8>>",
    "PAdES DSS keyed VRI /TU report field",
  );
  assertFileContains(
    "crates/chancela-pades/src/dss.rs",
    "pub fn has_vri_tu_for_key(&self, vri_key: &[u8]) -> bool",
    "PAdES DSS keyed VRI /TU lookup helper",
  );
  assertFileContains(
    "crates/chancela-pades/src/renewal.rs",
    "dss.has_vri_tu_for_key(&signature.vri_key)",
    "PAdES multi-signature renewal keyed VRI /TU check",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "multi_signature_renewal_plan_matches_tu_to_the_specific_vri_key",
    "PAdES multi-signature keyed VRI /TU regression coverage",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "assert!(report.dss.has_vri_tu_for_key(&first_signature.vri_key));",
    "PAdES keyed VRI /TU positive assertion",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "assert!(!report.dss.has_vri_tu_for_key(&second_signature.vri_key));",
    "PAdES keyed VRI /TU negative assertion",
  );
  assertFileContains(
    "crates/chancela-api/src/pdf_signature_validation.rs",
    "pub vri_tu_keys: Vec<String>",
    "PDF signature validation keyed VRI /TU response field",
  );
  assertFileContains(
    "crates/chancela-api/src/pdf_signature_validation.rs",
    "vri_tu_keys: vri_keys_text(&report.vri_tu_keys)",
    "PDF signature validation keyed VRI /TU payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "vri_tu_keys: dss_vri_keys_text(&report.vri_tu_keys)",
    "signature evidence status keyed VRI /TU payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "Optional RFC 3339 validation time to write as local DSS VRI `/TU` metadata.",
    "PAdES DSS attach validation_time request marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "attach_pdf_dss_with_validation_time(&input_pdf, &evidence.dss, validation_time)",
    "PAdES DSS attach caller validation_time writer marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "cc_dss_attach_api_accepts_validation_time_and_reports_tu_renewal_plan",
    "PAdES DSS attach validation_time API coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "dss_attach_rejects_malformed_validation_time_without_digest_change_or_event",
    "PAdES DSS attach malformed validation_time refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "validation_time must be an RFC 3339 timestamp",
    "PAdES DSS attach malformed validation_time error marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "monitor_timestamp_renewal",
    "PAdES DSS attach renewal monitor-state API marker",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "ltv_renewal_plan_monitors_when_local_evidence_inputs_are_present",
    "PAdES renewal monitor-state local evidence coverage",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "crate_find(&with_dss, b\"/TU (D:20260709120000Z)\")",
    "PAdES DSS VRI /TU local evidence byte marker",
  );
  assertFileContains(
    "crates/chancela-pades/src/tests.rs",
    "LtvRenewalPlanAction::MonitorTimestampRenewal",
    "PAdES renewal monitor-state action marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_records_bounded_archive_and_idempotent_repeat",
    "bounded retention execution regression coverage",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "useDryRunPrivacyRetentionPolicy",
    "web retention policy dry-run hook",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function RetentionPolicyPanel",
    "Settings privacy retention policy panel",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function RetentionDryRunPanel",
    "Settings privacy retention dry-run panel",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "destructive_execution_supported",
    "Settings privacy retention non-destructive execution marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "lists, creates, patches, and dry-runs retention policies without destructive execution",
    "Settings privacy retention policy UI regression coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "would_execute: false",
    "Settings privacy retention dry-run no-execution assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "/execute|delete|anonymize/",
    "Settings privacy retention destructive endpoint refusal assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "!call.body?.includes('\"anonymize\"')",
    "Settings privacy retention destructive payload refusal assertion",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/en-US.ts",
    "settings.privacy.retention.dryRun.notice.body",
    "i18n retention dry-run boundary keys",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/pt-PT.ts",
    "settings.privacy.retention.execution.false",
    "i18n retention non-destructive execution key",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    "\"execution_status\": \"awaiting_review\"",
    "retention execution review-queue fixture awaiting marker",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    "\"destructive_disposal_completed\": false",
    "retention execution fixture non-destructive marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "usePrivacyRetentionExecutions",
    "web retention execution review queue hook",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "listRetentionExecutions: (status?: RetentionExecutionStatus)",
    "web retention execution client status filter marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function RetentionExecutionReviewQueue",
    "Settings retention execution review queue marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "privacy-retention-execution-status",
    "Settings retention execution status filter marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "Fila de revisão de execução",
    "Settings retention execution review queue coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "/v1/privacy/retention-executions?status=executed",
    "Settings retention execution status-filter coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_request_records_manual_review_for_non_destructive_policy",
    "API retention manual-review execution request coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "/v1/privacy/retention-executions?status=awaiting_review",
    "API retention execution awaiting-review filter coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    '("/v1/privacy/retention-due-candidates", RouteClass::Gated)',
    "API retention due-candidates route classification",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "`GET /v1/privacy/retention-due-candidates` — read-only closed-book archive retention scanner",
    "API retention due-candidates read-only handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "unsupported_retention_period: {period:?}; expected a single-component period like P10Y, P6M, or P30D",
    "API retention due-candidates supported-period boundary",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_closed_book_with_active_archive_policy_becomes_due",
    "API retention due-candidates active-policy coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_unsupported_retention_period_fails_closed",
    "API retention due-candidates unsupported-period coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_get_is_non_mutating",
    "API retention due-candidates non-mutating GET coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "fn retention_prior_bounded_due_candidate_projection",
    "API retention due-candidates prior bounded projection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "fn retention_execution_record_is_safe_bounded_prior",
    "API retention prior projection safe evidence gate marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "RETENTION_PRIOR_BOUNDED_ARCHIVE_NEXT_STEP",
    "API retention prior projection canonical archive next-step marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_project_prior_bounded_execution_without_mutation",
    "API retention due-candidates prior bounded archive projection coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_ignore_unsafe_prior_bounded_execution_flags",
    "API retention due-candidates unsafe prior projection refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_project_prior_bounded_no_action_recorded_without_mutation",
    "API retention due-candidates prior bounded no-action projection coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "prior execution next_step must not surface unsafe term",
    "API retention prior projection canonical next-step safety marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_surface_existing_review_without_mutation",
    "API retention due-candidates existing-review surfacing coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "GET must not write another retention execution record",
    "API retention due-candidates existing-review no-extra-record marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"full_erasure_completed": false',
    "retention due-candidates fixture false full-erasure marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"prior_execution": {',
    "retention due-candidates fixture prior execution marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"bounded_executor": true',
    "retention due-candidates fixture prior bounded executor marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"next_step": "Prior bounded archive evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action."',
    "retention due-candidates fixture canonical prior next-step marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"code": "unsupported_retention_period"',
    "retention due-candidates fixture unsupported-period marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "usePrivacyRetentionDueCandidates",
    "web retention due-candidates hook",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "listRetentionDueCandidates: ()",
    "web retention due-candidates client marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function RetentionDueCandidatesPanel",
    "Settings retention due-candidates panel marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "shows unsupported-period blocked due candidates without a destructive completion claim",
    "Settings retention due-candidates unsupported-period coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "call.url.endsWith('/v1/privacy/retention-due-candidates')",
    "Settings retention due-candidates page-load request marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "async function requestRetentionReview(candidate: RetentionDueCandidate)",
    "Settings retention due-candidate review request handler",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "execution_mode: 'review_only'",
    "Settings retention due-candidate forced review-only request marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function retentionQueuedReviewForCandidate",
    "Settings retention due-candidate queued-review matcher",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Revisão já na fila",
    "Settings retention due-candidate queued-review status marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Evidência delimitada existente",
    "Settings retention due-candidate projected evidence action-suppression marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "prior.targets_acted_count",
    "Settings retention due-candidate projected evidence target-count marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "{queuedReview.execution_status} · {queuedReview.id}",
    "Settings retention due-candidate queued-review id marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Pedido em {formatDateTime(queuedReview.requested_at)}",
    "Settings retention due-candidate queued-review time marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "void qc.invalidateQueries({ queryKey: keys.privacyRetentionDueCandidates });",
    "web retention due-candidate query refresh after execution record",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "void qc.invalidateQueries({ queryKey: ['privacy', 'retention-executions'] });",
    "web retention execution query refresh after execution record",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "records a review-only request from a due retention candidate row",
    "Settings retention due-candidate review request coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "Pedir revisão de evidência",
    "Settings retention due-candidate operator action marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "shows already queued review state for a due retention candidate without posting again",
    "Settings retention due-candidate queued-review no-POST coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "shows projected bounded execution and does not offer duplicate review",
    "Settings retention due-candidate projected evidence no-POST coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "awaiting_review · retention-exec-queued-due",
    "Settings retention due-candidate queued-review status/id coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "execution_request: {",
    "Settings retention due-candidate dry-run execution_request marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "toBeGreaterThan(initialDueCandidateGets)",
    "Settings retention due-candidate query refresh assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "!call.body?.includes('execute_supported')",
    "Settings retention due-candidate no execute-supported payload marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_review_only_duplicate_returns_existing_queue_without_new_history_or_ledger",
    "API retention duplicate review-only reuse coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "duplicate review request must not write another execution record",
    "API retention duplicate review-only no-extra-record marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "duplicate review request must not append another ledger event",
    "API retention duplicate review-only no-extra-ledger marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_review_only_concurrent_duplicates_create_one_queue_and_ledger_event",
    "API retention concurrent duplicate guard coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "concurrent duplicate review requests must create one execution record",
    "API retention concurrent duplicate one-record marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "concurrent duplicate review requests must append one ledger event",
    "API retention concurrent duplicate one-ledger marker",
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
    "crates/chancela-api/src/data_status.rs",
    "fn sqlite_logical_table",
    "data status SQLite per-table logical usage helper",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    'id: format!("sqlite_table_{table}")',
    "data status SQLite per-table logical usage id marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "sqlite_logical_usage_includes_per_table_payload_stats",
    "data status SQLite per-table logical payload coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "UsageBasis::SqliteLogicalPayload",
    "data status SQLite logical payload basis marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'assert_eq!(ledger["basis"], "sqlite_logical_payload");',
    "API data status SQLite logical payload response coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "sqlite logical usage not reported",
    "API data status old SQLite logical placeholder rejection",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_metadata_validation_reports_stage_channel_and_authored_metadata_drift",
    "template stage/channel metadata drift coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    'POST_ACT_SEALED_PROVENANCE_FIELDS: &[&str] = &["ata_number", "payload_digest"]',
    "template post-act sealed provenance required-fields marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "authored_post_act_templates_bind_sealed_act_provenance",
    "template authored post-act sealed provenance guard coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_metadata_validation_reports_post_act_missing_sealed_provenance_bindings",
    "template post-act missing provenance regression coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_includes_representation_instrument_for_every_supported_family",
    "template catalog representation/proxy family coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_includes_agenda_item_template_for_every_supported_family",
    "template catalog agenda-item family coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "standalone agenda item templates should not be channel-scoped",
    "template catalog agenda-item channel-neutral marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "agenda-item wording missing from text",
    "template catalog agenda-item rendering marker",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ponto-ordem-trabalhos.json",
    "\"id\": \"csc-ponto-ordem-trabalhos/v1\"",
    "commercial company agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-ponto-ordem-trabalhos.json",
    "\"id\": \"condominio-ponto-ordem-trabalhos/v1\"",
    "condominium agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-ponto-ordem-trabalhos.json",
    "\"id\": \"assoc-ponto-ordem-trabalhos/v1\"",
    "association agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-ponto-ordem-trabalhos.json",
    "\"id\": \"fundacao-ponto-ordem-trabalhos/v1\"",
    "foundation agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-ponto-ordem-trabalhos.json",
    "\"id\": \"cooperativa-ponto-ordem-trabalhos/v1\"",
    "cooperative agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_includes_book_transport_term_for_every_supported_family",
    "template catalog book transport family coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "convocatoria_templates_render_dispatch_proof_for_every_notice_family",
    "template catalog all-family dispatch-proof rendering coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "attendance_list_templates_render_structured_attendees_for_every_supported_family",
    "template catalog all-family attendance-list rendering coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    'reg.specs().len(),\n            101',
    "template catalog 101-asset census marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "per_family(EntityFamily::CommercialCompany), 41",
    "template catalog 41 CSC census marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "csc_quota_division_and_unification_templates_keep_pending_law_refs",
    "template catalog CSC quota parity Pending law-ref coverage",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "csc.deliberacao.maioria_qualificada",
    "template catalog CSC quota majority threshold marker",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-divisao-quotas.json",
    "\"id\": \"csc-ata-divisao-quotas/v1\"",
    "commercial company quota division template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-divisao-quotas.json",
    "\"rule_pack_id\": \"csc-art63/v2\"",
    "commercial company quota division rule-pack marker",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-unificacao-quotas.json",
    "\"id\": \"csc-ata-unificacao-quotas/v1\"",
    "commercial company quota unification template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-unificacao-quotas.json",
    "\"rule_pack_id\": \"csc-art63/v2\"",
    "commercial company quota unification rule-pack marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_includes_csc_delegation_and_revocation_templates",
    "template catalog CSC delegation/revocation coverage",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-delegacao-poderes.json",
    "\"id\": \"csc-ata-delegacao-poderes/v1\"",
    "commercial company delegation powers template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-revogacao-poderes.json",
    "\"id\": \"csc-ata-revogacao-poderes/v1\"",
    "commercial company revocation powers template asset",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "should not introduce unresolved threshold text",
    "template catalog CSC delegation/revocation no-new-threshold coverage",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-procuracao-representacao.json",
    "\"id\": \"csc-procuracao-representacao/v1\"",
    "commercial company representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-procuracao-representacao.json",
    "\"id\": \"condominio-procuracao-representacao/v1\"",
    "condominium representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-procuracao-representacao.json",
    "\"id\": \"assoc-procuracao-representacao/v1\"",
    "association representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-procuracao-representacao.json",
    "\"id\": \"fundacao-procuracao-representacao/v1\"",
    "foundation representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-procuracao-representacao.json",
    "\"id\": \"cooperativa-procuracao-representacao/v1\"",
    "cooperative representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-termo-transporte.json",
    "\"id\": \"condominio-termo-transporte/v1\"",
    "condominium book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-termo-transporte.json",
    "\"id\": \"assoc-termo-transporte/v1\"",
    "association book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-termo-transporte.json",
    "\"id\": \"fundacao-termo-transporte/v1\"",
    "foundation book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-termo-transporte.json",
    "\"id\": \"cooperativa-termo-transporte/v1\"",
    "cooperative book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-convocatoria-orgao.json",
    "Comprovativo de expedição",
    "foundation convocatoria dispatch-proof heading",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-convocatoria-ag.json",
    "Comprovativo de expedição",
    "cooperative convocatoria dispatch-proof heading",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-aviso-convocatoria.json",
    "carta registada com aviso de receção",
    "condominium convocatoria dispatch channel rendering",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-lista-presencas.json",
    "capital {{ weight.Capital }}",
    "commercial company attendance capital-weight rendering",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_rejects_tampered_signature_value",
    "TSL XML-DSig tamper regression coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_accepts_p256_ecdsa_signed_by_embedded_cert",
    "TSL XML-DSig P-256 ECDSA acceptance coverage",
  );
  assertFileContains(
    "crates/chancela-tsl/tests/tsl_fixture.rs",
    "tsl_signature_validation_rejects_der_encoded_p256_ecdsa_signature_value",
    "TSL XML-DSig P-256 raw r||s boundary coverage",
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
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    'className="trust-accepted-hash"',
    "web TSA accepted hash wrapper marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    '<TrustResultGroup title="Registos TSA">',
    "web TSA records result group marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "expect(acceptedHashGroup.classList.contains('trust-accepted-hash')).toBe(true);",
    "web TSA accepted hash compact-display coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "const tsaRecordsGroup = screen.getByRole('group', { name: 'Registos TSA' });",
    "web TSA Registos TSA grouped-list coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "pub identifier_match: Option<Vec<IdentifierMatchField>>",
    "API trust catalog optional identifier_match field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "fingerprint_hits[0].identifier_match",
    "API trust catalog certificate identifier_match coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "all(|record| record.identifier_match.is_none())",
    "API trust catalog omits identifier_match without identifier filter coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    "IDENTIFIER_MATCH_LABELS",
    "web trust identifier-match label map marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/TrustCatalogPage.tsx",
    "Matched by technical catalog identifier only",
    "web trust identifier-match technical explanation marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "Matched by technical catalog identifier only: certificate SHA-256",
    "web TSL identifier-match explanation coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "expect(writeText).toHaveBeenCalledWith(certificateSha256);",
    "web TSL copy-safe full certificate hash coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "Matched by technical catalog identifier only: subject key ID",
    "web TSA identifier-match explanation coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "expect(writeText).toHaveBeenCalledWith(ski);",
    "web TSA copy-safe full SKI coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/trust.test.tsx",
    "legal validity|external validation|provider approval|qualified-status",
    "web trust identifier-match no legal/provider claim marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".trust-result-group",
    "web trust catalog grouped result CSS marker",
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
    "crates/chancela-mcp/src/server.rs",
    "WORKFLOW_PROVENANCE_REVIEW_PROMPT_NAME",
    "MCP workflow provenance review prompt name marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "workflow_provenance_review_checklist",
    "MCP workflow provenance review prompt catalog marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "chancela://mcp/workflow-provenance-review",
    "MCP workflow provenance review resource URI marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "workflow_provenance_review_resource_payload",
    "MCP workflow provenance review resource payload marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "prompts_get_returns_workflow_provenance_review_without_http_or_secret",
    "MCP workflow provenance review prompt no-secret/no-call coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_workflow_provenance_review_returns_static_categories_without_http_or_secret",
    "MCP workflow provenance review resource static coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"bridge_calls": false',
    "MCP workflow provenance review no bridge call marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"api_calls": false',
    "MCP workflow provenance review no API call marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"provider_calls": false',
    "MCP workflow provenance review no provider call marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"source_certification": false',
    "MCP workflow provenance review no source-certification claim marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "DRAFT_SIGNED_COMPARISON_REVIEW_PROMPT_NAME",
    "MCP draft-signed comparison review prompt name marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "draft_signed_comparison_review_checklist",
    "MCP draft-signed comparison review prompt catalog marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "chancela://mcp/draft-signed-comparison-review",
    "MCP draft-signed comparison review resource URI marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "draft_signed_comparison_review_resource_payload",
    "MCP draft-signed comparison review resource payload marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "prompts_get_returns_draft_signed_comparison_review_without_http_or_secret",
    "MCP draft-signed comparison review prompt no-secret/no-call coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_draft_signed_comparison_review_returns_static_categories_without_http_or_secret",
    "MCP draft-signed comparison review resource static coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_draft_signed_comparison_review_rejects_arguments_and_extra_params",
    "MCP draft-signed comparison review resource rejects args coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"local_json_only": true',
    "MCP draft-signed comparison review local JSON marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"external_validation": false',
    "MCP draft-signed comparison no external-validation claim marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"signature_qualification": false',
    "MCP draft-signed comparison no signature-qualification claim marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"full_ai_mcp_completion_claimed": false',
    "MCP spec coverage no full AI/MCP completion marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "fn ai_draft_source_provenance",
    "MCP deterministic AI draft statement-source builder marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "\"statement_sources\": statement_sources",
    "MCP AI draft statement-source envelope marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "attach_ai_draft_statement_sources",
    "MCP AI draft request provenance injection marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "\"authoritative_source_claimed\": false",
    "MCP AI statement-source authoritative claim false marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dto.rs",
    "Unsafe truthy flags are ignored",
    "API AI statement-source unsafe claim clamp marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dto.rs",
    "ignored_client_claims",
    "API AI statement-source ignored client claims marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ai_draft_requires_accepted_human_verification_before_signing",
    "API AI statement-source persistence/clamp coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/tests/live_api.rs",
    "API persisted statement source rows",
    "MCP live API persisted AI statement-source coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const statementSources = provenance.statement_sources ?? [];",
    "web AI review statement-source row rendering marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const sourceTypeCounts = Array.from",
    "web AI review grouped source-type counts marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const sourceType = aiRecordedSourceValue(source.source_type, missingLabel);",
    "web AI review source_type fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const path = aiRecordedSourceValue(source.path, missingLabel);",
    "web AI review statement-source path fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const sourceLabel = aiRecordedSourceValue(source.source_label, missingLabel);",
    "web AI review statement-source label fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const humanVerificationStatus = aiRecordedSourceValue",
    "web AI review statement-source status fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "`human_verified=${aiBooleanFlagLabel(source.human_verified)}`",
    "web AI review conservative human_verified flag marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "`authoritative_source_claimed=${aiClaimFlagLabel(",
    "web AI review conservative authoritative-source claim marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "`legal_validity_claimed=${aiClaimFlagLabel(",
    "web AI review conservative legal-validity claim marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "renders grouped provenance summary by source_type",
    "web AI review grouped source-type summary coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "renders statement-source rows with path type label status and conservative flags",
    "web AI review statement-source row field/flag coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "renders missing statement-source fields with missing labels",
    "web AI review missing field fallback coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "keeps missing and empty statement_sources safe",
    "web AI review missing/empty statement_sources coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "records reject and accept decisions and only enables Signing after acceptance",
    "web AI review accept/reject unchanged gate coverage",
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
    "apps/web/src/api/client.ts",
    "typeof body === 'string'",
    "web client external-validator manual JSON upload path marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "post<ExternalValidatorReportUploadResponse>('/v1/external-validator-reports', body)",
    "web client external-validator structured upload path marker",
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
    "crates/chancela-api/src/settings.rs",
    "pub struct WorkflowReminderSettings",
    "API workflow reminder policy settings shape",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub const DEFAULT_WORKFLOW_REMINDER_DASHBOARD_LIMIT: u16 = 5;",
    "API workflow reminder dashboard-limit default marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub const DEFAULT_WORKFLOW_REMINDER_DUE_SOON_DAYS: u16 = 45;",
    "API workflow reminder due-soon default marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub const DEFAULT_WORKFLOW_REMINDER_ATTENDANCE_LOOKAHEAD_DAYS: u16 = 45;",
    "API workflow reminder attendance lookahead default marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub profile_calendar: bool",
    "API workflow reminder profile-calendar source toggle marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub act_follow_ups: bool",
    "API workflow reminder act follow-up source toggle marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "pub attendance_hygiene: bool",
    "API workflow reminder attendance-hygiene source toggle marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"dashboard_limit": 5',
    "settings contract workflow reminder dashboard-limit default marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"due_soon_days": 45',
    "settings contract workflow reminder due-soon default marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"attendance_lookahead_days": 45',
    "settings contract workflow reminder attendance lookahead default marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"profile_calendar": true',
    "settings contract workflow reminder profile-calendar source default marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"act_follow_ups": true',
    "settings contract workflow reminder act-follow-ups source default marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"attendance_hygiene": true',
    "settings contract workflow reminder attendance-hygiene source default marker",
  );
  assertFileContains(
    "apps/web/src/api/settingsDefaults.test.ts",
    "defaults local dashboard reminders to the existing generated output policy",
    "web settings default workflow reminder policy coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "renders and autosaves the workflow reminder policy fields",
    "Settings workflow reminder policy UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "Gerar lembretes locais",
    "Settings workflow reminder master toggle marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "workflow-reminders-dashboard-limit",
    "Settings workflow reminder dashboard-limit input marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "workflow-reminders-due-soon-days",
    "Settings workflow reminder due-soon input marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "workflow-reminders-attendance-lookahead-days",
    "Settings workflow reminder attendance lookahead input marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "setWorkflowReminderSource('profile_calendar', checked)",
    "Settings workflow reminder profile-calendar toggle marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "setWorkflowReminderSource('act_follow_ups', checked)",
    "Settings workflow reminder act-follow-ups toggle marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "setWorkflowReminderSource('attendance_hygiene', checked)",
    "Settings workflow reminder attendance-hygiene toggle marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "if !policy.enabled",
    "dashboard reminder policy enabled=false suppression marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminders.truncate(policy.dashboard_limit as usize);",
    "dashboard reminder policy limit marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "policy.attendance_lookahead_days",
    "dashboard reminder policy attendance lookahead marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "default_reminder_policy_preserves_existing_families",
    "dashboard reminder default-family preservation coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "disabled_reminder_policy_suppresses_only_reminder_output",
    "dashboard reminder disabled-policy suppression coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_source_toggles_suppress_only_their_family",
    "dashboard reminder source-toggle family coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_numeric_policy_controls_limit_and_day_windows",
    "dashboard reminder numeric policy coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_status_uses_calendar_day_delta_across_year_boundary",
    "dashboard reminder absolute day-delta year-boundary coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "let recent_events = if redaction.is_guest()",
    "dashboard guest recent-events redaction implementation marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "dashboard_recent_events_redacts_guest_feed_but_keeps_owner_and_reader_feed",
    "API dashboard guest recent-events redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "authorized non-guest reader should still see recent ledger events",
    "API dashboard Leitor recent-events preservation marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'with_session(get("/v1/ledger/events"), &guest_token)',
    "API dashboard Guest still forbidden from ledger events marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'assert_eq!(guest_dashboard["recent_events"], json!([]));',
    "API dashboard Guest recent_events empty marker",
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
    "renders dashboard subtabs in the requested order",
    "dashboard dates tab order coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "type DashboardTab = 'stats' | 'activity' | 'current' | 'dates' | 'queue' | 'events'",
    "dashboard dates tab route-state marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "{ id: 'dates', label: t('dashboard.tabs.dates'), icon: <Icon.Calendar /> }",
    "dashboard dates tab nav marker",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/pt-PT.ts",
    "'dashboard.tabs.dates': 'Datas'",
    "dashboard dates tab pt-PT i18n marker",
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
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "keeps current open books to the five newest and reports hidden items",
    "dashboard open-books summary cap coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "keeps dated reminders to the five earliest dates after dedupe",
    "dashboard dated-reminder summary cap coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "dashboard.openItems.more",
    "dashboard hidden open-books count marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "dashboard.dates.more",
    "dashboard hidden dated-reminders count marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "marks the six main stats cards as a compact desktop metrics row",
    "dashboard desktop-six metrics row coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    'data-dashboard-density="desktop-six"',
    "dashboard desktop-six density marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".dashboard-tab--stats > .dashboard-metrics--summary",
    "dashboard compact summary metrics CSS marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.css",
    ".dashboard-workqueue__action.btn--iconOnly",
    "dashboard compact work-queue action sizing marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "keeps terminal imported-document review disabled until guardrails are acknowledged",
    "imported-document guardrail acknowledgement UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    'aria-label="Recibo de revisão"',
    "imported-document review receipt group marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "const hasReceipt = importedDocumentHasReviewReceipt(document);",
    "imported-document review receipt derives from existing view marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Sem recibo de revisão",
    "imported-document pending no fake receipt marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Não criado nem validado por esta revisão.",
    "imported-document review receipt no signed-artifact claim marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Não declarada por esta revisão.",
    "imported-document review receipt no legal-acceptance claim marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "expect(within(receipt).queryByText('Revisto em')).toBeNull();",
    "imported-document review receipt pending hides reviewed-at marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "expect(within(receipt).getByText('Limites exigidos')).toBeTruthy();",
    "imported-document review receipt guardrail coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "isBlockedReviewReceiptEndpoint",
    "imported-document review receipt no extra endpoint helper marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "reviewCalls.filter((call) => isBlockedReviewReceiptEndpoint(call.url))).toEqual([])",
    "imported-document review receipt no extra routes coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    '("/v1/documents/generated/{document_id}", RouteClass::Gated)',
    "API generated-document by-id route classified gated marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    "generated_document_download_route_is_classified_as_gated",
    "API generated-document route classification coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    'download: format!("/v1/documents/generated/{document_id}")',
    "API generated-document returned download route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub async fn get_generated_document_pdf",
    "API generated-document by-id handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "document_by_id(document_id)",
    "API generated-document durable by-id lookup marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "fn in_memory_generated_document_key",
    "API generated-document in-memory by-id lookup marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "by-id generated-document reads inherit `act.read` from the document's owning act",
    "API generated-document act.read gate marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "helper preserves `/v1/acts/{id}/document` as the canonical sealed Ata target",
    "API generated-document canonical Ata route preservation marker",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "should_generate_condominium_absent_owner_communication",
    "API condominium absent-owner seal hook marker",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "generate_condominium_absent_owner_communication",
    "API condominium absent-owner communication generation call marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID",
    "API condominium absent-owner communication template marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    'status: "required_pending"',
    "API condominium absent-owner pending dispatch status marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "evidence_attached: false",
    "API condominium absent-owner false dispatch evidence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "dispatch_completed: false",
    "API condominium absent-owner false dispatch completion marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "communication generated automatically; dispatch evidence is not attached",
    "API condominium absent-owner no dispatch proof marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "on_demand_generate_persists_a_chosen_document_and_emits_the_event",
    "API generated-document durable download coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "in_memory_generated_document_download_uses_returned_url_and_keeps_canonical_ata",
    "API generated-document in-memory download coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "on-demand document download must not point at the canonical Ata endpoint",
    "API generated-document no canonical endpoint reuse marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "The canonical Ata endpoint still serves the original sealed Ata for signing/bundles",
    "API generated-document canonical Ata remains sealed marker",
  );
  assertFileContains(
    "crates/chancela-server/tests/e2e_act_document_persistence.rs",
    "condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata",
    "server condominium absent-owner communication auto-generation coverage",
  );
  assertFileContains(
    "crates/chancela-server/tests/e2e_act_document_persistence.rs",
    'Some("condominio-comunicacao-ausentes/v1")',
    "server condominium absent-owner generated template coverage",
  );
  assertFileContains(
    "crates/chancela-server/tests/e2e_act_document_persistence.rs",
    'Some("required_pending")',
    "server condominium absent-owner pending dispatch header coverage",
  );
  assertFileContains(
    "crates/chancela-server/tests/e2e_act_document_persistence.rs",
    "Ata + absent-owner communication document events after restart",
    "server condominium absent-owner generated events restart coverage",
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
    "apps/web/src/features/entities/entities.test.tsx",
    "pins entity table and filter CSS to single-line no-overflow rules",
    "entity table no-overflow CSS coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "async function themeCss(): Promise<string>",
    "entity CSS test async helper for browser-gate-safe dynamic import",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "const nodeFs = 'node:fs';",
    "entity CSS test node:fs dynamic import indirection",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "const { readFileSync } = (await import(nodeFs)) as",
    "entity CSS test runtime node:fs dynamic import marker",
  );
  assertFileDoesNotContain(
    "apps/web/src/features/entities/entities.test.tsx",
    "import { readFileSync } from 'node:fs';",
    "entity CSS test static node:fs import removed",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "expect(primaryRule).toContain('flex-wrap: nowrap;');",
    "entity primary filter desktop nowrap CSS assertion",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "expect(mobilePrimaryRule).toContain('flex-wrap: wrap;');",
    "entity primary filter mobile wrap CSS assertion",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));",
    "entity advanced filter no-overflow grid assertion",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "renders the default entity table columns as single-line truncating cells",
    "entity default single-line table coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/EntitiesPage.enrichment.test.tsx",
    "expect(cells).toHaveLength(REGISTERED_ENTITY_COLUMNS.length)",
    "entity enriched single-line table coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/EntitiesPage.tsx",
    "className=\"stack--tight entities-filters\"",
    "entity filter no-overflow wrapper marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".entities-filterbar__primary",
    "entity primary filter CSS marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".entities-table__cell--truncate > .truncate",
    "entity single-line truncation CSS marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".entities-table .table-wrap",
    "entity table-wrap overflow CSS marker",
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
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "externalValidatorReports.table.metadataOnly",
    "Ferramentas external-validator compact metadata-only action marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "const RAW_REPORT_MAX_BYTES = 2 * 1024 * 1024;",
    "Ferramentas external-validator raw report local size bound marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "function safeSourceFilename",
    "Ferramentas external-validator safe source filename helper marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "async function selectRawReportFile",
    "Ferramentas external-validator raw report file selection marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "content_base64: rawReport.contentBase64",
    "Ferramentas external-validator raw report content_base64 submit marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "source_filename: rawReport.sourceFilename",
    "Ferramentas external-validator safe source filename submit marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "sourceFilename: safeSourceFilename(next.name)",
    "Ferramentas external-validator local safe filename summary marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ExternalValidatorReportsPanel.tsx",
    "(!rawReportFile || !!rawReport)",
    "Ferramentas external-validator raw report upload waits for local summary marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "pdf-validator-report-actions",
    "PDF validator compact report action layout marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "pdfValidator.report.status",
    "PDF validator compact report status copy marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "dss.vri_tu_keys",
    "PDF validator DSS VRI /TU UI marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "DocTimeStampValidationReport",
    "PDF validator DocTimeStamp validation UI marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "multi_signature_local_renewal_plan",
    "PDF validator multi-signature renewal-plan UI marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "report.trust.live_trusted_list_validation_performed",
    "PDF validator live trust guardrail UI marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/PdfSignatureValidatorPanel.tsx",
    "report.qualification.legal_effect_assessed",
    "PDF validator legal-effect guardrail UI marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "renders a valid response with structure, PAdES, DSS, LTV and trust sections",
    "PDF validator DSS/LTV/trust UI coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "DSS-VRI-TU-1",
    "PDF validator VRI /TU fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "record_signature_dss_validation_time",
    "PDF validator local renewal gap coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "technical PDF/PAdES evidence validation only",
    "PDF validator no-live-trust legal notice marker",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/en-US.ts",
    "pdfValidator.field.vriTuKeys",
    "PDF validator i18n VRI/TU key",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/en-US.ts",
    "pdfValidator.field.legalLtvClaimed",
    "PDF validator i18n legal LTV guardrail key",
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
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "selecting a raw report does not upload automatically",
    "Ferramentas external-validator raw report no-auto-upload coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "submits selected raw report bytes through raw_report.content_base64 without rendering them",
    "Ferramentas external-validator raw report explicit upload coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "renders backend raw report summary and no-claim notice without raw bytes",
    "Ferramentas external-validator raw report summary/no-claim coverage",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "expect(screen.queryByText(RAW_EXTERNAL_VALIDATOR_REPORT_TEXT)).toBeNull()",
    "Ferramentas external-validator raw report DOM redaction assertion",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "renders popup notification controls as icon-only actions with tooltip labels",
    "notification bell icon-only action coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "expectIconOnlyControl(viewAll, 'Ver todas')",
    "notification bell footer view-all icon-only coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.tsx",
    "notification-center__view-all btn btn--ghost btn--icon btn--iconOnly",
    "notification bell footer view-all icon-only marker",
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
    "apps/web/src/features/notifications/NotificationsPage.test.tsx",
    "renders active notification page actions as icon-only controls with tooltip labels",
    "notifications page active action icon-only coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "const acknowledge = within(dialog).getByRole('button', { name: 'Reconhecer' })",
    "notification bell acknowledge icon-only coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "folds compact popup item tags into the title without separate row badges",
    "notification compact popup tag coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationsPage.tsx",
    "            compact",
    "notifications page compact list marker",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationsPage.test.tsx",
    "notifications-list--compact",
    "notifications page compact list coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationsPage.test.tsx",
    "selector: '.notifications-list__title-tag'",
    "notifications page title-folded tag coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationsPage.test.tsx",
    "queryByText('Alerta', { selector: '.badge' })",
    "notifications page separate badge removal coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "keeps the bell bubble and popup on explicit shell-safe layers",
    "notification bell shell-safe layer coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "cssNumber(css, '.notification-bell__count', 'z-index')",
    "notification bell count z-index assertion",
  );
  assertFileContains(
    "apps/web/src/features/notifications/NotificationBell.test.tsx",
    "expect(countRule).toMatch(/pointer-events:\\s*none;/);",
    "notification bell count pointer-events assertion",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".notifications-list--compact",
    "notifications compact list CSS marker",
  );
  assertFileContains(
    "apps/web/src/features/onboarding/onboarding.test.tsx",
    "email: 'operador@example.pt'",
    "onboarding first-user email coverage",
  );
  assertFileContains(
    "apps/web/src/features/onboarding/OnboardingWizard.tsx",
    "email: email.trim() || undefined",
    "onboarding first-user email payload marker",
  );
  assertFileContains(
    "apps/web/src/features/users/users.test.tsx",
    "creates a user with a valid slug and sends identity email fields",
    "user creation email coverage",
  );
  assertFileContains(
    "apps/web/src/features/users/users.test.tsx",
    "updates a user email via PATCH /v1/users/{id}",
    "user edit email PATCH coverage",
  );
  assertFileContains(
    "apps/web/src/features/users/EditUserPage.tsx",
    "email: trimmedEmail === '' ? null : trimmedEmail",
    "user edit nullable email payload marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "renders and saves a signatory email through the act patch body",
    "act signatory email coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "onChange={(e) => update(i, { email: orNull(e.target.value) })}",
    "act signatory email field marker",
  );
  assertFileContains(
    "apps/web/src/features/books/OpenBookForm.tsx",
    "export function parseTermoSignatories(rows: TermoSignatoryDraft[]): BookTermoSignatoryInput[]",
    "book opening structured termo signatory parser marker",
  );
  assertFileContains(
    "apps/web/src/features/books/CloseBookForm.tsx",
    "required_signatories: parseTermoSignatories(signatories)",
    "book closing structured termo signatory payload marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface BookTermoSignatory",
    "web BookTermoSignatory contract marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export type BookTermoSignatoryInput = string | BookTermoSignatory;",
    "web BookTermoSignatory legacy-compatible input marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "required_signatory_records_abertura?: BookTermoSignatory[] | null;",
    "web book opening structured signatory read field marker",
  );
  assertFileContains(
    "crates/chancela-core/src/book.rs",
    "pub struct TermoSignatory",
    "core structured termo signatory marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dto.rs",
    "pub required_signatory_records_abertura: Option<Vec<TermoSignatoryView>>",
    "API book structured signatory read field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dto.rs",
    "pub enum TermoSignatoryInput",
    "API legacy-compatible termo signatory input marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dto.rs",
    "Legacy(String)",
    "API termo signatory legacy string compatibility marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "displays structured opening and closing signatories with capacity and email",
    "book structured signatory display coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "submits signatory name, capacity and normalized email fields in required_signatories",
    "book opening structured signatory submit coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "submits structured closing signatories",
    "book closing structured signatory submit coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function permissionSummary",
    "data management permission summary marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "data-status-cleanups",
    "data management cleanup list marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "previews retained export cleanup before explicit confirmed execution",
    "data management retained-export preview-before-execution coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "exports_dry_run_reports_cleanup_plan_without_removing_files",
    "API retained-export dry-run planning core coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "assert_eq!(response.would_delete_files, 2);",
    "API retained-export dry-run would-delete file counter marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "assert_eq!(response.deleted_bytes, 0);",
    "API retained-export dry-run zero-deleted-bytes marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "cleanup_policy_rejects_retained_export_fields_for_crash_target",
    "API non-export cleanup policy field rejection marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "const EXPORT_CLEANUP_PREVIEW_BODY =",
    "data management retained-export preview payload marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "const EXPORT_CLEANUP_EXECUTION_BODY =",
    "data management retained-export execution payload marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "minimum_age_days: 30",
    "data management retained-export preview minimum-age marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "dry_run: false",
    "data management retained-export execution dry-run false marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "keep_latest: 5",
    "data management retained-export keep-latest marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "Nenhum ficheiro foi removido",
    "data management retained-export no-files-removed copy marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "foram removidos",
    "data management retained-export deleted-counter execution copy marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "canConfirm={activeCleanup?.target !== 'exports' || hasExportCleanupPreview}",
    "data management retained-export shared modal preview gate marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "data-status-cleanup__main",
    "data management compact cleanup row DOM coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "data-status-cleanup__main",
    "data management compact cleanup row implementation marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".data-status-cleanup__main",
    "data management compact cleanup row CSS marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "kind?: string;",
    "web data usage optional kind marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "['kind', 'row_count']",
    "web data status contract optional kind tolerance marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "kind: 'sqlite_logical_table'",
    "web data status sqlite logical table fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "const tablePayloads = sqliteGroup.querySelector('.data-status-sqlite-table-list')!;",
    "web data status sqlite table list DOM coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "const tableRows = tablePayloads.querySelectorAll('.data-status-sqlite-table-row');",
    "web data status sqlite table row DOM coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "expect(tablePayloads.textContent).not.toContain('SQLite table ledger_events');",
    "web data status sqlite table redundant-label coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "const SQLITE_LOGICAL_TABLE_KIND = 'sqlite_logical_table';",
    "web data status sqlite logical table kind marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function isSqliteTableConcern",
    "web data status sqlite table classifier marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function sqliteTableLabel",
    "web data status sqlite table label helper marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function SqliteTablePayloadList",
    "web data status sqlite table list component marker",
  );
  assertFileContains(
    "crates/chancela-store/src/recovery.rs",
    "pub fn restore_preflight(",
    "store non-destructive restore preflight marker",
  );
  assertFileContains(
    "crates/chancela-store/src/recovery.rs",
    "snapshot ledger verified from an isolated copy",
    "store restore preflight isolated snapshot ledger marker",
  );
  assertFileContains(
    "crates/chancela-store/src/recovery.rs",
    "member {} digest mismatch",
    "store restore preflight member digest refusal marker",
  );
  assertFileContains(
    "crates/chancela-store/tests/recovery.rs",
    "restore_preflight_verifies_without_mutating_live_store_or_sidecars",
    "store restore preflight non-mutating coverage",
  );
  assertFileContains(
    "crates/chancela-store/tests/recovery.rs",
    "preflight does not append restore audit events",
    "store restore preflight no ledger restored event assertion",
  );
  assertFileContains(
    "crates/chancela-api/src/recovery.rs",
    "pub async fn restore_store_preflight",
    "API restore preflight route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/recovery.rs",
    "but never swaps the live DB, stages sidecars, appends restore events, reloads memory, or mutates",
    "API restore preflight non-mutating boundary marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "restoreLedgerPreflight: (body: RestorePreflightBody)",
    "web restore preflight client marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "Read-only whole-store restore preflight",
    "web restore preflight hook boundary marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface RestorePreflightManifest",
    "web restore preflight bounded manifest contract marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function BackupManifestReport",
    "web bounded backup manifest evidence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/backup/recovery-drills",
    "API backup recovery drill receipt route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "never executes restore, never stages sidecars, and persists only bounded, whitelisted evidence",
    "API backup recovery drill non-destructive module boundary marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub async fn create_backup_recovery_drill",
    "API backup recovery drill create handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub async fn list_backup_recovery_drills",
    "API backup recovery drill list handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "reject_true_flag(\"restore_executed\", req.restore_executed)?;",
    "API backup recovery drill restore-executed overclaim refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "reject_true_flag(\"offsite_custody_proven\", req.offsite_custody_proven)?;",
    "API backup recovery drill custody overclaim refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "BackupRecoveryDrillManifestEvidence::from",
    "API backup recovery drill bounded manifest evidence marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "backup_recovery_drill_creates_receipt_from_preflight_and_persists_whitelist_only",
    "API backup recovery drill whitelist-only receipt coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "drill receipt must not swap or rewrite the live database",
    "API backup recovery drill no live DB swap coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "drill receipt must not stage or replace sidecars",
    "API backup recovery drill no sidecar staging coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "drill receipt must not append ledger.restored",
    "API backup recovery drill no ledger restored event coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "backup_recovery_drill_rejects_overclaim_flags_without_restore",
    "API backup recovery drill overclaim refusal coverage",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    "\"restore_executed\": false",
    "backup recovery drill contract restore-executed false marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    "\"offsite_custody_proven\": false",
    "backup recovery drill contract custody false marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "createBackupRecoveryDrill: (body: BackupRecoveryDrillBody)",
    "web backup recovery drill client marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "no live restore endpoint is called by this mutation",
    "web backup recovery drill hook non-restore marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "manifest: BackupRecoveryDrillManifestEvidence | null;",
    "web backup recovery drill nullable manifest contract marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "restore_executed: false;",
    "web backup recovery drill false restore flag contract marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "backup.recovery-drill.json → BackupRecoveryDrillReceipt",
    "web backup recovery drill fixture contract coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "type OptionalKeys<T>",
    "web contract optional-key helper build marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "(`skip_serializing_if`) keys are permitted-but-not-required",
    "web contract optional wire-key tolerance marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "['operator_notes', 'custody_location']",
    "web backup recovery drill optional receipt keys marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function buildRecoveryDrillBody",
    "web backup recovery drill exact-submit body helper marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "setDrillPassphrase('');",
    "web backup recovery drill passphrase clearing marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "sem restauro ao vivo, sem certificação",
    "web backup recovery drill explicit bounded UI copy marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "posts a preflight-only recovery drill receipt with exact passphrase",
    "web backup recovery drill exact passphrase coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "expect(calls.some((c) => c.url === '/v1/ledger/recovery/restore')).toBe(false);",
    "web backup recovery drill no live restore call coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "clicking restore preflight preserves exact passphrase and calls only preflight, not restore",
    "web restore preflight exact passphrase/no-restore coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "renders failed restore preflight safely when manifest is null",
    "web restore preflight nullable manifest coverage",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".data-status-sqlite-table-list",
    "web data status sqlite table list CSS marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".data-status-sqlite-table-row",
    "web data status sqlite table row CSS marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    'id: "platform_logs"',
    "data status platform logs filesystem classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    'id: "backup_recovery_drills"',
    "data status backup recovery drills filesystem classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    'concern_for_root("platform-logs.json").id, "platform_logs"',
    "data status platform logs root classifier coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    'concern_for_root("backup-recovery-drills.json").id',
    "data status backup recovery drills root classifier coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'data_status_filesystem_concern(&body, "platform_logs")',
    "API data status platform logs filesystem concern coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'data_status_filesystem_concern(&body, "backup_recovery_drills")',
    "API data status backup recovery drills filesystem concern coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "crate::platform_logs::PLATFORM_LOGS_FILE",
    "API data status platform logs relative root marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "crate::backup_recovery::BACKUP_RECOVERY_DRILLS_FILE",
    "API data status backup recovery drills relative root marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "global = off",
    "platform logging global off kill switch marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_service_override_can_lower_threshold_or_turn_service_off",
    "platform log service override coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '"/v1/platform/logs/forwarded"',
    "platform forwarded log route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    "POST platform.logs.write@Global",
    "platform forwarded log authz route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "Permission::PlatformLogsWrite",
    "platform forwarded log write permission gate marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "Result<Option<PlatformLogEntry>, ApiError>",
    "platform log retained-entry Option return marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "if let Some(entry) = retained",
    "platform forwarded log retained-entry audit gate marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "append_forwarded_log_accepted_event(&state, &actor, &attestor, &entry).await?;",
    "platform forwarded log accepted audit append marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "platform.log.forwarded.accepted",
    "platform forwarded log accepted audit kind marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "ForwardedPlatformLogAcceptedAuditPayload",
    "platform forwarded log sanitized audit payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "ForwardedPlatformLogRouteOutcomeAuditPayload",
    "platform forwarded log denied audit payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "ForwardedPlatformLogRejectedAuditPayload",
    "platform forwarded log rejected audit payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "ForwardedPlatformLogSuppressedAuditPayload",
    "platform forwarded log suppressed audit payload marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "message_len_bytes: usize",
    "platform forwarded log audit message length marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "message_sha256: String",
    "platform forwarded log audit message digest marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "context_key_count: usize",
    "platform forwarded log audit context key-count marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "context_serialized_size_bytes: usize",
    "platform forwarded log audit context size marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_post_with_write_api_key_appears_in_tail",
    "platform forwarded log tail coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "event[\"payload_digest\"]",
    "platform forwarded log sanitized audit digest coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ledger event must not expose raw message or context",
    "platform forwarded log raw message/context audit redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_missing_bearer_writes_nothing",
    "platform forwarded log missing bearer unaudited coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "missing bearer must not append ledger events",
    "platform forwarded log missing bearer no-ledger marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_malformed_json_missing_or_invalid_bearer_writes_no_audit",
    "platform forwarded log malformed missing/invalid bearer unaudited coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "missing or invalid bearer must not append malformed JSON audit events",
    "platform forwarded log invalid bearer no-audit marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_malformed_json_with_owner_auth_audits_sanitized_rejection_without_tail_or_sidecar",
    "platform forwarded log malformed authenticated rejected audit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "authenticated malformed JSON should append one sanitized rejected audit event",
    "platform forwarded log malformed sanitized rejected audit marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_malformed_json_authenticated_rbac_denied_gets_only_route_outcome_audit",
    "platform forwarded log malformed RBAC denied audit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_authenticated_rbac_denied_gets_route_outcome_audit",
    "platform forwarded log RBAC denied audit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "denied audit must not expose forwarded payload",
    "platform forwarded log denied audit payload redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_global_and_service_off_suppress_without_sidecar",
    "platform forwarded log off suppression coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "suppressed forwarded log should append one audit event",
    "platform forwarded log off suppression audit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "suppressed audit must not expose raw message or target",
    "platform forwarded log suppressed audit payload redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_data_dir_post_persists_and_reloads",
    "platform forwarded log persistence coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "platform_logs_forwarded_rejects_invalid_structured_payloads",
    "platform forwarded log validation coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "invalid forwarded logs should append one sanitized rejected event each",
    "platform forwarded log invalid request rejected audit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "rejected audit must not expose raw payload material",
    "platform forwarded log rejected audit payload redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "ForwardedLogRejectionReason::UnsupportedField",
    "platform forwarded log no stdout/stderr field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "is_secret_like_context_key",
    "platform forwarded log secret-like context key marker",
  );
  assertFileContains(
    "crates/chancela-authz/src/role.rs",
    "platform_log_write_is_seeded_only_to_owner_and_platform_admin",
    "platform log write role seed coverage",
  );
  assertFileContains(
    "crates/chancela-authz/src/role.rs",
    "{} should not hold platform.logs.write by default",
    "platform log write API Client excluded by default marker",
  );
  assertFileContains(
    "contracts/platform.services.json",
    "\"actual_runtime_status\": \"unknown\"",
    "platform services honest MCP status fixture",
  );
  assertFileContains(
    "contracts/platform.control.json",
    "\"kind\": \"supervisor_required\"",
    "platform service control supervisor-required fixture",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "renders only meaningful platform action buttons from backend capabilities",
    "platform operations meaningful action coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "shows global-off effective platform logging even when service overrides remain stored",
    "platform operations effective logging coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/PlatformOperationsSection.tsx",
    "function effectiveLogLevel",
    "platform operations effective log helper marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PlatformOperationsSection.tsx",
    "function ActionCapabilities",
    "platform operations action-capability marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".platform-control-support",
    "platform operations action-capability CSS marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".platform-logging-effective__grid",
    "platform operations effective logging CSS marker",
  );
  assertFileContains(
    "package.json",
    "check:encrypted-build-defaults",
    "encrypted build defaults package script",
  );
  assertFileContains(
    "scripts/check-encrypted-build-defaults.mjs",
    "checkRootReleaseBuild",
    "encrypted build defaults static checker",
  );
  assertFileContains(
    "docker/Dockerfile.server",
    "--features chancela-server/sqlcipher",
    "Docker SQLCipher server build default",
  );
  assertFileContains(
    "apps/desktop/package.json",
    "tauri build --features sqlcipher",
    "desktop SQLCipher package build default",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "keeps books filter and table CSS from forcing horizontal scroll or wrapping rows",
    "books filter/table no-overflow CSS coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "async function themeCss(): Promise<string>",
    "books CSS test async helper for browser-gate-safe dynamic import",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "const nodeFs = 'node:fs';",
    "books CSS test node:fs dynamic import indirection",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "const { readFileSync } = (await import(nodeFs)) as",
    "books CSS test runtime node:fs dynamic import marker",
  );
  assertFileDoesNotContain(
    "apps/web/src/features/books/books.test.tsx",
    "import { readFileSync } from 'node:fs';",
    "books CSS test static node:fs import removed",
  );
  assertFileContains(
    "apps/web/src/features/books/BooksPage.tsx",
    "books-filterbar__primary",
    "books primary filterbar marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BooksTable.tsx",
    "books-table__cell--truncate",
    "books truncating table cell marker",
  );
  assertFileContains(
    "apps/web/src/desktop/saveFile.test.ts",
    "falls back to a browser blob download when a requested save picker is unavailable",
    "browser save picker unavailable fallback coverage",
  );
  assertFileContains(
    "apps/web/src/desktop/saveFile.test.ts",
    "falls back to a browser blob download when the requested save picker write fails",
    "browser save picker failed-write fallback coverage",
  );
  assertFileExists(
    "apps/web/src/features/documents/ActDocumentPanel.save.test.tsx",
    "act document export save prompt test file",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.save.test.tsx",
    "ActDocumentPanel export save prompts",
    "act document export save prompt coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.save.test.tsx",
    "routes a working-copy export through the save prompt helper with response metadata",
    "act working-copy export save prompt coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "exports the selected audit format with the current filters through the save helper",
    "ledger archive filtered export format coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "shows a bounded first page for a 1000-log archive and loads more by cursor",
    "ledger archive bounded first page coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "/v1/ledger/events/page?before_seq=900&limit=100&order=desc",
    "ledger archive cursor load-more marker",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "applies server-backed filters and exposes an icon-only clear button with a tooltip",
    "ledger archive filter and clear-control coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "/v1/ledger/archive/document?format=txt&chain=book%3Abook-123456789&scope=act%3A88&limit=100&order=desc",
    "ledger archive filtered export request marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "serializes paged ledger filters for newest-first lazy loading",
    "ledger archive paged filter serialization coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "downloads ledger archive formats through the bounded format query",
    "ledger archive interchange format coverage",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "next_cursor: number | null;",
    "ledger archive numeric cursor type marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ledger_events_page_handles_thousand_event_chain_without_duplicates",
    "ledger archive thousand-event cursor API coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ledger_events_page_filters_by_chain_scope_kind_actor_and_date",
    "ledger archive server-backed filter API coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ledger_archive_document_limit_matches_paged_list_for_filtered_exports",
    "ledger archive shared export/list limit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "[(\"0\", 1_usize), (\"500\", 250_usize)]",
    "ledger archive page limit normalization marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "exports a book bundle through the save prompt helper",
    "book bundle export save prompt coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "preferBrowserSavePicker",
    "books export save prompt marker",
  );
  assertFileContains(
    "apps/web/e2e/export-save-hardening.spec.ts",
    "sealed act PDF save prompt cancellation stays visible without browser-download fallback",
    "browser export save cancellation coverage",
  );
  assertFileContains(
    "apps/web/e2e/export-save-hardening.spec.ts",
    "installCancelledBrowserSavePicker",
    "browser export save cancellation helper marker",
  );
  assertFileContains(
    "apps/web/e2e/export-save-hardening.spec.ts",
    "Guardar cancelado: ${PDF_FILENAME}.",
    "browser export save cancellation visible message marker",
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
    "crates/chancela-api/src/database.rs",
    "pub const DB_KEY_SOURCE_ENV: &str = \"CHANCELA_DB_KEY_SOURCE\";",
    "API database encryption key-source env marker",
  );
  assertFileContains(
    "crates/chancela-api/src/database.rs",
    "HardwareDerivedFallbackUnavailable",
    "API database encryption hardware fallback unavailable marker",
  );
  assertFileContains(
    "crates/chancela-api/src/database.rs",
    "\"hardware\" | \"hardware_bound\" | \"hardware_derived\" | \"hardware_derived_fallback\"",
    "API database encryption hardware fallback selector marker",
  );
  assertFileContains(
    "crates/chancela-api/src/database.rs",
    "hardware_derived_fallback_request_fails_closed_without_static_key",
    "API database encryption hardware fallback fail-closed unit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "pub database_encryption: DatabaseEncryptionStatus",
    "API data status database encryption object marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "pub key_source: DatabaseEncryptionKeySourceStatus",
    "API data status encryption key-source marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "pub hardware_derived_fallback: HardwareDerivedFallbackStatus",
    "API data status hardware fallback marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "fail_closed_if_requested: true",
    "API data status hardware fallback fail-closed marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/data_key_ops.rs",
    "hardware_derived_fallback_source_request_fails_closed_without_static_key",
    "API data key source hardware fallback fail-closed coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/data_key_ops.rs",
    "data_status_reports_operator_key_source_and_blocked_plaintext_migration",
    "API data status key-source preflight coverage",
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
    "apps/web/src/features/templates/TemplatesCatalogPage.tsx",
    "templates-controls__primary templates-filterbar__primary",
    "web template compact primary filter marker",
  );
  assertFileContains(
    "apps/web/src/features/templates/TemplatesCatalogPage.tsx",
    "details className=\"templates-controls__advanced templates-advanced-filters filter-advanced\"",
    "web template collapsed advanced filter marker",
  );
  assertFileContains(
    "apps/web/src/features/templates/TemplatesCatalogPage.test.tsx",
    "keeps templates filters compact, collapsible, and overflow-safe in CSS",
    "web template compact no-overflow coverage",
  );
  assertFileContains(
    "apps/web/src/features/templates/TemplatesCatalogPage.test.tsx",
    "expect(advanced.open).toBe(false);",
    "web template advanced filters collapsed assertion",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    ".templates-controls__filters",
    "web template advanced filter CSS marker",
  );
  assertFileContains(
    "apps/web/src/theme.css",
    "grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));",
    "web template advanced filter responsive grid marker",
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
    "apps/web/src/i18n/locales/en-US.ts",
    "Selected by the operator in this browser; sent only on explicit upload.",
    "i18n external-validator raw report explicit-upload provenance marker",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/en-US.ts",
    "Technical evidence only: no legal validation, external certification, PDF/UA certification, PAdES certification, or proof of compliance is claimed.",
    "i18n external-validator no legal/certification/compliance claim marker",
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
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Updated 2026-07-11 from the current CI configuration and head `3e72e08`",
    "CI/E2E hardening plan current head marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Focused Gate Snapshot Through `3e72e08`",
    "CI/E2E hardening plan focused snapshot head marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent trust catalog display checks through `c3d874b`",
    "CI/E2E hardening plan trust catalog focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree PDF accessibility checks",
    "CI/E2E hardening plan PDF accessibility focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "accessibility report JSON version 7, structural-depth evidence",
    "CI/E2E hardening plan PDF accessibility v7 structural-depth marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`writer_owned_decorative_artifacts_accounted_for`",
    "CI/E2E hardening plan PDF accessibility writer-owned decorative marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`LimitedTaggedStructure` remains machine-visible",
    "CI/E2E hardening plan PDF/UA bounded-structure caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent export-save checks through `ff1823a`",
    "CI/E2E hardening plan export-save focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent dashboard density checks through `2ffae33`",
    "CI/E2E hardening plan dashboard density focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent SQLite logical-usage checks through `2187a67`",
    "CI/E2E hardening plan SQLite logical usage focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent browser export-save gate checks through `fd70ca0`",
    "CI/E2E hardening plan browser export-save gate checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent web SQLite table-usage checks through `c1c57fe`",
    "CI/E2E hardening plan web SQLite table usage checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent keyed PAdES VRI `/TU` checks through `76fc229`",
    "CI/E2E hardening plan keyed PAdES VRI /TU checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree PAdES DSS validation-time checks",
    "CI/E2E hardening plan PAdES validation-time checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "do not fetch live OCSP, CRL,",
    "CI/E2E hardening plan PAdES no-live-fetch caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent compact notification/entity filter checks through `2c88b90`",
    "CI/E2E hardening plan compact notification/entity checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent compact template-filter checks through `5db121a`",
    "CI/E2E hardening plan compact template checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree retained-export cleanup UX checks",
    "CI/E2E hardening plan retained-export cleanup UX checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "copy, disabled execution button before preview, shared-modal confirmation\n  gate, execution payload that preserves the policy fields",
    "CI/E2E hardening plan retained-export preview no-delete marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree post-act template semantic-lint checks",
    "CI/E2E hardening plan post-act template semantic lint marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "test/build-time catalog consistency only",
    "CI/E2E hardening plan post-act template lint no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent compliance tooling checks through `3e72e08`",
    "CI/E2E hardening plan compliance tooling checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree AI provenance checks",
    "CI/E2E hardening plan AI provenance focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree MCP workflow provenance review checks",
    "CI/E2E hardening plan MCP workflow provenance checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`workflow_provenance_review_checklist` prompt",
    "CI/E2E hardening plan MCP workflow provenance prompt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`chancela://mcp/workflow-provenance-review` resource",
    "CI/E2E hardening plan MCP workflow provenance resource marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no AI or MCP completion claim",
    "CI/E2E hardening plan MCP workflow provenance no-completion marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree MCP draft-vs-signed comparison review checks",
    "CI/E2E hardening plan MCP draft-signed comparison checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`draft_signed_comparison_review_checklist` prompt",
    "CI/E2E hardening plan MCP draft-signed comparison prompt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`chancela://mcp/draft-signed-comparison-review` resource",
    "CI/E2E hardening plan MCP draft-signed comparison resource marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "false AI-01/full\n  AI/MCP completion flags",
    "CI/E2E hardening plan MCP draft-signed no completion marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree dashboard guest recent-events redaction checks",
    "CI/E2E hardening plan dashboard guest redaction checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Guest refusal from\n  `/v1/ledger/events`",
    "CI/E2E hardening plan dashboard Guest ledger refusal marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no permission grants",
    "CI/E2E hardening plan dashboard no permission grant marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree generated-document by-id download checks",
    "CI/E2E hardening plan generated-document by-id checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`/v1/documents/generated/{document_id}`",
    "CI/E2E hardening plan generated-document route marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "preservation of `/v1/acts/{act_id}/document` as the sealed Ata bytes",
    "CI/E2E hardening plan generated-document canonical Ata marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata",
    "CI/E2E hardening plan absent-owner communication server command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "pending dispatch\n  evidence status, and restart persistence",
    "CI/E2E hardening plan absent-owner pending dispatch persistence marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no signing, bundle, template, threshold,\n  law, provider, registry, dispatch-sent proof, dispatch completion, legal\n  sufficiency, or legal-effect claim",
    "CI/E2E hardening plan generated-document no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "explicit external-validator raw\nreport upload UI guardrails",
    "CI/E2E hardening plan external-validator raw upload UI headline marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The UI keeps manual JSON metadata upload working, computes filename/type/size/\n  digest/provenance locally",
    "CI/E2E hardening plan external-validator manual JSON and local summary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "does not upload\n  on selection",
    "CI/E2E hardening plan external-validator no-auto-upload marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`raw_report.content_base64` plus `content_type`,\n  `size_bytes`, `sha256`, and safe `source_filename` only on explicit upload",
    "CI/E2E hardening plan external-validator explicit upload payload marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "not external-validator legal acceptance, certification,\n  PDF/UA/PAdES certification, compliance proof",
    "CI/E2E hardening plan external-validator no-certification/compliance claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no live AI provider\n  calls, no model accuracy or AI quality assessment",
    "CI/E2E hardening plan AI provenance caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree data-status sidecar classification checks",
    "CI/E2E hardening plan data-status sidecar classification marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`platform-logs.json` as\n  `platform_logs`",
    "CI/E2E hardening plan data-status platform logs marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`backup-recovery-drills.json` as\n  `backup_recovery_drills`",
    "CI/E2E hardening plan data-status backup recovery drills marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree local DGLAB interchange manifest API checks",
    "CI/E2E hardening plan local DGLAB interchange checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "manual JSON metadata upload continuity, raw report file\n  selection with local filename/type/size/digest/provenance summary",
    "CI/E2E hardening plan external-validator focused web checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "authority/legal validation, report replay\n  certification, external certification, PDF/UA/PAdES certification, compliance\n  proof",
    "CI/E2E hardening plan external-validator focused no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree raw external-validator report download checks",
    "CI/E2E hardening plan external-validator raw byte download checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report",
    "CI/E2E hardening plan external-validator raw-report route marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "attachment headers",
    "CI/E2E hardening plan external-validator attachment header marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no auto-upload, no UI raw\n  rendering",
    "CI/E2E hardening plan external-validator no auto-upload/raw-render marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree imported-document review receipt checks",
    "CI/E2E hardening plan imported-document review receipt checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "pending `Sem recibo de\n  revisão` without fake reviewer/time/note/guardrail details",
    "CI/E2E hardening plan imported-document no fake receipt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no new route, schema, mutation, download, OCR, conversion, signed\n  artifact, or legal acceptance behavior",
    "CI/E2E hardening plan imported-document receipt no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree trust catalog identifier-match checks",
    "CI/E2E hardening plan trust identifier-match checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "optional\n  `identifier_match` on identifier-filtered TSL/TSA rows",
    "CI/E2E hardening plan trust identifier_match field marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "technical-only match explanation copy, truncated display, and full\n  hash/SKI copy actions",
    "CI/E2E hardening plan trust copy-safe identifier marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`chancela-local-dglab-interchange-manifest/v1`",
    "CI/E2E hardening plan local DGLAB schema marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`GET /v1/books/{id}/archive/local-dglab-interchange-manifest`",
    "CI/E2E hardening plan local DGLAB API marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "ZIP sidecar member, import flow, package validation change, persisted package\n  bytes, ledger event",
    "CI/E2E hardening plan local DGLAB caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The current restore preflight slice is non-destructive evidence only",
    "CI/E2E hardening plan restore preflight caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The current backup recovery-drill slice records preflight-only receipts",
    "CI/E2E hardening plan backup recovery drill receipt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "live restore, DB swap, sidecar staging, ledger restore append",
    "CI/E2E hardening plan backup recovery drill caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current checkpoint metadata/static checks through `3e72e08` plus working-tree",
    "CI/E2E hardening plan current checkpoint checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree paper-book OCR conversion-dossier checks",
    "CI/E2E hardening plan paper-book conversion-dossier checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "POST and no canonical paper-book conversion",
    "CI/E2E hardening plan paper-book conversion-dossier caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree agenda-item template checks",
    "CI/E2E hardening plan agenda-item template marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "101 total / 41 CSC",
    "CI/E2E hardening plan template catalog count marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`csc-ata-delegacao-poderes/v1` / `csc-ata-revogacao-poderes/v1` proposed",
    "CI/E2E hardening plan CSC delegation/revocation marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree external-signing envelope UI checks",
    "CI/E2E hardening plan external-signing envelope UI checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "later sequential slot 409 refusal",
    "CI/E2E hardening plan external signer linked-invite policy marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "workflow-only envelope list/create UI",
    "CI/E2E hardening plan external-signing workflow-only UI marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "safe sequential 409 messaging without raw backend/token-like",
    "CI/E2E hardening plan external-signing safe 409 marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "ExternalSigningWorkflowsPage.test.tsx",
    "CI/E2E hardening plan external-signing workflow test command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "plus local ASiC inspection endpoint and ASiC ZIP decompression-bound coverage",
    "CI/E2E hardening plan ASiC header marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The current ASiC inspection slice exposes `POST /v1/signature/asic/inspect`",
    "CI/E2E hardening plan ASiC audit-note marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree ASiC inspection/decompression checks",
    "CI/E2E hardening plan ASiC focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "cargo\n  test -p chancela-api --test asic_signature_validation --locked",
    "CI/E2E hardening plan ASiC API command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "cargo test -p chancela-signing\n  --test roundtrip --locked asic_",
    "CI/E2E hardening plan ASiC signing command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "ASiC-XAdES unsupported diagnostics with no XAdES validation",
    "CI/E2E hardening plan ASiC XAdES unsupported marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "underdeclared entries that must still produce inspection blockers",
    "CI/E2E hardening plan ASiC underdeclared blocker marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no signing, storage, archive mutation, live\n  provider calls",
    "CI/E2E hardening plan ASiC no-claim caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree TSL XML-DSig checks",
    "CI/E2E hardening plan TSL P-256 XML-DSig checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree backup recovery-drill receipt checks",
    "CI/E2E hardening plan backup recovery drill focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "live DB swap, sidecar staging, ledger restore append",
    "CI/E2E hardening plan backup recovery drill focused caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "optional receipt keys",
    "CI/E2E hardening plan backup recovery drill optional keys marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree workflow reminder policy checks",
    "CI/E2E hardening plan workflow reminder policy checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "focused `cargo test -p\n  chancela-api --locked reminder_` coverage",
    "CI/E2E hardening plan workflow reminder API command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`workflow.reminders` defaults",
    "CI/E2E hardening plan workflow reminder default marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "compact Gestão controls",
    "CI/E2E hardening plan workflow reminder Settings UI marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "absolute\n  calendar-day reminder status across year boundaries",
    "CI/E2E hardening plan workflow reminder year-boundary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no new legal-calendar rules, law-source\n  authority, threshold verification",
    "CI/E2E hardening plan workflow reminder caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "release workflow static\nassurance for the unsigned/local-only trust posture",
    "CI/E2E hardening plan release workflow static assurance header marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree release workflow static-guard checks",
    "CI/E2E hardening plan release workflow static-guard checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "SBOM package-linkage self-test, and package\n  provenance fixture checks",
    "CI/E2E hardening plan release metadata lane marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`releaseTrust.imagePublication/signing/notarization/attestation.status`",
    "CI/E2E hardening plan release nested trust path marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`--require-clean-source`, `releaseTrust.mode = unsigned-dev`",
    "CI/E2E hardening plan release unsigned-dev attestation marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Production package validation also requires `--manifest` when\n  either package mode or expected mode",
    "CI/E2E hardening plan release production manifest-required marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "does not add signing, notarization, attestation,\n  registry publishing, reproducible-build proof, or production trust claims",
    "CI/E2E hardening plan release workflow static-only boundary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "release workflow unsigned/local-only static\n  guard, clean-source provenance gate, and production-package manifest-required",
    "CI/E2E hardening plan checkpoint release static guard summary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree seeded role drift diagnostic checks",
    "CI/E2E hardening plan seeded role drift checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "does not auto-reconcile roles, grant permissions, or weaken authorization",
    "CI/E2E hardening plan seeded role drift no-grant marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree archive readability/ZK caveat checks",
    "CI/E2E hardening plan archive readability caveat checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no keys, decryption material, connectors, custody\n  proof",
    "CI/E2E hardening plan archive caveat no-key/custody marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree template family/channel guard checks",
    "CI/E2E hardening plan template family/channel checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no asset wording, legal threshold, provider behavior",
    "CI/E2E hardening plan template family/channel no-wording marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree MCP discoverability checks",
    "CI/E2E hardening plan MCP discoverability checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "contains no `raw-report`, `content_base64`, or\n  upload path/schema exposure",
    "CI/E2E hardening plan MCP no raw-report exposure marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "structured platform-log forwarded-ingest/failure-audit slices",
    "CI/E2E hardening plan structured platform log header marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree structured platform-log ingestion checks",
    "CI/E2E hardening plan structured platform log checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`cargo test -p chancela-api --locked platform_logs_forwarded`",
    "CI/E2E hardening plan structured platform log API command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "platform_log_write_is_seeded_only_to_owner_and_platform_admin",
    "CI/E2E hardening plan platform log write seed command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "older\n  customized Platform Administrator roles may need an explicit admin update",
    "CI/E2E hardening plan platform log role upgrade caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no lifecycle control, stdout/stderr capture,\n  production supervisor/SIEM/HA/observability proof",
    "CI/E2E hardening plan structured platform log caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Accepted retained\n  forwarded entries append sanitized `platform.log.forwarded.accepted` ledger",
    "CI/E2E hardening plan forwarded log accepted audit marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Missing/invalid bearer\n  requests stay unaudited",
    "CI/E2E hardening plan forwarded log bearer unaudited marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "sanitized `platform.log.forwarded.denied`, `.rejected`, and `.suppressed`\n  ledger audits",
    "CI/E2E hardening plan forwarded log failure audit marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "audit payloads avoid raw body/message/context keys/parse errors/\n  stdout/stderr/tokens/secrets/user strings",
    "CI/E2E hardening plan forwarded log failure audit redaction marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree retention due-candidate checks",
    "CI/E2E hardening plan retention due-candidates checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "erasure records on page load",
    "CI/E2E hardening plan retention due-candidates non-mutating UI marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "dry-run `execution_request` with forced/default `review_only`",
    "CI/E2E hardening plan retention due-candidates review-only request marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Duplicate `review_only` requests for the same candidate/policy,\n  including concurrent duplicates, reuse the existing `awaiting_review`\n  execution record",
    "CI/E2E hardening plan retention duplicate-review marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Due-candidate reads can also project prior safe bounded `executed`\n  archive/no-action evidence",
    "CI/E2E hardening plan retention prior projection marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "canonical bounded `prior_execution.next_step` text",
    "CI/E2E hardening plan retention prior canonical next-step marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "candidate resolution is implemented",
    "CI/E2E hardening plan retention due-candidates no-resolution caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "not real C14N, signer trust anchoring, certificate",
    "CI/E2E hardening plan TSL P-256 caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent web focused checks through `5aad733`",
    "CI/E2E hardening plan current web focused checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Recent notification footer checks through `938b61e`",
    "CI/E2E hardening plan notification footer checks marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "implementation snapshot `3e72e087b27aa22ef97d13e1dc003fb0a4c110ea`",
    "spec coverage current implementation snapshot marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "release clean-source provenance gating, seeded role-drift\ndiagnostics",
    "spec coverage five-slice header marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Release clean-source provenance gate",
    "spec coverage release clean-source bullet marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`manifest.sourceProvenance.sourceTreeState` is `dirty` or `unknown`",
    "spec coverage release clean-source dirty/unknown marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Seeded role drift diagnostic",
    "spec coverage seeded role drift bullet marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "auto-reconcile roles, grant permissions, or weaken authorization checks",
    "spec coverage seeded role drift no-grant marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Archive readability/ZK caveat metadata",
    "spec coverage archive readability caveat bullet marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "default old v1 manifests conservatively",
    "spec coverage archive readability old-v1 default marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Template family/channel rule guard",
    "spec coverage template family/channel bullet marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "test-only `FamilyChannelMismatch` issues",
    "spec coverage template FamilyChannelMismatch marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "MCP discoverability updates",
    "spec coverage MCP discoverability bullet marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`settings.read` tool with a closed no-arg schema",
    "spec coverage MCP external-validator closed schema marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "release workflow static assurance\nfor the unsigned/local-only trust posture",
    "spec coverage release workflow static assurance header marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Working tree keeps Architecture/Release/CI **PARTIAL**",
    "spec coverage release workflow static-guard checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "the Docker job's no-push/local-load posture",
    "spec coverage release workflow Docker no-push marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`releaseTrust.imagePublication/signing/notarization/attestation.status`\n  context",
    "spec coverage release workflow nested trust path marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`releaseTrust.mode = unsigned-dev`, `attestation.status = not_attested`",
    "spec coverage release workflow unsigned-dev not-attested marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Production package\n  validation now also requires `--manifest` whenever either the package metadata",
    "spec coverage release workflow production manifest-required marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "static workflow/package metadata assurance\n  only; it does not add signing, notarization, attestation, registry publishing",
    "spec coverage release workflow static-only boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Working tree keeps Architecture/Data/Roles/CI **PARTIAL**",
    "spec coverage structured platform log checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`POST\n  /v1/platform/logs/forwarded` now accepts supervisor- or operator-forwarded",
    "spec coverage platform forwarded log route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "non-meta `platform.logs.write@Global`",
    "spec coverage platform forwarded log permission marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "API Client does not receive it\n  by default",
    "spec coverage platform log API Client default exclusion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "older customized Platform Administrator roles may need\n  an explicit admin role update",
    "spec coverage platform log persisted role caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "raw `stdout`/`stderr` fields, blank or oversized service/target/message",
    "spec coverage platform forwarded log validation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "global/service `off` suppression",
    "spec coverage platform forwarded log off suppression marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "append exactly one sanitized\n  `platform.log.forwarded.accepted` ledger event",
    "spec coverage platform forwarded log accepted audit marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "message length/SHA-256, context\n  key count, and context serialized size",
    "spec coverage platform forwarded log sanitized audit payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Authenticated\n  RBAC denial appends one sanitized `platform.log.forwarded.denied` route",
    "spec coverage platform forwarded log denied audit marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "append sanitized `platform.log.forwarded.rejected` reason-code audits",
    "spec coverage platform forwarded log rejected audit marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`platform.log.forwarded.suppressed` digest-only audits",
    "spec coverage platform forwarded log suppressed audit marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Missing or invalid\n  bearer requests remain unaudited",
    "spec coverage platform forwarded log bearer unaudited marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no raw body,\n  message, context keys, parse errors, stdout, stderr, tokens, secrets, or user\n  strings",
    "spec coverage platform forwarded log no raw failure audit payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Internal logging callers still ignore the returned `Option`",
    "spec coverage platform log internal Option suppression marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "does not add process lifecycle control,\n  stdout/stderr tailing or capture, production",
    "spec coverage platform forwarded log no lifecycle/stdout caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "a generalized observability sink, log retention/deletion\n  semantics, or a legal/compliance claim",
    "spec coverage platform forwarded log observability/retention/legal caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "data-status filesystem\n  telemetry now classifies `platform-logs.json` under `platform_logs`",
    "spec coverage data-status platform logs classification marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`backup-recovery-drills.json` under `backup_recovery_drills`",
    "spec coverage data-status backup recovery drills classification marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "storage telemetry classification only; it does not add deletion, retention\n  execution",
    "spec coverage data-status telemetry-only caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Working tree keeps Data/Documents/UX/CI **PARTIAL**: `POST\n  /v1/data/cleanup` export dry-runs now compute",
    "spec coverage retained-export dry-run planning checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`would_delete_files`,\n  `would_delete_directories`, and `would_delete_bytes` while keeping",
    "spec coverage retained-export would-delete counters marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`deleted_files`, `deleted_directories`, and `deleted_bytes` at zero",
    "spec coverage retained-export zero-deleted counters marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "preview-only exports\n  request of `{ target: \"exports\", dry_run: true, minimum_age_days: 30",
    "spec coverage retained-export preview payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not GDPR erasure, legal disposal, archive deletion,\n  certification",
    "spec coverage retained-export no-erasure-disposal marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Working tree keeps Signatures/Documents/UX/CI **PARTIAL**",
    "spec coverage external-validator raw upload UI partial checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "File selection computes a local safe\n  summary",
    "spec coverage external-validator raw file local summary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "does not upload automatically. The existing manual JSON\n  metadata path still works",
    "spec coverage external-validator no-auto-upload and manual JSON marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "the UI sends `raw_report.content_base64` with `content_type`,\n  `size_bytes`, `sha256`, and a safe `source_filename`",
    "spec coverage external-validator explicit raw upload payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "file-selection/no-auto-upload UI, submit payload,\n  summary-only rendering, and no-claim notice markers",
    "spec coverage external-validator checkpoint marker list",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "UI and response rendering\n  show only filename/type/size/digest/provenance summaries and never raw report\n  contents",
    "spec coverage external-validator summary-only rendering marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not\n  external-validator legal acceptance, legal validation, certification,\n  PDF/UA/PAdES certification, compliance proof",
    "spec coverage external-validator no certification/compliance claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "/v1/external-validator-reports/{case_id}/{validator_family}/raw-report` now\n  lets `settings.read` actors download only retained raw external-validator\n  report bytes",
    "spec coverage external-validator raw-report byte download checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "metadata-only/manifest-only\n  raw-report summaries, and sidecars without retained bytes return 404",
    "spec coverage external-validator raw-report manifest-only 404 marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "unsafe\n  identities, malformed sidecars, and duplicate or ambiguous identities fail\n  closed",
    "spec coverage external-validator raw-report fail-closed marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "upload remains explicit. This is technical byte preservation/access only: no\n  auto-upload",
    "spec coverage external-validator raw-report no auto-upload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "static `workflow_provenance_review_checklist` prompt and the read-only\n  `chancela://mcp/workflow-provenance-review` resource",
    "spec coverage MCP workflow provenance prompt/resource marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no bridge/API/provider calls, no secrets, and\n  explicit false legal-validity",
    "spec coverage MCP workflow provenance no-call/no-secret marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not workflow completion, AI completion, MCP\n  completion, source certification",
    "spec coverage MCP workflow provenance no-completion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "static `draft_signed_comparison_review_checklist` prompt and read-only\n  `chancela://mcp/draft-signed-comparison-review` resource",
    "spec coverage MCP draft-signed comparison prompt/resource marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "accepts only `uri` with\n  no arguments or extra params",
    "spec coverage MCP draft-signed comparison rejects args marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`ai_01_claimed` and `full_ai_mcp_completion_claimed` false",
    "spec coverage MCP draft-signed no AI completion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not AI completion, MCP completion, automated\n  comparison, source certification",
    "spec coverage MCP draft-signed no completion/comparison marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`GET /v1/dashboard`\n  now returns `recent_events: []` for guest/minimal redaction callers",
    "spec coverage dashboard guest recent-events redaction marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Guest remains\n  forbidden from `GET /v1/ledger/events`",
    "spec coverage dashboard Guest ledger forbidden marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "adds no permission\n  grants or broader privacy/anonymization completion claim",
    "spec coverage dashboard no permission grant marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "on-demand generated\n  post-act documents now return `/v1/documents/generated/{document_id}`",
    "spec coverage generated-document by-id route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "durable and in-memory\n  modes",
    "spec coverage generated-document durable/in-memory marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "canonical\n  `/v1/acts/{act_id}/document` route remains the sealed Ata target",
    "spec coverage generated-document canonical Ata route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "generates `condominio-comunicacao-ausentes/v1` automatically alongside the\n  Ata",
    "spec coverage condominium absent-owner auto-generation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`required_pending`, `evidence_attached=false`, and\n  `dispatch_completed=false`",
    "spec coverage condominium absent-owner pending dispatch marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no\n  signing, bundle, template, threshold, law, provider, registry, dispatch-sent\n  proof, dispatch completion, legal sufficiency, or legal-effect claim",
    "spec coverage generated-document no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "identifier-filtered\n  TSL/TSA catalog rows can now include optional `identifier_match` explanations",
    "spec coverage trust identifier-match checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "preserves strict lookup behavior for complete\n  certificate SHA-256 fingerprints/SKIs",
    "spec coverage trust identifier-match strict lookup marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "copies full SHA-256/SKI\n  values",
    "spec coverage trust copy-safe identifier marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "derived `Recibo de revisão` panel built from the existing imported\n  document view fields",
    "spec coverage imported-document review receipt checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Pending documents show `Sem recibo de revisão` and no\n  fake reviewer/time/note/guardrail receipt",
    "spec coverage imported-document no fake receipt marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no OCR, conversion, PDF/A replacement, signed\n  artifact creation/validation, new route/schema/mutation/download, or legal\n  acceptance claim",
    "spec coverage imported-document review receipt no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`3e72e08` keeps Legal/Data/Signatures/Documents/UX/CI **PARTIAL**",
    "spec coverage compliance tooling checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "local PAdES DSS\n  attach now accepts an optional caller-supplied `validation_time`",
    "spec coverage PAdES DSS validation_time checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Malformed `validation_time` is rejected without digest or audit-event\n  mutation",
    "spec coverage PAdES DSS malformed validation_time caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "bounded P-256 ECDSA-SHA256 verification",
    "spec coverage TSL P-256 XML-DSig marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "broad ECDSA/XML-DSig profile support, legal trust certification",
    "spec coverage TSL P-256 caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`POST\n  /v1/signature/asic/inspect` exposes read-only local technical ASiC profile",
    "spec coverage ASiC inspect endpoint checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "declared\n  fixity, readable ZIP shape, and unsafe member paths",
    "spec coverage ASiC inspect fixity/zip/path marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "local CAdES\n  cryptographic validation only when the package is blocker-free",
    "spec coverage ASiC inspect bounded CAdES-only marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "ASiC-XAdES and direct XAdES remain structured unsupported diagnostics:\n  XAdES validation is not performed",
    "spec coverage ASiC inspect no-XAdES-validation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "per-member and aggregate actual decompressed-size caps across payloads",
    "spec coverage ASiC actual decompressed-size caps marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "underdeclared ZIP entries cannot\n  bypass inspection blockers",
    "spec coverage ASiC underdeclared ZIP blocker marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "read-only local `POST /v1/signature/asic/inspect` ASiC profile inspection",
    "spec coverage matrix ASiC inspect route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "ASiC inspection beyond the read-only local technical endpoint and bounded CAdES candidate validation",
    "spec coverage matrix ASiC remaining-gap marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`POST /v1/signature/asic/inspect` is a read-only local technical inspection endpoint",
    "spec coverage ASiC overclaim endpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "and `xades_validation_performed: false`",
    "spec coverage ASiC overclaim XAdES false marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "do not sign, store,\n  mutate archives, call live providers",
    "spec coverage ASiC overclaim no-sign/store/live marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "read-only `GET /v1/privacy/retention-due-candidates`",
    "spec coverage retention due-candidates read-only marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "erasure records on page load",
    "spec coverage retention due-candidates non-mutating UI marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "forced/default `review_only`",
    "spec coverage retention due-candidates review-only request marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Duplicate `review_only` requests for the same candidate/policy\n  reuse the existing `awaiting_review` execution",
    "spec coverage retention duplicate review-only reuse marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "shows queued review status/id/time instead of\n  posting again",
    "spec coverage retention queued-review UI marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Due-candidate reads can also project safe prior bounded\n  `executed` archive/no-action evidence",
    "spec coverage retention prior bounded projection marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "uses canonical bounded `prior_execution.next_step` text\n  instead of persisted free-form text",
    "spec coverage retention prior projection canonical text marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Projected\n  prior bounded archive/no-action executions on due-candidate rows are read-only\n  internal evidence projections",
    "spec coverage retention prior projection no-overclaim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "candidates, approve legal disposal",
    "spec coverage retention due-candidates no-resolution caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "non-destructive restore preflight evidence",
    "spec coverage restore preflight evidence boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "recovery-drill receipt route records preflight-only bounded evidence",
    "spec coverage recovery drill receipt bounded evidence marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Recovery/backup matrix note",
    "spec coverage recovery backup matrix note marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "swap the live DB, stage/replace sidecars",
    "spec coverage recovery drill no destructive restore caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "metadata-only, non-canonical conversion",
    "spec coverage paper-book conversion-dossier implemented boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "idempotent duplicate creation",
    "spec coverage paper-book conversion-dossier idempotency marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "BookDetail now lists existing dossier metadata and exposes creation\n  only for accepted OCR drafts without an existing dossier",
    "spec coverage paper-book conversion-dossier UI marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no automatic dossier POST",
    "spec coverage paper-book conversion-dossier no automatic POST marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "loads 101 JSON template assets",
    "spec coverage template 101-asset marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`ponto-ordem-trabalhos/v1` Convocatoria\n  standalone agenda-item templates for all five supported families",
    "spec coverage agenda-item template marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "metadata guard now\n  also requires authored `BlockSpec` template strings for `Certidao` and\n  `Extrato` assets",
    "spec coverage post-act template metadata guard marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`ata_number` and\n  `payload_digest`, with whole-catalog and synthetic missing-binding regression",
    "spec coverage post-act template provenance fields marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "test/build-time coverage only",
    "spec coverage post-act template build-time-only marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "asset wording is unchanged",
    "spec coverage post-act template no-wording-change marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "101 total / 41 CSC",
    "spec coverage template CSC count marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "csc-ata-divisao-quotas/v1",
    "spec coverage CSC quota division template marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "csc-ata-unificacao-quotas/v1",
    "spec coverage CSC quota unification template marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "csc-ata-delegacao-poderes/v1",
    "spec coverage CSC delegation powers template marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "csc-ata-revogacao-poderes/v1",
    "spec coverage CSC revocation powers template marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "delegation/revocation templates render proposed resolution text only",
    "spec coverage CSC delegation/revocation proposed text boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "can mark only the\n  linked external envelope slot signed when that slot has no identity\n  requirements",
    "spec coverage external invite no-identity slot technical completion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "the normal envelope read/list completion summary then reflects\n  the technical slot state through `signed_required_slot_count` and blocking\n  slot IDs",
    "spec coverage external invite completion summary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Identity-required slots are not auto-signed from PDF upload alone\n  and return a bounded blocked reason",
    "spec coverage external invite identity-required blocked marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Replay of the same signed evidence is\n  idempotent, with no duplicate signed documents, slot evidence, or update\n  events",
    "spec coverage external invite replay idempotency marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "bounded in the web UI before file read and by\n  the matching backend body-limit envelope",
    "spec coverage external invite upload size-bound marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no provider calls, trust-list checks, QES/qualified status,\n  legal validity, provider completion, act finalization, or full envelope legal\n  completion is claimed",
    "spec coverage external invite no provider/legal completion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Non-pt locales keep new external invite upload/result\n  keys localized without Portuguese source leakage through i18n guards",
    "spec coverage external invite non-pt locale guard marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/official_signature_import.rs",
    "async fn linked_external_invite_upload_marks_only_linked_slot_signed()",
    "API linked external invite signed-PDF slot completion coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/official_signature_import.rs",
    'assert_eq!(envelope["completion"]["signed_required_slot_count"], 1);',
    "API linked external invite completion summary coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/official_signature_import.rs",
    "async fn linked_external_invite_upload_does_not_auto_sign_identity_required_slot()",
    "API linked external invite identity-required block coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/official_signature_import.rs",
    '"signature.external_envelope.updated"',
    "API linked external invite update-event idempotency marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/ExternalSignerInvitePage.test.tsx",
    "rejects an oversized signed PDF before reading or submitting it",
    "web external invite pre-read signed-PDF size guard coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/ExternalSignerInvitePage.tsx",
    "Raw PDF bytes; the backend route has a larger JSON/base64 envelope limit for this cap",
    "web external invite signed-PDF size cap boundary marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "post(signature::respond_external_signer_invite).layer(DefaultBodyLimit::max(\n                signature::OFFICIAL_SIGNATURE_IMPORT_ENVELOPE_BYTES",
    "API external invite respond backend body limit marker",
  );
  assertFileContains(
    "apps/web/src/i18n/i18n.test.ts",
    "keeps external invite signed-PDF evidence copy localized outside source Portuguese",
    "i18n external invite signed-PDF non-pt leakage guard coverage",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "later sequential slots fail with 409",
    "spec coverage external signer linked-invite order-policy marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "lists per-act workflow-only external-signing envelopes",
    "spec coverage external-signing envelope UI marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "leaving the slot unselected\n  preserves the tracking-only payload",
    "spec coverage external-signing tracking-only payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "without raw\n  backend/token-like detail and clears the warning after slot selection changes",
    "spec coverage external-signing safe sequential 409 marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Provider-backed signing, document-gated legal completion, provider completion,\n  act finalization, full envelope legal completion, and qualified status remain\n  incomplete",
    "spec coverage external-signing provider completion caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "optional `operator_notes` / `custody_location` receipt keys",
    "spec coverage backup recovery drill optional receipt keys marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "deterministic `ai_provenance.statement_sources[]` rows",
    "spec coverage deterministic AI statement-source rows marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "authoritative-source certification, or AI-quality assessment",
    "spec coverage AI statement-source caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`GET\n  /v1/books/{id}/archive/local-dglab-interchange-manifest`, gated by\n  `book.export@Book`, returns a deterministic local\n  `LocalDglabInterchangeManifest` scaffold",
    "spec coverage local DGLAB interchange API marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "validates back against\n  the source manifest",
    "spec coverage local DGLAB source manifest validation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no ZIP sidecar member, package validation change,\n  persisted package bytes, ledger event",
    "spec coverage local DGLAB no sidecar/persisted-bytes caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "BookDetail\n  exposes a direct save action that calls that GET endpoint and saves\n  `application/json` with a `.json` filename",
    "spec coverage local DGLAB BookDetail JSON save marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "local scaffold metadata JSON only: no\n  official DGLAB export, government filing",
    "spec coverage local DGLAB metadata-only no-official-export marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "grouped statement-source counts by `source_type`, row\n  path/type/label/status",
    "spec coverage AI richer provenance UI marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "automated draft-vs-signed comparison execution, a\n  complete provenance experience",
    "spec coverage AI no automated draft-vs-signed execution caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Current matrix alignment note",
    "spec coverage current matrix alignment note marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Current working-tree workflow reminder policy keeps Workflows/UX/CI\n  **PARTIAL**",
    "spec coverage workflow reminder policy checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`workflow.reminders` with `enabled`,\n  `dashboard_limit`, `due_soon_days`, `attendance_lookahead_days`",
    "spec coverage workflow reminder settings shape marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Defaults preserve the prior generated dashboard behavior: enabled, limit 5,\n  45-day due-soon status, 45-day attendance lookahead",
    "spec coverage workflow reminder defaults marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`enabled=false` suppresses reminder feed/cards without\n  removing other dashboard data",
    "spec coverage workflow reminder enabled=false boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "source toggles suppress only profile-calendar, act-follow-up, or\n  attendance-hygiene reminders respectively",
    "spec coverage workflow reminder source-toggle boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "absolute calendar-day\n  deltas across year boundaries",
    "spec coverage workflow reminder year-boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "they do not add legal-calendar rules, law-source authority, threshold\n  verification, external delivery/email/ICS/CalDAV/webhook",
    "spec coverage workflow reminder caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`5db121a` keeps Template Catalog/UX/CI **PARTIAL**",
    "spec coverage compact template filter checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`2c88b90` keeps UX/Workflows/CI **PARTIAL**",
    "spec coverage compact notifications/entity filter checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`76fc229` keeps Signatures/Documents/CI **PARTIAL**",
    "spec coverage keyed PAdES VRI /TU checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`c1c57fe` keeps UX/Data/CI **PARTIAL**",
    "spec coverage web SQLite table usage checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`fd70ca0` keeps CI/UX **PARTIAL**",
    "spec coverage browser export-save gate checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`c3d874b` keeps UX/Signatures/Trust/CI **PARTIAL**",
    "spec coverage trust catalog hash display checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`fdb9376` keeps Documents/CI **PARTIAL**",
    "spec coverage decorative content accounting checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "PDF accessibility report JSON\n  version 7 now includes writer-owned decorative-artifact evidence",
    "spec coverage PDF accessibility report v7 marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "default fixture no longer reports `no_alt_text_model`",
    "spec coverage PDF accessibility default fixture no-alt blocker reduction marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`LimitedTaggedStructure` remains machine-visible",
    "spec coverage PDF/UA limited tagged structure caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`ff1823a` keeps UX/Documents/CI **PARTIAL**",
    "spec coverage export save cancellation checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`2ffae33` keeps UX/Workflows/CI **PARTIAL**",
    "spec coverage dashboard density checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`2187a67` keeps Data/Architecture/CI **PARTIAL**",
    "spec coverage SQLite logical usage checkpoint marker",
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

function assertFileDoesNotContain(relativePath, needle, label) {
  assertFileExists(relativePath, label);
  const body = readFileSync(join(repoRoot, relativePath), "utf8");
  assert.ok(
    !body.includes(needle),
    `${label} still contains removed marker ${needle}`,
  );
}
