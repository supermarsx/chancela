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
    name: "API per-book import preflight tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-api", "--locked", "books_import_preflight"],
    ],
  },
  {
    name: "archive local DGLAB interchange API/scaffold tests",
    command: [
      "cargo",
      ["test", "-p", "chancela-archive", "--locked", "local_dglab_interchange"],
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
    name: "API absent-owner generated dispatch-evidence tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-api",
        "--locked",
        "absent_owner_dispatch_evidence_",
      ],
    ],
  },
  {
    name: "store generated-document dispatch evidence tests",
    command: [
      "cargo",
      [
        "test",
        "-p",
        "chancela-store",
        "--test",
        "store",
        "--locked",
        "generated_document_dispatch_evidence",
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
    "crates/chancela-api/src/users.rs",
    "pub password: String,",
    "API create-user password field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "before password policy/hash work for non-bootstrap requests",
    "API create-user auth-before-policy marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "crate::password_policy::enforce(",
    "API create-user password policy enforcement marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "attestation::hash_secret_with_seed(&req.password, &seed)?",
    "API create-user hardened verifier seed marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "password_hash: Some(password_hash)",
    "API create-user stored password hash marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "let bootstrap = bootstrap_state_for_insert(&users, is_bootstrap, has_authenticated_actor)?;",
    "API create-user bootstrap write-lock recheck marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "create_user_stale_unauthenticated_bootstrap_is_rejected_at_insert_recheck",
    "API stale bootstrap loser rejection coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "sem a palavra-passe atual ou uma frase de recuperação válida",
    "API cross-user credential proof uniform refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "without clearing `password_hash` or the attestation key",
    "API remove-secret no-clear boundary marker",
  );
  assertFileContains(
    "crates/chancela-api/src/users.rs",
    "não é permitido remover a palavra-passe; defina uma nova palavra-passe em alternativa",
    "API remove-secret 409 replacement guidance marker",
  );
  assertFileContains(
    "crates/chancela-api/src/session.rs",
    "pub password: String,",
    "API create-session password field marker",
  );
  assertFileContains(
    "crates/chancela-api/src/session.rs",
    "let Some(stored) = user.password_hash.clone() else",
    "API create-session legacy no-hash refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/session.rs",
    "palavra-passe não configurada para este utilizador",
    "API create-session no-hash 409 message marker",
  );
  assertFileContains(
    "crates/chancela-api/src/session.rs",
    "verify_secret_with_seed(&req.password, &stored, &seed)",
    "API create-session password verification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create_user_requires_password_and_persists_hardened_hash",
    "API create-user password/hash coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create_user_rejects_missing_or_weak_password_with_policy_errors",
    "API create-user missing/weak password coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create_user_rejects_unauthenticated_non_bootstrap_before_password_policy",
    "API create-user unauth-before-policy coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create_session_requires_password_for_hashed_user",
    "API create-session password-required coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "create_session_rejects_legacy_no_hash_user_409",
    "API create-session legacy no-hash coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "legacy no-hash rejection must not return a session token",
    "API legacy no-hash no-token assertion marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "legacy no-hash rejection must not insert a session",
    "API legacy no-hash no-session assertion marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "Correct proof still cannot remove the password; replacing it via POST is supported.",
    "API self remove-secret 409 coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "Correct-password cross-user remove-secret",
    "API cross-user remove-secret 409 coverage marker",
  );
  assertFileContains(
    "apps/web/src/features/users/UserCreateForm.tsx",
    "if (password.length === 0)",
    "web user creation requires password marker",
  );
  assertFileContains(
    "apps/web/src/features/users/UserCreateForm.tsx",
    "password !== password2",
    "web user creation password confirmation marker",
  );
  assertFileContains(
    "apps/web/src/features/users/users.test.tsx",
    "creates a user with a valid slug and sends identity email fields",
    "web user creation password payload coverage",
  );
  assertFileContains(
    "apps/web/src/features/users/users.test.tsx",
    "hides the remove-password action for users that already have a password",
    "web remove-password action hidden coverage",
  );
  assertFileContains(
    "apps/web/src/features/onboarding/onboarding.test.tsx",
    "walks welcome → org → user → password → recovery → finish and marks onboarding complete",
    "web onboarding password-required path coverage",
  );
  assertFileContains(
    "apps/web/src/features/onboarding/onboarding.test.tsx",
    "does not expose a password skip path and blocks weak passwords before the server",
    "web onboarding no password skip coverage",
  );
  assertFileContains(
    "apps/web/src/features/session/session.test.tsx",
    "prompts for a password for every roster user and sends it",
    "web sign-in password prompt coverage",
  );
  assertFileContains(
    "apps/web/src/features/session/session.test.tsx",
    "bootstrap: empty roster → create a user with password → password sign-in lands in the app",
    "web bootstrap create password sign-in coverage",
  );
  assertFileContains(
    "apps/web/src/features/session/session.test.tsx",
    'roster present: "criar novo utilizador" routes back to sign-in',
    "web signed-out non-bootstrap create refusal coverage",
  );
  assertFileContains(
    "apps/web/src/features/session/session.test.tsx",
    "switches to a has_secret user by prompting for the password",
    "web current-user switch password coverage",
  );
  assertFileContains(
    "apps/web/src/features/session/SignIn.tsx",
    "api.createSession({ user_id: user.id, password: createdPassword })",
    "web bootstrap sign-in uses created password marker",
  );
  assertFileContains(
    "apps/web/src/features/session/CurrentUserPicker.tsx",
    "picking one prompts for a password",
    "web current-user picker password marker",
  );
  assertFileContains(
    "apps/web/e2e/auth.ts",
    "export const OPERATOR_PASSWORD = 'Str0ng!Vault9';",
    "browser e2e shared operator password marker",
  );
  assertFileContains(
    "apps/web/e2e/auth.ts",
    "Complete the first-run wizard: organization → operator → password → recovery phrase.",
    "browser e2e onboarding helper password marker",
  );
  assertFileContains(
    "apps/web/e2e/fixtures.ts",
    "has no configured password verifier",
    "browser e2e reset refuses no-password operator marker",
  );
  assertFileContains(
    "apps/web/e2e/session.spec.ts",
    "settings-created users require passwords and switch current user with that password",
    "focused browser auth settings-created password user coverage",
  );
  assertFileContains(
    "apps/web/e2e/first-launch-onboarding.spec.ts",
    "fresh install requires strong password onboarding, recovery phrase, then opens the app",
    "focused browser auth first-launch password onboarding coverage",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "password-required account creation/session static markers",
    "CI checkpoints password-required auth lane marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree password-required auth checks",
    "CI/E2E hardening plan password-required auth checks marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Password-required account creation/session slice",
    "spec coverage password-required auth checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Focused Playwright auth proof pins",
    "spec coverage focused Playwright auth proof marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "the browser suite is not exhaustive",
    "CI/E2E hardening plan browser-suite non-exhaustive auth caveat",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "the broad browser suite/matrix\nremains unclaimed",
    "CI checkpoints broad browser matrix unclaimed auth caveat",
  );
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
    "crates/chancela-store/src/schema.rs",
    "paper_book_ocr_conversion_execution_artifacts",
    "store paper-book OCR conversion execution artifact schema marker",
  );
  assertFileContains(
    "crates/chancela-store/tests/store.rs",
    "paper_book_ocr_conversion_execution_artifact_round_trips_idempotent_and_binds_dossier",
    "store paper-book OCR conversion execution artifact round-trip coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/paper_import.rs",
    "paper_book_ocr_conversion_artifact_records_accepted_draft_act",
    "API paper-book OCR conversion execution artifact coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "PAPER_BOOK_OCR_CONVERSION_EXECUTION_ARTIFACT_NOTICE",
    "API paper-book OCR conversion execution artifact notice marker",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "conversion_execution_artifact: Option<PaperBookOcrConversionExecutionArtifactView>",
    "API paper-book OCR conversion execution artifact response marker",
  );
  assertFileContains(
    "crates/chancela-api/src/paper_import.rs",
    "conversion_execution_artifacts: Option<Vec<PaperBookOcrConversionExecutionArtifactView>>",
    "API paper-book OCR conversion dossier artifact list marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "conversion_execution_artifacts[]",
    "web contract paper-book OCR conversion dossier artifact fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "Reviewed OCR conversion execution evidence for mutable draft promotion only",
    "web paper-book OCR conversion execution evidence rendering coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "reviewed_conversion_execution_artifact",
    "BookDetail paper-book OCR reviewed conversion artifact marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "creates a metadata-only conversion dossier for an accepted OCR draft on operator action",
    "web paper-book conversion dossier operator-action coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    'aria-label="Resumo de profundidade OCR e dossier do livro em papel"',
    "web paper-book OCR/dossier review-depth summary marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Sem rascunho OCR revisto nos metadados carregados.",
    "web paper-book OCR/dossier no-reviewed-draft fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Sem rascunho OCR aceite.",
    "web paper-book OCR/dossier no-accepted-draft fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Sem dossier aplicável sem rascunho aceite.",
    "web paper-book OCR/dossier no-dossier fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Ata canónica, documento canónico, pacote de arquivo, assinatura, selo, PDF/A, PDF/UA e",
    "web paper-book OCR/dossier explicit exclusions marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Só metadados: sim · ata canónica: não · documento canónico: não · pacote de arquivo: não",
    "web paper-book OCR/dossier metadata-only no-claim flags marker",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "Preflight canónico OCR read-only",
    "web paper-book OCR canonical-conversion read-only preflight marker",
  );
  assertFileContains(
    "apps/web/src/features/books/books.test.tsx",
    "legal_acceptance_recorded_is_operator_evidence_only",
    "web paper-book OCR canonical-conversion preflight operator-evidence boundary coverage",
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
    "paper-book import preserves non-canonical package, OCR review, and dossier evidence",
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
    "apps/web/src/api/client.ts",
    "updateExternalSigningEnvelope",
    "web external-signing envelope PATCH client marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "export function useUpdateExternalSigningEnvelope(actId: string)",
    "web external-signing envelope update hook marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "const updated = await api.updateExternalSigningEnvelope('env-1'",
    "web external-signing envelope client PATCH coverage marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "expect(fetchMock.mock.calls[2][1]?.method).toBe('PATCH');",
    "web external-signing envelope client PATCH method marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "function SlotEvidenceMetadata",
    "web SigningPanel stored slot evidence metadata marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "function slotCanRecordTechnicalEvidence",
    "web SigningPanel pending initiated slot evidence action marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "function buildSlotEvidenceRows",
    "web SigningPanel slot evidence row builder marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "identity_requirement: requirement,",
    "web SigningPanel identity-requirement tagged evidence marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "submits identity-tagged slot evidence without completing the envelope",
    "web SigningPanel identity-required no-complete evidence coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "expect(bodies[0]).not.toHaveProperty('complete');",
    "web SigningPanel operator evidence omits complete marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/external_signing_envelopes.rs",
    "signed_slot_evidence_without_complete_stays_workflow_open",
    "API external-signing signed slot evidence no-complete coverage",
  );
  assertFileContains(
    "apps/web/e2e/external-signing-operator-evidence.spec.ts",
    "signed-in operator records external signer slot evidence as technical evidence only",
    "browser external-signing operator evidence proof marker",
  );
  assertFileContains(
    "apps/web/e2e/external-signing-operator-evidence.spec.ts",
    "expect(updateBodies[0]).not.toHaveProperty('complete');",
    "browser external-signing operator evidence no-complete marker",
  );
  assertFileContains(
    "apps/web/e2e/external-signing-operator-evidence.spec.ts",
    "assertNoProviderCredentialOrClaimFields(updateBodies[0]);",
    "browser external-signing operator evidence no-provider-secret marker",
  );
  assertFileContains(
    "apps/web/e2e/external-signing-operator-evidence.spec.ts",
    "expect(unexpectedProviderCalls).toEqual([]);",
    "browser external-signing operator evidence no-provider-calls marker",
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
    "patch_act_written_resolution_review_receipts_reject_proof_claims",
    "written-resolution review receipt false-claim rejection coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "written_resolution_evidence review_receipts are append-only",
    "written-resolution review receipt append-only API guard",
  );
  assertFileContains(
    "crates/chancela-api/src/acts.rs",
    "compliance_reports_written_resolution_evidence_status_only",
    "written-resolution evidence compliance status coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/CompliancePanel.tsx",
    "Written-resolution local evidence review",
    "written-resolution review-depth compliance panel marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "renders local review receipt depth from compliance without proof wording",
    "written-resolution editor review-depth rendering coverage",
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
    "crates/chancela-api/src/lib.rs",
    "/v1/books/import/preflight",
    "API per-book import preflight route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    '("/v1/books/import/preflight", RouteClass::Gated)',
    "API per-book import preflight route classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/bundles.rs",
    "`POST /v1/books/import/preflight?policy=refuse|quarantine_copy`",
    "API per-book import preflight raw-byte endpoint doc marker",
  );
  assertFileContains(
    "crates/chancela-api/src/bundles.rs",
    "import and returns a no-mutation preview with no `import_id`",
    "API per-book import preflight no-import-id doc marker",
  );
  assertFileContains(
    "crates/chancela-api/src/bundles.rs",
    "Preflight did not append ledger.imported, store an imported_books record",
    "API per-book import preflight no-mutation preview marker",
  );
  assertFileContains(
    "crates/chancela-api/src/bundles.rs",
    "Operator-safety preview only: not legal archive certification, not production signed-import validation beyond existing checks, and not DGLAB/legal acceptance.",
    "API per-book import preflight no-overclaim marker",
  );
  assertFileContains(
    "crates/chancela-store/src/recovery.rs",
    "It never inserts `imported_books` rows and never appends `ledger.imported`.",
    "store per-book import preflight no imported_books or ledger marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "assert_import_preflight_did_not_mutate",
    "API per-book import preflight no-mutation helper marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "books_import_preflight_valid_bundle_summarizes_without_mutation",
    "API per-book import preflight valid coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "books_import_preflight_tampered_bundle_reports_quarantine_without_mutation",
    "API per-book import preflight tampered coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "books_import_preflight_collision_refuse_blocks_without_mutation",
    "API per-book import preflight collision coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'preview.get("import_id").is_none()',
    "API per-book import preflight no import_id assertion marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "preflightImportBook: (bytes: ArrayBuffer | Blob, policy: CollisionPolicy = 'refuse')",
    "web client per-book import preflight raw bytes marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "Read-only preflight for a book bundle import (`POST /v1/books/import/preflight`, t54).",
    "web hook per-book import preflight no-mutation marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.tsx",
    "importPreflightPreview.policy === importPolicy",
    "web per-book import preflight policy-gated confirm marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.tsx",
    "if (!isCurrentImportRequest(generation, file, policy)) return;",
    "web per-book import preflight stale response guard marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "preflights a selected bundle before confirm import and shows the honest final verdict",
    "web per-book import preflight preview-confirm coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "clears a stale book import preflight when a different file is selected",
    "web per-book import preflight stale selected-file coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "ignores a deferred import preflight when the policy changes before it resolves",
    "web per-book import preflight stale policy coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/LivrosIntegridadeSection.test.tsx",
    "ignores a deferred import preflight when a different file is selected before it resolves",
    "web per-book import preflight deferred stale file coverage",
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
    "read-only technical ASiC signature inspection",
    "API ASiC inspection route-classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "Local technical ASiC signature inspection for arbitrary ASiC ZIP containers",
    "API ASiC inspection technical scope marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "projects the local `validate_asic_container` technical report across recognised CAdES, XAdES",
    "API ASiC inspection validate_asic_container projection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "No live provider call",
    "API ASiC inspection no-live-provider marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "storage mutation, or archive mutation",
    "API ASiC inspection no-archive-mutation marker",
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
    "pub technical_validation: AsicTechnicalValidationReport",
    "API ASiC inspection technical_validation response marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "fn asic_technical_validation_report(bytes: &[u8]) -> AsicTechnicalValidationReport",
    "API ASiC inspection technical validation builder marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "match validate_asic_container(bytes)",
    "API ASiC inspection validate_asic_container call marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "fn project_asic_validation_report(report: &AsicValidationReport) -> AsicTechnicalValidationReport",
    "API ASiC inspection AsicValidationReport projection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "fn technical_signature_report(signature: &AsicSignatureValidation) -> AsicTechnicalSignatureReport",
    "API ASiC inspection AsicSignatureValidation projection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "archive: &AsicArchiveTimestampValidation",
    "API ASiC inspection AsicArchiveTimestampValidation projection marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic_validate.rs",
    "pub struct AsicSignatureValidation",
    "signing ASiC validation signature report struct marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic_validate.rs",
    "pub struct AsicArchiveTimestampValidation",
    "signing ASiC validation archive timestamp report struct marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic_validate.rs",
    "pub struct AsicValidationReport",
    "signing ASiC validation report struct marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic_validate.rs",
    "pub struct AsicEmbeddedEvidenceIndicator",
    "signing ASiC embedded evidence indicator struct marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/asic_validate.rs",
    "fn diagnose_embedded_evidence",
    "signing ASiC embedded evidence diagnostics marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "pub embedded_evidence: AsicEmbeddedEvidenceReport",
    "API ASiC embedded evidence technical report marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "timestamp_trust_validation: NOT_PERFORMED",
    "API ASiC embedded evidence timestamp trust not_performed marker",
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
    "crates/chancela-api/src/asic_signature_validation.rs",
    "trust_validation: NOT_PERFORMED",
    "API ASiC inspection trust validation not_performed marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "revocation_validation: NOT_PERFORMED",
    "API ASiC inspection revocation validation not_performed marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "provider_validation: NOT_PERFORMED",
    "API ASiC inspection provider validation not_performed marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "timestamp_trust_validation: NOT_PERFORMED",
    "API ASiC inspection timestamp trust validation not_performed marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "qualified_signature_claimed: false",
    "API ASiC inspection qualified signature false marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "qes_claimed: false",
    "API ASiC inspection QES false marker",
  );
  assertFileContains(
    "crates/chancela-api/src/asic_signature_validation.rs",
    "b_lta_claimed: false",
    "API ASiC inspection B-LTA false marker",
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
    "asic_signature_validation_xades_s_and_e_use_technical_report",
    "API ASiC inspection XAdES technical report coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_mixed_e_cades_xades_archive_timestamp_reports_consistency",
    "API ASiC inspection mixed/archive timestamp coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_mixed_e_archive_timestamp_tamper_is_technical_only_invalid",
    "API ASiC inspection archive timestamp tamper coverage",
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
    "crates/chancela-signing/tests/asic_full.rs",
    "asic_s_xades_t_reports_embedded_lt_lta_indicators_without_claims",
    "signing ASiC embedded LT/LTA diagnostics coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/asic_signature_validation.rs",
    "asic_signature_validation_reports_embedded_lt_lta_diagnostics_without_claims",
    "API ASiC embedded LT/LTA diagnostics no-claim coverage",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "embedded LT/LTA-like diagnostics report local member/element",
    "spec coverage ASiC embedded LT/LTA technical-only marker",
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
    '!created.to_string().contains("content_base64")',
    "API external-validator raw report create response byte redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '!listed.to_string().contains("content_base64")',
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
    "crates/chancela-api/src/roles.rs",
    "apply_seeded_role_reconciliation",
    "API seeded role drift explicit apply handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/roles.rs",
    "role.seeded_drift_reconciled",
    "API seeded role drift explicit audit marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "/v1/roles/{id}/seeded-drift-reconciliation",
    "API seeded role drift reconciliation route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "seeded_role_drift_reconciliation_is_explicit_idempotent_and_audited",
    "API seeded role drift explicit apply coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "seeded_role_drift_reconciliation_requires_role_manage_and_subset",
    "API seeded role drift role.manage and subset coverage",
  );
  assertFileContains(
    "apps/web/src/features/rbac/FuncoesSection.tsx",
    "drift.requires_manual_review",
    "web RBAC seeded role drift manual-review marker",
  );
  assertFileContains(
    "apps/web/src/features/rbac/FuncoesSection.tsx",
    "Aplicar defaults em falta",
    "web RBAC seeded role drift explicit apply action marker",
  );
  assertFileContains(
    "apps/web/src/features/rbac/rbac.test.tsx",
    "shows seeded role drift as a manual-review status",
    "web RBAC seeded role drift coverage marker",
  );
  assertFileContains(
    "apps/web/src/features/rbac/rbac.test.tsx",
    "applies seeded role drift only after explicit admin review action",
    "web RBAC seeded role drift explicit apply coverage",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`GET`/`POST /v1/roles/{id}/seeded-drift-reconciliation`",
    "spec coverage seeded role drift reconciliation marker",
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
    "get_external_validator_report_metadata",
    "MCP external-validator report metadata lookup tool marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "path_template: \"/external-validator-reports/{case_id}/{validator_family}\"",
    "MCP external-validator safe metadata endpoint marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "assert_eq!(tool.input_schema, closed_empty_schema())",
    "MCP external-validator closed no-arg schema marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/registry.rs",
    "external_validator_report_metadata_tool_rejects_raw_upload_content_path_or_bytes_args",
    "MCP external-validator metadata lookup closed schema rejection coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "tools_call_external_validator_report_metadata_routes_to_safe_metadata_endpoint_only",
    "MCP external-validator metadata lookup tool-call route coverage",
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
    "pub struct RoleMapEntryReport",
    "PDF accessibility role-map target evidence report",
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
    "pub struct StructureTreeEvidenceReport",
    "PDF accessibility structure-tree evidence report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct StructureDepthReport",
    "PDF accessibility structural-depth report",
  );
  assertFileContains(
    "crates/chancela-doc/src/accessibility.rs",
    "pub struct MarkedContentCoverageReport",
    "PDF accessibility marked-content coverage report",
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
    "accessibility_bounded_local_pdf_diagnostics_are_emitted_without_pdfua_claim",
    "PDF accessibility v9 local diagnostics no-claim coverage",
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
    '\\"version\\":9',
    "PDF accessibility report JSON v9 coverage",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"structure_tree\\":{',
    "PDF accessibility JSON structure-tree marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"mapped_roles\\":[',
    "PDF accessibility JSON role-map target marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"structure_depth\\":{',
    "PDF accessibility JSON structural-depth marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"marked_content\\":{',
    "PDF accessibility JSON marked-content marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"known_layout_artifact_targets\\":[',
    "PDF accessibility JSON marked-artifact target marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"artifact_scope_operator\\":\\"BMC\\"',
    "PDF accessibility JSON marked-artifact operator marker",
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
    'StructureRole::KeyValueTable => "Table"',
    "PDF key-value table structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/layout.rs",
    'StructureRole::TableHeaderCell => "TH"',
    "PDF table header cell structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/layout.rs",
    'StructureRole::TableDataCell => "TD"',
    "PDF table data cell structure role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/pdfa.rs",
    'layout::StructureRole::TableRow => "TR"',
    "PDF structure tree table row role marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"key_value_tables_have_table_semantics\\":true',
    "PDF accessibility table semantics complete JSON marker",
  );
  assertFileContains(
    "crates/chancela-doc/src/tests.rs",
    '\\"pdf_ua_blockers\\":[\\"limited_tagged_structure\\"]',
    "PDF accessibility reduced bounded blocker list marker",
  );
  assertFileDoesNotContain(
    "crates/chancela-doc/src/tests.rs",
    '\\"pdf_ua_blockers\\":[\\"no_alt_text_model\\",\\"limited_tagged_structure\\"]',
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
    'attachment; filename=\\"{filename}\\"',
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
    "MCP resource/prompt coverage including workflow provenance review",
    "CI checkpoints MCP review-aids lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "chancela://mcp/chronology-review-summary",
    "CI checkpoints MCP chronology review summary URI marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "dashboard guest recent-events redaction",
    "CI checkpoints dashboard guest recent-events redaction lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated-document by-id\ndownload route plus absent-owner dispatch-evidence recording",
    "CI checkpoints generated-document dispatch-evidence route lane marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "dashboard absent-owner dispatch-evidence reminders",
    "CI checkpoints dashboard absent-owner reminder lane marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "generated absent-owner evidence UI",
    "CI checkpoints generated absent-owner evidence UI lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "raw-report byte download API",
    "CI checkpoints external-validator raw-report byte lane marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "web shell accessibility/focus markers for the skip link to `#main-content`, route-change main landmark focus, route-crash `main#main-content` preservation, PageHeader h1 rendering, and modal focus-trap behavior",
    "CI checkpoints web shell accessibility/focus lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "src/app/layout.test.tsx src/app/router.test.tsx src/ui/PageHeader.test.tsx src/ui/useFocusTrap.test.ts",
    "CI checkpoints web shell accessibility/focus command marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "external-signing stored slot evidence rendering",
    "CI checkpoints external-signing stored slot evidence lane marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "`PATCH` slot payloads that omit `complete:true`",
    "CI checkpoints external-signing PATCH no-complete lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "e2e/external-signing-operator-evidence.spec.ts",
    "CI checkpoints external-signing operator evidence browser command marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "browser no-secret boundary for PIN, OTP, CAN, credential, token, password, passphrase",
    "CI checkpoints external-signing operator evidence browser no-secret marker",
  );
  assertFileMatches(
    "docs/CI-CHECKPOINTS.md",
    /they do not prove provider calls[\s\S]*trust-list\s+checks[\s\S]*QES\/\s*qualified status[\s\S]*legal validity[\s\S]*provider completion[\s\S]*act\s+finalization[\s\S]*provider-backed slot signing[\s\S]*full envelope legal\s+completion/u,
    "CI checkpoints external-signing operator evidence no-claim marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "Official signed-PDF handoff browser proof",
    "CI checkpoints official signed-PDF browser lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "client-declared trace context only",
    "CI checkpoints official signed-PDF client-declared marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "collecting no PIN, OTP, CAN, credential, token, password, passphrase, or\n  private-key material",
    "CI checkpoints official signed-PDF no-secret marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "does not perform\n  trust-list validation, claim qualified status, or complete legal signing\n  acceptance",
    "CI checkpoints official signed-PDF no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree official signed-PDF handoff browser checks",
    "CI/E2E hardening plan official signed-PDF browser marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "e2e/official-signed-handoff.spec.ts",
    "CI/E2E hardening plan official signed-PDF command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "technical signed-PDF\n  evidence only",
    "CI/E2E hardening plan official signed-PDF technical-only marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "imported-document review receipt UI",
    "CI checkpoints imported-document receipt lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "imported-document review-depth/receipt/history markers for technical review\nhistory",
    "CI checkpoints imported-document review-depth static marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "neutral missing-preservation copy, pending/reviewed states, no-claim\nOCR/",
    "CI checkpoints imported-document neutral/no-claim static marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "canonical paper-book conversion,\npaper-book canonical act/document/archive-package creation, paper-book PDF/A/PDF-UA",
    "CI checkpoints paper-book no canonical artifacts static marker",
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
    "MCP draft-vs-signed comparison review prompt/resource plus deterministic\nlocal comparison report/no-call/no-claim markers",
    "CI checkpoints MCP draft-signed deterministic report marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "dashboard guest\n`recent_events: []` redaction and no-permission-grant\nmarkers",
    "CI checkpoints static dashboard guest redaction marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated-document by-id route, dispatch-evidence route, `act.read`/\n`document.generate` gates, durable/in-memory, canonical Ata preservation,\nabsent-owner communication auto-generation, dispatch-evidence store,\nidempotency, selected-recipient evidence coverage, evidence-attached headers,\nno dispatch completion, web client/hooks/panel/i18n metadata-only evidence UI,\ngenerated-document deep-link query/hash focus routing, one-time\nActDocumentPanel dispatch-evidence selection/focus, no send/delivery/\nlegal-notice copy, no-claim markers, and dashboard reminder/notification\nsource/action/deep-link/no-date ordering/fixture markers",
    "CI checkpoints static generated-document dispatch-evidence marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated-document deep-link query/hash focus routing, one-time\nActDocumentPanel dispatch-evidence selection/focus",
    "CI checkpoints static generated-document deep-link focus marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "dashboard reminder/notification\nsource/action/deep-link/no-date ordering/fixture markers",
    "CI checkpoints static dashboard notification deep-link marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "dashboard reminder/notification source/action/deep-link/no-date ordering/fixture markers",
    "CI checkpoints static dashboard absent-owner reminder marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "no dispatch completion, web client/hooks/panel/i18n metadata-only evidence UI,\ngenerated-document deep-link query/hash focus routing, one-time\nActDocumentPanel dispatch-evidence selection/focus, no send/delivery/\nlegal-notice copy, no-claim markers",
    "CI checkpoints static generated absent-owner evidence UI marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "`x-chancela-dispatch-completed=false`",
    "CI checkpoints generated-document false dispatch-completed header marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "operator-supplied external-signing slot evidence markers prove stored technical evidence display",
    "CI checkpoints external-signing operator evidence boundary marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata",
    "CI checkpoints absent-owner communication server command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "absent_owner_dispatch_evidence_",
    "CI checkpoints absent-owner dispatch-evidence API command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "generated_document_dispatch_evidence",
    "CI checkpoints generated-document dispatch-evidence store command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only",
    "CI checkpoints generated dispatch archive preservation test marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata",
    "CI checkpoints generated dispatch bundle preservation test marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "validation_report.evidence_index.generated_dispatch_evidence",
    "CI checkpoints generated dispatch bundle evidence-index marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "evidence/generated-dispatch/{document_id}.json",
    "CI checkpoints generated dispatch archive sidecar marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "no promotion into top-level/canonical `manifest.document_ids`",
    "CI checkpoints generated dispatch no manifest promotion marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "exclusion of `operator_note`, `idempotency_key`, note-derived stable fingerprints, generated communication bytes, and imported proof bytes",
    "CI checkpoints generated dispatch redaction marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "false `proof_bytes_included`, `bytes_included`, `operator_note_included`, `dispatch_completed`, legal-notice/legal-sufficiency, provider, registry, DGLAB, and legal-archive acceptance flags",
    "CI checkpoints generated dispatch false-claim marker",
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
    "imported-document review-depth/receipt/history markers for technical review\nhistory",
    "CI checkpoints static imported-document receipt marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "trust identifier-match explanation/copy-safe hash and\nSKI markers",
    "CI checkpoints static trust identifier-match marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retained-export cleanup preview-token/manifest gating",
    "CI checkpoints retained-export preview-token manifest lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retention explicit evidence-state markers (`review_queued`, `blocked`,\n`bounded_archive_recorded`, `bounded_no_action_recorded`,\n`prior_bounded_evidence_available`), duplicate review-only request guards",
    "CI checkpoints retention duplicate-review lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retention due-candidate explicit evidence-state enum markers,\nduplicate-review, queued-status, prior bounded evidence suppression,\nactive/suppressed candidate count fields, suppression-summary copy, eligible\nbounded archive/no-action `execute_supported` UI markers",
    "CI checkpoints retention bounded suppression static marker",
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
    'productionWithoutManifest.releaseTrust.mode = "production";',
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
    'status_scope: "declared_capacity_evidence_only".to_owned()',
    "declared signer-capacity evidence scope marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    'verification_status: "not_checked_by_scap".to_owned()',
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
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "export function BatchSigningPanel",
    "web CC batch signing panel component marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "const ccBatchSign = useCcBatchSign();",
    "web CC batch signing hook usage marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "pin: trimmedPin || undefined",
    "web CC batch signing optional transient PIN request marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "setPin('');",
    "web CC batch signing PIN clear marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "signing.ccBatch.result.authMode",
    "web CC batch signing auth-mode display marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "response.signer_capacity_evidence",
    "web CC batch signing declared capacity evidence display marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.tsx",
    "response.results.map",
    "web CC batch signing per-document results marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "<BatchSigningPanel currentAct={act} bookScope={bookScope} />",
    "web signing panel mounts CC batch signing panel marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "export function useCcBatchSign()",
    "web CC batch signing mutation hook marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "post<CcBatchSignResponse>('/v1/signature/cc/batch-sign', body)",
    "web CC batch signing client route marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface CcBatchSignBody",
    "web CC batch signing request contract marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface CcBatchSignResponse",
    "web CC batch signing response contract marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.test.tsx",
    "submits the exact request shape and renders per-document success and error results",
    "web CC batch signing request/results regression coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.test.tsx",
    "omits PIN when blank and labels per-document authentication only from the response",
    "web CC batch signing auth-mode honesty coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.test.tsx",
    "clears the transient PIN on error and keeps the request body transient",
    "web CC batch signing PIN error-clear regression coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.test.tsx",
    "clears PIN on reset and unmount without writing storage",
    "web CC batch signing no-storage regression coverage",
  );
  assertFileContains(
    "apps/web/src/features/signing/BatchSigningPanel.test.tsx",
    "resets transient batch state when the current act changes in a reused panel",
    "web CC batch signing route/current-act reset coverage",
  );
  assertFileContains(
    "apps/web/e2e/local-cc-batch-signing.spec.ts",
    "Focused browser proof for the local/co-located CC batch-signing UI.",
    "web CC batch signing focused Playwright proof marker",
  );
  assertFileContains(
    "apps/web/e2e/local-cc-batch-signing.spec.ts",
    "POST /v1/signature/cc/batch-sign",
    "web CC batch signing browser route marker",
  );
  assertFileContains(
    "apps/web/e2e/local-cc-batch-signing.spec.ts",
    "optional transient PIN request/clear/no-storage behavior",
    "web CC batch signing browser PIN boundary marker",
  );
  assertFileContains(
    "apps/web/e2e/local-cc-batch-signing.spec.ts",
    "route-stubbed local browser proof only",
    "web CC batch signing browser no-live-provider boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "CC batch UI evidence only",
    "spec coverage local CC batch signing no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "route-stubbed local browser proof only",
    "spec coverage local CC batch signing browser proof boundary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "local CC batch UI evidence only: not CMD batch signing",
    "CI/E2E hardening local CC batch signing no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "route-stubbed Playwright proof",
    "CI/E2E hardening local CC batch signing browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "local CC batch-signing UI markers for BatchSigningPanel",
    "CI checkpoints local CC batch signing marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "route-stubbed local browser proof only",
    "CI checkpoints local CC batch signing browser proof boundary marker",
  );
  assertFileContains(
    "apps/web/src/app/layout.tsx",
    '<a className="skip-link" href="#main-content">',
    "web layout skip-link main-content target marker",
  );
  assertFileContains(
    "apps/web/src/app/layout.tsx",
    "mainRef.current?.focus();",
    "web layout route-change main focus marker",
  );
  assertFileContains(
    "apps/web/src/app/router.tsx",
    "same `main#main-content` skip-link target here for data-router failures",
    "web route-crash fallback main-content rationale marker",
  );
  assertFileContains(
    "apps/web/src/app/router.tsx",
    '<main id="main-content" tabIndex={-1} className="route-transition">',
    "web route-crash fallback main target marker",
  );
  assertFileContains(
    "apps/web/src/app/layout.test.tsx",
    "keeps the skip-link target mounted when routed content crashes",
    "web layout skip-link target crash coverage",
  );
  assertFileContains(
    "apps/web/src/app/layout.test.tsx",
    "focuses the main landmark after pathname navigation",
    "web layout route-change main focus coverage",
  );
  assertFileContains(
    "apps/web/src/app/layout.test.tsx",
    "does not steal focus on same-path query and hash navigation",
    "web layout same-path focus retention coverage",
  );
  assertFileContains(
    "apps/web/src/app/router.test.tsx",
    "renders CrashScreen for a lazy route rejection instead of React Router default UI",
    "web router crash fallback main landmark coverage",
  );
  assertFileContains(
    "apps/web/src/app/router.test.tsx",
    "expect(main.id).toBe('main-content');",
    "web router fallback main-content assertion marker",
  );
  assertFileContains(
    "apps/web/src/ui/PageHeader.test.tsx",
    "renders the title as a level-1 heading",
    "web PageHeader h1 coverage",
  );
  assertFileContains(
    "apps/web/src/ui/PageHeader.test.tsx",
    "getByRole('heading', { level: 1, name: 'Entidades' })",
    "web PageHeader h1 role assertion marker",
  );
  assertFileContains(
    "apps/web/src/ui/useFocusTrap.test.ts",
    "moves focus into the container on activation",
    "web focus trap activation coverage",
  );
  assertFileContains(
    "apps/web/src/ui/useFocusTrap.test.ts",
    "restores focus to the pre-open element when the trap unmounts",
    "web focus trap restore coverage",
  );
  assertFileContains(
    "apps/web/src/ui/useFocusTrap.test.ts",
    "wraps Tab from the last focusable to the first",
    "web focus trap Tab wrap coverage",
  );
  assertFileContains(
    "apps/web/src/ui/useFocusTrap.test.ts",
    "wraps Shift+Tab from the first focusable to the last",
    "web focus trap Shift+Tab wrap coverage",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "web accessibility/focus guard evidence",
    "spec coverage web accessibility/focus evidence marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not complete UX coverage,\n  WCAG/legal accessibility certification",
    "spec coverage web accessibility/focus no-certification marker",
  );
  assertFileContains(
    "crates/chancela-core/src/seal.rs",
    "manual_signature_original_reference_is_required_before_mutation",
    "core manual-signature original-reference required-before-mutation coverage",
  );
  assertFileContains(
    "crates/chancela-core/src/seal.rs",
    "manual_signature_original_reference_is_frozen_in_seal_metadata",
    "core manual-signature original-reference immutable metadata coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "guest_act_read_redacts_manual_signature_original_reference",
    "API guest act manual-signature original-reference redaction coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "guest_book_act_feed_redacts_manual_signature_original_reference",
    "API guest feed manual-signature original-reference redaction coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "requires a manual original reference before sealing when compliance is clean",
    "web manual-signature original-reference clean seal coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "blocks manual original references containing control characters before submit",
    "web manual-signature original-reference control-character refusal coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "ActView.seal_metadata.manual_signature_original_reference",
    "web contract manual-signature original-reference seal metadata marker",
  );
  assertFileContains(
    "apps/web/e2e/book-helpers.ts",
    "manual_signature_original_reference",
    "Playwright seal helper manual-signature original-reference request marker",
  );
  assertFileContains(
    "apps/web/e2e/manual-signature-original-reference.spec.ts",
    "manual sealing requires, captures, and preserves the signed-original reference",
    "focused Playwright manual-signature original-reference browser proof marker",
  );
  assertFileContains(
    "apps/web/e2e/manual-signature-original-reference.spec.ts",
    "not a qualified/eIDAS/legal signature validity claim",
    "focused Playwright manual-signature original-reference no-claim boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "manual-signature original-reference metadata",
    "spec coverage manual-signature original-reference metadata marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "not a qualified/eIDAS/legal signature validity claim",
    "spec coverage manual-signature original-reference no-claim marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "manual-signature original-reference metadata markers",
    "CI checkpoints manual-signature original-reference marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "no qualified/eIDAS/legal\nsignature validity",
    "CI checkpoints manual-signature original-reference no-claim marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub enum RemoteBatchAuthMode",
    "signing core repeated remote-session auth-mode type marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub struct RemoteBatchPendingDocument",
    "signing core repeated remote-session pending type marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub struct RemoteBatchConfirmDocument<'a>",
    "signing core repeated remote-session confirm type marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub fn initiate_remote_pdf_batch_repeated_sessions",
    "signing core repeated remote-session PDF initiate helper marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub fn initiate_remote_prepared_batch_repeated_sessions",
    "signing core repeated remote-session prepared initiate helper marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "pub fn confirm_remote_pdf_batch_repeated_sessions",
    "signing core repeated remote-session confirm helper marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "RemoteSigningSource::initiate`] once, producing one [`RemoteSignSession`] per document",
    "signing core repeated remote-session one-digest initiate no-batch marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/batch.rs",
    "Always [`RemoteBatchAuthMode::PerDocumentActivation`] for this seam",
    "signing core repeated remote-session per-document activation marker",
  );
  assertFileContains(
    "crates/chancela-signing/src/lib.rs",
    "confirm_remote_pdf_batch_repeated_sessions, initiate_remote_pdf_batch_repeated_sessions",
    "signing core repeated remote-session public export marker",
  );
  assertFileContains(
    "crates/chancela-signing/tests/batch.rs",
    "remote_repeated_batch_opens_and_confirms_one_session_per_pdf",
    "signing core repeated remote-session happy-path coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/batch.rs",
    "remote_repeated_batch_prepare_failure_is_per_document",
    "signing core repeated remote-session prepare isolation coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/batch.rs",
    "remote_repeated_batch_confirm_failure_is_per_document",
    "signing core repeated remote-session confirm isolation coverage",
  );
  assertFileContains(
    "crates/chancela-signing/tests/batch.rs",
    "remote_repeated_batch_pending_records_do_not_store_activation_secrets",
    "signing core repeated remote-session secret-free pending coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub struct PendingInfo",
    "API pending signature info response marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub provider_id: String",
    "API pending signature provider_id marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub family: String",
    "API pending signature family marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "pub activation_hint: Option<String>",
    "API pending signature activation_hint marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "fn pending_provider_info(pending: &PendingCmdSession) -> PendingProviderInfo",
    "API pending_provider_info bridge marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "provider_id?: string",
    "web PendingInfo provider_id type marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "family?: string",
    "web PendingInfo family type marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "activation_hint?: string",
    "web PendingInfo activation_hint type marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.tsx",
    "function providerFromPending",
    "web providerFromPending reload-adoption marker",
  );
  assertFileMatches(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    /restores (?:a reloaded CMD pending session|an older CMD pending session without provider metadata) through the dedicated confirm path/u,
    "web restores a reloaded CMD pending session through the dedicated confirm path marker",
  );
  assertFileContains(
    "apps/web/src/features/signing/SigningPanel.test.tsx",
    "restores a reloaded CSC pending session through the generic remote confirm path",
    "web CSC pending session generic remote confirm reload-adoption coverage",
  );
  assertFileContains(
    "apps/web/e2e/remote-signing-pending-session.spec.ts",
    "pending CSC/QTSP session resumes after reload and confirms through provider remote endpoint",
    "web pending CSC/QTSP route-stubbed browser resume coverage",
  );
  assertFileContains(
    "apps/web/e2e/remote-signing-pending-session.spec.ts",
    "legacy CMD pending session resumes after reload and confirms through CMD endpoint",
    "web legacy CMD route-stubbed browser resume coverage",
  );
  assertFileContains(
    "apps/web/e2e/remote-signing-pending-session.spec.ts",
    "endpointMismatches",
    "web pending-session negative endpoint assertion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`GET\n  /v1/acts/{id}/signature` returns additive pending-session provider metadata",
    "spec coverage pending-session provider identity bridge marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Focused route-stubbed Playwright proof now pins\n  reload adoption/routing",
    "spec coverage pending-session browser proof marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "This is pending-session adoption/routing only",
    "spec coverage pending-session provider identity no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Core repeated remote-session orchestration seam",
    "spec coverage repeated remote-session seam marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "core-only: no API route, no web UI",
    "spec coverage repeated remote-session core-only no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "provider-certified remote batch, not single OTP/PIN/SAD authorizing multiple\n  documents, not CMD multiple-sign, not CSC/QTSP multi-hash/SAD batch, and not\n  SCAP/legal-capacity proof",
    "spec coverage repeated remote-session remote-batch no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Each document still opens and confirms its\n  own remote session/activation",
    "CI/E2E hardening repeated remote-session per-document marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`GET /v1/acts/{id}/signature` returns additive pending-session provider\n  metadata",
    "CI/E2E hardening pending-session provider identity bridge marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "This is reload\n  adoption/routing only",
    "CI/E2E hardening pending-session provider identity no-claim marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "e2e/remote-signing-pending-session.spec.ts",
    "CI/E2E hardening pending-session browser command marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "core-only no-API/no-web boundary",
    "CI checkpoints repeated remote-session core-only marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "apps/web/e2e/remote-signing-pending-session.spec.ts",
    "CI checkpoints pending-session browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "route-stubbed reload adoption/routing only and uses fake activation/OTP\nvalues",
    "CI checkpoints pending-session browser boundary marker",
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
    'crate_find(&with_dss, b"/TU (D:20260709120000Z)")',
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
    '"execution_status": "awaiting_review"',
    "retention execution review-queue fixture awaiting marker",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    '"destructive_disposal_completed": false',
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
    "retention_due_candidates_suppress_prior_bounded_archive_without_mutation",
    "API retention due-candidates prior bounded archive suppression coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_ignore_unsafe_prior_bounded_execution_flags",
    "API retention due-candidates unsafe prior projection refusal coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_due_candidates_suppress_prior_bounded_no_action_without_mutation",
    "API retention due-candidates prior bounded no-action suppression coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "suppression summary must not surface unsafe term",
    "API retention prior bounded suppression summary safety marker",
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
    '"suppression_summary": {',
    "retention due-candidates fixture suppression summary marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"suppressed_by_bounded_evidence_count": 2',
    "retention due-candidates fixture bounded suppression count marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"note": "Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review."',
    "retention due-candidates fixture suppression note marker",
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
    "async function requestRetentionReview(",
    "Settings retention due-candidate review request handler",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate: RetentionDueCandidate",
    "Settings retention due-candidate review request candidate type marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function retentionCandidateCanRecordNoActionEvidence",
    "Settings retention due-candidate no-action eligibility helper",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function retentionCandidateCanRecordArchiveEvidence",
    "Settings retention due-candidate archive eligibility helper",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate.disposal_action === 'no_action'",
    "Settings retention due-candidate no-action disposal gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate.disposal_action === 'archive'",
    "Settings retention due-candidate archive disposal gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate.destructive_action === false",
    "Settings retention due-candidate non-destructive gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate.blockers.length === 0",
    "Settings retention due-candidate blocker-free gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "candidate.legal_hold_blockers.length === 0",
    "Settings retention due-candidate legal-hold-free gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "!queuedReview",
    "Settings retention due-candidate queued-review exclusion gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "!candidate.prior_execution",
    "Settings retention due-candidate prior-execution exclusion gate",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "onRequestReview(candidate, 'execute_supported')",
    "Settings retention due-candidate execute-supported no-action action marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Registar evidência sem ação",
    "Settings retention due-candidate bounded no-action evidence copy",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Registar evidência de arquivo",
    "Settings retention due-candidate bounded archive evidence copy",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Regista apenas evidência delimitada de no-action; não aprova nem executa",
    "Settings retention due-candidate bounded no-action caveat copy",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Regista apenas evidência delimitada de arquivo; não aprova nem executa",
    "Settings retention due-candidate bounded archive caveat copy",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "executionMode: 'review_only' | 'execute_supported' = 'review_only'",
    "Settings retention due-candidate default review-only mode marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "onRequestReview(candidate, 'review_only')",
    "Settings retention due-candidate review-only action marker",
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
    "records bounded no-action evidence from an eligible due retention candidate row",
    "Settings retention due-candidate bounded no-action evidence coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "records bounded archive evidence from an eligible due retention candidate row",
    "Settings retention due-candidate bounded archive evidence coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "keeps bounded no-action evidence unavailable for ineligible due retention candidates",
    "Settings retention due-candidate ineligible no-action evidence coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "keeps bounded archive evidence unavailable for unsafe due retention candidates",
    "Settings retention due-candidate unsafe archive evidence coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "execution_mode: 'execute_supported'",
    "Settings retention due-candidate execute-supported payload assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "requested_policy_id: 'retention-no-action'",
    "Settings retention due-candidate no-action policy payload assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "requested_policy_id: 'retention-archive'",
    "Settings retention due-candidate archive policy payload assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "within(candidateRow!).queryByText(/GDPR erasure|legal erasure|full erasure/i)",
    "Settings retention due-candidate no erasure-copy assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "!call.body?.includes('full_erasure_completed')",
    "Settings retention due-candidate no full-erasure payload assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "!call.body?.includes('legal_hold')",
    "Settings retention due-candidate no legal-hold mutation payload assertion",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "Boolean(call.body?.includes('execute_supported'))",
    "Settings retention due-candidate execute-supported POST probe",
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
    "suppresses projected bounded execution rows and leaves execution history visible",
    "Settings retention due-candidate suppressed evidence history coverage",
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
    "apps/web/src/api/types.ts",
    "export const RETENTION_EVIDENCE_STATES = [\n  'review_queued',\n  'blocked',\n  'bounded_archive_recorded',\n  'bounded_no_action_recorded',\n  'prior_bounded_evidence_available',",
    "web retention explicit evidence-state enum marker",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    '"evidence_state": "bounded_archive_recorded"',
    "retention executions fixture bounded archive evidence-state marker",
  );
  assertFileContains(
    "contracts/retention.due-candidates.json",
    '"suppressed_candidate_count": 2',
    "retention due-candidates fixture bounded evidence suppression marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    'json!("Bounded archive evidence recorded; no destructive operation was performed.")',
    "API retention bounded archive no-destructive next-step marker",
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
    "crates/chancela-api/src/authz.rs",
    '"/v1/privacy/retention-executions/{id}/review-closure"',
    "API retention review-closure route classification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "`POST /v1/privacy/retention-executions/{id}/review-closure` — close operator review evidence without executing disposal.",
    "API retention review-closure no-disposal handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "retention execution review closure already exists with different evidence",
    "API retention review-closure conflict marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "review_closure_note or review_closure_evidence is required",
    "API retention review-closure evidence-required marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "review closure records bounded evidence only",
    "API retention review-closure no-overclaim marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_review_closure_records_review_only_and_idempotent_duplicate",
    "API retention review-closure idempotent review-only coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_review_closure_accepts_bounded_and_blocked_categories",
    "API retention review-closure outcome-category coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_review_closure_rejects_claims_flags_unknowns_and_authz",
    "API retention review-closure authz/overclaim coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "retention_execution_review_closure_persists_and_due_candidates_stay_non_mutating",
    "API retention review-closure persistence/non-mutating coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "idempotent duplicate must not append another ledger event",
    "API retention review-closure no-duplicate-ledger marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/privacy.rs",
    "due-candidate GET must not write execution records",
    "API retention review-closure due-candidate no-write marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "closeRetentionExecutionReview: (id: string, body: CloseRetentionExecutionReviewBody)",
    "web retention review-closure client route marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export const RETENTION_REVIEW_CLOSURE_DECISIONS = [",
    "web retention review-closure decision enum marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "RETENTION_REVIEW_CLOSURE_OVERCLAIM_TERMS",
    "web retention review-closure contract overclaim marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "`${label}.review closure needs note or evidence`",
    "web retention review-closure contract evidence-required marker",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    '"decision_state": "review_closed"',
    "retention executions fixture review-closed marker",
  );
  assertFileContains(
    "contracts/retention.executions.json",
    '"review_closure_decision": "bounded_evidence_acknowledged"',
    "retention executions fixture bounded closure marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "function retentionReviewClosureDecisionForOutcome",
    "Settings retention review-closure decision mapper marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "RETENTION_REVIEW_CLOSURE_FALSE_FLAGS",
    "Settings retention review-closure false flags marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Registar revisão operacional",
    "Settings retention review-closure action copy marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "maps retention execution review closure decisions from outcome categories",
    "Settings retention review-closure outcome mapping coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "does not show the retention review closure action for already closed records",
    "Settings retention review-closure hidden action coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "/v1/privacy/retention-executions/retention-exec-awaiting/review-closure",
    "Settings retention review-closure POST route coverage",
  );
  assertFileContains(
    "apps/web/e2e/settings-privacy-retention-suppression.spec.ts",
    "expectClosureBodyStaysNonLegal",
    "browser retention review-closure non-legal assertion marker",
  );
  assertFileContains(
    "apps/web/e2e/settings-privacy-retention-suppression.spec.ts",
    "routes.retentionLifecycleMutations).toEqual([])",
    "browser retention review-closure no lifecycle mutations marker",
  );
  assertFileContains(
    "apps/web/e2e/settings-privacy-retention-suppression.spec.ts",
    "countRouteRequests(routes, 'GET /v1/privacy/retention-due-candidates')).toBe(",
    "browser retention review-closure stable due-candidate count marker",
  );
  assertFileContains(
    "crates/chancela-api/src/books.rs",
    "Local operator workflow/status evidence only; active book legal hold blocks retention/disposal review",
    "API book legal-hold operator workflow no-claim marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "eligible_for_bounded_evidence_review",
    "API archive disposal bounded workflow status marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    'hold["operator_workflow"]["status"]',
    "API legal-hold operator workflow coverage",
  );
  assertFileContains(
    "apps/web/src/features/books/BookDetailPage.tsx",
    "não aprova descarte nem",
    "BookDetail legal-hold no-approval copy marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Estado local de legal hold e descarte",
    "Settings legal-hold disposal status summary marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "não aprova descarte, não resolve candidatos",
    "Settings legal-hold disposal status no-mutation coverage",
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
    '"authority_notified": false',
    "breach playbook receipt contract fixture",
  );
  assertFileContains(
    "contracts/privacy.transfer-controls.json",
    '"data_transfer_executed": false',
    "transfer control receipt contract fixture",
  );
  assertFileContains(
    "contracts/privacy.dpias.json",
    '"authority_filing_completed": false',
    "DPIA receipt false authority filing contract fixture",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "pub struct DpiaAdvisoryReviewSummary",
    "DPIA advisory review summary DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "compliance_certification_completed: false",
    "DPIA receipt false compliance certification marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "Sem submissão à",
    "settings DPIA receipt no-authority-filing UI marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "pub struct PrivacyAdvisoryReviewSummary",
    "privacy advisory review summary DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "authority_notification_claimed: false",
    "privacy advisory review false authority notification marker",
  );
  assertFileContains(
    "crates/chancela-api/src/privacy.rs",
    "transfer_execution_claimed: false",
    "privacy advisory review false transfer execution marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "privacy_control_review_reminders(",
    "dashboard privacy control review reminder builder marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "This dashboard reminder is local and advisory only",
    "dashboard privacy review advisory caveat marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "privacy_control_review_reminders_cover_missing_overdue_and_source_toggle",
    "dashboard privacy review reminder unit coverage marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "renders privacy control review reminders with settings routing and source markers",
    "web dashboard privacy review reminder source-rule unit marker",
  );
  assertFileContains(
    "apps/web/e2e/privacy-control-review-reminders.spec.ts",
    "privacy control review reminders stay local and follow the settings source toggle",
    "privacy control review reminder browser proof marker",
  );
  assertFileContains(
    "apps/web/e2e/privacy-control-review-reminders.spec.ts",
    "privacyRecordMutations",
    "privacy control review reminder browser no-mutation marker",
  );
  assertFileContains(
    "apps/web/e2e/privacy-control-review-reminders.spec.ts",
    "PRIVACY_TRANSFER_REVIEW_RULE",
    "privacy transfer control review browser reminder marker",
  );
  assertFileContains(
    "contracts/privacy.breach-playbooks.json",
    '"advisory_review":',
    "breach advisory review contract fixture marker",
  );
  assertFileContains(
    "contracts/privacy.transfer-controls.json",
    '"advisory_review":',
    "transfer advisory review contract fixture marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"source_rule": "privacy-breach-playbook-review"',
    "dashboard privacy review reminder contract fixture marker",
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
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official signed-PDF handoff import is technical evidence only in the browser",
    "official signed-PDF handoff browser proof spec marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "`/v1/acts/${ACT_ID}/signature/official/import`",
    "official signed-PDF handoff browser import route marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official_import_preserves_uploaded_signed_pdf_as_technical_evidence",
    "official signed-PDF handoff browser preserve guardrail marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official_import_trust_validation_not_performed",
    "official signed-PDF handoff browser trust guardrail marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official_import_qualified_status_not_claimed",
    "official signed-PDF handoff browser qualified guardrail marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official_import_legal_status_not_claimed",
    "official signed-PDF handoff browser legal guardrail marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "official_import_no_secret_factor_collected",
    "official signed-PDF handoff browser no-secret guardrail marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "Official handoff import stores technical signed-PDF evidence only; acknowledgements record guardrails and do not claim trust-list, qualified-signature, or legal completion.",
    "official signed-PDF handoff browser API notice marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "expectNoCredentialInputs",
    "official signed-PDF handoff browser no credential inputs marker",
  );
  assertFileContains(
    "apps/web/e2e/official-signed-handoff.spec.ts",
    "expectNoPositiveClaimText",
    "official signed-PDF handoff browser no positive legal/trust claim marker",
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
    "crates/chancela-api/src/data_status.rs",
    "pub struct DataPayloadStats",
    "data status SQLite payload stats DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "PayloadEstimateMethod::LocalLoadedPayloadEstimate",
    "data status SQLite payload stats local estimate method marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "fn largest_sqlite_payload_table",
    "data status SQLite largest payload table helper marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'assert_eq!(ledger["basis"], "sqlite_logical_payload");',
    "API data status SQLite logical payload response coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'event_table["payload_stats"]["estimate_method"]',
    "API data status SQLite payload stats response coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    'body["usage"]["sqlite_largest_payload_table"]["estimate_method"]',
    "API data status SQLite largest table response coverage",
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
    '"id": "csc-ponto-ordem-trabalhos/v1"',
    "commercial company agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-ponto-ordem-trabalhos.json",
    '"id": "condominio-ponto-ordem-trabalhos/v1"',
    "condominium agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-ponto-ordem-trabalhos.json",
    '"id": "assoc-ponto-ordem-trabalhos/v1"',
    "association agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-ponto-ordem-trabalhos.json",
    '"id": "fundacao-ponto-ordem-trabalhos/v1"',
    "foundation agenda-item template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-ponto-ordem-trabalhos.json",
    '"id": "cooperativa-ponto-ordem-trabalhos/v1"',
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
    "reg.specs().len(),\n            101",
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
    '"id": "csc-ata-divisao-quotas/v1"',
    "commercial company quota division template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-divisao-quotas.json",
    '"rule_pack_id": "csc-art63/v2"',
    "commercial company quota division rule-pack marker",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-unificacao-quotas.json",
    '"id": "csc-ata-unificacao-quotas/v1"',
    "commercial company quota unification template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-unificacao-quotas.json",
    '"rule_pack_id": "csc-art63/v2"',
    "commercial company quota unification rule-pack marker",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "catalog_includes_csc_delegation_and_revocation_templates",
    "template catalog CSC delegation/revocation coverage",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-delegacao-poderes.json",
    '"id": "csc-ata-delegacao-poderes/v1"',
    "commercial company delegation powers template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-ata-revogacao-poderes.json",
    '"id": "csc-ata-revogacao-poderes/v1"',
    "commercial company revocation powers template asset",
  );
  assertFileContains(
    "crates/chancela-templates/src/lib.rs",
    "should not introduce unresolved threshold text",
    "template catalog CSC delegation/revocation no-new-threshold coverage",
  );
  assertFileContains(
    "crates/chancela-templates/assets/csc-procuracao-representacao.json",
    '"id": "csc-procuracao-representacao/v1"',
    "commercial company representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-procuracao-representacao.json",
    '"id": "condominio-procuracao-representacao/v1"',
    "condominium representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-procuracao-representacao.json",
    '"id": "assoc-procuracao-representacao/v1"',
    "association representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-procuracao-representacao.json",
    '"id": "fundacao-procuracao-representacao/v1"',
    "foundation representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-procuracao-representacao.json",
    '"id": "cooperativa-procuracao-representacao/v1"',
    "cooperative representation/proxy template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/condominio-termo-transporte.json",
    '"id": "condominio-termo-transporte/v1"',
    "condominium book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/assoc-termo-transporte.json",
    '"id": "assoc-termo-transporte/v1"',
    "association book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/fundacao-termo-transporte.json",
    '"id": "fundacao-termo-transporte/v1"',
    "foundation book transport template asset",
  );
  assertFileContains(
    "crates/chancela-templates/assets/cooperativa-termo-transporte.json",
    '"id": "cooperativa-termo-transporte/v1"',
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
    "tsl_signature_validation_accepts_p256_ecdsa_signed_by_anchored_cert",
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
    "resources_read_draft_signed_comparison_report_accepts_arguments_and_is_deterministic_without_http_or_secret",
    "MCP draft-signed comparison deterministic report coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_draft_signed_comparison_report_rejects_bad_arguments_and_extra_params",
    "MCP draft-signed comparison report invalid args coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"kind": "chancela_mcp_draft_signed_comparison_report"',
    "MCP draft-signed deterministic comparison report payload marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"source": "local_mcp_deterministic_comparator"',
    "MCP draft-signed local deterministic comparator marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"ai_provider_calls": false',
    "MCP draft-signed no AI provider call marker",
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
    "chancela://mcp/chronology-review-summary",
    "MCP chronology review summary resource URI marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "chronology_review_summary_resource_payload",
    "MCP chronology review summary resource payload marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_chronology_review_summary_returns_static_guidance_without_http_or_secret",
    "MCP chronology review summary static guidance coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_chronology_review_summary_accepts_arguments_and_counts_chronology_without_http_or_secret",
    "MCP chronology review summary deterministic counts coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "resources_read_chronology_review_summary_rejects_bad_arguments_and_extra_params",
    "MCP chronology review summary invalid args coverage",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"kind": "chancela_mcp_chronology_review_summary_report"',
    "MCP chronology deterministic summary report payload marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"source": "local_mcp_deterministic_chronology_summarizer"',
    "MCP chronology local deterministic summarizer marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"registry_calls": false',
    "MCP chronology no registry call marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"legal_service_calls": false',
    "MCP chronology no legal-service call marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"ai_completed_claim": false',
    "MCP chronology no AI-completed claim marker",
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
    '"statement_sources": statement_sources',
    "MCP AI draft statement-source envelope marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    "attach_ai_draft_statement_sources",
    "MCP AI draft request provenance injection marker",
  );
  assertFileContains(
    "crates/chancela-mcp/src/server.rs",
    '"authoritative_source_claimed": false',
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
    "const statusCounts = Array.from",
    "web AI review grouped review-status counts marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const missingProvenanceRows = statementSources.filter(aiSourceFieldMissing).length;",
    "web AI review missing provenance summary marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "const pendingOrUnverifiedRows = statementSources.filter",
    "web AI review pending/uncertain provenance summary marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "bounded local provenance panel; deterministic local; offline/static review guidance; no bridge/API/AI-provider/hidden-provider calls; no secrets",
    "web AI review offline/static no-provider-call boundary marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "signature_qualification: false",
    "web AI review false boundary flags marker",
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
    "renders deterministic local review status and no-claim boundaries",
    "web AI review local review summary/no-claim boundary coverage",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "no bridge/API/AI-provider/hidden-provider calls; no secrets",
    "web AI review no bridge/API/provider/no-secret coverage marker",
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
    "crates/chancela-api/src/settings.rs",
    "pub privacy_control_reviews: bool",
    "API workflow reminder privacy-control-review source toggle marker",
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
    "contracts/settings.json",
    '"privacy_control_reviews": true',
    "settings contract workflow reminder privacy-control-review source default marker",
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
    "apps/web/src/features/settings/SettingsPage.tsx",
    "setWorkflowReminderSource('privacy_control_reviews', checked)",
    "Settings workflow reminder privacy-control-review toggle marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/PrivacyComplianceSection.tsx",
    "AdvisoryReviewBadge",
    "Settings privacy advisory review badge marker",
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
    "fn dashboard_reminder_due_date_sort_key(reminder: &DashboardReminder) -> (bool, Option<Date>)",
    "dashboard reminder no-date sort-key helper marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "(due_date.is_none(), due_date)",
    "dashboard reminder no-date after dated sort marker",
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
    "unsupported_profile_calendar_advisory",
    "dashboard profile-calendar unsupported-preset advisory builder marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "profile_calendar_preset_params(",
    "dashboard profile-calendar preset coverage metadata helper marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    '"calendar_preset_support"',
    "dashboard profile-calendar support status param marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "does not calculate a legal deadline for this preset",
    "dashboard profile-calendar unsupported-preset no-deadline copy marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "profile_calendar_supported_preset_exposes_local_coverage_basis",
    "dashboard profile-calendar supported-preset coverage basis test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "unsupported_profile_calendar_without_due_offset_surfaces_no_due_date_advisory",
    "dashboard profile-calendar unsupported-preset no-date coverage marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "renders unsupported profile-calendar presets as pending no-due-date advisories",
    "web dashboard profile-calendar unsupported-preset advisory coverage marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"source_rule": "condominio-annual"',
    "dashboard contract profile-calendar unsupported-preset advisory fixture marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"calendar_preset_support": "supported"',
    "dashboard contract profile-calendar supported coverage metadata fixture marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"unsupported_reason": "missing_local_due_date_rule"',
    "dashboard contract profile-calendar unsupported no-rule metadata fixture marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "absent_owner_dispatch_evidence_reminders(",
    "dashboard absent-owner dispatch-evidence reminder source marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "document.template_id != crate::documents::CONDOMINIUM_ABSENT_OWNER_COMMUNICATION_TEMPLATE_ID",
    "dashboard absent-owner generated-template filter marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "act.state != ActState::Sealed || act.ata_number.is_none()",
    "dashboard absent-owner sealed Ata filter marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    '"required_pending" | "operator_evidence_partial"',
    "dashboard absent-owner pending/partial status filter marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "absent_owner_dispatch_evidence_dashboard_reminder",
    "dashboard absent-owner reminder builder marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "due_date: String::new()",
    "dashboard absent-owner no due-date marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    'severity: "Advisory".to_owned()',
    "dashboard absent-owner advisory severity marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    'status: "Pending".to_owned()',
    "dashboard absent-owner pending status marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    'source_rule: "absent-owner-dispatch-evidence".to_owned()',
    "dashboard absent-owner source-rule marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    'source_profile: "condominium-generated-communication".to_owned()',
    "dashboard absent-owner source-profile marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    '"open_absent_owner_dispatch_evidence"',
    "dashboard absent-owner action kind marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    '"/v1/documents/generated/{}/dispatch-evidence"',
    "dashboard absent-owner dispatch-evidence API href marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    'Some(format!("/atas/{}", act.id))',
    "dashboard absent-owner act route marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "This dashboard reminder is advisory only and does not claim \\",
    "dashboard absent-owner advisory no-claim reason prelude marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "sending, delivery, legal notice completion, or legal sufficiency.",
    "dashboard absent-owner advisory no-claim reason detail marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_generated_absent_owner_dispatch_evidence_required_pending_routes_to_act_document_workflow",
    "dashboard absent-owner required-pending coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_generated_absent_owner_dispatch_evidence_partial_routes_to_act_document_workflow",
    "dashboard absent-owner partial coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_generated_absent_owner_dispatch_evidence_covered_is_suppressed",
    "dashboard absent-owner covered suppression coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/dashboard.rs",
    "reminder_generated_absent_owner_no_due_date_does_not_evict_dated_reminders_before_limit",
    "dashboard absent-owner no-date limit ordering coverage marker",
  );
  assertFileContainsNormalized(
    "crates/chancela-api/src/dashboard.rs",
    `assert_eq!(reminders[0].source_rule, "csc-art376-annual");
        assert_eq!(reminders[0].due_date, "2026-03-31");`,
    "dashboard absent-owner no-date reminder does not evict dated reminder marker",
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
    "renders absent-owner dispatch evidence reminders with localized act routing",
    "web dashboard absent-owner dispatch reminder coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "open_absent_owner_dispatch_evidence",
    "web dashboard absent-owner action kind coverage",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "url.searchParams.set('generated_document_id', trimmedDocumentId);",
    "web dashboard absent-owner generated-document id deep-link marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "url.searchParams.set('focus', 'dispatch-evidence');",
    "web dashboard absent-owner dispatch-evidence focus query marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.tsx",
    "url.hash = 'generated-dispatch-evidence';",
    "web dashboard absent-owner dispatch-evidence hash marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "/atas/act-absent-1?generated_document_id=generated-absent-1&focus=dispatch-evidence#generated-dispatch-evidence",
    "web dashboard absent-owner expected deep-link href marker",
  );
  assertFileContains(
    "apps/web/src/features/dashboard/DashboardPage.test.tsx",
    "expect(within(item).getByText('Sem data')).toBeTruthy();",
    "web dashboard absent-owner no-date label coverage",
  );
  assertFileContains(
    "apps/web/src/features/notifications/notifications.ts",
    "url.searchParams.set('generated_document_id', trimmedDocumentId);",
    "web notifications absent-owner generated-document id deep-link marker",
  );
  assertFileContains(
    "apps/web/src/features/notifications/notifications.ts",
    "url.searchParams.set('focus', 'dispatch-evidence');",
    "web notifications absent-owner dispatch-evidence focus query marker",
  );
  assertFileContains(
    "apps/web/src/features/notifications/notifications.ts",
    "url.hash = 'generated-dispatch-evidence';",
    "web notifications absent-owner dispatch-evidence hash marker",
  );
  assertFileContains(
    "apps/web/src/features/notifications/notifications.test.ts",
    "/atas/act-absent-1?generated_document_id=generated-absent-1&focus=dispatch-evidence#generated-dispatch-evidence",
    "web notifications absent-owner expected deep-link href marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "export function actDocumentPanelTargetFromLocation(",
    "Ata editor generated-document deep-link target helper marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "params.get('generated_document_id')?.trim()",
    "Ata editor generated-document id query marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorPage.tsx",
    "hash === '#generated-dispatch-evidence'",
    "Ata editor dispatch-evidence hash target marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "actDocumentPanelTargetFromLocation(",
    "Ata editor generated-document deep-link helper test marker",
  );
  assertFileContains(
    "apps/web/src/features/acts/AtaEditorStructured.test.tsx",
    "?generated_document_id=generated-absent-1&focus=dispatch-evidence",
    "Ata editor generated-document focus query test marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    'id="generated-dispatch-evidence"',
    "ActDocumentPanel dispatch-evidence hash target marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "selects and focuses dispatch evidence from the generated-document navigation target once",
    "ActDocumentPanel one-time dispatch-evidence select/focus coverage",
  );
  assertFileContains(
    "apps/web/src/i18n/i18n.test.ts",
    "keeps absent-owner dispatch reminder copy advisory and status-aware",
    "web i18n absent-owner dispatch reminder advisory coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "Dashboard.reminders should include a pending no-due-date generated absent-owner fixture",
    "web contract dashboard absent-owner no-date fixture coverage",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"source_rule": "absent-owner-dispatch-evidence"',
    "dashboard contract absent-owner source-rule fixture marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"api_href": "/v1/documents/generated/generated-absent-owner-1/dispatch-evidence"',
    "dashboard contract absent-owner dispatch-evidence href fixture marker",
  );
  assertFileContains(
    "contracts/dashboard.json",
    '"route": "/atas/2f1c8e40-0000-4000-8000-000000000020"',
    "dashboard contract absent-owner act route fixture marker",
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
    'aria-label="Histórico técnico de revisão"',
    "imported-document technical review history group marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    'aria-label="Resumo de profundidade da revisão importada"',
    "imported-document review-depth summary group marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Preservação dos bytes originais não indicada nos metadados carregados",
    "imported-document missing preservation status neutral summary marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "OCR, conversão, substituição de PDF/A, PDF assinado, validação de assinatura, selo",
    "imported-document review-depth explicit exclusions marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "· selo: não · PDF/UA: não · aceitação legal: não.",
    "imported-document review-depth no-claim flags marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Histórico de revisão metadata-only para evidência não canónica",
    "imported-document technical review history no-claim copy marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface ImportedDocumentReviewHistoryEntry",
    "web imported-document review history contract type marker",
  );
  assertFileContains(
    "contracts/document.imported.json",
    '"review_history"',
    "imported-document review history contract fixture marker",
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
    "expect(within(receipt).getByText('Revisto em')).toBeTruthy();",
    "imported-document review receipt pending reviewed-at placeholder marker",
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
    "apps/web/src/api/client.ts",
    "listGeneratedDocuments: (actId: string) =>",
    "web generated-document discovery client marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "getGeneratedDocumentDispatchEvidence: (documentId: string) =>",
    "web generated-document dispatch-evidence GET client marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "recordGeneratedDocumentDispatchEvidence: (",
    "web generated-document dispatch-evidence POST client marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "export function useGeneratedDocuments(actId: string, enabled = true)",
    "web generated-document discovery hook marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "export function useGeneratedDocumentDispatchEvidence(documentId: string | null | undefined)",
    "web generated-document dispatch-evidence GET hook marker",
  );
  assertFileContains(
    "apps/web/src/api/hooks.ts",
    "export function useRecordGeneratedDocumentDispatchEvidence()",
    "web generated-document dispatch-evidence mutation hook marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface GeneratedDocumentDispatchEvidenceRequest",
    "web generated-document dispatch-evidence request type marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface GeneratedDocumentDispatchEvidenceList",
    "web generated-document dispatch-evidence list type marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "| 'operator_evidence_covered'",
    "web generated-document operator evidence covered status marker",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "routes generated-document discovery, PDF download, and dispatch evidence bodies",
    "web generated-document client route/body coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "await api.listGeneratedDocuments('act 1');",
    "web generated-document discovery client coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "await api.getGeneratedDocumentDispatchEvidence('generated doc');",
    "web generated-document dispatch-evidence GET coverage",
  );
  assertFileContains(
    "apps/web/src/api/client.test.ts",
    "await api.recordGeneratedDocumentDispatchEvidence('generated doc', {",
    "web generated-document dispatch-evidence POST coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "function GeneratedDispatchEvidenceRows",
    "web generated absent-owner evidence rows marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "function GeneratedDispatchEvidenceForm",
    "web generated absent-owner evidence form marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "documents.generated.noClaim.body",
    "web generated absent-owner no-claim body key marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "const body: GeneratedDocumentDispatchEvidenceRequest = {",
    "web generated absent-owner metadata-only request marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "renders generated communications, evidence rows, and no-claim copy",
    "web generated absent-owner communication list coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "posts metadata-only evidence with selected recipients and a locator",
    "web generated absent-owner evidence recording coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "expect(within(status).getByText('dispatch_completed')).toBeTruthy();",
    "web generated absent-owner dispatch completed label coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "expect(within(status).getByText('false')).toBeTruthy();",
    "web generated absent-owner dispatch completion false coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "expect(screen.queryByText('Aviso legal válido')).toBeNull();",
    "web generated absent-owner no legal notice validity copy coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "sending_performed_by_chancela: false",
    "web generated absent-owner no-sending flag coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "delivery_confirmed: false",
    "web generated absent-owner no-delivery flag coverage",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.test.tsx",
    "legal_notice_completion_claimed: false",
    "web generated absent-owner no-legal-notice flag coverage",
  );
  assertFileContains(
    "apps/web/src/i18n/i18n.test.ts",
    "keeps generated absent-owner communication copy localized outside source and English fallback text",
    "web generated absent-owner i18n leakage coverage",
  );
  assertFileContains(
    "apps/web/src/i18n/i18n.test.ts",
    "'documents.generated.noClaim.body'",
    "web generated absent-owner no-completion i18n key coverage",
  );
  assertFileContains(
    "apps/web/src/i18n/locales/en-US.ts",
    "Chancela did not send, confirm delivery, or complete legal notice",
    "web generated absent-owner no send/delivery/legal notice copy marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    '("/v1/documents/generated/{document_id}", RouteClass::Gated)',
    "API generated-document by-id route classified gated marker",
  );
  assertFileContains(
    "crates/chancela-api/src/authz.rs",
    '"/v1/documents/generated/{document_id}/dispatch-evidence"',
    "API generated-document dispatch-evidence route classified gated marker",
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
    "crates/chancela-api/src/lib.rs",
    'communication["dispatch_evidence_status"]["status"]',
    "API condominium absent-owner pending dispatch status marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '"x-chancela-dispatch-evidence-attached"',
    "API condominium absent-owner false dispatch evidence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '"x-chancela-dispatch-completed"',
    "API condominium absent-owner false dispatch completion marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '"/v1/documents/generated/{document_id}/dispatch-evidence"',
    "API generated-document dispatch-evidence route wiring marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub async fn record_generated_document_dispatch_evidence",
    "API generated-document dispatch-evidence POST handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub async fn get_generated_document_dispatch_evidence",
    "API generated-document dispatch-evidence GET handler marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "GeneratedDocumentDispatchEvidenceRequest",
    "API generated-document dispatch-evidence request DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "GeneratedDocumentDispatchEvidenceListView",
    "API generated-document dispatch-evidence list DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "ABSENT_OWNER_DISPATCH_EVIDENCE_EVENT_KIND",
    "API absent-owner dispatch-evidence event constant marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    '"absent_owner_communication.dispatch_evidence_recorded"',
    "API absent-owner dispatch-evidence event kind marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "selected_absent_recipients",
    "API absent-owner selected-recipient event marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "required_absent_recipients",
    "API absent-owner required-recipient event marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "operator_evidence_partial",
    "API absent-owner partial dispatch-evidence status marker",
  );
  assertFileDoesNotContain(
    "crates/chancela-api/src/documents.rs",
    "operator_evidence_complete",
    "API absent-owner operator evidence completion status removed",
  );
  assertFileDoesNotContain(
    "crates/chancela-api/src/documents.rs",
    "dispatch_completed: complete",
    "API absent-owner dispatch_completed not derived from coverage",
  );
  assertFileDoesNotContain(
    "crates/chancela-api/src/documents.rs",
    "operator_recorded_evidence_complete_only",
    "API absent-owner no operator-evidence completion basis marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "recorded_recipients",
    "API absent-owner recorded-recipient status marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "missing_recipients",
    "API absent-owner missing-recipient status marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    '"x-chancela-dispatch-evidence-status"',
    "API generated-document dispatch-evidence status header marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    '"x-chancela-dispatch-completed"',
    "API generated-document dispatch-completed header marker",
  );
  assertFileContainsNormalized(
    "crates/chancela-api/src/documents.rs",
    `assert_eq!(
            body["dispatch_evidence_status"]["dispatch_completed"],
            false
        );`,
    "API absent-owner dispatch evidence keeps completion false coverage",
  );
  assertFileMatches(
    "crates/chancela-api/src/documents.rs",
    /get\("x-chancela-dispatch-completed"\)[\s\S]{0,500}Some\("false"\)/u,
    "API generated-document dispatch-completed header remains false coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "sending_performed_by_chancela: false",
    "API absent-owner no-sending response flag marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "delivery_confirmed: false",
    "API absent-owner no-delivery response flag marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "legal_sufficiency_claimed: false",
    "API absent-owner no-legal-sufficiency response flag marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "legal_notice_completion_claimed: false",
    "API absent-owner no-legal-notice response flag marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "bytes_in_payload: false",
    "API absent-owner no-evidence-bytes response flag marker",
  );
  assertFileContainsNormalized(
    "crates/chancela-api/src/documents.rs",
    "assert_eq!(generated_bytes.as_ref(), communication.pdf_bytes.as_slice());",
    "API absent-owner generated bytes preservation coverage",
  );
  assertFileContainsNormalized(
    "crates/chancela-api/src/documents.rs",
    "assert_eq!(canonical.pdf_bytes, ata.pdf_bytes);",
    "API absent-owner canonical Ata preservation coverage",
  );
  assertFileContains(
    "crates/chancela-store/src/schema.rs",
    "CREATE TABLE IF NOT EXISTS generated_document_dispatch_evidence",
    "store generated-document dispatch-evidence table marker",
  );
  assertFileContains(
    "crates/chancela-store/src/schema.rs",
    "PRIMARY KEY (document_id, idempotency_key)",
    "store generated-document dispatch-evidence idempotency key marker",
  );
  assertFileContains(
    "crates/chancela-store/src/lib.rs",
    "generated_document_dispatch_evidence_by_key",
    "store generated-document dispatch-evidence idempotent lookup marker",
  );
  assertFileContains(
    "crates/chancela-store/src/lib.rs",
    "upsert_generated_document_dispatch_evidence",
    "store generated-document dispatch-evidence idempotent upsert marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "absent_owner_dispatch_evidence_records_status_idempotently_and_preserves_bytes",
    "API absent-owner dispatch-evidence focused coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "exact retry must not append a duplicate ledger event",
    "API absent-owner dispatch-evidence no duplicate event marker",
  );
  assertFileContains(
    "crates/chancela-store/tests/store.rs",
    "generated_document_dispatch_evidence_round_trips_idempotently_by_idempotency_key",
    "store generated-document dispatch-evidence round-trip coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub(crate) struct GeneratedDispatchEvidencePreservationIndex",
    "API generated dispatch preservation index marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub(crate) struct GeneratedDispatchEvidencePreservationRecord",
    "API generated dispatch preservation record marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "pub(crate) async fn generated_dispatch_evidence_preservation_indexes_for_act",
    "API generated dispatch preservation index loader marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "generated_dispatch_evidence: generated_dispatch_evidence.to_vec()",
    "API document bundle generated dispatch evidence index marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "proof_bytes_included: false",
    "API generated dispatch no proof bytes marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "bytes_included: false",
    "API generated dispatch record no bytes marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "operator_note_included: false",
    "API generated dispatch no operator-note marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    'const GENERATED_DISPATCH_EVIDENCE_ARCHIVE_PATH_PREFIX: &str = "evidence/generated-dispatch/";',
    "API archive generated dispatch sidecar prefix marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    'const GENERATED_DISPATCH_EVIDENCE_ARCHIVE_PATH_PATTERN: &str =\n    "evidence/generated-dispatch/{document_id}.json";',
    "API archive generated dispatch sidecar pattern marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "file.act_id = Some(parse_generated_dispatch_act_id(entry)?);",
    "API archive generated dispatch sidecar act-only marker",
  );
  assertFileContains(
    "crates/chancela-api/src/archive_package.rs",
    "generated_dispatch_evidence_archive_index",
    "API archive generated dispatch evidence index marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only",
    "API archive generated dispatch preservation coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata",
    "API document bundle generated dispatch preservation coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "generated communication metadata sidecar must not promote its id into manifest.document_ids",
    "API archive generated dispatch no manifest promotion coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "generated communication proof/PDF bytes are not added by this metadata-only slice",
    "API archive generated dispatch no generated bytes coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "free-form operator notes are excluded from preservation output",
    "API archive generated dispatch operator-note redaction coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/archive_package.rs",
    "note-derived stable identifiers are excluded from preservation output",
    "API archive generated dispatch idempotency redaction coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "operator notes stay out of preservation evidence",
    "API bundle generated dispatch operator-note redaction coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "note-derived stable identifiers stay out of preservation evidence",
    "API bundle generated dispatch idempotency redaction coverage marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "communication generated automatically; operator-recorded dispatch evidence does not cover every required absent recipient",
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
    "apps/web/src/features/entities/entities.test.tsx",
    "chronology-rail__item",
    "entity chronology visual rail unit coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "Encosto Estratégico->Certidão",
    "entity chronology Mermaid-derived path unit coverage",
  );
  assertFileContains(
    "apps/web/src/features/entities/EntityChronologyPanel.tsx",
    "function GraphPathSummary",
    "entity chronology richer visualization UI marker",
  );
  assertFileContains(
    "crates/chancela-api/src/chronology.rs",
    "pub graph: ChronologyGraphBundle",
    "API entity chronology structured graph response field",
  );
  assertFileContains(
    "crates/chancela-api/src/chronology.rs",
    "pub analytics: ChronologyAnalyticsView",
    "API entity chronology local analytics response field",
  );
  assertFileContains(
    "crates/chancela-api/src/chronology.rs",
    "source_inscription_count",
    "API entity chronology source inscription analytics marker",
  );
  assertFileContains(
    "apps/web/src/features/entities/EntityChronologyPanel.tsx",
    "function ChronologyAnalytics",
    "web entity chronology analytics panel marker",
  );
  assertFileContains(
    "apps/web/src/features/entities/entities.test.tsx",
    "Resumo analítico local",
    "web entity chronology analytics render coverage",
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
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "Current working-tree entity chronology analytics summary keeps Entity/UX/CI **PARTIAL**",
    "spec coverage entity chronology analytics checkpoint marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "event totals, dated/undated counts, event-kind counts, unique source-inscription counts/list, and structured graph node/edge/warning counts",
    "spec coverage entity chronology analytics values marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "no chronology editing, legal ownership/priority conclusion, registry certification, DRE verification, external call, or authority-approved graph",
    "spec coverage entity chronology analytics no-claim marker",
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
    'className="stack--tight entities-filters"',
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
    "crates/chancela-api/src/settings.rs",
    "pub data_management: DataManagementSettings",
    "API settings data-management policy shape marker",
  );
  assertFileContains(
    "crates/chancela-api/src/settings.rs",
    "DEFAULT_RETAINED_EXPORT_CLEANUP_MINIMUM_AGE_DAYS",
    "API retained-export cleanup policy default marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "renders and autosaves retained-export cleanup preview policy defaults",
    "Settings retained-export cleanup policy autosave coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "Política de limpeza de exportações retidas",
    "Settings retained-export cleanup policy UI marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function exportCleanupBody",
    "data management retained-export settings-derived payload builder marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "settings.data?.data_management?.retained_export_cleanup ?? DEFAULT_EXPORT_CLEANUP_POLICY",
    "data management retained-export settings fallback marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "minimum_age_days: 45",
    "data management retained-export settings minimum-age marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "preview_token: 'export-preview-token-1'",
    "data management retained-export preview token marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "keep_latest: 9",
    "data management retained-export settings keep-latest marker",
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
  assertFileMatches(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    /activeCleanup\.target === 'exports'[\s\S]{0,900}cleanup\.mutateAsync\(\{[\s\S]{0,200}\.\.\.exportCleanupExecutionBody,[\s\S]{0,200}preview_token:\s*exportCleanupPreviewToken,[\s\S]{0,200}\}\)/u,
    "data management retained-export execution preview-token payload marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "keeps retained export cleanup confirmation disabled when preview has no server token",
    "data management retained-export no-token disabled coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "export cleanup execution requires a valid preview_token from a dry-run preview",
    "API retained-export execution preview-token required marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "export cleanup preview_token is invalid or expired; run preview again",
    "API retained-export stale preview-token rejection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "export cleanup preview_token does not match the requested cleanup policy; run preview again",
    "API retained-export mismatched preview-token rejection marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "fn execute_export_cleanup_manifest",
    "API retained-export selected preview manifest execution marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "for candidate in &record.manifest.files",
    "API retained-export selected preview manifest file deletion marker",
  );
  assertFileContains(
    "crates/chancela-api/src/data_status.rs",
    "let mut directories = record.manifest.directories",
    "API retained-export selected preview manifest directory deletion marker",
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
    "['kind', 'row_count', 'payload_stats']",
    "web data status contract optional payload stats tolerance marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "assertDataPayloadStats",
    "web data status payload stats contract helper marker",
  );
  assertFileContains(
    "contracts/data.status.json",
    '"sqlite_largest_payload_table"',
    "data status contract largest SQLite payload table fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "kind: 'sqlite_logical_table'",
    "web data status sqlite logical table fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "sqlite_largest_payload_table",
    "web data status sqlite largest table fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "Média: 256 B/linha",
    "web data status sqlite average bytes rendering coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "não provam eliminação, retenção, custódia",
    "web data status sqlite local-estimate no-claim copy coverage",
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
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function sqlitePayloadStats",
    "web data status sqlite payload stats helper marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "data.status.usage.sqliteLogicalHint",
    "web data status sqlite local-estimate caveat marker",
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
    "plus sidecars under a unique temp dir for isolated load/readback evidence",
    "store restore preflight isolated material/readback marker",
  );
  assertFileContains(
    "crates/chancela-store/src/recovery.rs",
    "pub sqlcipher_encryption_verified: Option<bool>",
    "store restore preflight SQLCipher-proof boundary field",
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
    "crates/chancela-store/tests/recovery.rs",
    "isolated.sidecar_materialized_file_count",
    "store restore preflight sidecar readback coverage",
  );
  assertFileContains(
    "crates/chancela-store/tests/recovery.rs",
    "preflight does not rewrite the live DB file",
    "store restore preflight no live DB mutation coverage",
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
    "crates/chancela-api/src/settings.rs",
    "pub backup_recovery: BackupRecoveryPolicySettings",
    "API backup recovery local policy settings marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub freshness: BackupRecoveryFreshnessReview",
    "API backup recovery drill freshness review marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub rpo_rto_certified: bool",
    "API backup recovery freshness no RPO/RTO certification marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "backup_recovery_drill_list_reports_stale_verified_receipt_against_policy",
    "API backup recovery stale freshness coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    'reject_true_flag("restore_executed", req.restore_executed)?;',
    "API backup recovery drill restore-executed overclaim refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    'reject_true_flag("offsite_custody_proven", req.offsite_custody_proven)?;',
    "API backup recovery drill custody overclaim refusal marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "BackupRecoveryDrillManifestEvidence::from",
    "API backup recovery drill bounded manifest evidence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub isolated_restore_verified: bool",
    "API backup recovery drill isolated verification flag marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "pub isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification",
    "API backup recovery drill isolated verification object marker",
  );
  assertFileContains(
    "crates/chancela-api/src/backup_recovery.rs",
    "record as preflight-only isolated snapshot evidence",
    "API backup recovery drill isolated verification next-step marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "backup_recovery_drill_creates_receipt_from_preflight_and_persists_whitelist_only",
    "API backup recovery drill whitelist-only receipt coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    'assert_eq!(receipt["isolated_restore_verified"], true);',
    "API backup recovery drill isolated verified coverage",
  );
  assertFileContains(
    "crates/chancela-api/tests/backup_recovery_drill.rs",
    "run a new recovery drill to record isolated snapshot verification",
    "API backup recovery drill legacy isolated-not-recorded coverage",
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
    '"restore_executed": false',
    "backup recovery drill contract restore-executed false marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    '"isolated_restore_verified": true',
    "backup recovery drill contract isolated verified marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    '"sqlcipher_encryption_verified": null',
    "backup recovery drill contract SQLCipher-at-rest not-proven marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    "isolated sidecar readback covered 2 file(s)",
    "backup recovery drill contract sidecar readback marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill.json",
    '"offsite_custody_proven": false',
    "backup recovery drill contract custody false marker",
  );
  assertFileContains(
    "contracts/backup.recovery-drill-list.json",
    '"rpo_rto_certified": false',
    "backup recovery drill list contract RPO/RTO no-claim marker",
  );
  assertFileContains(
    "contracts/settings.json",
    '"backup_recovery": {',
    "settings contract backup recovery policy marker",
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
    "isolated_restore_verification: BackupRecoveryDrillIsolatedRestoreVerification;",
    "web backup recovery drill isolated verification contract marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "restore_executed: false;",
    "web backup recovery drill false restore flag contract marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface BackupRecoveryFreshnessReview",
    "web backup recovery freshness contract marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "Política local de recuperação de backups",
    "web settings backup recovery policy UI marker",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.tsx",
    "function RecoveryFreshnessReviewReport",
    "web recovery freshness summary UI marker",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "backup.recovery-drill.json → BackupRecoveryDrillReceipt",
    "web backup recovery drill fixture contract coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "backup.recovery-drill-list.json → BackupRecoveryDrillList",
    "web backup recovery drill list contract coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "BackupRecoveryDrillReceipt.isolated_restore_verification",
    "web backup recovery drill isolated verification contract coverage",
  );
  assertFileContains(
    "apps/web/src/contracts/contracts.test.ts",
    "expect(isolated.status).toBe('verified');",
    "web backup recovery drill isolated verified contract assertion",
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
    "Verificação isolada",
    "web backup recovery drill isolated verification rendering coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "Ficheiros sidecar materializados",
    "web backup recovery drill sidecar readback rendering coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "expect(calls.some((c) => c.url === '/v1/ledger/recovery/restore')).toBe(false);",
    "web backup recovery drill no live restore call coverage",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.test.tsx",
    "renders and autosaves local backup recovery freshness policy defaults",
    "web settings backup recovery policy coverage",
  );
  assertFileContains(
    "apps/web/src/features/recovery/GestaoDadosSection.test.tsx",
    "renders local backup recovery policy freshness without claiming restore or RPO/RTO certification",
    "web recovery freshness no-claim coverage",
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
    "pub struct PlatformLogRetentionMetadata",
    "platform log retention metadata DTO marker",
  );
  assertFileContains(
    "crates/chancela-api/src/platform_logs.rs",
    "dropped_before_seq",
    "platform log dropped-before sequence marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '"retention_limit": platform_logs::PLATFORM_LOG_RETENTION_LIMIT',
    "API platform log retention metadata coverage marker",
  );
  assertFileContains(
    "apps/web/src/api/types.ts",
    "export interface PlatformLogRetentionMetadata",
    "web platform log retention metadata type marker",
  );
  assertFileContains(
    "apps/web/src/features/settings/SettingsPage.tsx",
    "settings.platform.logs.retention.droppedBefore",
    "Settings platform log retention metadata UI marker",
  );
  assertFileContains(
    "contracts/platform.logs.json",
    '"retention_limit": 512',
    "platform logs contract retention metadata fixture marker",
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
    'event["payload_digest"]',
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
    '"actual_runtime_status": "unknown"',
    "platform services honest MCP status fixture",
  );
  assertFileContains(
    "contracts/platform.control.json",
    '"kind": "supervisor_required"',
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
    "apps/web/e2e/platform-operations.spec.ts",
    "platform operations renders API/MCP rows and records MCP start as supervisor-required only",
    "platform operations route-stubbed browser proof marker",
  );
  assertFileContains(
    "apps/web/e2e/platform-operations.spec.ts",
    "/v1/platform/services/mcp_stdio/actions/start",
    "platform operations MCP desired-state POST browser marker",
  );
  assertFileContains(
    "apps/web/e2e/platform-operations.spec.ts",
    "service_overrides",
    "platform operations log override autosave browser marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "focused `e2e/platform-operations.spec.ts` browser proof is route-stubbed",
    "CI/E2E hardening plan platform operations browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "e2e/platform-operations.spec.ts",
    "CI checkpoints platform operations browser command marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "focused\n  browser proof in `apps/web/e2e/platform-operations.spec.ts` is route-stubbed",
    "spec coverage platform operations browser proof marker",
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
    "shows a bounded first page for a 1000+ log archive and loads more by cursor",
    "ledger archive bounded first page coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "/v1/ledger/events/page?before_seq=950&limit=100&order=desc",
    "ledger archive cursor load-more marker",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "applies server-backed filters and exposes an icon-only clear button with a tooltip",
    "ledger archive filter and clear-control coverage",
  );
  assertFileContains(
    "apps/web/src/features/ledger/LedgerPage.test.tsx",
    "/v1/ledger/archive/document?format=txt&q=approved+digest&chain=book%3Abook-123456789&scope=act%3A88&limit=100&order=desc",
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
    "ledger_events_page_uses_store_pager_after_reload_and_memory_clear",
    "ledger archive store-pager reload coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "ledger_archive_document_limit_matches_paged_list_for_filtered_exports",
    "ledger archive shared export/list limit coverage",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    '[("0", 1_usize), ("500", 250_usize)]',
    "ledger archive page limit normalization marker",
  );
  assertFileContains(
    "crates/chancela-api/src/ledger_events_page.rs",
    ".ledger_events_page(&store_query(&query))",
    "ledger archive store-backed selector marker",
  );
  assertFileContains(
    "crates/chancela-store/src/lib.rs",
    "pub fn ledger_events_page(",
    "store ledger persisted pager implementation marker",
  );
  assertFileContains(
    "crates/chancela-store/tests/store.rs",
    "ledger_events_page_walks_persisted_events_newest_first_without_duplicates",
    "store ledger persisted newest-first paging coverage",
  );
  assertFileContains(
    "crates/chancela-store/tests/store.rs",
    "ledger_events_page_fills_sparse_chain_and_text_filtered_pages",
    "store ledger persisted filtered sparse page coverage",
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
    'pub const DB_KEY_SOURCE_ENV: &str = "CHANCELA_DB_KEY_SOURCE";',
    "API database encryption key-source env marker",
  );
  assertFileContains(
    "crates/chancela-api/src/database.rs",
    "HardwareDerivedFallbackUnavailable",
    "API database encryption hardware fallback unavailable marker",
  );
  assertFileContains(
    "crates/chancela-api/src/database.rs",
    '"hardware" | "hardware_bound" | "hardware_derived" | "hardware_derived_fallback"',
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
    'details className="templates-controls__advanced templates-advanced-filters filter-advanced"',
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
    "apps/web/e2e/imported-document-review.spec.ts",
    "acknowledged_guardrail_ids: IMPORTED_REVIEW_GUARDRAIL_IDS",
    "imported document review guardrail acknowledgement browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/imported-document-review.spec.ts",
    "await expect(decisions).toHaveCount(2)",
    "imported document review history order browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/imported-document-review.spec.ts",
    "expect(downloadedPaths).not.toContain(IMPORT_BYTES_PATH)",
    "imported document review no imported-bytes PDF export marker",
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
    "entity detail loads route-stubbed chronology rows, visualization paths, and copyable Mermaid source",
    "entity chronology visualization browser coverage",
  );
  assertFileContains(
    "apps/web/e2e/chronology-and-pdf-validator.spec.ts",
    "Cronologia Browser E2E -> Certidão permanente",
    "entity chronology browser visualization path marker",
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
    "apps/web/e2e/absent-owner-dispatch-evidence.spec.ts",
    "dashboard reminder opens generated absent-owner dispatch evidence and records metadata only",
    "absent-owner dispatch-evidence browser workflow coverage",
  );
  assertFileContains(
    "apps/web/e2e/absent-owner-dispatch-evidence.spec.ts",
    "condominio-comunicacao-ausentes/v1",
    "absent-owner dispatch-evidence browser generated template marker",
  );
  assertFileContains(
    "apps/web/e2e/absent-owner-dispatch-evidence.spec.ts",
    "?generated_document_id=${GENERATED_DOCUMENT_ID}&focus=dispatch-evidence#generated-dispatch-evidence",
    "absent-owner dispatch-evidence browser deep-link marker",
  );
  assertFileContains(
    "apps/web/e2e/absent-owner-dispatch-evidence.spec.ts",
    "Registe apenas metadados de evidência. A Chancela não enviou, não confirmou entrega e não completou aviso legal.",
    "absent-owner dispatch-evidence browser metadata-only no-claim copy marker",
  );
  assertFileContains(
    "apps/web/e2e/absent-owner-dispatch-evidence.spec.ts",
    "Envio pela Chancela=false; confirmação de entrega=false; suficiência legal=false; reivindicação de conclusão=false; bytes no payload=false.",
    "absent-owner dispatch-evidence browser false flags marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Route-stubbed browser proof now pins\n  the dashboard reminder -> generated-document dispatch-evidence workflow",
    "spec coverage absent-owner dispatch-evidence browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "Focused Playwright browser proof is guarded by\n  `apps/web/e2e/absent-owner-dispatch-evidence.spec.ts`",
    "CI checkpoints absent-owner dispatch-evidence browser proof marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Focused route-stubbed browser proof is\n  `npm run test:browser --workspace apps/web -- e2e/absent-owner-dispatch-evidence.spec.ts`",
    "CI/E2E hardening plan absent-owner dispatch-evidence browser command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Updated 2026-07-12 from the current CI configuration and head `869e02f`",
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
    "accessibility report JSON version 9, structure-tree diagnostics",
    "CI/E2E hardening plan PDF accessibility v9 structure-tree marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "marked-content coverage counts",
    "CI/E2E hardening plan PDF accessibility marked-content marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "marked-artifact target/operator evidence",
    "CI/E2E hardening plan PDF accessibility marked-artifact evidence marker",
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
    "payload, no-files-removed result copy, disabled execution button until a\n  tokened preview exists, shared-modal confirmation gate, execution payload with\n  that `preview_token`",
    "CI/E2E hardening plan retained-export preview-token manifest marker",
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
    "bounded local provenance panel",
    "CI/E2E hardening plan bounded local AI provenance panel marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no bridge/API/AI-provider/hidden-provider calls",
    "CI/E2E hardening plan AI provenance no provider/API call marker",
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
    "deterministic local comparison report mode",
    "CI/E2E hardening plan MCP draft-signed deterministic report marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "false AI-01/full AI/MCP completion flags",
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
    "Current working-tree generated-document by-id download, dispatch-evidence, and\n  dashboard absent-owner reminder checks",
    "CI/E2E hardening plan generated-document dispatch-evidence checks marker",
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
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "operator-supplied dispatch evidence with exact-retry idempotency",
    "CI/E2E hardening plan absent-owner dispatch-evidence idempotency marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`npm run test --workspace apps/web -- src/api/client.test.ts src/contracts/contracts.test.ts src/features/dashboard/DashboardPage.test.tsx src/features/documents/ActDocumentPanel.test.tsx src/i18n/i18n.test.ts`",
    "CI/E2E hardening plan generated absent-owner focused web command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "the `contracts/dashboard.json` pending no-due-date\n  generated absent-owner fixture",
    "CI/E2E hardening plan generated absent-owner dashboard contract fixture marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "web client/panel/i18n/dashboard/notification deep-link/focus/contract markers",
    "CI/E2E hardening plan generated absent-owner web static-map marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`focus=dispatch-evidence`",
    "CI/E2E hardening plan generated-document dispatch-evidence focus marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`#generated-dispatch-evidence`",
    "CI/E2E hardening plan generated-document dispatch-evidence hash marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`actDocumentPanelTargetFromLocation`",
    "CI/E2E hardening plan Ata editor target helper marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "notification deep-link routing, one-time ActDocumentPanel dispatch-evidence selection/focus",
    "CI/E2E hardening plan notification deep-link ActDocumentPanel focus marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "reminder_generated_absent_owner_no_due_date_does_not_evict_dated_reminders_before_limit",
    "CI/E2E hardening plan dashboard absent-owner no-date ordering coverage marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no dispatch-completed header claim",
    "CI/E2E hardening plan absent-owner no dispatch-completed header claim marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no sealed act, canonical Ata, or generated-byte mutation; no mail, email, SMS, or provider sending",
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
    "no bridge/API/AI-provider/hidden-provider calls, no secrets,\n  no model accuracy or AI quality assessment",
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
    "Current working-tree imported-document review receipt/history checks",
    "CI/E2E hardening plan imported-document review receipt checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`Histórico técnico de revisão` group, pending `Sem recibo de revisão` without",
    "CI/E2E hardening plan imported-document no fake receipt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "metadata-only\n  review history for non-canonical evidence",
    "CI/E2E hardening plan imported-document receipt/history no-claim marker",
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
    "SPEC-COVERAGE.md",
    "Trust/import/static request-boundary hardening",
    "spec coverage trust/import/static hardening marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "trust/import/static hardening markers for unsafe TSL/TSA URL refusal",
    "spec coverage recent-landed trust/import/static marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "API trust/import/static hardening markers",
    "CI checkpoints trust/import/static hardening lane marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree trust/import/static hardening checks",
    "CI/E2E hardening plan trust/import/static checks marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "rejects unsafe schemes plus localhost, loopback, private, link-local, reserved, and unspecified ranges including `0.0.0.0/8`; validates resolved addresses before runtime fetch; pins the resolved address into `reqwest`; and disables redirects plus system proxy use",
    "CI/E2E hardening plan outbound URL policy marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "loopback allowance is debug/test-only, exact-origin scoped, RAII-dropped, and has no env-var production bypass",
    "CI/E2E hardening plan scoped loopback allowance marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "invalid signature/trust-anchor XML fails closed and does not promote or replace the cache; unsafe URL imports fail before fetching or cache replacement",
    "CI/E2E hardening plan invalid TSL import fail-closed marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`/v1/books/import` has route-level and handler-level body limits and rejects oversized bodies before staging",
    "CI/E2E hardening plan books import body limit marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The current per-book import preflight slice exposes raw-byte `POST",
    "CI/E2E hardening plan per-book import preflight marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "no `ledger.imported`, no `imported_books`, no retained",
    "CI/E2E hardening plan per-book import preflight no-mutation marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "API per-book import preflight:",
    "CI checkpoints per-book import preflight lane marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "web preview-confirm flow markers, stale file/policy response guards",
    "CI checkpoints web import preflight stale guard marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Per-book import preflight",
    "spec coverage per-book import preflight checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "explicit confirm import; stale preview responses for an older file or policy are ignored",
    "spec coverage per-book import preflight stale guard marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Per-book import preflight is an operator-safety preview only",
    "spec coverage per-book import preflight no-overclaim marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "security headers including CSP `frame-ancestors 'none'`",
    "CI/E2E hardening plan static/API security headers marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "does not exhaustively prove hostile DNS/rebinding resistance, production qualified trust, legal validity, live provider readiness, DGLAB certification, or full release hardening",
    "CI/E2E hardening plan trust/import/static caveat marker",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "outbound_url_policy_rejects_reserved_ipv4_zero_eight",
    "API trust outbound URL 0.0.0.0/8 test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "local_trust_url_test_allowance_is_scoped_to_registered_origin",
    "API trust scoped loopback allowance test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "settings_put_rejects_private_loopback_metadata_tsl_tsa_urls",
    "API settings unsafe TSL/TSA URL refusal test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "trust_policy_url_backed_tsl_source_rejects_unsafe_url_before_fetch",
    "API signing trust policy unsafe TSL source test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/signature.rs",
    "timestamp_unsafe_tsa_url_fails_before_network_or_pdf_processing",
    "API timestamp unsafe TSA URL pre-network test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "import_from_file_with_invalid_signature_persists_failure_without_replacing_cache",
    "API trust invalid signature cache preservation test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/trust.rs",
    "import_from_unsafe_url_persists_failure_without_fetching_or_cache",
    "API trust unsafe URL import no-fetch cache test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "books_import_rejects_body_above_route_limit_before_staging",
    "API books import route-limit before staging test marker",
  );
  assertFileContains(
    "crates/chancela-api/src/lib.rs",
    "security_headers_apply_to_static_spa_fallback_and_assets",
    "API/static security headers test marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "trust_refresh_rejects_unsafe_tsl_source_without_replacing_cache",
    "API trust refresh unsafe TSL cache preservation test marker",
  );
  assertFileContains(
    "crates/chancela-api/tests/cc_signing.rs",
    "cc_sign_rejects_real_tsl_source_with_invalid_signature",
    "API CC signing invalid TSL source test marker",
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
    "prove isolated open/load/readback",
    "CI/E2E hardening plan isolated restore proof marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "The current backup recovery-drill slice records preflight-only receipts",
    "CI/E2E hardening plan backup recovery drill receipt marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`isolated_restore_verified`, `isolated_restore_verification`",
    "CI/E2E hardening plan backup recovery drill isolated receipt fields marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "live restore, DB swap, sidecar staging, ledger restore append",
    "CI/E2E hardening plan backup recovery drill caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "SQLCipher-at-rest proof",
    "CI/E2E hardening plan backup recovery drill SQLCipher caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current checkpoint metadata/static checks through `869e02f`",
    "CI/E2E hardening plan current checkpoint checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Current working-tree paper-book OCR conversion-dossier and execution-artifact\n  checks",
    "CI/E2E hardening plan paper-book conversion-dossier checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "neutral/not-indicated copy when\n  preservation status is missing",
    "CI/E2E hardening plan imported-document neutral preservation-status marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "signature\n  validation/seal/PDF-UA/certification/legal acceptance",
    "CI/E2E hardening plan imported-document no-claim exclusion marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "fallbacks for no OCR draft/no accepted draft/no dossier",
    "CI/E2E hardening plan paper-book summary fallback marker",
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
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "operator-supplied technical evidence for pending/initiated slots",
    "CI/E2E hardening plan external-signing operator evidence marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`PATCH /v1/external-signing/envelopes/{id}` with a `slots` payload that omits",
    "CI/E2E hardening plan external-signing PATCH no-complete marker",
  );
  assertFileMatches(
    "docs/CI-E2E-HARDENING-PLAN.md",
    /operator-supplied technical slot evidence only[\s\S]*not provider signing[\s\S]*PIN\/OTP\/passphrase collection[\s\S]*provider calls[\s\S]*trust-list checks[\s\S]*QES\/\s*qualified status[\s\S]*legal validity[\s\S]*provider completion[\s\S]*act finalization[\s\S]*envelope legal completion[\s\S]*public token exposure/u,
    "CI/E2E hardening plan external-signing operator evidence no-claim marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "identity-requirement-tagged evidence rows are required before submit when configured",
    "CI/E2E hardening plan external-signing identity-tagged evidence marker",
  );
  assertFileContainsNormalized(
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
    "external-signing-operator-evidence.spec.ts",
    "CI/E2E hardening plan external-signing operator evidence browser spec marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "stored slot evidence metadata after the update, browser no-secret boundary",
    "CI/E2E hardening plan external-signing operator evidence browser boundary marker",
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
    "chancela-signing --test roundtrip --locked asic_",
    "CI/E2E hardening plan ASiC signing command marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`technical_validation` projected from\n  `validate_asic_container` across CAdES, XAdES, mixed ASiC-E signatures",
    "CI/E2E hardening plan ASiC technical_validation marker",
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
    "isolated DB materialization/open/load",
    "CI/E2E hardening plan backup recovery drill isolated DB checks marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "live DB swap, sidecar staging, ledger restore append",
    "CI/E2E hardening plan backup recovery drill focused caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "optional receipt keys",
    "CI/E2E hardening plan backup recovery drill optional keys marker",
  );
  assertFileContainsNormalized(
    "docs/CI-CHECKPOINTS.md",
    "backup recovery-drill `isolated_restore_verified` / `isolated_restore_verification` receipt markers",
    "CI checkpoints backup recovery drill isolated receipt marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "They do not prove live restore execution, live DB\nswap, live sidecar staging, `ledger.restored` append, SQLCipher-at-rest proof",
    "CI checkpoints backup recovery drill no-claim marker",
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
    "Profile-calendar\n  coverage/status metadata now distinguishes supported local-rule presets",
    "CI/E2E hardening plan profile-calendar coverage metadata marker",
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
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "identity-requirement-tagged row markers, release workflow unsigned/local-only static guard, clean-source provenance gate, and production-package manifest-required",
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
    "Current retention evidence checks through `869e02f`",
    "CI/E2E hardening plan retention due-candidates checks marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "explicit and\n  non-destructive: `review_queued`, `blocked`, `bounded_archive_recorded`,\n  `bounded_no_action_recorded`, and `prior_bounded_evidence_available`",
    "CI/E2E hardening plan retention explicit evidence-state marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "erasure records on page load",
    "CI/E2E hardening plan retention due-candidates non-mutating UI marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "dry-run `execution_request` with forced/default `review_only` for review\n  queues or `execute_supported` for bounded evidence recording",
    "CI/E2E hardening plan retention due-candidates review-only request marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Duplicate `review_only` requests for the same candidate/policy, including\n  concurrent duplicates, reuse the existing `awaiting_review` execution record",
    "CI/E2E hardening plan retention duplicate-review marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "Due-candidate\n  reads can also derive prior safe bounded `executed` archive/no-action\n  evidence",
    "CI/E2E hardening plan retention bounded suppression marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "from the active candidate list by derived evidence only: `candidate_count`\n  reports active unsuppressed rows, `suppressed_candidate_count` and\n  `suppressed_by_bounded_evidence_count` report bounded-evidence omissions",
    "CI/E2E hardening plan retention suppression count marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "optional `suppression_summary` explains that execution history remains\n  queryable for review",
    "CI/E2E hardening plan retention suppression summary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`execute_supported` path only for eligible `disposal_action === archive` or\n  `disposal_action === no_action` due-candidates",
    "CI/E2E hardening plan retention eligible archive/no-action execute-supported marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    '`execution_mode: "execute_supported"`; ineligible rows remain review-only',
    "CI/E2E hardening plan retention execute-supported payload boundary marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "scanner/review/bounded archive/no-action evidence UI plus operational closure\n  only: no physical deletion, anonymization, redaction completion",
    "CI/E2E hardening plan retention due-candidates no-disposal caveat marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "`POST /v1/privacy/retention-executions/{id}/review-closure` records separate\n  review closure fields",
    "CI/E2E hardening plan retention review-closure route marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "idempotent same-closure repeats,\n  conflict on different closure evidence",
    "CI/E2E hardening plan retention review-closure idempotency marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "keeps due-candidate counts stable",
    "CI/E2E hardening plan retention review-closure browser count marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "retention\nreview-closure route/client/contract/Settings/browser markers",
    "CI checkpoints retention review-closure static marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "not real C14N,\n  certificate path/revocation/policy validation",
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
    "implementation snapshot `7fcf5ef5f1c2fbd5b9eb26d6aac5c1240144a365`",
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
    "There is still no startup auto-reconciliation, Owner edit,\n  removal, unrestricted grant, or authorization bypass",
    "spec coverage seeded role drift bounded reconciliation caveat marker",
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
    "read-only\n  local retained-tail metadata",
    "spec coverage platform log retention visibility marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "retention/deletion execution\n  semantics beyond the visible 512-entry local tail bound",
    "spec coverage platform log no retention execution semantics marker",
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
    "a generalized observability sink, retention/deletion execution\n  semantics beyond the visible 512-entry local tail bound, or a legal/compliance\n  claim",
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
    "`deleted_files`, `deleted_directories`, and `deleted_bytes` at zero, returning\n  a server-bound `preview_token`",
    "spec coverage retained-export zero-deleted counters marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Settings now persists\n  retained-export cleanup preview defaults under\n  `data_management.retained_export_cleanup`",
    "spec coverage retained-export settings policy marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "preview\n  payload using those configured `minimum_age_days` and `keep_latest` defaults",
    "spec coverage retained-export settings-derived preview payload marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "posts the `preview_token`,\n  rejects stale or mismatched tokens, executes only the server-selected preview manifest",
    "spec coverage retained-export preview-token manifest execution marker",
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
    "bounded local provenance panel",
    "spec coverage bounded local AI provenance panel marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no bridge/API/AI-provider/hidden-provider\n  calls",
    "spec coverage AI provenance no provider/API call marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "static `draft_signed_comparison_review_checklist` prompt and read-only\n  `chancela://mcp/draft-signed-comparison-review` resource",
    "spec coverage MCP draft-signed comparison prompt/resource marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "deterministic local comparison report\n  over caller-supplied identifiers",
    "spec coverage MCP draft-signed deterministic report marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`ai_01_claimed` and `full_ai_mcp_completion_claimed` false",
    "spec coverage MCP draft-signed no AI completion marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "technical comparison signal only with human review still required",
    "spec coverage MCP draft-signed technical signal only marker",
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
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "`GET /v1/dashboard` add `Pending`/`Advisory` no-due-date reminders",
    "spec coverage dashboard absent-owner reminder marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`POST`/`GET` `/v1/documents/generated/{document_id}/dispatch-evidence`",
    "spec coverage condominium absent-owner dispatch-evidence route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`generated_document_dispatch_evidence`",
    "spec coverage condominium absent-owner dispatch-evidence store marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "absent-recipient evidence coverage and evidence-attached status/header state while keeping `dispatch_completed=false` and `x-chancela-dispatch-completed=false`",
    "spec coverage condominium absent-owner no dispatch completion marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "Follow-on web coverage now surfaces the generated absent-owner communication list, generated PDF fetch, stored evidence rows, metadata-only evidence recording form, `operator_evidence_*` status display, `documents.generated.noClaim.*` copy, and generated-document deep links",
    "spec coverage generated absent-owner web follow-on marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`generated_document_id`",
    "spec coverage generated-document deep-link id marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`focus=dispatch-evidence`",
    "spec coverage generated-document dispatch-evidence focus marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`#generated-dispatch-evidence`",
    "spec coverage generated-document dispatch-evidence hash marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "selects and focuses the dispatch-evidence form once",
    "spec coverage generated-document one-time dispatch-evidence focus marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "/atas/{act_id}?generated_document_id={document_id}&focus=dispatch-evidence#generated-dispatch-evidence",
    "spec coverage dashboard absent-owner deep-link route marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "`operator_evidence_covered` is suppressed",
    "spec coverage dashboard absent-owner covered suppression marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "server sorting keeps valid dated reminders ahead of no-date reminders before `dashboard_limit` truncation",
    "spec coverage dashboard absent-owner no-date sort marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "action kind `open_absent_owner_dispatch_evidence`",
    "spec coverage dashboard absent-owner action kind marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "without changing `dispatch_completed=false` or claiming send/delivery/legal-notice completion",
    "spec coverage generated absent-owner web no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`absent_owner_communication.dispatch_evidence_recorded`",
    "spec coverage condominium absent-owner dispatch event marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "no mail, email, SMS, or provider sending, and no delivery, legal notice completion, legal sufficiency, legal effect, provider execution, registry filing, signing, bundle readiness, template legal review, threshold correctness, law verification claim, or dashboard ledger-event append",
    "spec coverage generated-document no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "validation_report.evidence_index.generated_dispatch_evidence",
    "spec coverage generated dispatch bundle evidence-index marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "evidence/generated-dispatch/{document_id}.json",
    "spec coverage generated dispatch archive sidecar marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "`EvidenceReport` metadata entries with `act_id` only and no `document_id`",
    "spec coverage generated dispatch EvidenceReport act-only marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "manifest.document_ids",
    "spec coverage generated dispatch no manifest promotion marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "It excludes `operator_note`, `idempotency_key`, note-derived stable fingerprints, generated communication bytes, and imported proof bytes",
    "spec coverage generated dispatch redaction marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only",
    "spec coverage generated dispatch archive preservation test marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "document_bundle_indexes_generated_absent_owner_dispatch_evidence_without_replacing_ata",
    "spec coverage generated dispatch bundle preservation test marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "generated dispatch-evidence bundle/archive indexes are metadata-only preservation pointers, not canonical document promotion",
    "spec coverage generated dispatch metadata-only matrix marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "document-bundle/archive generated dispatch-evidence metadata preservation",
    "CI/E2E plan generated dispatch preservation header marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "validation_report.evidence_index.generated_dispatch_evidence",
    "CI/E2E plan generated dispatch bundle evidence-index marker",
  );
  assertFileContains(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "evidence/generated-dispatch/{document_id}.json",
    "CI/E2E plan generated dispatch archive sidecar marker",
  );
  assertFileContainsNormalized(
    "docs/CI-E2E-HARDENING-PLAN.md",
    "not promoted into top-level/canonical `manifest.document_ids`",
    "CI/E2E plan generated dispatch no manifest promotion marker",
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
    "includes a `Recibo de revisão` panel plus bounded technical review history\n  projected from the imported-document view",
    "spec coverage imported-document review receipt checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "sends all four `acknowledged_guardrail_ids`",
    "spec coverage imported-document guardrail acknowledgement browser marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "renders two\n  ordered `review_history` entries with metadata-only/no-claim copy",
    "spec coverage imported-document ordered history browser marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Pending documents show `Sem recibo\n  de revisão` and no fake reviewer/time/note/guardrail receipt",
    "spec coverage imported-document no fake receipt marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "missing preservation status renders neutral/not-indicated copy rather than a bytes-preserved claim",
    "spec coverage imported-document neutral missing preservation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "technical review history only for non-canonical evidence; no OCR, conversion,\n  PDF/A replacement",
    "spec coverage imported-document review receipt no-claim marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "browser route contract markers for all four `acknowledged_guardrail_ids`",
    "CI checkpoints imported-document guardrail browser marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "ordered review-history rendering",
    "CI checkpoints imported-document ordered history marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "legacy DOC/OLE imports now also expose a bounded\n  local `canonical_conversion_preflight` evidence report",
    "spec coverage imported-document legacy DOC preflight marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "legacy_imported_document_canonical_conversion_preflight",
    "API imported-document legacy DOC preflight report marker",
  );
  assertFileContains(
    "crates/chancela-api/src/documents.rs",
    "document_import_validation_reports_legacy_doc_canonical_conversion_preflight_evidence",
    "API imported-document legacy DOC preflight coverage marker",
  );
  assertFileContains(
    "contracts/document.imported.json",
    "\"canonical_conversion_preflight\"",
    "contract imported-document preflight fixture marker",
  );
  assertFileContains(
    "apps/web/src/features/documents/ActDocumentPanel.tsx",
    "Pré-flight local de conversão canónica",
    "web imported-document legacy DOC preflight panel marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "create\n  canonical records, create signed PDFs, create seals, validate signatures, add PDF/UA",
    "spec coverage imported-document review-depth no-runtime-behavior marker",
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
    "broad ECDSA/XML-DSig profile validation",
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
    "`technical_validation` response is projected from\n  `chancela-signing::validate_asic_container` / `AsicValidationReport`",
    "spec coverage ASiC inspect technical_validation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "per-signature `AsicSignatureValidation` fields for CAdES, XAdES, and mixed\n  ASiC-E containers plus per-archive-timestamp",
    "spec coverage ASiC inspect signature/archive projection marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "legacy bounded `cades` object remains for compatibility",
    "spec coverage ASiC inspect legacy cades marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "enforces both per-member and aggregate actual decompressed-size caps across",
    "spec coverage ASiC actual decompressed-size caps marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "underdeclared ZIP\n  entries cannot bypass inspection blockers",
    "spec coverage ASiC underdeclared ZIP blocker marker",
  );
  assertFileContains(
    "apps/web/src/api/client.ts",
    "post<AsicSignatureInspectionResponse>('/v1/signature/asic/inspect', body)",
    "web ASiC inspector client route marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/AsicSignatureInspectorPanel.tsx",
    "Inspetor técnico ASiC",
    "web ASiC inspector panel title marker",
  );
  assertFileContainsNormalized(
    "apps/web/src/features/ferramentas/AsicSignatureInspectorPanel.tsx",
    "Não assina, não guarda artefactos, não chama prestadores e não consulta TSL/TSA/OCSP/CRL ao vivo.",
    "web ASiC inspector no-call/no-mutation boundary marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/AsicSignatureInspectorPanel.tsx",
    "Limitações explícitas",
    "web ASiC inspector visible limitations marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "uploads an ASiC container as base64 with declared SHA-256 and size",
    "web ASiC inspector request body coverage marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "unreferenced_timestamp_token_member",
    "web ASiC inspector unreferenced timestamp marker",
  );
  assertFileContains(
    "apps/web/src/features/ferramentas/ferramentas.test.tsx",
    "archive timestamp META-INF/ASiCArchiveManifest.tst could not be parsed",
    "web ASiC inspector archive timestamp diagnostic marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "Ferramentas now exposes this as a sibling read-only ASiC inspector on the signature tools surface",
    "spec coverage ASiC inspector UI checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "diagnostic/caveat rendering, and fail-closed endpoint refusals",
    "spec coverage ASiC inspector caveat/fail-closed marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "read-only local `POST /v1/signature/asic/inspect` ASiC profile inspection",
    "spec coverage matrix ASiC inspect route marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "ASiC inspection beyond the read-only local technical endpoint and local `technical_validation` projection",
    "spec coverage matrix ASiC remaining-gap marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`POST /v1/signature/asic/inspect` is a read-only local technical inspection endpoint",
    "spec coverage ASiC overclaim endpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "projects `technical_validation` from\n  `chancela-signing::validate_asic_container` across CAdES, XAdES, mixed ASiC-E signatures",
    "spec coverage ASiC overclaim technical_validation marker",
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
    "record bounded archive evidence for\n  `disposal_action: archive` or bounded no-action evidence for `disposal_action: no_action`",
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
    "Due-candidate reads also derive prior safe bounded `executed`\n  archive/no-action evidence",
    "spec coverage retention bounded suppression marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "evidence states are explicit:\n  `review_queued`, `blocked`, `bounded_archive_recorded`, `bounded_no_action_recorded`, and\n  `prior_bounded_evidence_available`",
    "spec coverage retention evidence-state text marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Safe prior bounded archive/no-action executions can suppress active\n  due-candidate rows only as read-only internal evidence projections",
    "spec coverage retention bounded suppression no-overclaim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "legal disposal\n  completion, or GDPR erasure",
    "spec coverage retention due-candidates no-resolution caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Book\n  legal-hold views and archive disposal status now expose derived local\n  `operator_workflow` summaries",
    "spec coverage legal-hold disposal workflow status marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "without posting lifecycle mutations",
    "spec coverage legal-hold disposal status no-mutation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "**Retention execution review closure:** `POST\n  /v1/privacy/retention-executions/{id}/review-closure`",
    "spec coverage retention review-closure section marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "same closure is idempotent and keeps the\n  original close actor/time plus the single closure ledger event",
    "spec coverage retention review-closure idempotency marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "does not change the execution status/outcome, perform or approve\n  disposal",
    "spec coverage retention review-closure no-overclaim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "non-destructive restore preflight evidence",
    "spec coverage restore preflight evidence boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`isolated_restore_verified`,\n  `isolated_restore_verification`",
    "spec coverage backup recovery drill isolated receipt fields marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "recovery-drill receipt route records preflight-only bounded evidence",
    "spec coverage recovery drill receipt bounded evidence marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "isolated restore material/readback and cleanup proof",
    "spec coverage recovery drill isolated material/readback proof marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Recovery/backup matrix note",
    "spec coverage recovery backup matrix note marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "swap the live DB, stage/replace live sidecars",
    "spec coverage recovery drill no destructive restore caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "SQLCipher-at-rest proof",
    "spec coverage recovery drill SQLCipher caveat marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "or make coverage FULL",
    "spec coverage recovery drill no FULL coverage marker",
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
    "BookDetail OCR/dossier review-depth summary is derived from loaded metadata\n  only and has explicit fallbacks for no OCR draft, no accepted draft, and no\n  dossier",
    "spec coverage paper-book OCR/dossier metadata-derived summary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "no automatic dossier POST",
    "spec coverage paper-book conversion-dossier no automatic POST marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "reviewed `conversion_execution_artifact` row/view",
    "spec coverage paper-book conversion execution artifact row marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "promotion response exposes optional `conversion_execution_artifact`, and dossier responses can include `conversion_execution_artifacts`",
    "spec coverage paper-book conversion execution artifact response marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "`reviewed_conversion_execution_artifact: true`, no raw OCR text in artifact or ledger payloads",
    "spec coverage paper-book conversion execution artifact redaction marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "bounded reviewed execution evidence for a mutable drafting aid only",
    "spec coverage paper-book conversion execution artifact no-overclaim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "do not create\n  canonical acts, create canonical documents or archive packages, create PDF/A\n  or PDF/UA",
    "spec coverage paper-book OCR/dossier no canonical artifacts marker",
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
    "route-stubbed Playwright coverage now pins the official signed-PDF handoff\n  import browser path",
    "spec coverage official signed-PDF browser proof marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "client-declared trace context only",
    "spec coverage official signed-PDF client-declared marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "collecting no PIN, OTP,\n  CAN, credential, token, password, passphrase, or private-key material",
    "spec coverage official signed-PDF no-secret marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "does\n  not perform trust-list validation, claim qualified status, or complete legal\n  signing acceptance",
    "spec coverage official signed-PDF no-claim marker",
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
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "SigningPanel also displays stored slot evidence metadata",
    "spec coverage external-signing stored slot evidence marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "requires every configured identity requirement to have a tagged evidence row before submit",
    "spec coverage external-signing identity-tagged evidence marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "sends no `complete:true`",
    "spec coverage external-signing no-complete payload marker",
  );
  assertFileMatches(
    "SPEC-COVERAGE.md",
    /This is operator-supplied technical workflow evidence only[\s\S]*not provider\s+signing[\s\S]*provider completion[\s\S]*legal envelope completion[\s\S]*QES\/\s*qualified status[\s\S]*act\s+finalization/u,
    "spec coverage external-signing operator evidence no-claim marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "apps/web/e2e/external-signing-operator-evidence.spec.ts",
    "spec coverage external-signing operator evidence browser spec marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "captured `PATCH /v1/external-signing/envelopes/{id}` request body, browser no-secret boundary",
    "spec coverage external-signing operator evidence browser request marker",
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
    "Current working-tree privacy DPIA/breach/transfer advisory review status and\n  reminder depth keeps Legal/Compliance/Data/Workflows/UX/CI **PARTIAL**",
    "spec coverage privacy advisory review checkpoint marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`advisory_review` summary derived only from local `evidence_receipts`",
    "spec coverage privacy advisory review local derivation marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`workflow.reminders.sources.privacy_control_reviews` lets Settings suppress\n  only that reminder family",
    "spec coverage privacy reminder source toggle marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Focused route-stubbed browser proof now pins Settings > Privacidade rendering",
    "spec coverage privacy reminder browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "apps/web/e2e/privacy-control-review-reminders.spec.ts",
    "CI checkpoints privacy reminder browser proof marker",
  );
  assertFileContains(
    "docs/CI-CHECKPOINTS.md",
    "without privacy\n  record mutation",
    "CI checkpoints privacy reminder no-mutation marker",
  );
  assertFileContainsNormalized(
    "SPEC-COVERAGE.md",
    "does not notify authorities or data subjects, approve transfers, execute transfers, certify adequacy/compliance, file DPIAs with an authority",
    "spec coverage privacy advisory no-claim caveat marker",
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
    "toggles for `profile_calendar`, `act_follow_ups`, `attendance_hygiene`, and\n  `privacy_control_reviews`",
    "spec coverage workflow reminder source-toggle boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "absolute calendar-day\n  deltas across year boundaries",
    "spec coverage workflow reminder year-boundary marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "Profile-calendar reminders expose local preset coverage/status params",
    "spec coverage profile-calendar coverage metadata marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "unsupported presets remain pending no-date advisories with no\n  due-year or due-basis",
    "spec coverage profile-calendar unsupported no-date/no-basis marker",
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
    "PDF accessibility report JSON\n  version 9 now includes bounded structure-tree diagnostics",
    "spec coverage PDF accessibility report v9 structure-tree marker",
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
  assertFileContains(
    "SPEC-COVERAGE.md",
    "additive per-table `payload_stats` with\n  `estimated_payload_bytes`, `row_count`, `average_bytes_per_row`",
    "spec coverage data-status payload stats working-tree marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "`local_loaded_payload_estimate`, and `sqlite_largest_payload_table` summary\n  metadata",
    "spec coverage data-status local estimate and largest table marker",
  );
  assertFileContains(
    "SPEC-COVERAGE.md",
    "read-only local payload telemetry only; it does not add cleanup execution,\n  deletion/retention semantics",
    "spec coverage data-status payload stats no-claim marker",
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
  const body = readFileSync(join(repoRoot, relativePath), "utf8").replaceAll(
    "\r\n",
    "\n",
  );
  assert.ok(
    body.includes(needle),
    `${label} missing expected marker ${needle}`,
  );
}

function assertFileContainsNormalized(relativePath, needle, label) {
  assertFileExists(relativePath, label);
  const body = readFileSync(join(repoRoot, relativePath), "utf8");
  assert.ok(
    normalizeWhitespace(body).includes(normalizeWhitespace(needle)),
    `${label} missing expected marker ${needle}`,
  );
}

function assertFileMatches(relativePath, pattern, label) {
  assertFileExists(relativePath, label);
  const body = readFileSync(join(repoRoot, relativePath), "utf8");
  assert.ok(pattern.test(body), `${label} missing expected marker ${pattern}`);
}

function normalizeWhitespace(value) {
  return value.replace(/\s+/gu, " ").trim();
}

function assertFileDoesNotContain(relativePath, needle, label) {
  assertFileExists(relativePath, label);
  const body = readFileSync(join(repoRoot, relativePath), "utf8");
  assert.ok(
    !body.includes(needle),
    `${label} still contains removed marker ${needle}`,
  );
}
