#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const generatorDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(generatorDir, "..", "..", "..");

const DEFAULT_OUT_DIR = join(
  repoRoot,
  "docs",
  "compliance",
  "generated",
  "ama-cmd-evidence-pack",
);
const DEFAULT_GENERATED_AT = "not-recorded-deterministic-run";
const TEMPLATE_ROOT_FILES = new Set(["README.md", "CHECKLIST.md"]);
const MANIFEST_SCHEMA = "ama-cmd-evidence-pack-manifest-v1";
const REQUIRED_MANIFEST_CLAIM_BOUNDARY = Object.freeze({
  status: "draft_evidence_pack_only",
  production_approval: "not_claimed",
  legal_compliance: "not_claimed",
  requires_external_evidence: true,
});
const EVIDENCE_SLOT_STATUS = "placeholder_until_evidence_attached";
const IMPLEMENTATION_CLAIM_BOUNDARY =
  "repository_evidence_only_not_authority_approval";
const UNRESOLVED_TEMPLATE_TOKEN = /\{\{[^{}\s]+\}\}/u;

const IMPLEMENTATION_EVIDENCE_MAP = [
  {
    sourceId: "ama-cmd-private-protocol-template",
    evidenceTopic: "Protocol/application and authority correspondence",
    authorityExpectation:
      "Attach the completed protocol/application, submission receipt, authority correspondence, and redaction decision before making production-enablement claims.",
    implementationFiles: [
      "docs/compliance/ama-cmd/templates/signed-protocol-application-index.md",
      "docs/compliance/ama-cmd/templates/production-applicationid-certificate-evidence.md",
      "docs/compliance/ama-cmd/templates/no-approval-claim.md",
    ],
    verificationCommands: [
      "node docs/compliance/ama-cmd/generate-evidence-pack.mjs --force",
    ],
    externalEvidenceBlocker:
      "Signed protocol/application, AMA acceptance or activation record, and approved redactions are still required.",
  },
  {
    sourceId: "ama-cmd-signature-docs",
    evidenceTopic: "SCMD SIG-02 operation flow",
    authorityExpectation:
      "Show how GetCertificate, CCMovelSign, ProcessId, ValidateOtp, and the returned raw signature are handled without treating the OTP as the signature artifact.",
    implementationFiles: [
      "crates/chancela-cmd/src/lib.rs",
      "crates/chancela-cmd/src/flow.rs",
      "crates/chancela-cmd/src/soap.rs",
      "crates/chancela-cmd/tests/mock_flow.rs",
      "crates/chancela-cmd/TESTING.md",
    ],
    verificationCommands: ["cargo test -p chancela-cmd --locked"],
    externalEvidenceBlocker:
      "Live preprod/prod evidence requires an AMA-issued ApplicationId, a registered test signer, and the human OTP ceremony.",
  },
  {
    sourceId: "ama-cmd-signature-docs",
    evidenceTopic: "Production ApplicationId and field-encryption gate",
    authorityExpectation:
      "Separate pre-production from production values, require the AMA production field-encryption certificate for prod, and keep secrets out of evidence.",
    implementationFiles: [
      "crates/chancela-cmd/src/config.rs",
      "crates/chancela-cmd/src/field_encryption.rs",
      "crates/chancela-cmd/tests/mock_flow.rs",
      "docs/compliance/ama-cmd/templates/production-applicationid-certificate-evidence.md",
    ],
    verificationCommands: ["cargo test -p chancela-cmd --locked"],
    externalEvidenceBlocker:
      "Production remains blocked until AMA assigns production credentials and the production certificate/public-key evidence is attached.",
  },
  {
    sourceId: "ama-autenticacao-docs",
    evidenceTopic: "Product claim boundary and provider responsibilities",
    authorityExpectation:
      "Show that Chancela is an orchestration, validation, and evidence-capture layer, not a QTSP, certification authority, or AMA approval substitute.",
    implementationFiles: [
      "docs/CMD-LEGAL-INTEGRATION.md",
      "docs/ARCHITECTURE.md",
      "docs/compliance/ama-cmd/templates/authority-review-summary.md",
      "docs/compliance/ama-cmd/templates/CHECKLIST.md",
    ],
    verificationCommands: [
      "node docs/compliance/ama-cmd/generate-evidence-pack.mjs --force",
    ],
    externalEvidenceBlocker:
      "Legal/security reviewer sign-off and authority feedback must be attached before stronger wording is used.",
  },
  {
    sourceId: "ama-cmd-signature-docs",
    evidenceTopic: "Two-phase app path and non-secret pending session",
    authorityExpectation:
      "Demonstrate an initiate/confirm flow that persists only non-secret session state and validates the resulting signed PDF in offline tests.",
    implementationFiles: [
      "crates/chancela-signing/src/cmd_session.rs",
      "crates/chancela-signing/src/remote.rs",
      "crates/chancela-signing/tests/cmd_two_phase.rs",
      "crates/chancela-api/tests/remote_signing.rs",
    ],
    verificationCommands: [
      "cargo test -p chancela-signing --test cmd_two_phase --locked",
      "cargo test -p chancela-api --test remote_signing cmd_over_generic_path_produces_a_validating_signed_pdf --locked",
    ],
    externalEvidenceBlocker:
      "Offline tests do not replace AMA preprod/prod test runs, authority acceptance, or production activation evidence.",
  },
];

const EVIDENCE_FOLDERS = [
  {
    path: "evidence/signed-protocol-application",
    title: "Signed Protocol/Application Documents",
    body: [
      "Place signed protocol/application documents, authority correspondence, and a redacted index here.",
      "Do not treat a blank AMA template, draft form, or unsigned protocol as approval evidence.",
      "Recommended files: signed-protocol.pdf, authority-submission-receipt.pdf, redaction-notes.md.",
    ],
  },
  {
    path: "evidence/production-applicationid-certificate",
    title: "Production ApplicationId and Certificate Evidence",
    body: [
      "Place redacted evidence that AMA/SCMD assigned the production ApplicationId and required production certificate/public-key material here.",
      "Do not commit secrets, private keys, production PINs, OTPs, or unredacted credential screens.",
      "Recommended files: applicationid-assignment-redacted.pdf, production-certificate-fingerprint.txt, config-screenshot-redacted.png.",
    ],
  },
  {
    path: "evidence/test-evidence",
    title: "Pre-Production/Test Evidence",
    body: [
      "Place the pre-production signed-document examples and validation records here.",
      "For each example, keep the original document, signed document, cryptographic digest, signed digest, ProcessID, and validation notes together.",
      "Recommended subfolders: example-01 through example-05, signed-guidelines-report-ltv.pdf, integration-source-checksum.txt.",
    ],
  },
  {
    path: "evidence/app-video",
    title: "Short App Video",
    body: [
      "Place the demonstrative video or a link manifest here.",
      "The video should show the relevant integration flow without exposing secrets, production identifiers, OTPs, private data, or unredacted credentials.",
      "Recommended files: app-video.mp4 or video-link.md, app-video-transcript.md, redaction-review.md.",
    ],
  },
];

function parseArgs(argv) {
  const parsed = {
    out: DEFAULT_OUT_DIR,
    force: false,
    check: false,
    caseName: "Chancela AMA/CMD authority review evidence pack",
    caseNameProvided: false,
    generatedAt: process.env.SOURCE_DATE_EPOCH
      ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
      : DEFAULT_GENERATED_AT,
    generatedAtProvided: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    } else if (arg === "--force") {
      parsed.force = true;
    } else if (arg === "--check") {
      parsed.check = true;
    } else if (arg === "--out") {
      index += 1;
      if (!argv[index]) {
        throw new Error("--out requires a path");
      }
      parsed.out = argv[index];
    } else if (arg === "--case-name") {
      index += 1;
      if (!argv[index]) {
        throw new Error("--case-name requires a value");
      }
      parsed.caseName = argv[index];
      parsed.caseNameProvided = true;
    } else if (arg === "--generated-at") {
      index += 1;
      if (!argv[index]) {
        throw new Error("--generated-at requires a value");
      }
      parsed.generatedAt = argv[index];
      parsed.generatedAtProvided = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function usage() {
  return [
    "Usage:",
    "  node docs/compliance/ama-cmd/generate-evidence-pack.mjs [--out <dir>] [--case-name <name>] [--generated-at <value>] [--force]",
    "  node docs/compliance/ama-cmd/generate-evidence-pack.mjs --check [--out <dir>] [--case-name <name>] [--generated-at <value>]",
    "",
    "Creates an AMA/CMD authority-review evidence pack using only Node built-ins.",
    "With --check, validates an existing generated pack without writing files.",
    "By default, output is written to docs/compliance/generated/ama-cmd-evidence-pack.",
    "The default generated-at marker is deterministic. Pass --generated-at or SOURCE_DATE_EPOCH for a dated authority pack.",
  ].join("\n");
}

function renderTemplate(input, context) {
  return input
    .replaceAll("{{caseName}}", context.caseName)
    .replaceAll("{{generatedAt}}", context.generatedAt)
    .replaceAll("{{sourceTable}}", context.sourceTable)
    .replaceAll("{{sourceBullets}}", context.sourceBullets);
}

function sourceTable(metadata) {
  const rows = metadata.sources.map((source) => {
    return `| ${source.id} | ${source.source_type} | ${source.url} | ${source.expected_use} |`;
  });

  return [
    "| Source ID | Type | URL | Pack Use |",
    "| --- | --- | --- | --- |",
    ...rows,
  ].join("\n");
}

function sourceBullets(metadata) {
  return metadata.sources
    .map((source) => {
      return `- ${source.id}: ${source.url}`;
    })
    .join("\n");
}

function sourceMarkdown(metadata, generatedAt) {
  return [
    "# Official Source Metadata",
    "",
    `Generated at: ${generatedAt}`,
    `Source metadata last verified at: ${metadata.last_verified_at}`,
    "",
    metadata.verification_note,
    "",
    sourceTable(metadata),
    "",
    "## Warnings",
    "",
    ...metadata.sources.map(
      (source) => `- ${source.id}: ${source.pack_warning}`,
    ),
    "",
  ].join("\n");
}

function implementationFileStatus(filePath) {
  return {
    path: filePath,
    status: existsSync(resolve(repoRoot, filePath)) ? "present" : "missing",
  };
}

function packFilePath(outDir, relativePath) {
  return join(outDir, ...relativePath.split("/"));
}

async function readSourceMetadata() {
  return JSON.parse(
    await readFile(join(generatorDir, "source-metadata.json"), "utf8"),
  );
}

function implementationEvidenceMap() {
  return IMPLEMENTATION_EVIDENCE_MAP.map((entry) => ({
    ...entry,
    implementationFiles: entry.implementationFiles.map(implementationFileStatus),
  }));
}

function requireMappedFilesPresent(map) {
  const missing = map
    .flatMap((entry) => entry.implementationFiles)
    .filter((file) => file.status === "missing")
    .map((file) => file.path);
  if (missing.length > 0) {
    throw new Error(
      `Implementation evidence map references missing files: ${missing.join(", ")}`,
    );
  }
}

function tableCell(input) {
  return String(input).replaceAll("|", "\\|").replaceAll("\n", "<br>");
}

function markdownItems(items) {
  return items.map((item) => `- ${item}`).join("<br>");
}

function implementationEvidenceMarkdown(map, generatedAt) {
  const rows = map.map((entry) => {
    const files = markdownItems(
      entry.implementationFiles.map(
        (file) => `\`${file.path}\` (${file.status})`,
      ),
    );
    const commands = markdownItems(
      entry.verificationCommands.map((command) => `\`${command}\``),
    );
    return [
      entry.sourceId,
      entry.evidenceTopic,
      entry.authorityExpectation,
      files,
      commands,
      entry.externalEvidenceBlocker,
    ]
      .map(tableCell)
      .join(" | ");
  });

  return [
    "# AMA/CMD Implementation Evidence Map",
    "",
    `Generated at: ${generatedAt}`,
    "",
    "This map links official AMA/CMD source expectations to local repository files and",
    "test commands that can support authority review. A `present` file status means only",
    "that the file existed when the pack was generated. It is not AMA approval,",
    "production activation, certification, or legal review.",
    "",
    "| Source ID | Evidence topic | Authority-review expectation | Local files | Verification commands | External evidence blocker |",
    "| --- | --- | --- | --- | --- | --- |",
    ...rows.map((row) => `| ${row} |`),
    "",
  ].join("\n");
}

function manifest(metadata, generatedAt, caseName, implementationMap) {
  return {
    schema: MANIFEST_SCHEMA,
    case_name: caseName,
    generated_at: generatedAt,
    claim_boundary: { ...REQUIRED_MANIFEST_CLAIM_BOUNDARY },
    official_sources: metadata.sources.map((source) => ({
      id: source.id,
      url: source.url,
      source_type: source.source_type,
    })),
    evidence_slots: EVIDENCE_FOLDERS.map((folder) => ({
      path: folder.path,
      status: EVIDENCE_SLOT_STATUS,
    })),
    implementation_evidence_map: implementationMap.map((entry) => ({
      source_id: entry.sourceId,
      evidence_topic: entry.evidenceTopic,
      authority_expectation: entry.authorityExpectation,
      implementation_files: entry.implementationFiles,
      verification_commands: entry.verificationCommands,
      external_evidence_blocker: entry.externalEvidenceBlocker,
      claim_boundary: IMPLEMENTATION_CLAIM_BOUNDARY,
    })),
  };
}

async function writeKnownFile(filePath, content, force) {
  await mkdir(dirname(filePath), { recursive: true });
  if (existsSync(filePath) && !force) {
    throw new Error(
      `Refusing to overwrite existing file without --force: ${filePath}`,
    );
  }
  await writeFile(filePath, content, "utf8");
}

async function renderedTemplateFiles(context) {
  const templateDir = join(generatorDir, "templates");
  const entries = (await readdir(templateDir, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .sort((left, right) => left.name.localeCompare(right.name));
  const files = new Map();

  for (const entry of entries) {
    const sourcePath = join(templateDir, entry.name);
    const template = await readFile(sourcePath, "utf8");
    const rendered = renderTemplate(template, context);
    const targetPath = TEMPLATE_ROOT_FILES.has(entry.name)
      ? entry.name
      : `templates/${entry.name}`;

    files.set(targetPath, rendered);
  }

  return files;
}

async function copyTemplates(outDir, context, force) {
  for (const [relativePath, content] of await renderedTemplateFiles(context)) {
    await writeKnownFile(packFilePath(outDir, relativePath), content, force);
  }
}

function evidencePlaceholderMarkdown(folder) {
  return [
    `# ${folder.title}`,
    "",
    ...folder.body.map((line) => `- ${line}`),
    "",
    "Status: placeholder only until concrete evidence is attached and reviewed.",
    "",
  ].join("\n");
}

async function writeEvidencePlaceholders(outDir, force) {
  for (const folder of EVIDENCE_FOLDERS) {
    await writeKnownFile(
      packFilePath(outDir, `${folder.path}/README.md`),
      evidencePlaceholderMarkdown(folder),
      force,
    );
  }
}

async function expectedGeneratedFiles(
  metadata,
  generatedAt,
  caseName,
  implementationMap,
) {
  const context = {
    caseName,
    generatedAt,
    sourceTable: sourceTable(metadata),
    sourceBullets: sourceBullets(metadata),
  };
  const files = await renderedTemplateFiles(context);

  files.set(
    "sources/official-source-metadata.json",
    `${JSON.stringify({ generated_at: generatedAt, ...metadata }, null, 2)}\n`,
  );
  files.set("sources/SOURCES.md", sourceMarkdown(metadata, generatedAt));
  files.set(
    "manifest.json",
    `${JSON.stringify(manifest(metadata, generatedAt, caseName, implementationMap), null, 2)}\n`,
  );
  files.set(
    "IMPLEMENTATION-EVIDENCE-MAP.md",
    implementationEvidenceMarkdown(implementationMap, generatedAt),
  );

  for (const folder of EVIDENCE_FOLDERS) {
    files.set(
      `${folder.path}/README.md`,
      evidencePlaceholderMarkdown(folder),
    );
  }

  return files;
}

async function readRequiredText(outDir, relativePath, errors) {
  try {
    return await readFile(packFilePath(outDir, relativePath), "utf8");
  } catch (error) {
    errors.push(
      `${relativePath}: missing or unreadable generated file (${error.code ?? error.message})`,
    );
    return null;
  }
}

function parseJsonText(relativePath, text, errors) {
  if (text === null) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch (error) {
    errors.push(`${relativePath}: invalid JSON (${error.message})`);
    return null;
  }
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateManifestClaimBoundaries(manifestData, errors) {
  if (manifestData.schema !== MANIFEST_SCHEMA) {
    errors.push(`manifest.json: schema must be ${MANIFEST_SCHEMA}`);
  }

  const claimBoundary = manifestData.claim_boundary ?? {};
  for (const [key, expected] of Object.entries(
    REQUIRED_MANIFEST_CLAIM_BOUNDARY,
  )) {
    if (claimBoundary[key] !== expected) {
      errors.push(`manifest.json: claim_boundary.${key} must be ${expected}`);
    }
  }

  const evidenceSlots = Array.isArray(manifestData.evidence_slots)
    ? manifestData.evidence_slots
    : [];
  if (!Array.isArray(manifestData.evidence_slots)) {
    errors.push("manifest.json: evidence_slots must be an array");
  }

  for (const folder of EVIDENCE_FOLDERS) {
    const evidenceSlot = evidenceSlots.find((slot) => slot.path === folder.path);
    if (!evidenceSlot) {
      errors.push(`manifest.json: missing evidence slot ${folder.path}`);
    } else if (evidenceSlot.status !== EVIDENCE_SLOT_STATUS) {
      errors.push(
        `manifest.json: evidence slot ${folder.path} must remain ${EVIDENCE_SLOT_STATUS}`,
      );
    }
  }

  const evidenceMap = Array.isArray(manifestData.implementation_evidence_map)
    ? manifestData.implementation_evidence_map
    : [];
  if (!Array.isArray(manifestData.implementation_evidence_map)) {
    errors.push("manifest.json: implementation_evidence_map must be an array");
  }

  for (const entry of evidenceMap) {
    if (entry.claim_boundary !== IMPLEMENTATION_CLAIM_BOUNDARY) {
      errors.push(
        `manifest.json: implementation evidence map entry "${entry.evidence_topic}" must use claim boundary ${IMPLEMENTATION_CLAIM_BOUNDARY}`,
      );
    }
  }
}

function validateOfficialSources(
  metadata,
  manifestData,
  generatedSourceMetadata,
  sourceMarkdownText,
  errors,
) {
  const expectedSources = metadata.sources.map((source) => ({
    id: source.id,
    url: source.url,
    source_type: source.source_type,
  }));

  if (!sameJson(manifestData.official_sources, expectedSources)) {
    errors.push(
      "manifest.json: official_sources must match docs/compliance/ama-cmd/source-metadata.json",
    );
  }

  if (
    generatedSourceMetadata &&
    !sameJson(generatedSourceMetadata, {
      generated_at: manifestData.generated_at,
      ...metadata,
    })
  ) {
    errors.push(
      "sources/official-source-metadata.json: generated metadata must match source-metadata.json and manifest generated_at",
    );
  }

  for (const source of metadata.sources) {
    if (
      sourceMarkdownText !== null &&
      (!sourceMarkdownText.includes(source.id) ||
        !sourceMarkdownText.includes(source.url))
    ) {
      errors.push(
        `sources/SOURCES.md: missing official source ${source.id} (${source.url})`,
      );
    }
  }
}

function validateImplementationReferences(
  metadata,
  manifestData,
  mapMarkdown,
  errors,
) {
  const officialSourceIds = new Set(metadata.sources.map((source) => source.id));
  const entries = manifestData.implementation_evidence_map;

  if (!Array.isArray(entries) || entries.length === 0) {
    errors.push(
      "manifest.json: implementation_evidence_map must include review evidence entries",
    );
    return;
  }

  for (const entry of entries) {
    if (!officialSourceIds.has(entry.source_id)) {
      errors.push(
        `manifest.json: implementation evidence entry "${entry.evidence_topic}" references unknown source ${entry.source_id}`,
      );
    }

    if (!Array.isArray(entry.implementation_files)) {
      errors.push(
        `manifest.json: implementation evidence entry "${entry.evidence_topic}" must list implementation_files`,
      );
      continue;
    }

    for (const file of entry.implementation_files) {
      if (typeof file.path !== "string" || file.path.length === 0) {
        errors.push(
          `manifest.json: implementation evidence entry "${entry.evidence_topic}" has an invalid file path`,
        );
        continue;
      }

      if (file.status !== "present") {
        errors.push(
          `manifest.json: implementation file ${file.path} must be marked present`,
        );
      }

      if (!existsSync(resolve(repoRoot, file.path))) {
        errors.push(
          `manifest.json: implementation file ${file.path} does not exist in the repository`,
        );
      }

      if (
        mapMarkdown !== null &&
        !mapMarkdown.includes(`\`${file.path}\` (${file.status})`)
      ) {
        errors.push(
          `IMPLEMENTATION-EVIDENCE-MAP.md: missing rendered file reference ${file.path} (${file.status})`,
        );
      }
    }
  }
}

async function validateExpectedFiles(outDir, expectedFiles, errors) {
  const actualFiles = new Map();
  let checkedFileCount = 0;

  for (const [relativePath, expected] of expectedFiles) {
    const actual = await readRequiredText(outDir, relativePath, errors);
    actualFiles.set(relativePath, actual);
    if (actual === null) {
      continue;
    }

    checkedFileCount += 1;
    if (actual !== expected) {
      errors.push(
        `${relativePath}: content differs from deterministic generator output`,
      );
    }

    if (UNRESOLVED_TEMPLATE_TOKEN.test(actual)) {
      errors.push(`${relativePath}: contains an unresolved template token`);
    }
  }

  return { actualFiles, checkedFileCount };
}

function throwCheckFailure(errors) {
  if (errors.length === 0) {
    return;
  }

  throw new Error(
    [
      "AMA/CMD evidence pack check failed:",
      ...errors.map((error) => `- ${error}`),
    ].join("\n"),
  );
}

async function checkEvidencePack(args) {
  const outDir = resolve(process.cwd(), args.out);
  const errors = [];
  const metadata = await readSourceMetadata();
  const manifestText = await readRequiredText(outDir, "manifest.json", errors);
  const manifestData = parseJsonText("manifest.json", manifestText, errors);

  if (
    manifestData === null ||
    typeof manifestData !== "object" ||
    Array.isArray(manifestData)
  ) {
    errors.push("manifest.json: must be a JSON object");
  }
  throwCheckFailure(errors);

  const generatedAt = args.generatedAtProvided
    ? args.generatedAt
    : manifestData.generated_at;
  const caseName = args.caseNameProvided
    ? args.caseName
    : manifestData.case_name;

  if (!caseName) {
    errors.push("manifest.json: case_name is required for generated checks");
  }
  if (!generatedAt) {
    errors.push("manifest.json: generated_at is required for generated checks");
  }

  const implementationMap = implementationEvidenceMap();
  try {
    requireMappedFilesPresent(implementationMap);
  } catch (error) {
    errors.push(error.message);
  }

  const expectedFiles = await expectedGeneratedFiles(
    metadata,
    generatedAt,
    caseName,
    implementationMap,
  );
  const { actualFiles, checkedFileCount } = await validateExpectedFiles(
    outDir,
    expectedFiles,
    errors,
  );
  const generatedSourceMetadata = parseJsonText(
    "sources/official-source-metadata.json",
    actualFiles.get("sources/official-source-metadata.json"),
    errors,
  );

  validateManifestClaimBoundaries(manifestData, errors);
  validateOfficialSources(
    metadata,
    manifestData,
    generatedSourceMetadata,
    actualFiles.get("sources/SOURCES.md"),
    errors,
  );
  validateImplementationReferences(
    metadata,
    manifestData,
    actualFiles.get("IMPLEMENTATION-EVIDENCE-MAP.md"),
    errors,
  );
  throwCheckFailure(errors);

  console.log(
    `AMA/CMD evidence pack check passed at ${outDir} (${checkedFileCount} generated files validated)`,
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }

  if (args.check) {
    await checkEvidencePack(args);
    return;
  }

  const outDir = resolve(process.cwd(), args.out);
  const generatedAt = args.generatedAt;
  const metadata = await readSourceMetadata();
  const implementationMap = implementationEvidenceMap();
  requireMappedFilesPresent(implementationMap);
  const context = {
    caseName: args.caseName,
    generatedAt,
    sourceTable: sourceTable(metadata),
    sourceBullets: sourceBullets(metadata),
  };

  await mkdir(outDir, { recursive: true });
  await copyTemplates(outDir, context, args.force);
  await writeKnownFile(
    join(outDir, "sources", "official-source-metadata.json"),
    `${JSON.stringify({ generated_at: generatedAt, ...metadata }, null, 2)}\n`,
    args.force,
  );
  await writeKnownFile(
    join(outDir, "sources", "SOURCES.md"),
    sourceMarkdown(metadata, generatedAt),
    args.force,
  );
  await writeKnownFile(
    join(outDir, "manifest.json"),
    `${JSON.stringify(manifest(metadata, generatedAt, args.caseName, implementationMap), null, 2)}\n`,
    args.force,
  );
  await writeKnownFile(
    join(outDir, "IMPLEMENTATION-EVIDENCE-MAP.md"),
    implementationEvidenceMarkdown(implementationMap, generatedAt),
    args.force,
  );
  await writeEvidencePlaceholders(outDir, args.force);

  console.log(`AMA/CMD evidence pack generated at ${outDir}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
