#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const generatorDir = dirname(fileURLToPath(import.meta.url));

const DEFAULT_OUT_DIR = join(generatorDir, "out", "evidence-pack");
const TEMPLATE_ROOT_FILES = new Set(["README.md", "CHECKLIST.md"]);

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
    caseName: "Chancela AMA/CMD authority review evidence pack",
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    } else if (arg === "--force") {
      parsed.force = true;
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
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function usage() {
  return [
    "Usage:",
    "  node compliance/ama-cmd/generate-evidence-pack.mjs [--out <dir>] [--case-name <name>] [--force]",
    "",
    "Creates an AMA/CMD authority-review evidence pack using only Node built-ins.",
    "By default, output is written to compliance/ama-cmd/out/evidence-pack.",
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

function manifest(metadata, generatedAt, caseName) {
  return {
    schema: "ama-cmd-evidence-pack-manifest-v1",
    case_name: caseName,
    generated_at: generatedAt,
    claim_boundary: {
      status: "draft_evidence_pack_only",
      production_approval: "not_claimed",
      legal_compliance: "not_claimed",
      requires_external_evidence: true,
    },
    official_sources: metadata.sources.map((source) => ({
      id: source.id,
      url: source.url,
      source_type: source.source_type,
    })),
    evidence_slots: EVIDENCE_FOLDERS.map((folder) => ({
      path: folder.path,
      status: "placeholder_until_evidence_attached",
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

async function copyTemplates(outDir, context, force) {
  const templateDir = join(generatorDir, "templates");
  const entries = await readdir(templateDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) {
      continue;
    }

    const sourcePath = join(templateDir, entry.name);
    const template = await readFile(sourcePath, "utf8");
    const rendered = renderTemplate(template, context);
    const targetPath = TEMPLATE_ROOT_FILES.has(entry.name)
      ? join(outDir, entry.name)
      : join(outDir, "templates", entry.name);

    await writeKnownFile(targetPath, rendered, force);
  }
}

async function writeEvidencePlaceholders(outDir, force) {
  for (const folder of EVIDENCE_FOLDERS) {
    const body = [
      `# ${folder.title}`,
      "",
      ...folder.body.map((line) => `- ${line}`),
      "",
      "Status: placeholder only until concrete evidence is attached and reviewed.",
      "",
    ].join("\n");

    await writeKnownFile(join(outDir, folder.path, "README.md"), body, force);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }

  const outDir = resolve(process.cwd(), args.out);
  const generatedAt = new Date().toISOString();
  const sourceMetadataPath = join(generatorDir, "source-metadata.json");
  const metadata = JSON.parse(await readFile(sourceMetadataPath, "utf8"));
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
    `${JSON.stringify(manifest(metadata, generatedAt, args.caseName), null, 2)}\n`,
    args.force,
  );
  await writeEvidencePlaceholders(outDir, args.force);

  console.log(`AMA/CMD evidence pack generated at ${outDir}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
