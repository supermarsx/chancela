import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { assertSidecar, readJson, validateCorpus } from "./validate-validator-corpus.mjs";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const corpusRoot = join(repoRoot, "docs", "fixtures", "validator-corpus");
const manifestPath = join(corpusRoot, "manifest.json");
const validatorFamilies = new Set(["eu-dss", "adobe"]);

export function recordValidatorSidecar({
  caseId,
  family,
  report,
  tool,
  version,
  operator,
  environment,
  command,
  runAt = new Date().toISOString(),
  observed,
  force = false,
  root = corpusRoot,
  manifest = readJson(join(root, "manifest.json")),
}) {
  assertRequired(caseId, "--case");
  assertRequired(family, "--family");
  assertRequired(report, "--report");
  assertRequired(tool, "--tool");
  assertRequired(version, "--version");
  assertRequired(operator, "--operator");
  assertRequired(environment, "--environment");
  assertRequired(command, "--command");

  if (!validatorFamilies.has(family)) {
    throw new Error(`unsupported validator family ${family}; expected eu-dss or adobe`);
  }

  const fixtureCase = manifest.cases.find((item) => item.id === caseId);
  if (!fixtureCase) {
    throw new Error(`unknown validator corpus case ${caseId}`);
  }

  const sidecarRelPath = fixtureCase.sidecars?.[family];
  if (!sidecarRelPath) {
    throw new Error(`case ${caseId} does not declare a ${family} sidecar`);
  }

  const sidecarPath = join(root, sidecarRelPath);
  const sidecar = readJson(sidecarPath);
  const previousStatus = sidecar.validator.run_status;
  if (sidecar.validator.run_status === "recorded" && !force) {
    throw new Error(`${caseId}/${family} is already recorded; pass --force to replace the sidecar metadata`);
  }

  const sourceReportPath = resolveInputPath(report);
  if (!existsSync(sourceReportPath)) {
    throw new Error(`raw validator report does not exist: ${report}`);
  }

  const sidecarDir = dirname(sidecarPath);
  const reportsDir = join(dirname(sidecarDir), "reports");
  mkdirSync(reportsDir, { recursive: true });
  const { reportPath, preservationAction } = stageReport(sourceReportPath, reportsDir, family);
  const reportRelPath = relative(sidecarDir, reportPath).replaceAll("\\", "/");

  const documentPath = normalize(join(sidecarDir, sidecar.document.path));
  const documentBytes = readFileSync(documentPath);
  const reportBytes = readFileSync(reportPath);
  const normalizedRunAt = normalizeTimestamp(runAt);

  sidecar.validator = {
    ...sidecar.validator,
    name: tool,
    version,
    run_status: "recorded",
    run_at: normalizedRunAt,
    operator,
    command,
    environment,
    report_path: reportRelPath,
  };
  sidecar.document = {
    ...sidecar.document,
    sha256: sha256(documentBytes),
    bytes: documentBytes.length,
  };
  sidecar.evidence_scope = evidenceScope();
  sidecar.report = {
    path: reportRelPath,
    sha256: sha256(reportBytes),
    bytes: reportBytes.length,
    captured_at: normalizedRunAt,
    content_type: inferContentType(reportPath),
    source_filename: basename(sourceReportPath),
    preserved_at: normalizedRunAt,
    preserved_by: operator,
    preservation_action: preservationAction,
  };
  sidecar.observed = normalizeObserved(observed);
  sidecar.status_transition = {
    from: previousStatus,
    to: "recorded",
    at: normalizedRunAt,
    by: operator,
    reason:
      previousStatus === "recorded"
        ? "operator_replaced_raw_validator_report"
        : "operator_recorded_raw_validator_report",
    command,
  };
  sidecar.notes = [
    `Recorded from raw ${family} validator report at ${reportRelPath}.`,
    "This sidecar preserves technical external-validator evidence only; it is not a legal validity decision.",
  ];

  assertSidecar({ fixtureCase, family, sidecar, sidecarPath, corpusRoot: root });
  writeFileSync(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`);
  validateCorpus({ root, path: join(root, "manifest.json") });
  return { sidecarPath, reportPath, sidecar };
}

export function evidenceScope() {
  return {
    kind: "external_validator_report",
    technical_only: true,
    legal_validity_assessment: "not_assessed",
    claim: "technical_validator_evidence_only",
  };
}

function normalizeObserved(observed) {
  if (observed === undefined) {
    return {
      transcription_status: "raw_report_only",
      legal_validity_assessment: "not_assessed",
      summary: "Raw external validator report preserved; structured validator findings were not transcribed.",
      findings: null,
    };
  }

  return {
    transcription_status: "operator_transcribed",
    legal_validity_assessment: "not_assessed",
    summary: "Structured technical findings were transcribed by the operator from the raw validator report.",
    findings: observed,
  };
}

function stageReport(sourceReportPath, reportsDir, family) {
  const sourceResolved = resolve(sourceReportPath);
  const reportsResolved = resolve(reportsDir);
  if (sourceResolved.startsWith(`${reportsResolved}\\`) || sourceResolved.startsWith(`${reportsResolved}/`)) {
    return { reportPath: sourceResolved, preservationAction: "already_in_corpus" };
  }

  const destination = join(reportsDir, `${family}-${basename(sourceReportPath)}`);
  if (normalize(sourceResolved) !== normalize(destination)) {
    copyFileSync(sourceReportPath, destination);
  }
  return { reportPath: destination, preservationAction: "copied_to_corpus" };
}

function inferContentType(path) {
  switch (extname(path).toLowerCase()) {
    case ".xml":
      return "application/xml";
    case ".json":
      return "application/json";
    case ".html":
    case ".htm":
      return "text/html";
    case ".pdf":
      return "application/pdf";
    case ".txt":
    case ".log":
      return "text/plain";
    default:
      return "application/octet-stream";
  }
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--force") {
      options.force = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected argument ${arg}`);
    }
    const key = arg.slice(2).replaceAll("-", "_");
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${arg} requires a value`);
    }
    options[key] = value;
    index += 1;
  }

  if (options.observed_json) {
    options.observed = readJson(resolveInputPath(options.observed_json));
  }

  return {
    caseId: options.case,
    family: options.family,
    report: options.report,
    tool: options.tool,
    version: options.version,
    operator: options.operator,
    environment: options.environment,
    command: options.command,
    runAt: options.run_at,
    observed: options.observed,
    force: Boolean(options.force),
  };
}

function resolveInputPath(path) {
  return isAbsolute(path) ? path : resolve(process.cwd(), path);
}

function normalizeTimestamp(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`invalid ISO timestamp: ${value}`);
  }
  return parsed.toISOString();
}

function assertRequired(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} is required`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = recordValidatorSidecar(parseArgs(process.argv.slice(2)));
    console.log(`recorded ${relative(repoRoot, result.sidecarPath)} with raw report ${relative(repoRoot, result.reportPath)}`);
  } catch (error) {
    console.error(error.message);
    console.error(
      "usage: node scripts/record-validator-sidecar.mjs --case <id> --family <eu-dss|adobe> --report <file> --tool <name> --version <version> --operator <name> --environment <description> --command <command> [--run-at <iso>] [--observed-json <file>] [--force]",
    );
    process.exit(1);
  }
}
