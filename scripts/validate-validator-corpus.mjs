import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const corpusRoot = join(repoRoot, "docs", "fixtures", "validator-corpus");
const manifestPath = join(corpusRoot, "manifest.json");

const allowedRunStatuses = new Set(["pending_operator_run", "recorded"]);
const requiredFamilies = new Set(["eu-dss", "adobe"]);
const allowedRecordedTransitions = new Set([
  "operator_recorded_raw_validator_report",
  "operator_replaced_raw_validator_report",
]);
const allowedPreservationActions = new Set(["copied_to_corpus", "already_in_corpus"]);
const observedTranscriptionStatuses = new Set(["raw_report_only", "operator_transcribed"]);
const euDssExpectedRequiredKeys = [
  "overall_indication",
  "sub_indication",
  "pades_profile",
  "signature_count",
  "signature_timestamp_present",
  "dss_present",
  "doc_time_stamp_present",
  "tamper_detected",
];
const euDssExpectedOptionalKeys = new Set(["vri_present", "ocsp_count_min", "crl_count_min"]);

export function validateCorpus({ root = corpusRoot, path = manifestPath } = {}) {
  const manifest = readJson(path);
  assertExactKeys(
    manifest,
    ["schema", "updated_at", "purpose", "status_policy", "validator_families", "cases"],
    "manifest",
  );
  assert.equal(manifest.schema, "chancela-external-validator-corpus/v1");
  assert.match(manifest.updated_at, /^\d{4}-\d{2}-\d{2}$/);
  assertString(manifest.purpose, "manifest.purpose");
  assertStatusPolicy(manifest.status_policy);
  assert.ok(Array.isArray(manifest.cases), "manifest.cases must be an array");
  assert.ok(manifest.cases.length > 0, "manifest must declare at least one case");
  assert.deepEqual(new Set(manifest.validator_families), requiredFamilies);

  const caseIds = new Set();

  for (const fixtureCase of manifest.cases) {
    assertExactKeys(
      fixtureCase,
      ["id", "title", "profile", "category", "pdf", "expected_validation", "sidecars"],
      "case",
    );
    assertString(fixtureCase.id, "case.id");
    assert.ok(!caseIds.has(fixtureCase.id), `duplicate case id ${fixtureCase.id}`);
    caseIds.add(fixtureCase.id);

    assertString(fixtureCase.title, `${fixtureCase.id}.title`);
    assertString(fixtureCase.profile, `${fixtureCase.id}.profile`);
    assertString(fixtureCase.category, `${fixtureCase.id}.category`);
    assertObject(fixtureCase.pdf, `${fixtureCase.id}.pdf`);
    assertString(fixtureCase.pdf.path, `${fixtureCase.id}.pdf.path`);
    assert.equal(fixtureCase.pdf.generation_status, "generated", `${fixtureCase.id}.pdf.generation_status must be generated`);

    const pdfPath = join(root, fixtureCase.pdf.path);
    assert.ok(existsSync(pdfPath), `${fixtureCase.id} generated PDF is missing at ${fixtureCase.pdf.path}`);
    assertSha256(fixtureCase.pdf.sha256, `${fixtureCase.id}.pdf.sha256`);
    assertPositiveInteger(fixtureCase.pdf.bytes, `${fixtureCase.id}.pdf.bytes`);
    const pdfBytes = readFileSync(pdfPath);
    assert.equal(pdfBytes.length, fixtureCase.pdf.bytes, `${fixtureCase.id}.pdf.bytes must match committed PDF`);
    assert.equal(
      sha256(pdfBytes),
      fixtureCase.pdf.sha256,
      `${fixtureCase.id}.pdf.sha256 must match committed PDF`,
    );

    assertExpectedValidation(fixtureCase.id, fixtureCase.expected_validation);
    assertObject(fixtureCase.sidecars, `${fixtureCase.id}.sidecars`);
    assert.deepEqual(new Set(Object.keys(fixtureCase.sidecars)), requiredFamilies);

    for (const family of requiredFamilies) {
      const sidecarRelPath = fixtureCase.sidecars[family];
      assertString(sidecarRelPath, `${fixtureCase.id}.sidecars.${family}`);
      const sidecarPath = join(root, sidecarRelPath);
      assert.ok(existsSync(sidecarPath), `${fixtureCase.id} sidecar missing: ${sidecarRelPath}`);

      const sidecar = readJson(sidecarPath);
      assertSidecar({ fixtureCase, family, sidecar, sidecarPath, corpusRoot: root });
    }
  }

  return manifest;
}

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function assertSidecar({ fixtureCase, family, sidecar, sidecarPath, corpusRoot }) {
  assertExactKeys(
    sidecar,
    [
      "schema",
      "case_id",
      "validator",
      "document",
      "evidence_scope",
      "expected",
      "report",
      "observed",
      "status_transition",
      "notes",
    ],
    `${fixtureCase.id}.${family}`,
  );
  assert.equal(sidecar.schema, "chancela-external-validator-sidecar/v1");
  assert.equal(sidecar.case_id, fixtureCase.id);
  assertObject(sidecar.validator, `${fixtureCase.id}.${family}.validator`);
  assertExactKeys(
    sidecar.validator,
    ["family", "name", "version", "run_status", "run_at", "operator", "command", "environment", "report_path"],
    `${fixtureCase.id}.${family}.validator`,
  );
  assert.equal(sidecar.validator.family, family);
  assertString(sidecar.validator.name, `${fixtureCase.id}.${family}.validator.name`);
  assert.ok(
    allowedRunStatuses.has(sidecar.validator.run_status),
    `${fixtureCase.id}.${family}.validator.run_status must be pending_operator_run or recorded`,
  );
  assertObject(sidecar.document, `${fixtureCase.id}.${family}.document`);
  assertExactKeys(sidecar.document, ["path", "sha256", "bytes"], `${fixtureCase.id}.${family}.document`);
  assertString(sidecar.document.path, `${fixtureCase.id}.${family}.document.path`);
  assertObject(sidecar.expected, `${fixtureCase.id}.${family}.expected`);
  assert.ok(Array.isArray(sidecar.notes), `${fixtureCase.id}.${family}.notes must be an array`);
  assert.ok(sidecar.notes.length > 0, `${fixtureCase.id}.${family}.notes must not be empty`);
  for (const [index, note] of sidecar.notes.entries()) {
    assertString(note, `${fixtureCase.id}.${family}.notes[${index}]`);
    assertNoLegalOverclaimText(note, `${fixtureCase.id}.${family}.notes[${index}]`);
  }
  assertEvidenceScope(sidecar.evidence_scope, `${fixtureCase.id}.${family}.evidence_scope`);
  assertReportShape(sidecar.report, `${fixtureCase.id}.${family}.report`);

  const sidecarDocumentPath = normalize(join(dirname(sidecarPath), sidecar.document.path));
  const manifestDocumentPath = normalize(join(corpusRoot, fixtureCase.pdf.path));
  assert.equal(
    sidecarDocumentPath,
    manifestDocumentPath,
    `${fixtureCase.id}.${family}.document.path must point at manifest pdf.path`,
  );

  if (sidecar.validator.run_status === "recorded") {
    assertString(sidecar.validator.version, `${fixtureCase.id}.${family}.validator.version`);
    assertIsoTimestamp(sidecar.validator.run_at, `${fixtureCase.id}.${family}.validator.run_at`);
    assertString(sidecar.validator.operator, `${fixtureCase.id}.${family}.validator.operator`);
    assertString(sidecar.validator.environment, `${fixtureCase.id}.${family}.validator.environment`);
    assertString(sidecar.validator.command, `${fixtureCase.id}.${family}.validator.command`);
    assertString(sidecar.validator.report_path, `${fixtureCase.id}.${family}.validator.report_path`);
    assertObserved(sidecar.observed, `${fixtureCase.id}.${family}.observed`);
    assertRecordedTransition({
      transition: sidecar.status_transition,
      validator: sidecar.validator,
      label: `${fixtureCase.id}.${family}.status_transition`,
    });
    assertSha256(sidecar.document.sha256, `${fixtureCase.id}.${family}.document.sha256`);
    assertPositiveInteger(sidecar.document.bytes, `${fixtureCase.id}.${family}.document.bytes`);
    const documentBytes = readFileSync(sidecarDocumentPath);
    assert.equal(sidecar.document.bytes, documentBytes.length, `${fixtureCase.id}.${family}.document.bytes must match sidecar document.path`);
    assert.equal(sidecar.document.sha256, sha256(documentBytes), `${fixtureCase.id}.${family}.document.sha256 must match sidecar document.path`);
    assertReport({ fixtureCase, family, sidecar, sidecarPath });
  } else {
    assert.equal(sidecar.validator.version, null, `${fixtureCase.id}.${family}.validator.version must remain null`);
    assert.equal(sidecar.validator.run_at, null, `${fixtureCase.id}.${family}.validator.run_at must remain null`);
    assert.equal(sidecar.validator.operator, null, `${fixtureCase.id}.${family}.validator.operator must remain null`);
    assert.equal(sidecar.validator.command, null, `${fixtureCase.id}.${family}.validator.command must remain null`);
    assert.equal(sidecar.validator.environment, null, `${fixtureCase.id}.${family}.validator.environment must remain null`);
    assert.equal(sidecar.validator.report_path, null, `${fixtureCase.id}.${family}.validator.report_path must remain null`);
    assert.equal(sidecar.document.sha256, null, `${fixtureCase.id}.${family}.document.sha256 must remain null`);
    assert.equal(sidecar.document.bytes, null, `${fixtureCase.id}.${family}.document.bytes must remain null`);
    assert.equal(sidecar.observed, null, `${fixtureCase.id}.${family}.observed must remain null`);
    assertPendingReport(sidecar.report, `${fixtureCase.id}.${family}.report`);
    assertPendingTransition(sidecar.status_transition, `${fixtureCase.id}.${family}.status_transition`);
  }

  assertExpectedSidecar(fixtureCase.id, family, sidecar.expected);
}

function assertReport({ fixtureCase, family, sidecar, sidecarPath }) {
  assertString(sidecar.report.path, `${fixtureCase.id}.${family}.report.path`);
  assert.equal(sidecar.report.path, sidecar.validator.report_path, `${fixtureCase.id}.${family}.report.path must match validator.report_path`);
  assertSha256(sidecar.report.sha256, `${fixtureCase.id}.${family}.report.sha256`);
  assertPositiveInteger(sidecar.report.bytes, `${fixtureCase.id}.${family}.report.bytes`);
  assertIsoTimestamp(sidecar.report.captured_at, `${fixtureCase.id}.${family}.report.captured_at`);
  assert.equal(
    sidecar.report.captured_at,
    sidecar.validator.run_at,
    `${fixtureCase.id}.${family}.report.captured_at must match validator.run_at`,
  );
  assertMediaType(sidecar.report.content_type, `${fixtureCase.id}.${family}.report.content_type`);
  assertString(sidecar.report.source_filename, `${fixtureCase.id}.${family}.report.source_filename`);
  assert.ok(
    sidecar.report.source_filename === basename(sidecar.report.source_filename),
    `${fixtureCase.id}.${family}.report.source_filename must be a filename, not a path`,
  );
  assertIsoTimestamp(sidecar.report.preserved_at, `${fixtureCase.id}.${family}.report.preserved_at`);
  assert.equal(
    sidecar.report.preserved_at,
    sidecar.validator.run_at,
    `${fixtureCase.id}.${family}.report.preserved_at must match validator.run_at`,
  );
  assert.equal(
    sidecar.report.preserved_by,
    sidecar.validator.operator,
    `${fixtureCase.id}.${family}.report.preserved_by must match validator.operator`,
  );
  assert.ok(
    allowedPreservationActions.has(sidecar.report.preservation_action),
    `${fixtureCase.id}.${family}.report.preservation_action must describe corpus preservation`,
  );
  assert.match(
    sidecar.report.path,
    /^\.\.\/reports\/[^/\\]+$/,
    `${fixtureCase.id}.${family}.report.path must preserve raw reports under the case reports directory`,
  );

  const reportPath = normalize(join(dirname(sidecarPath), sidecar.report.path));
  assert.ok(existsSync(reportPath), `${fixtureCase.id}.${family} raw validator report is missing at ${sidecar.report.path}`);
  const reportBytes = readFileSync(reportPath);
  assert.equal(sidecar.report.bytes, reportBytes.length, `${fixtureCase.id}.${family}.report.bytes must match raw report`);
  assert.equal(sidecar.report.sha256, sha256(reportBytes), `${fixtureCase.id}.${family}.report.sha256 must match raw report`);
}

function assertReportShape(report, label) {
  assertObject(report, label);
  assertExactKeys(
    report,
    [
      "path",
      "sha256",
      "bytes",
      "captured_at",
      "content_type",
      "source_filename",
      "preserved_at",
      "preserved_by",
      "preservation_action",
    ],
    label,
  );
}

function assertPendingReport(report, label) {
  assert.equal(report.path, null, `${label}.path must remain null`);
  assert.equal(report.sha256, null, `${label}.sha256 must remain null`);
  assert.equal(report.bytes, null, `${label}.bytes must remain null`);
  assert.equal(report.captured_at, null, `${label}.captured_at must remain null`);
  assert.equal(report.content_type, null, `${label}.content_type must remain null`);
  assert.equal(report.source_filename, null, `${label}.source_filename must remain null`);
  assert.equal(report.preserved_at, null, `${label}.preserved_at must remain null`);
  assert.equal(report.preserved_by, null, `${label}.preserved_by must remain null`);
  assert.equal(report.preservation_action, "not_recorded", `${label}.preservation_action must be not_recorded`);
}

function assertExpectedValidation(caseId, expected) {
  assertObject(expected, `${caseId}.expected_validation`);
  assertExactKeys(
    expected,
    [
      "semantic_outcome",
      "signature_count",
      "requires_signature_timestamp",
      "requires_dss",
      "requires_doc_time_stamp",
      "tamper_expected",
    ],
    `${caseId}.expected_validation`,
  );
  assertString(expected.semantic_outcome, `${caseId}.expected_validation.semantic_outcome`);
  assertPositiveInteger(expected.signature_count, `${caseId}.expected_validation.signature_count`);
  for (const field of [
    "requires_signature_timestamp",
    "requires_dss",
    "requires_doc_time_stamp",
    "tamper_expected",
  ]) {
    assert.equal(typeof expected[field], "boolean", `${caseId}.expected_validation.${field} must be boolean`);
  }
}

function assertExpectedSidecar(caseId, family, expected) {
  assertPositiveInteger(expected.signature_count, `${caseId}.${family}.expected.signature_count`);

  for (const field of ["signature_timestamp_present", "doc_time_stamp_present", "tamper_detected"]) {
    assert.equal(typeof expected[field], "boolean", `${caseId}.${family}.expected.${field} must be boolean`);
  }

  if (family === "eu-dss") {
    assertAllowedKeys(expected, euDssExpectedRequiredKeys, euDssExpectedOptionalKeys, `${caseId}.${family}.expected`);
    assertString(expected.overall_indication, `${caseId}.${family}.expected.overall_indication`);
    assertNullableString(expected.sub_indication, `${caseId}.${family}.expected.sub_indication`);
    assertString(expected.pades_profile, `${caseId}.${family}.expected.pades_profile`);
    assert.equal(typeof expected.dss_present, "boolean", `${caseId}.${family}.expected.dss_present must be boolean`);
    if (expected.vri_present !== undefined) {
      assert.equal(typeof expected.vri_present, "boolean", `${caseId}.${family}.expected.vri_present must be boolean`);
    }
    if (expected.ocsp_count_min !== undefined) {
      assertNonNegativeInteger(expected.ocsp_count_min, `${caseId}.${family}.expected.ocsp_count_min`);
    }
    if (expected.crl_count_min !== undefined) {
      assertNonNegativeInteger(expected.crl_count_min, `${caseId}.${family}.expected.crl_count_min`);
    }
    return;
  }

  assertExactKeys(
    expected,
    [
      "summary",
      "signature_count",
      "signature_timestamp_present",
      "revocation_info_present",
      "document_certified_or_ltv_enabled",
      "doc_time_stamp_present",
      "tamper_detected",
    ],
    `${caseId}.${family}.expected`,
  );
  assertString(expected.summary, `${caseId}.${family}.expected.summary`);
  assert.equal(
    typeof expected.revocation_info_present,
    "boolean",
    `${caseId}.${family}.expected.revocation_info_present must be boolean`,
  );
  assert.equal(
    typeof expected.document_certified_or_ltv_enabled,
    "boolean",
    `${caseId}.${family}.expected.document_certified_or_ltv_enabled must be boolean`,
  );
}

function assertStatusPolicy(statusPolicy) {
  assertObject(statusPolicy, "manifest.status_policy");
  assertExactKeys(statusPolicy, ["pending_operator_run", "recorded"], "manifest.status_policy");
  assertString(statusPolicy.pending_operator_run, "manifest.status_policy.pending_operator_run");
  assertString(statusPolicy.recorded, "manifest.status_policy.recorded");
  assertNoLegalOverclaimText(statusPolicy.pending_operator_run, "manifest.status_policy.pending_operator_run");
  assertNoLegalOverclaimText(statusPolicy.recorded, "manifest.status_policy.recorded");
}

function assertEvidenceScope(scope, label) {
  assertObject(scope, label);
  assertExactKeys(scope, ["kind", "technical_only", "legal_validity_assessment", "claim"], label);
  assert.equal(scope.kind, "external_validator_report", `${label}.kind must describe external validator evidence`);
  assert.equal(scope.technical_only, true, `${label}.technical_only must be true`);
  assert.equal(scope.legal_validity_assessment, "not_assessed", `${label}.legal_validity_assessment must be not_assessed`);
  assert.equal(scope.claim, "technical_validator_evidence_only", `${label}.claim must avoid legal pass/fail claims`);
}

function assertObserved(observed, label) {
  assertObject(observed, label);
  assertExactKeys(observed, ["transcription_status", "legal_validity_assessment", "summary", "findings"], label);
  assert.ok(
    observedTranscriptionStatuses.has(observed.transcription_status),
    `${label}.transcription_status must be raw_report_only or operator_transcribed`,
  );
  assert.equal(observed.legal_validity_assessment, "not_assessed", `${label}.legal_validity_assessment must be not_assessed`);
  assertString(observed.summary, `${label}.summary`);
  assertNoLegalOverclaimText(observed.summary, `${label}.summary`);
  if (observed.transcription_status === "raw_report_only") {
    assert.equal(observed.findings, null, `${label}.findings must remain null for raw_report_only`);
    return;
  }

  assertObject(observed.findings, `${label}.findings`);
}

function assertRecordedTransition({ transition, validator, label }) {
  assertObject(transition, label);
  assertExactKeys(transition, ["from", "to", "at", "by", "reason", "command"], label);
  assert.ok(
    allowedRunStatuses.has(transition.from),
    `${label}.from must be a previous validator run status`,
  );
  assert.equal(transition.to, "recorded", `${label}.to must be recorded`);
  assertIsoTimestamp(transition.at, `${label}.at`);
  assert.equal(transition.at, validator.run_at, `${label}.at must match validator.run_at`);
  assert.equal(transition.by, validator.operator, `${label}.by must match validator.operator`);
  assert.ok(
    allowedRecordedTransitions.has(transition.reason),
    `${label}.reason must describe an operator raw-report recording transition`,
  );
  assert.equal(transition.command, validator.command, `${label}.command must match validator.command`);
}

function assertPendingTransition(transition, label) {
  assertObject(transition, label);
  assertExactKeys(transition, ["from", "to", "at", "by", "reason", "command"], label);
  assert.equal(transition.from, null, `${label}.from must remain null`);
  assert.equal(transition.to, "pending_operator_run", `${label}.to must remain pending_operator_run`);
  assert.equal(transition.at, null, `${label}.at must remain null`);
  assert.equal(transition.by, null, `${label}.by must remain null`);
  assert.equal(transition.reason, "awaiting_operator_run", `${label}.reason must be awaiting_operator_run`);
  assert.equal(transition.command, null, `${label}.command must remain null`);
}

function assertExactKeys(value, expectedKeys, label) {
  assertObject(value, label);
  assert.deepEqual(
    new Set(Object.keys(value)),
    new Set(expectedKeys),
    `${label} must contain exactly: ${expectedKeys.join(", ")}`,
  );
}

function assertAllowedKeys(value, requiredKeys, optionalKeys, label) {
  assertObject(value, label);
  const actualKeys = new Set(Object.keys(value));
  for (const key of requiredKeys) {
    assert.ok(actualKeys.has(key), `${label} missing required key ${key}`);
  }
  const allowedKeys = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of actualKeys) {
    assert.ok(allowedKeys.has(key), `${label} contains unsupported key ${key}`);
  }
}

function assertObject(value, label) {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must not be null`);
  assert.ok(!Array.isArray(value), `${label} must not be an array`);
}

function assertString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.length > 0, `${label} must not be empty`);
}

function assertNullableString(value, label) {
  if (value === null) {
    return;
  }
  assertString(value, label);
}

function assertSha256(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.match(value, /^[0-9a-f]{64}$/, `${label} must be lowercase sha256 hex`);
}

function assertPositiveInteger(value, label) {
  assert.equal(typeof value, "number", `${label} must be a number`);
  assert.ok(Number.isSafeInteger(value) && value > 0, `${label} must be a positive integer`);
}

function assertNonNegativeInteger(value, label) {
  assert.equal(typeof value, "number", `${label} must be a number`);
  assert.ok(Number.isSafeInteger(value) && value >= 0, `${label} must be a non-negative integer`);
}

function assertMediaType(value, label) {
  assertString(value, label);
  assert.match(value, /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i, `${label} must be an IANA-style media type`);
}

function assertIsoTimestamp(value, label) {
  assertString(value, label);
  assert.match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/, `${label} must be an ISO-8601 UTC timestamp`);
  assert.ok(!Number.isNaN(Date.parse(value)), `${label} must parse as a date`);
}

function assertNoLegalOverclaimText(value, label) {
  const forbidden = [
    /\blegally valid\b/i,
    /\blegally invalid\b/i,
    /\blegal validity (?:passed|failed|valid|invalid)\b/i,
    /\blegal(?:ly)? pass(?:ed)?\b/i,
    /\blegal(?:ly)? fail(?:ed)?\b/i,
  ];
  for (const pattern of forbidden) {
    assert.ok(!pattern.test(value), `${label} must not make a legal pass/fail claim`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const manifest = validateCorpus();
  console.log(`validator corpus manifest OK: ${manifest.cases.length} cases`);
}
