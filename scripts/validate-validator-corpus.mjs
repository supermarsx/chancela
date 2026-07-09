import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const corpusRoot = join(repoRoot, "docs", "fixtures", "validator-corpus");
const manifestPath = join(corpusRoot, "manifest.json");

const manifest = readJson(manifestPath);
const allowedRunStatuses = new Set(["pending_operator_run", "recorded"]);
const requiredFamilies = new Set(["eu-dss", "adobe"]);

assert.equal(manifest.schema, "chancela-external-validator-corpus/v1");
assert.match(manifest.updated_at, /^\d{4}-\d{2}-\d{2}$/);
assert.ok(Array.isArray(manifest.cases), "manifest.cases must be an array");
assert.ok(manifest.cases.length > 0, "manifest must declare at least one case");
assert.deepEqual(new Set(manifest.validator_families), requiredFamilies);

const caseIds = new Set();

for (const fixtureCase of manifest.cases) {
  assertString(fixtureCase.id, "case.id");
  assert.ok(!caseIds.has(fixtureCase.id), `duplicate case id ${fixtureCase.id}`);
  caseIds.add(fixtureCase.id);

  assertString(fixtureCase.title, `${fixtureCase.id}.title`);
  assertString(fixtureCase.profile, `${fixtureCase.id}.profile`);
  assertString(fixtureCase.category, `${fixtureCase.id}.category`);
  assertObject(fixtureCase.pdf, `${fixtureCase.id}.pdf`);
  assertString(fixtureCase.pdf.path, `${fixtureCase.id}.pdf.path`);
  assert.equal(fixtureCase.pdf.generation_status, "generated", `${fixtureCase.id}.pdf.generation_status must be generated`);

  const pdfPath = join(corpusRoot, fixtureCase.pdf.path);
  assert.ok(existsSync(pdfPath), `${fixtureCase.id} generated PDF is missing at ${fixtureCase.pdf.path}`);
  assertSha256(fixtureCase.pdf.sha256, `${fixtureCase.id}.pdf.sha256`);
  assertPositiveInteger(fixtureCase.pdf.bytes, `${fixtureCase.id}.pdf.bytes`);
  const pdfBytes = readFileSync(pdfPath);
  assert.equal(pdfBytes.length, fixtureCase.pdf.bytes, `${fixtureCase.id}.pdf.bytes must match committed PDF`);
  assert.equal(
    createHash("sha256").update(pdfBytes).digest("hex"),
    fixtureCase.pdf.sha256,
    `${fixtureCase.id}.pdf.sha256 must match committed PDF`,
  );

  assertExpectedValidation(fixtureCase.id, fixtureCase.expected_validation);
  assertObject(fixtureCase.sidecars, `${fixtureCase.id}.sidecars`);
  assert.deepEqual(new Set(Object.keys(fixtureCase.sidecars)), requiredFamilies);

  for (const family of requiredFamilies) {
    const sidecarRelPath = fixtureCase.sidecars[family];
    assertString(sidecarRelPath, `${fixtureCase.id}.sidecars.${family}`);
    const sidecarPath = join(corpusRoot, sidecarRelPath);
    assert.ok(existsSync(sidecarPath), `${fixtureCase.id} sidecar missing: ${sidecarRelPath}`);

    const sidecar = readJson(sidecarPath);
    assertSidecar({ fixtureCase, family, sidecar, sidecarPath });
  }
}

console.log(`validator corpus manifest OK: ${manifest.cases.length} cases`);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function assertSidecar({ fixtureCase, family, sidecar, sidecarPath }) {
  assert.equal(sidecar.schema, "chancela-external-validator-sidecar/v1");
  assert.equal(sidecar.case_id, fixtureCase.id);
  assertObject(sidecar.validator, `${fixtureCase.id}.${family}.validator`);
  assert.equal(sidecar.validator.family, family);
  assertString(sidecar.validator.name, `${fixtureCase.id}.${family}.validator.name`);
  assert.ok(
    allowedRunStatuses.has(sidecar.validator.run_status),
    `${fixtureCase.id}.${family}.validator.run_status must be pending_operator_run or recorded`,
  );
  assertObject(sidecar.document, `${fixtureCase.id}.${family}.document`);
  assertString(sidecar.document.path, `${fixtureCase.id}.${family}.document.path`);
  assertObject(sidecar.expected, `${fixtureCase.id}.${family}.expected`);
  assert.ok(Array.isArray(sidecar.notes), `${fixtureCase.id}.${family}.notes must be an array`);

  const sidecarDocumentPath = normalize(join(dirname(sidecarPath), sidecar.document.path));
  const manifestDocumentPath = normalize(join(corpusRoot, fixtureCase.pdf.path));
  assert.equal(
    sidecarDocumentPath,
    manifestDocumentPath,
    `${fixtureCase.id}.${family}.document.path must point at manifest pdf.path`,
  );

  if (sidecar.validator.run_status === "recorded") {
    assertString(sidecar.validator.version, `${fixtureCase.id}.${family}.validator.version`);
    assert.match(sidecar.validator.run_at, /^\d{4}-\d{2}-\d{2}T/, `${fixtureCase.id}.${family}.validator.run_at`);
    assertString(sidecar.validator.operator, `${fixtureCase.id}.${family}.validator.operator`);
    assertString(sidecar.validator.environment, `${fixtureCase.id}.${family}.validator.environment`);
    assertObject(sidecar.observed, `${fixtureCase.id}.${family}.observed`);
    assertSha256(sidecar.document.sha256, `${fixtureCase.id}.${family}.document.sha256`);
    assertPositiveInteger(sidecar.document.bytes, `${fixtureCase.id}.${family}.document.bytes`);
  } else {
    assert.equal(sidecar.validator.run_at, null, `${fixtureCase.id}.${family}.validator.run_at must remain null`);
    assert.equal(sidecar.validator.operator, null, `${fixtureCase.id}.${family}.validator.operator must remain null`);
    assert.equal(sidecar.observed, null, `${fixtureCase.id}.${family}.observed must remain null`);
  }

  assertExpectedSidecar(fixtureCase.id, family, sidecar.expected);
}

function assertExpectedValidation(caseId, expected) {
  assertObject(expected, `${caseId}.expected_validation`);
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
    assertString(expected.overall_indication, `${caseId}.${family}.expected.overall_indication`);
    assertString(expected.pades_profile, `${caseId}.${family}.expected.pades_profile`);
    assert.equal(typeof expected.dss_present, "boolean", `${caseId}.${family}.expected.dss_present must be boolean`);
    return;
  }

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

function assertObject(value, label) {
  assert.equal(typeof value, "object", `${label} must be an object`);
  assert.notEqual(value, null, `${label} must not be null`);
  assert.ok(!Array.isArray(value), `${label} must not be an array`);
}

function assertString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.length > 0, `${label} must not be empty`);
}

function assertSha256(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.match(value, /^[0-9a-f]{64}$/, `${label} must be lowercase sha256 hex`);
}

function assertPositiveInteger(value, label) {
  assert.equal(typeof value, "number", `${label} must be a number`);
  assert.ok(Number.isSafeInteger(value) && value > 0, `${label} must be a positive integer`);
}
