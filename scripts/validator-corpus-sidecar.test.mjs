import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { assertSidecar } from "./validate-validator-corpus.mjs";
import { recordValidatorSidecar } from "./record-validator-sidecar.mjs";

test("recorded sidecar requires raw report metadata that matches the report file", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/eu-dss-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:12.000Z",
      content_type: "text/plain",
      source_filename: "eu-dss-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: {
      transcription_status: "operator_transcribed",
      legal_validity_assessment: "not_assessed",
      summary: "EU DSS technical indication was transcribed from the raw report.",
      findings: {
        overall_indication: "TOTAL_PASSED",
      },
    },
  });

  assert.doesNotThrow(() =>
    assertSidecar({
      fixtureCase,
      family: "eu-dss",
      sidecar,
      sidecarPath,
      corpusRoot: root,
    }),
  );
});

test("pending sidecar remains pending and contains no report evidence", () => {
  const { root, fixtureCase, sidecarPath } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "pending_operator_run",
    document: {
      sha256: null,
      bytes: null,
    },
    report: {
      path: null,
      sha256: null,
      bytes: null,
      captured_at: null,
      content_type: null,
      source_filename: null,
      preserved_at: null,
      preserved_by: null,
      preservation_action: "not_recorded",
    },
    observed: null,
  });

  assert.doesNotThrow(() =>
    assertSidecar({
      fixtureCase,
      family: "eu-dss",
      sidecar,
      sidecarPath,
      corpusRoot: root,
    }),
  );
});

test("recorded sidecar fails without a committed raw report", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/missing-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:12.000Z",
      content_type: "text/plain",
      source_filename: "missing-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: {
      transcription_status: "operator_transcribed",
      legal_validity_assessment: "not_assessed",
      summary: "EU DSS technical indication was transcribed from the raw report.",
      findings: {
        overall_indication: "TOTAL_PASSED",
      },
    },
  });

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /raw validator report is missing/,
  );
});

test("pending sidecar fails if observed results are filled", () => {
  const { root, fixtureCase, sidecarPath } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "pending_operator_run",
    document: {
      sha256: null,
      bytes: null,
    },
    report: {
      path: null,
      sha256: null,
      bytes: null,
      captured_at: null,
      content_type: null,
      source_filename: null,
      preserved_at: null,
      preserved_by: null,
      preservation_action: "not_recorded",
    },
    observed: recordedObserved(),
  });

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /observed must remain null/,
  );
});

test("recorded sidecar fails without status transition evidence", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/eu-dss-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:12.000Z",
      content_type: "text/plain",
      source_filename: "eu-dss-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: recordedObserved(),
  });
  sidecar.status_transition = pendingTransition();

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /status_transition\.from must be a previous validator run status/,
  );
});

test("sidecar fails if it makes a legal validity claim", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/eu-dss-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:12.000Z",
      content_type: "text/plain",
      source_filename: "eu-dss-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: recordedObserved(),
  });
  sidecar.evidence_scope.legal_validity_assessment = "passed";

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /legal_validity_assessment must be not_assessed/,
  );
});

test("recorded sidecar fails if report preservation timestamps diverge from validator run", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/eu-dss-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:13.000Z",
      content_type: "text/plain",
      source_filename: "eu-dss-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: recordedObserved(),
  });

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /report\.captured_at must match validator\.run_at/,
  );

  sidecar.report.captured_at = "2026-07-09T10:11:12.000Z";
  sidecar.report.preserved_at = "2026-07-09T10:11:13.000Z";

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /report\.preserved_at must match validator\.run_at/,
  );
});

test("recorded sidecar ties observed findings to transcription status", () => {
  const { root, fixtureCase, sidecarPath, document, report } = makeFixture();
  const sidecar = makeEuDssSidecar({
    status: "recorded",
    document: {
      sha256: sha256(document),
      bytes: document.length,
    },
    report: {
      path: "../reports/eu-dss-report.txt",
      sha256: sha256(report),
      bytes: report.length,
      captured_at: "2026-07-09T10:11:12.000Z",
      content_type: "text/plain",
      source_filename: "eu-dss-report.txt",
      preserved_at: "2026-07-09T10:11:12.000Z",
      preserved_by: "operator@example.test",
      preservation_action: "already_in_corpus",
    },
    observed: recordedObserved(),
  });
  sidecar.observed.findings = null;

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /observed\.findings must not be null/,
  );

  sidecar.observed = {
    transcription_status: "raw_report_only",
    legal_validity_assessment: "not_assessed",
    summary: "Raw report was preserved without structured technical findings.",
    findings: {
      overall_indication: "TOTAL_PASSED",
    },
  };

  assert.throws(
    () =>
      assertSidecar({
        fixtureCase,
        family: "eu-dss",
        sidecar,
        sidecarPath,
        corpusRoot: root,
      }),
    /observed\.findings must remain null for raw_report_only/,
  );
});

test("recorder preserves raw report metadata and pending-to-recorded transition", () => {
  const { root, report } = makeFixture();
  const rawReport = join(root, "operator-export.xml");
  writeFileSync(rawReport, report);

  const result = recordValidatorSidecar({
    caseId: "sample",
    family: "eu-dss",
    report: rawReport,
    tool: "EU DSS validation",
    version: "6.2",
    operator: "operator@example.test",
    environment: "test workstation",
    command: "dss-cli validate sample.pdf --out operator-export.xml",
    runAt: "2026-07-09T10:11:12Z",
    root,
  });

  assert.ok(existsSync(result.reportPath), "raw report was copied into the corpus");
  assert.equal(result.sidecar.validator.run_status, "recorded");
  assert.equal(result.sidecar.report.path, "../reports/eu-dss-operator-export.xml");
  assert.equal(result.sidecar.report.content_type, "application/xml");
  assert.equal(result.sidecar.report.source_filename, "operator-export.xml");
  assert.equal(result.sidecar.report.preserved_by, "operator@example.test");
  assert.equal(result.sidecar.report.preservation_action, "copied_to_corpus");
  assert.equal(result.sidecar.status_transition.from, "pending_operator_run");
  assert.equal(result.sidecar.status_transition.to, "recorded");
  assert.equal(result.sidecar.status_transition.by, "operator@example.test");
  assert.equal(result.sidecar.observed.transcription_status, "raw_report_only");
  assert.equal(result.sidecar.observed.legal_validity_assessment, "not_assessed");
});

function makeFixture() {
  const root = mkdtempSync(join(tmpdir(), "chancela-validator-corpus-"));
  const caseId = "sample";
  const expectedDir = join(root, "cases", caseId, "expected");
  const inputDir = join(root, "cases", caseId, "input");
  const reportsDir = join(root, "cases", caseId, "reports");
  mkdirSync(expectedDir, { recursive: true });
  mkdirSync(inputDir, { recursive: true });
  mkdirSync(reportsDir, { recursive: true });

  const document = Buffer.from("%PDF-1.7\nsample\n%%EOF\n");
  const report = Buffer.from("EU DSS report export\nTOTAL_PASSED\n");
  writeFileSync(join(inputDir, `${caseId}.pdf`), document);
  writeFileSync(join(reportsDir, "eu-dss-report.txt"), report);

  const fixtureCase = {
    id: caseId,
    title: "Sample validator case",
    profile: "B-B",
    category: "baseline",
    pdf: {
      path: `cases/${caseId}/input/${caseId}.pdf`,
      generation_status: "generated",
      generated_by: "test fixture",
      sha256: sha256(document),
      bytes: document.length,
    },
    expected_validation: {
      semantic_outcome: "valid_signature_without_timestamp",
      signature_count: 1,
      requires_signature_timestamp: false,
      requires_dss: false,
      requires_doc_time_stamp: false,
      tamper_expected: false,
    },
    sidecars: {
      "eu-dss": `cases/${caseId}/expected/eu-dss.json`,
      adobe: `cases/${caseId}/expected/adobe.json`,
    },
  };
  writeFileSync(
    join(root, "manifest.json"),
    `${JSON.stringify(
      {
        schema: "chancela-external-validator-corpus/v1",
        updated_at: "2026-07-09",
        purpose: "Test validator corpus.",
        status_policy: {
          pending_operator_run: "PDF exists, but external validator output has not been recorded by an operator.",
          recorded: "Technical external-validator report evidence was preserved by an operator.",
        },
        validator_families: ["eu-dss", "adobe"],
        cases: [fixtureCase],
      },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(expectedDir, "eu-dss.json"),
    `${JSON.stringify(
      makeEuDssSidecar({
        status: "pending_operator_run",
        document: {
          sha256: null,
          bytes: null,
        },
        report: pendingReport(),
        observed: null,
      }),
      null,
      2,
    )}\n`,
  );
  writeFileSync(join(expectedDir, "adobe.json"), `${JSON.stringify(makeAdobeSidecar(), null, 2)}\n`);

  return {
    root,
    document,
    report,
    sidecarPath: join(expectedDir, "eu-dss.json"),
    fixtureCase,
  };
}

function makeEuDssSidecar({ status, document, report, observed }) {
  const recorded = status === "recorded";
  const command = "dss-cli validate sample.pdf";
  return {
    schema: "chancela-external-validator-sidecar/v1",
    case_id: "sample",
    validator: {
      family: "eu-dss",
      name: "EU DSS validation",
      version: recorded ? "6.2" : null,
      run_status: status,
      run_at: recorded ? "2026-07-09T10:11:12.000Z" : null,
      operator: recorded ? "operator@example.test" : null,
      command: recorded ? command : null,
      environment: recorded ? "test workstation" : null,
      report_path: recorded ? report.path : null,
    },
    document: {
      path: "../input/sample.pdf",
      sha256: document.sha256,
      bytes: document.bytes,
    },
    evidence_scope: evidenceScope(),
    expected: {
      overall_indication: "TOTAL_PASSED",
      pades_profile: "B-B",
      sub_indication: null,
      signature_count: 1,
      signature_timestamp_present: false,
      dss_present: false,
      doc_time_stamp_present: false,
      tamper_detected: false,
    },
    report,
    observed,
    status_transition: recorded
      ? {
          from: "pending_operator_run",
          to: "recorded",
          at: "2026-07-09T10:11:12.000Z",
          by: "operator@example.test",
          reason: "operator_recorded_raw_validator_report",
          command,
        }
      : pendingTransition(),
    notes: ["test fixture"],
  };
}

function makeAdobeSidecar() {
  return {
    schema: "chancela-external-validator-sidecar/v1",
    case_id: "sample",
    validator: {
      family: "adobe",
      name: "Adobe Acrobat signature panel",
      version: null,
      run_status: "pending_operator_run",
      run_at: null,
      operator: null,
      command: null,
      environment: null,
      report_path: null,
    },
    document: {
      path: "../input/sample.pdf",
      sha256: null,
      bytes: null,
    },
    evidence_scope: evidenceScope(),
    expected: {
      summary: "Signature panel is expected to report a valid signature; trust depends on the operator trust store.",
      signature_count: 1,
      signature_timestamp_present: false,
      revocation_info_present: false,
      document_certified_or_ltv_enabled: false,
      doc_time_stamp_present: false,
      tamper_detected: false,
    },
    report: pendingReport(),
    observed: null,
    status_transition: pendingTransition(),
    notes: ["Pending operator run; this is not Adobe validation evidence."],
  };
}

function evidenceScope() {
  return {
    kind: "external_validator_report",
    technical_only: true,
    legal_validity_assessment: "not_assessed",
    claim: "technical_validator_evidence_only",
  };
}

function pendingReport() {
  return {
    path: null,
    sha256: null,
    bytes: null,
    captured_at: null,
    content_type: null,
    source_filename: null,
    preserved_at: null,
    preserved_by: null,
    preservation_action: "not_recorded",
  };
}

function pendingTransition() {
  return {
    from: null,
    to: "pending_operator_run",
    at: null,
    by: null,
    reason: "awaiting_operator_run",
    command: null,
  };
}

function recordedObserved() {
  return {
    transcription_status: "operator_transcribed",
    legal_validity_assessment: "not_assessed",
    summary: "EU DSS technical indication was transcribed from the raw report.",
    findings: {
      overall_indication: "TOTAL_PASSED",
    },
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
