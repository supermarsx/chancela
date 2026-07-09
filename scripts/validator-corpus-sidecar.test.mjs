import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { assertSidecar } from "./validate-validator-corpus.mjs";

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
    },
    observed: {
      overall_indication: "TOTAL_PASSED",
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
    },
    observed: {
      overall_indication: "TOTAL_PASSED",
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
    },
    observed: {
      overall_indication: "TOTAL_PASSED",
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
    /observed must remain null/,
  );
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

  return {
    root,
    document,
    report,
    sidecarPath: join(expectedDir, "eu-dss.json"),
    fixtureCase: {
      id: caseId,
      pdf: {
        path: `cases/${caseId}/input/${caseId}.pdf`,
      },
    },
  };
}

function makeEuDssSidecar({ status, document, report, observed }) {
  const recorded = status === "recorded";
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
      command: recorded ? "dss-cli validate sample.pdf" : null,
      environment: recorded ? "test workstation" : null,
      report_path: recorded ? report.path : null,
    },
    document: {
      path: "../input/sample.pdf",
      sha256: document.sha256,
      bytes: document.bytes,
    },
    expected: {
      overall_indication: "TOTAL_PASSED",
      pades_profile: "B-B",
      signature_count: 1,
      signature_timestamp_present: false,
      dss_present: false,
      doc_time_stamp_present: false,
      tamper_detected: false,
    },
    report,
    observed,
    notes: ["test fixture"],
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
