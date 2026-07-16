#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const exception = Object.freeze({
  advisoryId: "RUSTSEC-2023-0071",
  package: "rsa",
  version: "0.9.10",
  reviewBy: "2026-08-31",
});

function fail(message) {
  console.error(`[cargo-audit-policy] ${message}`);
  process.exit(1);
}

function validate(report, today = new Date().toISOString().slice(0, 10)) {
  if (today > exception.reviewBy) {
    return [`exception review date expired on ${exception.reviewBy}`];
  }
  const findings = report?.vulnerabilities?.list;
  if (!Array.isArray(findings)) {
    return ["cargo-audit report has no vulnerabilities.list array"];
  }

  const errors = [];
  let expectedCount = 0;
  for (const finding of findings) {
    const actual = {
      advisoryId: finding?.advisory?.id,
      package: finding?.package?.name,
      version: finding?.package?.version,
    };
    if (
      actual.advisoryId === exception.advisoryId &&
      actual.package === exception.package &&
      actual.version === exception.version
    ) {
      expectedCount += 1;
      continue;
    }
    errors.push(
      `unexpected advisory ${actual.advisoryId ?? "<missing>"} on ${actual.package ?? "<missing>"}@${actual.version ?? "<missing>"}`,
    );
  }
  if (expectedCount !== 1) {
    errors.push(
      `expected exactly one ${exception.advisoryId} finding on ${exception.package}@${exception.version}, found ${expectedCount}; remove or review the exception if upstream changed`,
    );
  }
  if (report?.vulnerabilities?.count !== findings.length) {
    errors.push("cargo-audit vulnerability count does not match its finding list");
  }
  return errors;
}

function selfTest() {
  const known = {
    vulnerabilities: {
      count: 1,
      list: [
        {
          advisory: { id: exception.advisoryId },
          package: { name: exception.package, version: exception.version },
        },
      ],
    },
  };
  assert.deepEqual(validate(known, "2026-07-16"), []);
  assert.ok(
    validate(
      {
        vulnerabilities: {
          count: 2,
          list: [
            ...known.vulnerabilities.list,
            {
              advisory: { id: "RUSTSEC-2099-0001" },
              package: { name: "example", version: "1.0.0" },
            },
          ],
        },
      },
      "2026-07-16",
    ).some((error) => error.includes("unexpected advisory")),
  );
  assert.ok(
    validate(known, "2026-09-01").some((error) => error.includes("expired")),
  );
  console.log("cargo audit exception policy self-test OK");
}

const args = process.argv.slice(2);
if (args[0] === "self-test") {
  selfTest();
  process.exit(0);
}
if (args.length !== 2 || args[0] !== "--input") {
  fail("usage: node scripts/check-cargo-audit-policy.mjs --input <cargo-audit.json>");
}

let report;
try {
  report = JSON.parse(readFileSync(args[1], "utf8"));
} catch (error) {
  fail(`cannot read cargo-audit JSON: ${error.message}`);
}
const errors = validate(report);
if (errors.length > 0) fail(errors.join("\n- "));
console.log(
  `cargo audit policy OK: only ${exception.advisoryId} on ${exception.package}@${exception.version}; mandatory review by ${exception.reviewBy}`,
);
