import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const coveragePath = join(repoRoot, "SPEC-COVERAGE.md");
const jsonOutput = process.argv.includes("--json");

const expectedSpecs = [
  "01",
  "02",
  "03",
  "04",
  "05",
  "06",
  "07",
  "08",
  "09",
  "10",
  "11",
];
const allowedStatuses = new Set(["PARTIAL", "BLOCKED", "COMPLETE"]);

const body = readFileSync(coveragePath, "utf8");
const snapshotCommit = extractSnapshotCommit(body);
const rows = parseSpecRows(body);

assert.equal(
  rows.length,
  expectedSpecs.length,
  `expected ${expectedSpecs.length} spec coverage rows, found ${rows.length}`,
);

for (const spec of expectedSpecs) {
  assert.ok(
    rows.some((row) => row.spec === spec),
    `missing spec/${spec} coverage row`,
  );
}

for (const row of rows) {
  assert.ok(
    allowedStatuses.has(row.status),
    `spec/${row.spec} has unsupported status ${row.status}`,
  );
  assert.ok(
    row.current.length > 20,
    `spec/${row.spec} current coverage is too terse`,
  );
  assert.ok(
    row.remaining.length > 20,
    `spec/${row.spec} remaining work is too terse`,
  );
  assert.ok(
    row.external.length > 3,
    `spec/${row.spec} external blockers column is empty`,
  );
}

assertRequiredSection("## Remaining Blockers");
assertRequiredSection("### Local product work");
assertRequiredSection("### External / provider / legal blockers");
assertRequiredSection("## Do Not Overstate");

if (rows.every((row) => row.status === "PARTIAL")) {
  assert.ok(
    body.includes("All top-level spec areas remain **PARTIAL**"),
    "all rows are PARTIAL but the summary does not state that boundary",
  );
}

const statusCounts = rows.reduce((counts, row) => {
  counts[row.status] = (counts[row.status] ?? 0) + 1;
  return counts;
}, {});

const summary = {
  snapshot_commit: snapshotCommit,
  spec_count: rows.length,
  status_counts: statusCounts,
  specs: rows.map(({ spec, label, status }) => ({ spec, label, status })),
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(
    `spec coverage OK: ${rows.length} rows at snapshot ${snapshotCommit}; statuses ${Object.entries(
      statusCounts,
    )
      .map(([status, count]) => `${status}=${count}`)
      .join(", ")}`,
  );
}

function extractSnapshotCommit(markdown) {
  const match = markdown.match(/implementation snapshot `([0-9a-f]{7,40})`/);
  assert.ok(match, "missing implementation snapshot commit marker");
  return match[1];
}

function parseSpecRows(markdown) {
  return markdown
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("| spec/"))
    .map((line) => {
      const cells = line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim());
      assert.equal(cells.length, 5, `malformed coverage row: ${line}`);
      const labelMatch = cells[0].match(/^spec\/(\d{2})\s+(.+)$/u);
      assert.ok(labelMatch, `malformed spec label: ${cells[0]}`);
      return {
        spec: labelMatch[1],
        label: labelMatch[2],
        status: cells[1],
        current: cells[2],
        remaining: cells[3],
        external: cells[4],
      };
    });
}

function assertRequiredSection(section) {
  assert.ok(
    body.includes(section),
    `missing required coverage section ${section}`,
  );
}
