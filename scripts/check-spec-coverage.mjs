import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const coveragePath = join(repoRoot, "SPEC-COVERAGE.md");
const ciCheckpointsPath = join(repoRoot, "docs", "CI-CHECKPOINTS.md");
const hardeningPlanPath = join(repoRoot, "docs", "CI-E2E-HARDENING-PLAN.md");
const recentLandedPath = join(repoRoot, "scripts", "checkpoint-recent-landed.mjs");
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
const ciCheckpoints = readFileSync(ciCheckpointsPath, "utf8");
const hardeningPlan = readFileSync(hardeningPlanPath, "utf8");
const recentLanded = readFileSync(recentLandedPath, "utf8");
const currentHead = gitRevParse("HEAD");
const currentHeadShort = currentHead.slice(0, 7);
const snapshotCommit = extractSnapshotCommit(body);
const rows = parseSpecRows(body);

assert.equal(
  snapshotCommit,
  currentHead,
  `implementation snapshot ${snapshotCommit} does not match current HEAD ${currentHead}`,
);

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
assertSnapshotCoherence();

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

function assertSnapshotCoherence() {
  assertIncludes(
    body,
    `Current \`${currentHeadShort}\``,
    "SPEC-COVERAGE.md current checkpoint short marker",
  );
  assertIncludes(
    hardeningPlan,
    `Current checkpoint metadata/static checks through \`${currentHeadShort}\``,
    "CI/E2E hardening plan current checkpoint marker",
  );
  assertIncludes(
    recentLanded,
    `implementation snapshot \`${currentHead}\``,
    "recent-landed static map spec snapshot marker",
  );
  assertIncludes(
    recentLanded,
    `Current checkpoint metadata/static checks through \`${currentHeadShort}\``,
    "recent-landed static map hardening-plan checkpoint marker",
  );
  assertIncludes(
    ciCheckpoints,
    "markers drift from current HEAD",
    "CI checkpoints spec coverage drift-check description",
  );
}

function assertIncludes(markdown, needle, label) {
  assert.ok(
    markdown.includes(needle),
    `${label} missing expected marker ${needle}`,
  );
}

function gitRevParse(revision) {
  const result = spawnSync("git", ["rev-parse", revision], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  if (result.error) {
    throw result.error;
  }

  assert.equal(
    result.status,
    0,
    `git rev-parse ${revision} failed: ${result.stderr.trim()}`,
  );

  const commit = result.stdout.trim();
  assert.match(
    commit,
    /^[0-9a-f]{40}$/u,
    `git rev-parse ${revision} returned invalid commit ${commit}`,
  );
  return commit;
}
