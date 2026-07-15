import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const coveragePath = join(repoRoot, "SPEC-COVERAGE.md");
const aiProvenancePath = join(repoRoot, "docs", "AI-PROVENANCE.md");
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
const checkpointPaths = new Set([
  ".github/workflows/ci.yml",
  ".github/funding.yml",
  "SPEC-COVERAGE.md",
  "apps/web/vite.config.ts",
  "docs/AI-PROVENANCE.md",
  "docs/ARCHITECTURE.md",
  "docs/CI-CHECKPOINTS.md",
  "docs/CI-E2E-HARDENING-PLAN.md",
  "docs/CI-RELEASE-HARDENING.md",
  "docs/ci-assurance-waivers.json",
  "package.json",
  "scripts/check-ci-assurance-waivers.mjs",
  "scripts/check-spec-coverage.mjs",
  "scripts/checkpoint-recent-landed.mjs",
]);

const body = readFileSync(coveragePath, "utf8");
const aiProvenance = readFileSync(aiProvenancePath, "utf8");
const ciCheckpoints = readFileSync(ciCheckpointsPath, "utf8");
const hardeningPlan = readFileSync(hardeningPlanPath, "utf8");
const recentLanded = readFileSync(recentLandedPath, "utf8");
const currentHead = gitRevParse("HEAD");
const declaredSnapshotCommit = extractSnapshotCommit(body);
const snapshotCommit = gitRevParse(`${declaredSnapshotCommit}^{commit}`);
const snapshotCommitShort = snapshotCommit.slice(0, 7);
const rows = parseSpecRows(body);

assertSnapshotCommitIsCurrentOrCheckpointParent();

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
    `Current \`${snapshotCommitShort}\``,
    "SPEC-COVERAGE.md current checkpoint short marker",
  );
  assertIncludes(
    hardeningPlan,
    `Current checkpoint metadata/static checks through \`${snapshotCommitShort}\``,
    "CI/E2E hardening plan current checkpoint marker",
  );
  assertIncludes(
    recentLanded,
    `implementation snapshot \`${snapshotCommit}\``,
    "recent-landed static map spec snapshot marker",
  );
  assertIncludes(
    recentLanded,
    `Current checkpoint metadata/static checks through \`${snapshotCommitShort}\``,
    "recent-landed static map hardening-plan checkpoint marker",
  );
  assertIncludes(
    ciCheckpoints,
    "markers drift from the declared implementation snapshot",
    "CI checkpoints spec coverage drift-check description",
  );
  assertIncludes(
    aiProvenance,
    "## MCP local review resources",
    "AI provenance MCP local review section",
  );
  assertIncludes(
    aiProvenance,
    "`chancela://mcp/meeting-metadata-extraction-review` follows the same boundary.",
    "AI provenance MCP meeting metadata review marker",
  );
  assertIncludes(
    aiProvenance,
    "requires human verification and does not echo raw document text",
    "AI provenance MCP no-echo boundary marker",
  );
  assertIncludes(
    aiProvenance,
    "These resources do not fetch providers, call the API",
    "AI provenance MCP no-call boundary marker",
  );
  assertIncludes(
    aiProvenance,
    "or claim PDF/UA conformance, DGLAB certification, legal validity",
    "AI provenance MCP no-claim boundary marker",
  );
}

function assertIncludes(markdown, needle, label) {
  assert.ok(
    markdown.includes(needle),
    `${label} missing expected marker ${needle}`,
  );
}

function assertSnapshotCommitIsCurrentOrCheckpointParent() {
  if (snapshotCommit === currentHead) {
    return;
  }

  let candidate = currentHead;
  const checkpointCommits = [];

  while (candidate !== snapshotCommit) {
    const parents = gitCommitParents(candidate);
    assert.equal(
      parents.length,
      1,
      `implementation snapshot ${snapshotCommit} is not current HEAD ${currentHead}, and checkpoint candidate ${candidate} is not a single-parent commit`,
    );

    const changedPaths = gitChangedPaths(candidate);
    assert.ok(
      changedPaths.length > 0,
      `checkpoint candidate ${candidate} has no changed paths to classify as a pure spec/checker checkpoint commit`,
    );

    const nonCheckpointPaths = changedPaths.filter(
      (path) => !checkpointPaths.has(path),
    );
    assert.deepEqual(
      nonCheckpointPaths,
      [],
      `implementation snapshot ${snapshotCommit} is behind checkpoint commit ${candidate}, but that commit also changes non-checkpoint files: ${nonCheckpointPaths.join(
        ", ",
      )}`,
    );

    checkpointCommits.push(candidate);
    candidate = parents[0];
  }

  assert.ok(
    checkpointCommits.length > 0,
    `implementation snapshot ${snapshotCommit} must match current HEAD ${currentHead} or an ancestor reached through pure spec/checker checkpoint commits`,
  );
}

function gitCommitParents(revision) {
  const line = gitOutput(["rev-list", "--parents", "-n", "1", revision]);
  const [head, ...parents] = line.split(/\s+/u);
  assert.equal(
    head,
    gitRevParse(revision),
    `git rev-list ${revision} did not match rev-parse ${revision}`,
  );
  return parents;
}

function gitChangedPaths(revision) {
  const output = gitOutput([
    "diff-tree",
    "--no-commit-id",
    "--name-only",
    "-r",
    revision,
  ]);
  if (output.length === 0) {
    return [];
  }
  return output.split(/\r?\n/u).filter(Boolean);
}

function gitRevParse(revision) {
  const commit = gitOutput(["rev-parse", revision]);
  assert.match(
    commit,
    /^[0-9a-f]{40}$/u,
    `git rev-parse ${revision} returned invalid commit ${commit}`,
  );
  return commit;
}

function gitOutput(args) {
  const result = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: "utf8",
  });

  if (result.error) {
    throw result.error;
  }

  assert.equal(
    result.status,
    0,
    `git ${args.join(" ")} failed: ${result.stderr.trim()}`,
  );

  return result.stdout.trim();
}
