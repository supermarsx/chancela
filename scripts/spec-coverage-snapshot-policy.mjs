import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

/**
 * Enforce the implementation-snapshot boundary against the resulting Git tree.
 *
 * A snapshot may trail HEAD only when every final path changed since the
 * snapshot is an explicitly approved checkpoint path. Comparing the final
 * trees, rather than walking first parents, makes the policy correct for clean
 * merge commits while still catching substantive changes brought in by either
 * parent or introduced during conflict resolution.
 */
export function assertSnapshotPathPolicy({
  repoRoot,
  snapshotCommit,
  currentHead,
  checkpointPaths,
}) {
  assert.match(snapshotCommit, /^[0-9a-f]{40}$/u, "invalid snapshot commit");
  assert.match(currentHead, /^[0-9a-f]{40}$/u, "invalid current HEAD commit");
  assert.ok(checkpointPaths instanceof Set, "checkpointPaths must be a Set");

  if (snapshotCommit === currentHead) {
    return { mode: "current", changedPaths: [] };
  }

  const ancestor = gitRun(
    ["merge-base", "--is-ancestor", snapshotCommit, currentHead],
    repoRoot,
    { allowStatusOne: true },
  );
  assert.equal(
    ancestor.status,
    0,
    `implementation snapshot ${snapshotCommit} is not an ancestor of current HEAD ${currentHead}`,
  );

  // --no-renames preserves both sides of a move. Otherwise a rename from an
  // unapproved path into an approved path could hide the deleted source path.
  const changed = gitRun(
    [
      "diff",
      "--name-only",
      "--no-renames",
      "--diff-filter=ACDMRTUXB",
      `${snapshotCommit}..${currentHead}`,
      "--",
    ],
    repoRoot,
  ).stdout;
  const changedPaths = changed.split(/\r?\n/u).filter(Boolean).sort();
  const nonCheckpointPaths = changedPaths.filter(
    (path) => !checkpointPaths.has(path),
  );

  assert.deepEqual(
    nonCheckpointPaths,
    [],
    `implementation snapshot ${snapshotCommit} is behind current HEAD ${currentHead}, and the resulting tree changes non-checkpoint files: ${nonCheckpointPaths.join(
      ", ",
    )}`,
  );

  return { mode: "checkpoint-only", changedPaths };
}

function gitRun(args, cwd, { allowStatusOne = false } = {}) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0 && !(allowStatusOne && result.status === 1)) {
    assert.fail(
      `git ${args.join(" ")} failed with status ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return {
    status: result.status,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}
