import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { assertSnapshotPathPolicy } from "./spec-coverage-snapshot-policy.mjs";

const checkpointPaths = new Set([
  "docs/checkpoint-a.md",
  "docs/checkpoint-b.md",
]);

test("accepts an exact implementation snapshot", () => {
  withRepository(({ root, snapshot }) => {
    const result = policy(root, snapshot, snapshot);
    assert.deepEqual(result, { mode: "current", changedPaths: [] });
  });
});

test("accepts a checkpoint-only child commit", () => {
  withRepository(({ root, snapshot }) => {
    commitFile(root, "docs/checkpoint-a.md", "checkpoint A\n", "checkpoint A");
    const result = policy(root, snapshot, head(root));
    assert.deepEqual(result, {
      mode: "checkpoint-only",
      changedPaths: ["docs/checkpoint-a.md"],
    });
  });
});

test("accepts a clean merge whose resulting drift is checkpoint-only", () => {
  withRepository(({ root, snapshot }) => {
    git(root, ["switch", "-c", "checkpoint-a"]);
    commitFile(root, "docs/checkpoint-a.md", "checkpoint A\n", "checkpoint A");

    git(root, ["switch", "-c", "checkpoint-b", snapshot]);
    commitFile(root, "docs/checkpoint-b.md", "checkpoint B\n", "checkpoint B");

    git(root, ["switch", "checkpoint-a"]);
    git(root, ["merge", "--no-ff", "checkpoint-b", "-m", "merge checkpoints"]);

    const result = policy(root, snapshot, head(root));
    assert.deepEqual(result, {
      mode: "checkpoint-only",
      changedPaths: ["docs/checkpoint-a.md", "docs/checkpoint-b.md"],
    });
  });
});

test("rejects a substantive child commit and names its path", () => {
  withRepository(({ root, snapshot }) => {
    commitFile(root, "src/app.rs", "fn main() {}\n", "substantive change");
    assert.throws(
      () => policy(root, snapshot, head(root)),
      /resulting tree changes non-checkpoint files: src\/app\.rs/u,
    );
  });
});

test("rejects a merge that brings in a substantive path", () => {
  withRepository(({ root, snapshot }) => {
    git(root, ["switch", "-c", "checkpoint"]);
    commitFile(root, "docs/checkpoint-a.md", "checkpoint A\n", "checkpoint A");

    git(root, ["switch", "-c", "feature", snapshot]);
    commitFile(root, "src/feature.rs", "pub fn feature() {}\n", "feature");

    git(root, ["switch", "checkpoint"]);
    git(root, ["merge", "--no-ff", "feature", "-m", "merge feature"]);

    assert.throws(
      () => policy(root, snapshot, head(root)),
      /resulting tree changes non-checkpoint files: src\/feature\.rs/u,
    );
  });
});

test("rejects a snapshot that is not an ancestor of HEAD", () => {
  withRepository(({ root, snapshot }) => {
    git(root, ["switch", "--orphan", "unrelated"]);
    rmSync(join(root, "README.md"), { force: true });
    commitFile(root, "docs/checkpoint-a.md", "unrelated\n", "unrelated root");
    assert.throws(
      () => policy(root, snapshot, head(root)),
      /is not an ancestor of current HEAD/u,
    );
  });
});

function policy(repoRoot, snapshotCommit, currentHead) {
  return assertSnapshotPathPolicy({
    repoRoot,
    snapshotCommit,
    currentHead,
    checkpointPaths,
  });
}

function withRepository(run) {
  const root = mkdtempSync(join(tmpdir(), "chancela-spec-policy-"));
  try {
    git(root, ["init", "-b", "main"]);
    git(root, ["config", "user.name", "Chancela test"]);
    git(root, ["config", "user.email", "test@chancela.invalid"]);
    commitFile(root, "README.md", "implementation\n", "implementation snapshot");
    run({ root, snapshot: head(root) });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function commitFile(root, relativePath, contents, message) {
  const absolutePath = join(root, relativePath);
  mkdirSync(join(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, contents, "utf8");
  git(root, ["add", "--", relativePath]);
  git(root, ["commit", "-m", message]);
}

function head(root) {
  return git(root, ["rev-parse", "HEAD"]).stdout;
}

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  assert.equal(
    result.status,
    0,
    `git ${args.join(" ")} failed: ${result.stderr.trim()}`,
  );
  return { stdout: result.stdout.trim(), stderr: result.stderr.trim() };
}
