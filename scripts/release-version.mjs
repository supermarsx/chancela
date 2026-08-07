#!/usr/bin/env node
/**
 * Release-version automation for the CalVer `YY.N` scheme (see versioning.md).
 *
 *   node scripts/release-version.mjs compute [--json]
 *   node scripts/release-version.mjs bump [--dry-run] [--commit] [--tag]
 *   node scripts/release-version.mjs check-tag-parity
 *
 * `compute` derives the next release from the repository's git tags. `bump`
 * additionally rewrites every version-carrying manifest, and can create the
 * bump commit and the annotated tag.
 *
 * This script never pushes. Publishing a tag is an outward-facing act, so the
 * only place a push exists is the explicit step in
 * .github/workflows/auto-release.yml; no flag here can reach `origin`.
 *
 * All decision logic lives in release-version-lib.mjs and is unit-tested by
 * release-version.test.mjs.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  MANIFEST_TARGETS,
  compareRelease,
  computeNextRelease,
  parseManifestVersion,
  planRelease,
} from "./release-version-lib.mjs";

const defaultRepoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const USAGE = `Usage:
  node scripts/release-version.mjs compute [options]
  node scripts/release-version.mjs bump [options]
  node scripts/release-version.mjs check-tag-parity [options]

Options:
  --dry-run              Print the computed release and every file edit; write nothing.
  --commit               Create the bump commit (bump only; ignored with --dry-run).
  --tag                  Create the annotated release tag (bump only; ignored with --dry-run).
  --version <YY.N>       Override the computed release (must still not move backwards).
  --year <YYYY>          Override the build year (testing).
  --repo <path>          Operate on another checkout (testing).
  --json                 Emit machine-readable JSON.
  --emit-github-output   Append version/tag/changed outputs to $GITHUB_OUTPUT.
`;

function main(argv) {
  const options = parseArgs(argv);

  switch (options.command) {
    case "compute":
      return runCompute(options);
    case "bump":
      return runBump(options);
    case "check-tag-parity":
      return runCheckTagParity(options);
    default:
      process.stderr.write(USAGE);
      return 2;
  }
}

function runCompute(options) {
  const release = resolveRelease(options);
  report(options, release, []);
  emitGithubOutput(options, release, false);
  return 0;
}

function runBump(options) {
  const release = resolveRelease(options);
  const files = Object.fromEntries(
    MANIFEST_TARGETS.map((target) => [
      target.path,
      readFile(options.repoRoot, target.path),
    ]),
  );

  const plan = planRelease({ files, manifestVersion: release.manifestVersion });
  const changed = plan.filter((entry) => entry.changes.length > 0);

  report(options, release, plan);

  if (options.dryRun) {
    process.stdout.write(
      `\nDry run: no files written, no commit created, no tag created.\n`,
    );
    emitGithubOutput(options, release, changed.length > 0);
    return 0;
  }

  for (const entry of changed) {
    fs.writeFileSync(path.join(options.repoRoot, entry.path), entry.content);
  }

  verifyManifests(options.repoRoot);

  if (options.commit && changed.length > 0) {
    const paths = changed.map((entry) => entry.path);
    git(options.repoRoot, ["add", "--", ...paths]);
    // No `Release: yes` trailer and an explicit `[skip ci]`: this commit must
    // not re-trigger the release workflow it was created by. See the loop-guard
    // note in .github/workflows/auto-release.yml.
    git(options.repoRoot, [
      "commit",
      "-m",
      `chore(release): ${release.version} [skip ci]`,
      "-m",
      `Automated CalVer bump to ${release.manifestVersion} for tag ${release.tag}.`,
      "--",
      ...paths,
    ]);
    process.stdout.write(`Committed bump for ${release.version}.\n`);
  } else if (options.commit) {
    process.stdout.write(
      `Manifests already at ${release.manifestVersion}; nothing to commit.\n`,
    );
  }

  if (options.tag) {
    git(options.repoRoot, [
      "tag",
      "-a",
      release.tag,
      "-m",
      `Chancela ${release.version}`,
    ]);
    process.stdout.write(`Created tag ${release.tag} (not pushed).\n`);
  }

  emitGithubOutput(options, release, changed.length > 0);
  return 0;
}

/**
 * Proposed gate (not yet wired into CI): once a release exists, the manifests
 * on main must equal the newest release tag. The bump commit sets them to the
 * released version and nothing moves them until the next release, so the
 * invariant holds continuously rather than only at tag time.
 */
function runCheckTagParity(options) {
  const tags = readTags(options.repoRoot);
  const manifestVersion = readManifestVersion(options.repoRoot);
  const releases = tags
    .map((tag) => /^v(\d{2})\.([1-9]\d*)$/u.exec(tag))
    .filter((match) => match !== null)
    .map((match) => ({
      tag: match[0],
      year: Number(match[1]),
      sequence: Number(match[2]),
    }));

  if (releases.length === 0) {
    process.stdout.write(
      "No release tags yet; manifest/tag parity is not enforceable before the first release.\n",
    );
    return 0;
  }

  const latest = releases.reduce((best, release) =>
    compareRelease(release, best) > 0 ? release : best,
  );
  const expected = `${String(latest.year).padStart(2, "0")}.${latest.sequence}.0`;

  if (manifestVersion !== expected) {
    process.stderr.write(
      `Manifest version ${manifestVersion} does not match the newest release tag ${latest.tag} ` +
        `(expected ${expected}).\n`,
    );
    return 1;
  }

  process.stdout.write(
    `Manifests match the newest release tag ${latest.tag} (${manifestVersion}).\n`,
  );
  return 0;
}

function resolveRelease(options) {
  const tags = readTags(options.repoRoot);
  const manifestVersion = readManifestVersion(options.repoRoot);

  if (options.version === null) {
    return computeNextRelease({
      tags,
      year: options.year,
      manifestVersion,
    });
  }

  const match = /^(\d{2})\.([1-9]\d*)$/u.exec(options.version);
  if (!match) {
    throw new Error(
      `--version must be a canonical YY.N release, received "${options.version}"`,
    );
  }
  const forced = {
    year: Number(match[1]),
    sequence: Number(match[2]),
    version: options.version,
    tag: `v${options.version}`,
    manifestVersion: `${options.version}.0`,
    previousTag: null,
  };
  if (tags.includes(forced.tag)) {
    throw new Error(
      `Tag ${forced.tag} already exists; refusing to overwrite an existing release tag.`,
    );
  }
  if (compareRelease(forced, parseManifestVersion(manifestVersion)) < 0) {
    throw new Error(
      `Manifests are at ${manifestVersion}; --version ${options.version} would move the ` +
        `release version backwards.`,
    );
  }
  return forced;
}

function report(options, release, plan) {
  if (options.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          version: release.version,
          tag: release.tag,
          manifestVersion: release.manifestVersion,
          previousTag: release.previousTag,
          edits: plan.flatMap((entry) =>
            entry.changes.map((change) => ({ path: entry.path, ...change })),
          ),
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  process.stdout.write(`Next release: ${release.version}\n`);
  process.stdout.write(`Tag:          ${release.tag}\n`);
  process.stdout.write(`Manifests:    ${release.manifestVersion}\n`);
  process.stdout.write(
    `Previous tag: ${release.previousTag ?? "(none — first release)"}\n`,
  );

  if (plan.length === 0) {
    return;
  }

  process.stdout.write(`\nManifest edits:\n`);
  let edits = 0;
  for (const entry of plan) {
    if (entry.changes.length === 0) {
      process.stdout.write(
        `  ${entry.path}: already at ${release.manifestVersion}\n`,
      );
      continue;
    }
    for (const change of entry.changes) {
      edits += 1;
      process.stdout.write(
        `  ${entry.path}: ${change.field}: ${change.from} -> ${change.to}\n`,
      );
    }
  }
  process.stdout.write(`\n${edits} field(s) across ${plan.length} file(s).\n`);
}

function emitGithubOutput(options, release, changed) {
  if (!options.emitGithubOutput) {
    return;
  }
  const target = process.env.GITHUB_OUTPUT;
  if (!target) {
    throw new Error("--emit-github-output requires GITHUB_OUTPUT to be set");
  }
  fs.appendFileSync(
    target,
    [
      `version=${release.version}`,
      `tag=${release.tag}`,
      `manifest_version=${release.manifestVersion}`,
      `changed=${changed ? "true" : "false"}`,
      "",
    ].join("\n"),
  );
}

function verifyManifests(repoRoot) {
  // Resolved against the target checkout, not this file, so that --repo runs
  // gate the checkout they rewrote rather than the one the script lives in.
  const result = spawnSync(
    process.execPath,
    [path.join(repoRoot, "scripts", "check-versions.mjs")],
    { cwd: repoRoot, stdio: "inherit" },
  );
  if (result.status !== 0) {
    throw new Error(
      "check-versions.mjs rejected the rewritten manifests; the bump was not consistent.",
    );
  }
}

function readTags(repoRoot) {
  return git(repoRoot, ["tag", "--list"])
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function readManifestVersion(repoRoot) {
  const data = JSON.parse(readFile(repoRoot, "package.json"));
  return data.version;
}

function readFile(repoRoot, relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function git(repoRoot, args) {
  const result = spawnSync("git", args, { cwd: repoRoot, encoding: "utf8" });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed with status ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return result.stdout;
}

function parseArgs(argv) {
  const options = {
    command: argv[0] ?? "",
    repoRoot: defaultRepoRoot,
    year: new Date().getFullYear(),
    version: null,
    dryRun: false,
    commit: false,
    tag: false,
    json: false,
    emitGithubOutput: false,
  };

  for (let index = 1; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--commit":
        options.commit = true;
        break;
      case "--tag":
        options.tag = true;
        break;
      case "--json":
        options.json = true;
        break;
      case "--emit-github-output":
        options.emitGithubOutput = true;
        break;
      case "--version":
        options.version = requireValue(argv, (index += 1), "--version");
        break;
      case "--year":
        options.year = Number(requireValue(argv, (index += 1), "--year"));
        break;
      case "--repo":
        options.repoRoot = path.resolve(
          requireValue(argv, (index += 1), "--repo"),
        );
        break;
      default:
        throw new Error(`Unknown argument "${arg}"\n\n${USAGE}`);
    }
  }

  return options;
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (value === undefined) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

try {
  process.exit(main(process.argv.slice(2)));
} catch (error) {
  process.stderr.write(`release-version: ${error.message}\n`);
  process.exit(1);
}
