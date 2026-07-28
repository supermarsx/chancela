import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  MANIFEST_TARGETS,
  applyVersion,
  classifyTags,
  compareRelease,
  computeNextRelease,
  parseManifestVersion,
  planRelease,
} from "./release-version-lib.mjs";

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptsDir, "..");

// The rules from VERSIONING.md, as a table. Each row is a tag list plus a build
// year; `expected` is the release the automation must cut.
const computationTable = [
  {
    name: "empty tag list starts the year at 1",
    tags: [],
    year: 2026,
    expected: { version: "26.1", tag: "v26.1", previousTag: null },
  },
  {
    name: "same-year release increments N",
    tags: ["v26.1"],
    year: 2026,
    expected: { version: "26.2", tag: "v26.2", previousTag: "v26.1" },
  },
  {
    name: "increments from the highest N, not the tag count",
    tags: ["v26.1", "v26.2", "v26.5"],
    year: 2026,
    expected: { version: "26.6", tag: "v26.6", previousTag: "v26.5" },
  },
  {
    name: "year rollover resets N to 1 rather than continuing the count",
    tags: ["v26.1", "v26.3", "v26.7"],
    year: 2027,
    expected: { version: "27.1", tag: "v27.1", previousTag: "v26.7" },
  },
  {
    name: "a new year with releases already cut increments within that year",
    tags: ["v26.7", "v27.1"],
    year: 2027,
    expected: { version: "27.2", tag: "v27.2", previousTag: "v27.1" },
  },
  {
    name: "N crossing into double digits sorts numerically, not lexically",
    tags: ["v26.1", "v26.9", "v26.10"],
    year: 2026,
    expected: { version: "26.11", tag: "v26.11", previousTag: "v26.10" },
  },
  {
    name: "v26.9 yields v26.10, which lexical sorting would get wrong",
    tags: ["v26.7", "v26.8", "v26.9"],
    year: 2026,
    expected: { version: "26.10", tag: "v26.10", previousTag: "v26.9" },
  },
  {
    name: "tags outside the release namespace are ignored",
    tags: [
      "nightly-2026-01-01",
      "spec-freeze",
      "v1.2.3",
      "v2026.4",
      "release-26.9",
      "26.4",
      "v26.2",
    ],
    year: 2026,
    expected: { version: "26.3", tag: "v26.3", previousTag: "v26.2" },
  },
  {
    name: "a single-digit year pads to two digits",
    tags: [],
    year: 2005,
    expected: { version: "05.1", tag: "v05.1", previousTag: null },
  },
  {
    name: "an earlier year's tags do not seed the current year",
    tags: ["v24.9", "v25.12"],
    year: 2026,
    expected: { version: "26.1", tag: "v26.1", previousTag: "v25.12" },
  },
];

for (const row of computationTable) {
  test(`computeNextRelease: ${row.name}`, () => {
    const release = computeNextRelease({ tags: row.tags, year: row.year });
    assert.equal(release.version, row.expected.version);
    assert.equal(release.tag, row.expected.tag);
    assert.equal(release.previousTag, row.expected.previousTag);
    assert.equal(release.manifestVersion, `${row.expected.version}.0`);
  });
}

test("computeNextRelease accepts manifests already at the computed release", () => {
  // The first cut: manifests sit at 26.1.0 and no tag exists yet, so v26.1 is
  // the release and the manifest edit is a no-op.
  const release = computeNextRelease({
    tags: [],
    year: 2026,
    manifestVersion: "26.1.0",
  });
  assert.equal(release.version, "26.1");
});

test("computeNextRelease refuses to move backwards past drifted manifests", () => {
  assert.throws(
    () =>
      computeNextRelease({
        tags: ["v26.1"],
        year: 2026,
        manifestVersion: "26.5.0",
      }),
    /refusing to move the release version backwards/u,
  );
});

test("computeNextRelease refuses a tag from a later year than the build year", () => {
  assert.throws(
    () => computeNextRelease({ tags: ["v27.1"], year: 2026 }),
    /later year than the build year/u,
  );
});

test("computeNextRelease refuses to reuse an existing tag", () => {
  // Reachable only if the tag list itself is inconsistent, but the guard is the
  // difference between a failed run and an overwritten release record.
  assert.throws(
    () =>
      computeNextRelease({
        tags: ["v26.1", "v26.2"],
        year: 2026,
        manifestVersion: "26.9.0",
      }),
    /refusing to move the release version backwards/u,
  );
});

test("computeNextRelease rejects ambiguous tags inside the release namespace", () => {
  // `v26.1.0` could be a past release recorded in SemVer form. Skipping it the
  // way an unrelated tag is skipped would re-issue 26.1.
  assert.throws(
    () => computeNextRelease({ tags: ["v26.1.0"], year: 2026 }),
    /not canonical release tags: v26\.1\.0/u,
  );
  assert.throws(
    () => computeNextRelease({ tags: ["v26.01"], year: 2026 }),
    /not canonical release tags: v26\.01/u,
  );
  assert.throws(
    () => computeNextRelease({ tags: ["v26.0"], year: 2026 }),
    /not canonical release tags: v26\.0/u,
  );
});

test("computeNextRelease rejects a year with no unambiguous two-digit form", () => {
  assert.throws(
    () => computeNextRelease({ tags: [], year: 2100 }),
    /outside 2000-2099/u,
  );
  assert.throws(
    () => computeNextRelease({ tags: [], year: 1999 }),
    /outside 2000-2099/u,
  );
});

test("classifyTags separates releases, namespace collisions and noise", () => {
  const { releases, ambiguous } = classifyTags([
    "v26.1",
    "v26.1.0",
    "nightly",
    "v1.2.3",
  ]);
  assert.deepEqual(
    releases.map((release) => release.tag),
    ["v26.1"],
  );
  assert.deepEqual(ambiguous, ["v26.1.0"]);
});

test("compareRelease orders by year then numeric sequence", () => {
  assert.equal(
    compareRelease({ year: 26, sequence: 9 }, { year: 26, sequence: 10 }),
    -1,
  );
  assert.equal(
    compareRelease({ year: 27, sequence: 1 }, { year: 26, sequence: 99 }),
    1,
  );
  assert.equal(
    compareRelease({ year: 26, sequence: 3 }, { year: 26, sequence: 3 }),
    0,
  );
});

test("parseManifestVersion demands the canonical YY.N.0 form", () => {
  assert.deepEqual(parseManifestVersion("26.10.0"), { year: 26, sequence: 10 });
  for (const invalid of [
    "26.1",
    "26.1.1",
    "2026.1.0",
    "26.0.0",
    "v26.1.0",
    "",
  ]) {
    assert.throws(
      () => parseManifestVersion(invalid),
      /not a canonical manifest version/u,
      `expected ${JSON.stringify(invalid)} to be rejected`,
    );
  }
});

test("applyVersion rewrites a JSON manifest and leaves the rest of the file alone", () => {
  const before = `${JSON.stringify({ name: "x", version: "26.1.0", private: true }, null, 2)}\n`;
  const { content, changes } = applyVersion(
    { path: "package.json", kind: "json" },
    before,
    "26.2.0",
  );
  assert.deepEqual(changes, [
    { field: "version", from: "26.1.0", to: "26.2.0" },
  ]);
  assert.equal(JSON.parse(content).version, "26.2.0");
  assert.equal(JSON.parse(content).name, "x");
});

test("applyVersion reports no change when a manifest is already at the target", () => {
  const before = `${JSON.stringify({ version: "26.2.0" }, null, 2)}\n`;
  const { content, changes } = applyVersion(
    { path: "package.json", kind: "json" },
    before,
    "26.2.0",
  );
  assert.deepEqual(changes, []);
  assert.equal(content, before);
});

test("applyVersion refuses to rewrite JSON it would reformat", () => {
  assert.throws(
    () =>
      applyVersion(
        { path: "package.json", kind: "json" },
        `{"version":"26.1.0"}`,
        "26.2.0",
      ),
    /does not round-trip/u,
  );
});

test("applyVersion rewrites the workspace version key in a TOML manifest", () => {
  const before = [
    "[workspace]",
    'version = "not-this-one"',
    "",
    "[workspace.package]",
    'version = "26.1.0" # keep the comment',
    'edition = "2024"',
    "",
  ].join("\n");
  const { content, changes } = applyVersion(
    { path: "Cargo.toml", kind: "toml", section: "workspace.package" },
    before,
    "26.2.0",
  );
  assert.deepEqual(changes, [
    { field: "[workspace.package] version", from: "26.1.0", to: "26.2.0" },
  ]);
  assert.match(content, /^version = "26\.2\.0" # keep the comment$/mu);
  assert.match(content, /^version = "not-this-one"$/mu);
});

test("applyVersion refuses a TOML manifest without exactly one version key", () => {
  assert.throws(
    () =>
      applyVersion(
        { path: "Cargo.toml", kind: "toml", section: "workspace.package" },
        '[workspace]\nversion = "26.1.0"\n',
        "26.2.0",
      ),
    /exactly one \[workspace\.package\] version key; found 0/u,
  );
});

test("applyVersion rewrites lockfile workspace entries but never dependencies", () => {
  const before = `${JSON.stringify(
    {
      name: "chancela",
      version: "26.1.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "chancela", version: "26.1.0" },
        "apps/web": { name: "chancela-web", version: "26.1.0" },
        "node_modules/unlucky": { version: "26.1.0", resolved: "https://x" },
      },
    },
    null,
    2,
  )}\n`;

  const { content, changes } = applyVersion(
    { path: "package-lock.json", kind: "lock" },
    before,
    "26.2.0",
  );

  assert.deepEqual(changes, [
    { field: "version", from: "26.1.0", to: "26.2.0" },
    { field: 'packages[""].version', from: "26.1.0", to: "26.2.0" },
    { field: 'packages["apps/web"].version', from: "26.1.0", to: "26.2.0" },
  ]);

  const after = JSON.parse(content);
  assert.equal(after.version, "26.2.0");
  assert.equal(after.packages[""].version, "26.2.0");
  assert.equal(after.packages["apps/web"].version, "26.2.0");
  assert.equal(
    after.packages["node_modules/unlucky"].version,
    "26.1.0",
    "a dependency that happens to share the release version must not be repinned",
  );
});

test("applyVersion refuses a lockfile whose workspace version it cannot explain", () => {
  const before = `${JSON.stringify(
    {
      version: "26.1.0",
      packages: {
        "": { version: "26.1.0" },
        "apps/web": { version: "0.0.1" },
      },
    },
    null,
    2,
  )}\n`;
  assert.throws(
    () =>
      applyVersion(
        { path: "package-lock.json", kind: "lock" },
        before,
        "26.2.0",
      ),
    /refusing to guess whether it is a release version/u,
  );
});

test("planRelease refuses a target whose content was not supplied", () => {
  assert.throws(
    () => planRelease({ files: {}, manifestVersion: "26.2.0" }),
    /Missing content for release manifest package\.json/u,
  );
});

test("MANIFEST_TARGETS covers every file check-versions.mjs gates", () => {
  // check:versions is the existing contract for "all release metadata agrees".
  // If it grows a seventh manifest, the bump must learn about it in the same
  // change, or a release would ship one stale version field.
  const source = readFileSync(
    path.join(scriptsDir, "check-versions.mjs"),
    "utf8",
  );
  const gated = [...source.matchAll(/^\s{4}file: "([^"]+)",$/gmu)].map(
    (match) => match[1],
  );
  assert.equal(
    gated.length,
    6,
    "expected check-versions.mjs to gate six manifests",
  );

  const covered = new Set(MANIFEST_TARGETS.map((target) => target.path));
  for (const file of gated) {
    assert.ok(
      covered.has(file),
      `${file} is gated by check:versions but never bumped`,
    );
  }
});

test("planRelease applies cleanly to the real repository manifests", () => {
  // Guards against a manifest changing shape (a reformatted lockfile, a moved
  // Cargo section) in a way the bump would only discover mid-release.
  const files = Object.fromEntries(
    MANIFEST_TARGETS.map((target) => [
      target.path,
      readFileSync(path.join(repoRoot, target.path), "utf8"),
    ]),
  );
  const current = JSON.parse(files["package.json"]).version;
  const { year, sequence } = parseManifestVersion(current);
  const next = `${String(year).padStart(2, "0")}.${sequence + 1}.0`;

  const plan = planRelease({ files, manifestVersion: next });
  assert.equal(plan.length, MANIFEST_TARGETS.length);
  for (const entry of plan) {
    assert.ok(
      entry.changes.length > 0,
      `${entry.path} carries no version field the bump can move`,
    );
    for (const change of entry.changes) {
      assert.equal(change.from, current);
      assert.equal(change.to, next);
    }
  }
});
