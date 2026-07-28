/**
 * Pure logic for the CalVer `YY.N` release scheme documented in VERSIONING.md.
 *
 * Nothing here touches the filesystem, git, or the clock: callers pass in the
 * tag list, the build year and the file contents, and get back the computed
 * release plus the exact rewritten file bodies. That is what makes the rules
 * below testable (scripts/release-version.test.mjs) rather than only
 * observable by cutting a real release.
 *
 * The release record is the *tag list*, not the manifests. Manifests can drift
 * (a bad merge, a hand edit); a pushed tag is the artefact the release was
 * built from. Every rule below therefore derives from tags and uses the
 * manifests only as a backwards-movement guard.
 */

/** A canonical release tag: `v` + 2-digit year + `.` + a 1-based sequence. */
export const RELEASE_TAG_PATTERN = /^v(\d{2})\.([1-9]\d*)$/u;

/**
 * A tag that opens with `v<2 digits>.` sits inside the release namespace but is
 * not canonical (`v26.1.0`, `v26.01`, `v26.0`). Skipping it the way we skip an
 * unrelated tag would be a silent filter over exactly the tags most likely to
 * record a real past release, so those are an error. Tags outside the namespace
 * (`v1.2.3`, `nightly-2026-01-01`, `spec-freeze`) are genuinely unrelated and
 * are ignored.
 */
const NAMESPACE_TAG_PATTERN = /^v\d{2}\./u;

/** Manifest form: the canonical `YY.N` plus the `.0` patch SemVer demands. */
const MANIFEST_VERSION_PATTERN = /^(\d{2})\.([1-9]\d*)\.0$/u;

/**
 * The files that carry the release version. The first six are exactly the six
 * `npm run check:versions` gates; the two lockfiles are the "plus the lockfile
 * root `version` fields" clause of VERSIONING.md, which that gate does not
 * cover. release-version.test.mjs asserts this list stays a superset of
 * check-versions.mjs.
 */
export const MANIFEST_TARGETS = [
  { path: "package.json", kind: "json" },
  { path: "apps/web/package.json", kind: "json" },
  { path: "apps/desktop/package.json", kind: "json" },
  { path: "Cargo.toml", kind: "toml", section: "workspace.package" },
  {
    path: "apps/desktop/src-tauri/Cargo.toml",
    kind: "toml",
    section: "package",
  },
  { path: "apps/desktop/src-tauri/tauri.conf.json", kind: "json" },
  { path: "package-lock.json", kind: "lock" },
  { path: "apps/desktop/package-lock.json", kind: "lock" },
];

/** Orders two releases by (year, sequence). Both compared numerically. */
export function compareRelease(left, right) {
  if (left.year !== right.year) {
    return left.year < right.year ? -1 : 1;
  }
  if (left.sequence !== right.sequence) {
    return left.sequence < right.sequence ? -1 : 1;
  }
  return 0;
}

/** Splits a tag list into canonical releases, namespace collisions, and noise. */
export function classifyTags(tags) {
  const releases = [];
  const ambiguous = [];

  for (const tag of tags) {
    const match = RELEASE_TAG_PATTERN.exec(tag);
    if (match) {
      releases.push({
        tag,
        year: Number(match[1]),
        sequence: Number(match[2]),
      });
      continue;
    }
    if (NAMESPACE_TAG_PATTERN.test(tag)) {
      ambiguous.push(tag);
    }
  }

  return { releases, ambiguous };
}

/** Parses the `YY.N.0` manifest form into the same shape as a release tag. */
export function parseManifestVersion(value) {
  const match = MANIFEST_VERSION_PATTERN.exec(value ?? "");
  if (!match) {
    throw new Error(
      `"${value}" is not a canonical manifest version; expected YY.N.0 (see VERSIONING.md)`,
    );
  }
  return { year: Number(match[1]), sequence: Number(match[2]) };
}

/**
 * Computes the next release.
 *
 * - `YY` is the two-digit build year.
 * - `N` is one past the highest `N` already tagged **for that year**, so the
 *   first release of a new year resets to 1 rather than continuing the previous
 *   year's count.
 * - Sequences are compared numerically, so `v26.9` yields `v26.10`.
 * - Refuses to move backwards: a tag from a later year, or manifests already
 *   ahead of the computed release, is an error rather than a silent regression.
 * - Refuses to reuse an existing tag.
 *
 * @param {object} options
 * @param {string[]} options.tags Every tag in the repository.
 * @param {number} options.year Four-digit build year.
 * @param {string|null} options.manifestVersion Current `YY.N.0`, if known.
 */
export function computeNextRelease({
  tags = [],
  year,
  manifestVersion = null,
}) {
  const shortYear = twoDigitYear(year);
  const { releases, ambiguous } = classifyTags(tags);

  if (ambiguous.length > 0) {
    throw new Error(
      `Tags sit inside the vYY.N release namespace but are not canonical release tags: ` +
        `${[...ambiguous].sort().join(", ")}. Rename or delete them; refusing to guess ` +
        `the next release number while the tag namespace is ambiguous.`,
    );
  }

  const latest = releases.reduce(
    (best, release) =>
      best === null || compareRelease(release, best) > 0 ? release : best,
    null,
  );

  if (latest !== null && latest.year > shortYear) {
    throw new Error(
      `Latest release tag ${latest.tag} is from a later year than the build year ${year}; ` +
        `refusing to move the release version backwards.`,
    );
  }

  const thisYear = releases.filter((release) => release.year === shortYear);
  const sequence =
    thisYear.length === 0
      ? 1
      : Math.max(...thisYear.map((release) => release.sequence)) + 1;

  const next = {
    year: shortYear,
    sequence,
    version: `${pad(shortYear)}.${sequence}`,
    tag: `v${pad(shortYear)}.${sequence}`,
    manifestVersion: `${pad(shortYear)}.${sequence}.0`,
    previousTag: latest === null ? null : latest.tag,
  };

  if (tags.includes(next.tag)) {
    throw new Error(
      `Tag ${next.tag} already exists; refusing to overwrite an existing release tag.`,
    );
  }

  if (manifestVersion !== null) {
    const current = parseManifestVersion(manifestVersion);
    if (compareRelease(next, current) < 0) {
      throw new Error(
        `Manifests are at ${manifestVersion} but the computed release is ${next.version} ` +
          `(highest release tag: ${latest === null ? "none" : latest.tag}); refusing to ` +
          `move the release version backwards.`,
      );
    }
  }

  return next;
}

/**
 * Rewrites one file's version fields.
 *
 * @returns {{content: string, changes: Array<{field: string, from: string, to: string}>}}
 *   `changes` is empty when the file already carries the target version.
 */
export function applyVersion(target, content, manifestVersion) {
  parseManifestVersion(manifestVersion);

  switch (target.kind) {
    case "json":
      return applyJsonVersion(target, content, manifestVersion);
    case "lock":
      return applyLockVersion(target, content, manifestVersion);
    case "toml":
      return applyTomlVersion(target, content, manifestVersion);
    default:
      throw new Error(
        `Unknown manifest kind "${target.kind}" for ${target.path}`,
      );
  }
}

/**
 * Rewrites every target. `files` maps a target path to its current content;
 * a missing entry is an error, because a manifest that quietly dropped out of
 * the set would leave a stale version behind in a shipped release.
 */
export function planRelease({
  targets = MANIFEST_TARGETS,
  files,
  manifestVersion,
}) {
  return targets.map((target) => {
    const content = files[target.path];
    if (typeof content !== "string") {
      throw new Error(`Missing content for release manifest ${target.path}`);
    }
    const result = applyVersion(target, content, manifestVersion);
    return { path: target.path, ...result };
  });
}

function applyJsonVersion(target, content, manifestVersion) {
  const data = parseStableJson(target.path, content);
  if (typeof data.version !== "string" || data.version.length === 0) {
    throw new Error(
      `${target.path} is missing a non-empty string "version" field`,
    );
  }

  const from = data.version;
  if (from === manifestVersion) {
    return { content, changes: [] };
  }

  data.version = manifestVersion;
  return {
    content: serializeJson(data),
    changes: [{ field: "version", from, to: manifestVersion }],
  };
}

function applyLockVersion(target, content, manifestVersion) {
  const data = parseStableJson(target.path, content);
  if (typeof data.version !== "string" || data.version.length === 0) {
    throw new Error(`${target.path} is missing a top-level "version" field`);
  }

  const previous = data.version;
  const changes = [];

  if (previous !== manifestVersion) {
    data.version = manifestVersion;
    changes.push({ field: "version", from: previous, to: manifestVersion });
  }

  // Local entries are the lockfile's view of the root package and each
  // workspace. Registry dependencies live under a `node_modules/` key and must
  // never be touched — a dependency that happens to share the release version
  // would otherwise be silently repinned.
  for (const [key, entry] of Object.entries(data.packages ?? {})) {
    if (key.includes("node_modules/") || key.startsWith("node_modules")) {
      continue;
    }
    if (entry === null || typeof entry !== "object") {
      continue;
    }
    if (typeof entry.version !== "string") {
      continue;
    }
    if (entry.version === manifestVersion) {
      continue;
    }
    if (entry.version !== previous) {
      throw new Error(
        `${target.path} local package "${key || "<root>"}" is at ${entry.version}, ` +
          `which matches neither the lockfile version ${previous} nor the target ` +
          `${manifestVersion}; refusing to guess whether it is a release version.`,
      );
    }
    entry.version = manifestVersion;
    changes.push({
      field: `packages["${key}"].version`,
      from: previous,
      to: manifestVersion,
    });
  }

  return changes.length === 0
    ? { content, changes: [] }
    : { content: serializeJson(data), changes };
}

function applyTomlVersion(target, content, manifestVersion) {
  const newline = content.includes("\r\n") ? "\r\n" : "\n";
  const lines = content.replace(/^﻿/u, "").split(/\r?\n/u);
  const matches = [];
  let currentSection = "";

  for (const [index, line] of lines.entries()) {
    const sectionMatch = line.match(/^\s*\[([^\]]+)\]\s*(?:#.*)?$/u);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      continue;
    }
    if (currentSection !== target.section) {
      continue;
    }
    const versionMatch = line.match(
      /^(\s*version\s*=\s*")([^"]*)("\s*(?:#.*)?)$/u,
    );
    if (versionMatch) {
      matches.push({ index, versionMatch });
    }
  }

  if (matches.length !== 1) {
    throw new Error(
      `${target.path} must contain exactly one [${target.section}] version key; found ${matches.length}`,
    );
  }

  const [{ index, versionMatch }] = matches;
  const from = versionMatch[2];
  if (from === manifestVersion) {
    return { content, changes: [] };
  }

  lines[index] = `${versionMatch[1]}${manifestVersion}${versionMatch[3]}`;
  return {
    content: lines.join(newline),
    changes: [
      { field: `[${target.section}] version`, from, to: manifestVersion },
    ],
  };
}

/**
 * Parses JSON and proves that re-serializing it reproduces the file byte for
 * byte. Every JSON manifest in this repo is npm-formatted (two-space indent,
 * trailing newline), so the round trip holds today; if a file ever stops
 * round-tripping this throws instead of silently reformatting an unrelated
 * 150 KB lockfile as a side effect of a version bump.
 */
function parseStableJson(relativePath, content) {
  let data;
  try {
    data = JSON.parse(content);
  } catch (error) {
    throw new Error(`${relativePath} is not valid JSON: ${error.message}`);
  }

  if (serializeJson(data) !== content) {
    throw new Error(
      `${relativePath} does not round-trip through JSON.stringify with two-space ` +
        `indentation; refusing to rewrite it because doing so would reformat the ` +
        `whole file. Reformat it with npm/prettier first.`,
    );
  }

  return data;
}

function serializeJson(data) {
  return `${JSON.stringify(data, null, 2)}\n`;
}

function twoDigitYear(year) {
  if (!Number.isInteger(year)) {
    throw new Error(`Build year must be an integer; received ${String(year)}`);
  }
  if (year < 2000 || year > 2099) {
    throw new Error(
      `Build year ${year} is outside 2000-2099, where a two-digit YY is unambiguous; ` +
        `the YY.N scheme needs revisiting before releasing from that year.`,
    );
  }
  return year % 100;
}

function pad(shortYear) {
  return String(shortYear).padStart(2, "0");
}
