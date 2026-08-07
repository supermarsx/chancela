/**
 * BUILD PROVENANCE (t100) — the commit this bundle was built from, shaped for the one surface that
 * shows it: Settings → «Sobre».
 *
 * `vite.config.ts` resolves the commit at build time and inlines it as `__BUILD_COMMIT__` (raw and
 * unvalidated); everything below turns that into something displayable, or into `null`. This is
 * provenance, NOT a version: the release version stays `__APP_VERSION__` / `displayVersion()`, and
 * nothing here participates in the version-skew comparison (see versioning.md).
 *
 * ─── DEGRADE HONESTLY ──────────────────────────────────────────────────────────────────────────
 *
 * A build with no repository behind it (Docker — `.dockerignore` drops `.git` — a source tarball,
 * a machine without git) has no commit, and that is a normal outcome. {@link describeBuildCommit}
 * returns `null` for it, and the Sobre screen renders a sentence saying the build carries no
 * provenance. It never invents a hash, never shows a placeholder that reads like a value, and
 * never leaves a silent empty row: an unreadable fact is a bug, a fact that quietly looks real is
 * an evidentiary one (memory: `reject-never-silently-transform`).
 *
 * The same `null` is returned for anything malformed. A truncated hash, an env override supplying
 * a branch name, a date without an offset — all rejected here rather than rendered. Half a
 * provenance is not provenance.
 *
 * ─── THE CODENAME ──────────────────────────────────────────────────────────────────────────────
 *
 * See {@link buildCodename}. It is a mnemonic, deliberately labelled in the UI as an internal
 * reference, and it is never the identifier: the hash sits in the same table, in full.
 */

/**
 * How much of the 40-character hash the short form shows.
 *
 * Twelve, computed here rather than taken from `git rev-parse --short`, so that BOTH sources —
 * a git build and an env-supplied one — abbreviate identically. `--short` picks its length from the
 * repository's own object count, which would make the displayed value depend on where the build ran.
 * Twelve hex digits is well past ambiguity for a repository of this size and still quotable aloud.
 */
const SHORT_HASH_LENGTH = 12;

/** A full git object name: 40 lowercase hex digits. Nothing shorter is accepted. */
const HASH_PATTERN = /^[0-9a-f]{40}$/;

/**
 * ISO 8601 with an EXPLICIT offset — what `git log --format=%cI` emits. The offset is required, not
 * optional: a wall-clock string with no zone is not a moment in time, and an operator quoting a
 * build in a support thread must be able to read one unambiguously.
 */
const COMMITTED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * The codename word list: sixty-four rock and mineral names, in alphabetical order.
 *
 * WHY THESE WORDS. Chancela is an evidentiary records product read by notaries and administrators,
 * so the register is quiet and the vocabulary carries no claim. Every entry names a rock or a
 * mineral — a plain noun, nothing playful, and above all nothing that could be read as an assurance
 * about the release. "Estável", "Final", "Certificado" and their kind are exactly what a codename
 * must never sound like: a codename that reads as a guarantee is worse than no codename at all.
 *
 * They stay Portuguese in every locale. A codename is a proper name, not copy — translating it
 * would mean the same build answered to fourteen different names, which defeats the point of having
 * one to quote (the same reasoning that keeps `platformDiagnosticCode()`'s triplet untranslated).
 *
 * The list is committed here rather than pulled from a package: sixty-four words do not warrant a
 * dependency, and a dependency could reword them under us.
 *
 * ORDER IS LOAD-BEARING. Entries are indexed by position, so inserting, removing or reordering a
 * word renames every build whose byte lands at or after it. Append at the end only if this ever
 * grows — and note that a length that is not a power of two makes the derivation below slightly
 * biased (harmless for a mnemonic, but say so rather than discover it).
 */
export const BUILD_CODENAMES = [
  'Ágata',
  'Alabastro',
  'Âmbar',
  'Ametista',
  'Andesito',
  'Anfibolito',
  'Ardósia',
  'Arenito',
  'Argilito',
  'Azurite',
  'Basalto',
  'Bauxite',
  'Berilo',
  'Calcário',
  'Calcedónia',
  'Cassiterite',
  'Citrino',
  'Conglomerado',
  'Coríndon',
  'Cornalina',
  'Diorito',
  'Dolerito',
  'Dolomite',
  'Epídoto',
  'Esteatite',
  'Feldspato',
  'Fluorite',
  'Fonólito',
  'Gabro',
  'Galena',
  'Gnaisse',
  'Grafite',
  'Granito',
  'Granodiorito',
  'Grauvaque',
  'Hematite',
  'Jaspe',
  'Lazurite',
  'Malaquita',
  'Mármore',
  'Micaxisto',
  'Migmatito',
  'Moscovite',
  'Obsidiana',
  'Olivina',
  'Ónix',
  'Opala',
  'Pegmatito',
  'Peridotito',
  'Pirite',
  'Quartzito',
  'Quartzo',
  'Riólito',
  'Rodonite',
  'Serpentinito',
  'Sienito',
  'Sílex',
  'Siltito',
  'Topázio',
  'Travertino',
  'Turmalina',
  'Xisto',
  'Zeólito',
  'Zircão',
] as const;

/**
 * The build's codename, derived from its commit hash. Same commit, same codename, always.
 *
 * ─── REPRODUCE IT BY HAND ──────────────────────────────────────────────────────────────────────
 *
 * 1. Take the FIRST TWO characters of the full 40-hex-digit commit hash — its first byte.
 * 2. Read them as a hexadecimal number: 0 to 255.
 * 3. Take the remainder modulo 64, the length of {@link BUILD_CODENAMES}.
 * 4. That is the index, counting from 0, into the alphabetical list above.
 *
 * Worked example: hash `744f82f2…` → `74` → 116 → 116 mod 64 = 52 → entry 52 → «Riólito».
 *
 * Only the first byte is consulted, and that is on purpose: a rule a reader can carry out in their
 * head beats one that mixes the whole hash and can only be checked by running this function. The
 * codename is a MNEMONIC — "the Riólito build" — and identity is carried by the hash beside it, so
 * the one-in-sixty-four chance that two builds share a name costs nothing.
 *
 * Returns `null` for anything that is not a full hash, so a malformed value produces no name at all
 * rather than an arbitrary one.
 */
export function buildCodename(hash: string): string | null {
  if (!HASH_PATTERN.test(hash)) {
    return null;
  }
  const firstByte = Number.parseInt(hash.slice(0, 2), 16);
  return BUILD_CODENAMES[firstByte % BUILD_CODENAMES.length];
}

/** The build's commit, validated and ready to render. */
export interface BuildProvenance {
  /** The full 40-hex-digit commit hash — the unambiguous form, always reachable on screen. */
  hash: string;
  /** The first {@link SHORT_HASH_LENGTH} characters of {@link hash}. */
  shortHash: string;
  /** The committer date, ISO 8601 with an explicit offset, exactly as git emitted it. */
  committedAt: string;
  /** The mnemonic from {@link buildCodename}. */
  codename: string;
}

/**
 * Validate the inlined build global into something renderable, or `null`.
 *
 * Takes `unknown` because the value crosses a build-time boundary: it is whatever
 * `vite.config.ts` wrote into the bundle, which deliberately does no checking of its own. Every
 * rejection path leads to the same honest outcome on screen.
 */
export function describeBuildCommit(raw: unknown): BuildProvenance | null {
  if (raw === null || typeof raw !== 'object') {
    return null;
  }
  const { hash, committedAt } = raw as { hash?: unknown; committedAt?: unknown };
  if (typeof hash !== 'string' || typeof committedAt !== 'string') {
    return null;
  }
  // Lower-cased so a hash supplied in upper case through the env override still matches the
  // pattern and still derives the same codename as the identical commit read from git.
  const normalizedHash = hash.trim().toLowerCase();
  const normalizedDate = committedAt.trim();
  const codename = buildCodename(normalizedHash);
  if (codename === null || !COMMITTED_AT_PATTERN.test(normalizedDate)) {
    return null;
  }
  return {
    hash: normalizedHash,
    shortHash: normalizedHash.slice(0, SHORT_HASH_LENGTH),
    committedAt: normalizedDate,
    codename,
  };
}

/** This build's provenance, or `null` when it was built without a repository behind it. */
export const BUILD_COMMIT: BuildProvenance | null = describeBuildCommit(__BUILD_COMMIT__);
