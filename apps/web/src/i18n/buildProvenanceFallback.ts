/**
 * BUILD-PROVENANCE COPY (t100) — the row labels for the commit, commit date and codename that
 * Settings → «Sobre» gained, and the sentence it shows when the build carries none of them.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>` and TOTAL over 14 locales, so six keys folded into the
 * catalog would be 84 edits across files several live lanes are serialised on. This is the
 * established escape valve — `platformServiceFallback.ts`, `retentionNextStepFallback.ts`,
 * `serverEnvFallback.ts` and ~20 siblings: a pt-PT source object plus an English tier that
 * `satisfies` the same key set, behind a locale-aware resolver shaped like `useT`. A copy change
 * here moves 2 places in 1 file. If the catalog lock ever releases, folding these in is a
 * mechanical spread and the component switches to `t()` with no copy changes.
 *
 * ─── WHAT THE COPY MUST NOT DO ─────────────────────────────────────────────────────────────────
 *
 * The codename is an INTERNAL REFERENCE and the copy says so outright, in its own sentence, so
 * nobody reads «Riólito» as a product name, a support identifier or a release designation. The
 * unavailable sentence states plainly that this build carries no provenance, rather than leaving a
 * dash that would read like data.
 *
 * Every entry is a complete standalone label or sentence and none interpolates a noun into an
 * inflected phrase (memory: `i18n-interpolated-nouns-break-agreement`). pt-PT, never pt-BR, and no
 * invented anglicisms (memory: `pt-pt-no-invented-anglicisms`) — «commit» is git's own term of art,
 * borrowed unchanged as Portuguese technical usage already borrows it, not a coined word.
 *
 * The values themselves — hash, date, codename — are NOT copy and are not translated. See
 * `features/settings/buildProvenance.ts`.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';

export const buildProvenancePtPT = {
  /** Row label for the commit hash. The cell carries the short form and the full one beneath it. */
  'settings.about.build.commit': 'Commit da compilação',
  /** Row label for the committer date. */
  'settings.about.build.committedAt': 'Data do commit',
  /** Row label for the codename. */
  'settings.about.build.codename': 'Nome de código',
  /** The disclaimer under the codename — the whole reason the codename is safe to show. */
  'settings.about.build.codenameNote':
    'Referência interna a esta compilação. Não é o nome do produto nem a versão do produto.',
  /** Row label used INSTEAD of the three above when the build has no provenance. */
  'settings.about.build.provenance': 'Proveniência da compilação',
  /** The honest empty state: no hash was recorded, and the row says so. */
  'settings.about.build.unavailable':
    'Esta compilação não foi feita a partir de um repositório, pelo que não regista nenhum commit.',
} as const;

/** The key set the build-provenance rows resolve. */
export type BuildProvenanceCopyKey = keyof typeof buildProvenancePtPT;

/** English tier, served to the other 13 locales. */
export const buildProvenanceEnglish = {
  'settings.about.build.commit': 'Build commit',
  'settings.about.build.committedAt': 'Commit date',
  'settings.about.build.codename': 'Codename',
  'settings.about.build.codenameNote':
    'An internal reference to this build. It is not the product name and not the product version.',
  'settings.about.build.provenance': 'Build provenance',
  'settings.about.build.unavailable':
    'This build was not made from a repository, so it records no commit.',
} as const satisfies Record<BuildProvenanceCopyKey, string>;

/** The active copy tier: pt-PT gets the reviewed labels, every other locale gets English. */
export function useBuildProvenanceCopy(): Record<BuildProvenanceCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? buildProvenancePtPT : buildProvenanceEnglish;
}

/**
 * The rows' translate hook, shaped like `useT`: `const bt = useBuildProvenanceT();
 * bt('settings.about.build.codename')`. No key here takes a placeholder, so there is no
 * interpolation to do.
 */
export function useBuildProvenanceT(): (key: BuildProvenanceCopyKey) => string {
  const copy = useBuildProvenanceCopy();
  return useMemo(() => (key: BuildProvenanceCopyKey) => copy[key], [copy]);
}
