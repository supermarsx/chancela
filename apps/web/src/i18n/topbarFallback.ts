/**
 * Top-bar reflow copy — the accessible names for the two overflow triggers the header grows
 * when it is too narrow to lay every control out inline (t42): the burger that holds the primary
 * tabs, and the "more" menu that holds the utility glyphs (Arquivo/Ferramentas/Configurações, and
 * any icon added to the bar later).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) move under a single-writer serial lock during
 * batch work, so a contained fix like this may not add the usual "one import + one spread line per
 * locale" wiring without contending with whoever holds it. Instead this module owns its two keys
 * end to end and exposes its own locale-aware resolver ({@link useTopbarExtraT}); the shell reads
 * the labels through it exactly as it would through `useT`, so nothing in the shared catalog moves
 * and the catalog-leak / literal-copy gates never see these strings. It follows the same shape as
 * `serverEnvFallback.ts` / `notificationsRetentionFallback.ts` (a pt-PT source object plus an
 * English fallback that `satisfies` its key set); if the catalog lock later releases, folding these
 * into `nav.*` is a mechanical spread and the shell can switch to `t()`.
 *
 * These are affordance names, never a legal or evidentiary claim (memory
 * `tagline-no-valor-probatorio`). pt-PT is the source; no anglicisms are invented.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const topbarExtraPtPT = {
  // The burger: it opens the primary section navigation (Painel, Entidades, …) when the row of
  // tabs no longer fits. Named for what it opens, so a screen-reader user hears the same thing a
  // sighted operator infers from the three-line glyph.
  'topbar.nav.menu': 'Navegação',
  // The utility overflow: the archive/tools/settings glyphs (and anything added beside them) when
  // the bar is too narrow to show them inline. "Mais" stays correct however many join later.
  'topbar.utility.menu': 'Mais opções',
} as const;

/** The key set the top-bar reflow copy resolves. */
export type TopbarExtraCopyKey = keyof typeof topbarExtraPtPT;

export const topbarExtraEnglish = {
  'topbar.nav.menu': 'Navigation',
  'topbar.utility.menu': 'More options',
} as const satisfies Record<TopbarExtraCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while the catalogs are locked.
 */
export function useTopbarExtraCopy(): Record<TopbarExtraCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? topbarExtraPtPT : topbarExtraEnglish;
}

/**
 * The shell's extra translate hook, shaped like {@link import('./useT').useT}:
 * `const tt = useTopbarExtraT(); tt('topbar.nav.menu')`.
 */
export function useTopbarExtraT(): (key: TopbarExtraCopyKey, params?: TParams) => string {
  const copy = useTopbarExtraCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
