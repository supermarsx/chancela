/**
 * Atas-list search + filter copy (t47) — the search box, state/channel filters, result count and
 * filtered-empty note above a book's atas table, brought to parity with the books list filter bar.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are coordinated additively across several in-flight
 * tasks, so rather than take the shared "one import + one spread line per locale" wiring under a lock
 * for a handful of strings, this copy owns its keys end to end and exposes its own locale-aware
 * resolver ({@link useAtasFilterT}). The atas table reads it exactly as it would through `useT`, so
 * nothing in the shared catalog moves and the catalog-leak / literal-copy gates never see these
 * strings. It follows the shape of `actLifecycleFallback.ts` / `tableColumnsFallback.ts` (a pt-PT
 * source object plus an English fallback that `satisfies` the key set); folding these into the
 * catalog later is a mechanical spread.
 *
 * Copy already in the catalog is reused directly by the component (`books.th.*` for the column
 * headers, `books.filters.search.label` / `books.filters.state.*` / `books.filters.count` /
 * `books.filters.empty.title` for the generic filter chrome, `common.open` for the row action) — only
 * genuinely new, atas-specific strings live here.
 *
 * pt-PT is the source; no anglicisms are invented, and nothing here makes an evidentiary claim (a
 * search or filter is disposable view state, memory `tagline-no-valor-probatorio`).
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const atasFilterPtPT = {
  'acts.filters.aria': 'Pesquisar e filtrar atas',
  'acts.filters.search.placeholder': 'Número, título, canal ou estado',
  'acts.filters.channel.all': 'Todos os canais',
  'acts.filters.clear.aria': 'Limpar filtros de atas',
  'acts.filters.count.aria': 'A mostrar {shown} de {total} atas',
  'acts.filters.empty.body': 'Altere a pesquisa ou os filtros para voltar a ver atas.',
} as const;

/** The key set the atas filter copy resolves. */
export type AtasFilterCopyKey = keyof typeof atasFilterPtPT;

export const atasFilterEnglish = {
  'acts.filters.aria': 'Search and filter minutes',
  'acts.filters.search.placeholder': 'Number, title, channel or state',
  'acts.filters.channel.all': 'All channels',
  'acts.filters.clear.aria': 'Clear minutes filters',
  'acts.filters.count.aria': 'Showing {shown} of {total} minutes',
  'acts.filters.empty.body': 'Change the search or filters to see minutes again.',
} as const satisfies Record<AtasFilterCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useAtasFilterCopy(): Record<AtasFilterCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? atasFilterPtPT : atasFilterEnglish;
}

/**
 * The atas table's extra translate hook, shaped like {@link useT}:
 * `const at = useAtasFilterT(); at('acts.filters.search.placeholder')`.
 */
export function useAtasFilterT(): (key: AtasFilterCopyKey, params?: TParams) => string {
  const copy = useAtasFilterCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
