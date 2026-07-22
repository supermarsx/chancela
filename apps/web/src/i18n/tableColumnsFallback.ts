/**
 * Configurable-table copy (t37) — the per-user column pickers on the entities and books tables,
 * plus the reworded hint on the Settings entities-column card (now the *org default*, layered under
 * a personal override).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) sit under a single-writer serial lock during the
 * batch, so t37 may not add the usual "one import + one spread line per locale" wiring. This module
 * owns its keys end to end and exposes its own locale-aware resolver ({@link useTableColumnsT}); a
 * page reads copy through it exactly as through `useT`, so nothing in the shared catalog moves and
 * the catalog-leak / literal-copy gates never see these strings. It follows the same shape as
 * `notificationsRetentionFallback.ts` (a pt-PT source object plus an English fallback that
 * `satisfies` its key set); folding these into the catalog later is a mechanical spread.
 *
 * Copy that already exists in the catalog is reused directly by the pages (`books.th.*` for the book
 * column labels, `templates.columns.*` for the templates picker, the entity column labels for the
 * entities picker) — only genuinely new strings live here.
 *
 * pt-PT is the source; no anglicisms are invented, and nothing here makes an evidentiary claim (a
 * column choice is disposable UI state, memory `tagline-no-valor-probatorio`).
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const tableColumnsPtPT = {
  // — Selector de colunas (por utilizador) ————————————————————————————————
  'tableColumns.summary': 'Colunas',
  'tableColumns.entities.hint':
    'Escolha as colunas visíveis na sua lista de entidades. A escolha fica guardada na sua conta e acompanha-o em qualquer dispositivo.',
  'tableColumns.books.hint':
    'Escolha as colunas visíveis na lista de livros. A escolha fica guardada na sua conta e acompanha-o em qualquer dispositivo.',

  // — Cartão de definições: agora a predefinição da organização ——————————————
  'tableColumns.entities.orgDefaultHint':
    'As colunas que os novos utilizadores veem por predefinição na lista de entidades. Cada utilizador pode depois personalizar as suas próprias colunas na página de entidades.',
} as const;

/** The key set the configurable-table copy resolves. */
export type TableColumnsCopyKey = keyof typeof tableColumnsPtPT;

export const tableColumnsEnglish = {
  'tableColumns.summary': 'Columns',
  'tableColumns.entities.hint':
    'Choose which columns show in your entities list. Your choice is saved to your account and follows you across devices.',
  'tableColumns.books.hint':
    'Choose which columns show in the books list. Your choice is saved to your account and follows you across devices.',
  'tableColumns.entities.orgDefaultHint':
    'The columns new users see by default in the entities list. Each user can then personalise their own columns on the entities page.',
} as const satisfies Record<TableColumnsCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while the catalogs are locked.
 */
export function useTableColumnsCopy(): Record<TableColumnsCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? tableColumnsPtPT : tableColumnsEnglish;
}

/**
 * The pages' extra translate hook, shaped like {@link useT}:
 * `const ct = useTableColumnsT(); ct('tableColumns.summary')`.
 */
export function useTableColumnsT(): (key: TableColumnsCopyKey, params?: TParams) => string {
  const copy = useTableColumnsCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
