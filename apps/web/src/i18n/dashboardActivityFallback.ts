/**
 * "Atividade recente" badge copy (t54) — the category chips the dashboard's activity feed
 * (`RecentActivity` in `DashboardPage.tsx`) puts beside each event once the feed was broadened
 * beyond act/book/entity to every navigable ledger scope (user/role, administration, and the
 * Ferramentas surfaces). The three original chips — Ata / Livro / Entidade — stay in the shared
 * catalog under `dashboard.activity.kind.*`; only the NEW grouping labels live here.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are edited additively by several in-flight tasks
 * under a shared lock, so t54's handful of new chip labels own their keys end to end and expose
 * their own locale-aware resolver ({@link useDashboardActivityT}). `RecentActivity` reads them
 * exactly as it would through `useT`, so nothing in the shared catalog moves and the catalog-leak /
 * literal-copy gates never see these strings. It follows the shape of `atasFilterFallback.ts` /
 * `actBodyFallback.ts` (a pt-PT source object plus an English fallback that `satisfies` the key
 * set); folding these into the catalog later is a mechanical spread.
 *
 * Copy rule: these are plain category nouns, not claims. pt-PT is the source; no anglicisms are
 * invented ("Utilizador", "Administração", "Ferramentas" are the real pt-PT surface names).
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const dashboardActivityPtPT = {
  // People and access: user:{id}, the user-accounts surface, and RBAC roles.
  'dashboard.activity.category.user': 'Utilizador',
  // Administração: settings, repositories, provider credentials, platform/backup/e-mail/API keys,
  // chain recovery and the book archive — everything that lands on an admin/settings/archive surface.
  'dashboard.activity.category.admin': 'Administração',
  // Ferramentas: legislation, CAE and the trust list.
  'dashboard.activity.category.tools': 'Ferramentas',
} as const;

/** The key set the activity-category copy resolves. */
export type DashboardActivityCopyKey = keyof typeof dashboardActivityPtPT;

export const dashboardActivityEnglish = {
  'dashboard.activity.category.user': 'User',
  'dashboard.activity.category.admin': 'Administration',
  'dashboard.activity.category.tools': 'Tools',
} as const satisfies Record<DashboardActivityCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useDashboardActivityCopy(): Record<DashboardActivityCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? dashboardActivityPtPT : dashboardActivityEnglish;
}

/**
 * The activity feed's extra translate hook, shaped like {@link useT}:
 * `const at = useDashboardActivityT(); at('dashboard.activity.category.user')`.
 */
export function useDashboardActivityT(): (
  key: DashboardActivityCopyKey,
  params?: TParams,
) => string {
  const copy = useDashboardActivityCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
