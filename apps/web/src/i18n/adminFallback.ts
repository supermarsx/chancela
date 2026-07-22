/**
 * "Administração" copy (t36) — the admin surface at `/admin` that hosts the operations panes and
 * the integrations subtabs (Grupos / Conectores / Repositórios ZK).
 *
 * **Why this module is self-contained, not spread into the 14 locale catalogs.** It follows the
 * exact precedent of {@link ./serverEnvFallback} and {@link ./operationsFallback}: the shared
 * catalogs move under a single-writer serial lock during the batch, so t36 owns its two keys end
 * to end and exposes its own locale-aware resolver ({@link useAdminT}) rather than adding the usual
 * per-locale import + spread wiring. Consumers read this copy exactly as they would through `useT`,
 * so nothing in the shared catalog moves and the catalog completeness / leak gates never see it.
 *
 * The map shape is deliberately identical to the sibling fallbacks (a pt-PT source object plus an
 * English fallback that `satisfies` its key set): folding these into the catalog later is a
 * mechanical spread and each consumer switches to `t()` with no copy changes.
 *
 * Only NEW copy lives here. The integrations subtab LABELS reuse the existing `operations.tabs.*`
 * catalog keys (the strip is rendered by SettingsPage in admin-surface mode), so they are not
 * duplicated here.
 *
 * Consumers:
 *  - the `/admin` nav glyph (t36-e3, `layout.tsx`) reads `nav.admin` for its `aria-label` + tooltip;
 *  - SettingsPage in admin-surface mode (t36-e2) reads `admin.title` for the page header.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const adminPtPT = {
  'nav.admin': 'Administração',
  'admin.title': 'Administração',
} as const;

/** The key set the Administração surface resolves through this module. */
export type AdminCopyKey = keyof typeof adminPtPT;

export const adminEnglish = {
  'nav.admin': 'Administration',
  'admin.title': 'Administration',
} as const satisfies Record<AdminCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the catalog spread performs, kept here while the catalogs are locked.
 */
export function useAdminCopy(): Record<AdminCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? adminPtPT : adminEnglish;
}

/**
 * The surface's translate hook, shaped like {@link useT}:
 * `const at = useAdminT(); at('admin.title')`. Supports the same `{placeholder}` interpolation.
 */
export function useAdminT(): (key: AdminCopyKey, params?: TParams) => string {
  const copy = useAdminCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
