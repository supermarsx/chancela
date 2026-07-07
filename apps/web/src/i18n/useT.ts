/**
 * The React binding for i18n.
 *
 * The active locale lives in the {@link i18nStore} (a module singleton). {@link
 * AppearanceEffects} — mounted once in the shell — reads the committed settings and
 * pushes the locale into the store, so a settings PUT that changes the locale swaps the
 * catalog LIVE app-wide with no reload. `useT`/`useActiveLocale` only SUBSCRIBE to the
 * store, so they work in any component without a QueryClient in scope (an isolated
 * component renders the source locale by default), and re-render both when the locale
 * flips and when a late-arriving async catalog lands.
 *
 * `t` (module-level) is the non-React escape hatch for code outside the component tree
 * (the API client's thrown messages, the enum-label shim in `api/labels.ts`); it reads
 * the same store active locale.
 */
import { useSyncExternalStore } from 'react';
import type { Locale } from '../api/types';
import { i18nStore } from './store';
import { interpolate, type TParams } from './interpolate';
import type { MessageKey, TFunction } from './types';

/** The active UI locale, tracked in the store (kept in sync by AppearanceEffects). */
export function useActiveLocale(): Locale {
  // The version snapshot bumps on both a locale change and an async catalog landing.
  useSyncExternalStore(i18nStore.subscribe, i18nStore.getVersion, i18nStore.getVersion);
  return i18nStore.getActiveLocale();
}

/** The translate hook: `const t = useT(); t('nav.dashboard')`. */
export function useT(): TFunction {
  const locale = useActiveLocale();
  return (key, params) => interpolate(i18nStore.message(locale, key), params);
}

/** Non-React translate, for code outside the component tree. */
export function t(key: MessageKey, params?: TParams): string {
  return interpolate(i18nStore.message(i18nStore.getActiveLocale(), key), params);
}
