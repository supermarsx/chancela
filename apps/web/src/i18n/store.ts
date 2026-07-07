/**
 * The i18n runtime store: the active locale, the loaded catalogs, and a
 * subscribe/notify channel so React re-renders when a locale flips or an async catalog
 * lands.
 *
 * pt-PT is present from the start (imported eagerly) and is the fallback for any key a
 * not-yet-resolved catalog cannot answer. Switching to another locale kicks off its
 * dynamic import; until it resolves, `message()` serves pt-PT, then swaps live once the
 * chunk lands. This is a module singleton so the non-React `t()` (used in the API
 * client and the enum-label shim) reads the same active locale as the hooks.
 */
import type { Locale } from '../api/types';
import { ptPT } from './locales/pt-PT';
import { LOCALE_LOADERS } from './registry';
import type { Catalog, MessageKey } from './types';

const SOURCE_LOCALE: Locale = 'pt-PT';

const catalogs = new Map<Locale, Catalog>([[SOURCE_LOCALE, ptPT]]);
const listeners = new Set<() => void>();
let activeLocale: Locale = SOURCE_LOCALE;
let version = 0;

function emit(): void {
  version += 1;
  for (const listener of listeners) listener();
}

/** Kick off the (idempotent) dynamic import for a locale; emit when it lands. */
function ensureCatalog(locale: Locale): void {
  if (catalogs.has(locale)) return;
  const loader = LOCALE_LOADERS[locale];
  if (!loader) return; // source or unregistered → pt-PT fallback stands
  void loader().then((catalog) => {
    catalogs.set(locale, catalog);
    if (locale === activeLocale) emit();
  });
}

export const i18nStore = {
  /** Subscribe to locale/catalog changes; returns an unsubscribe. */
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },

  /** Monotonic version — the `useSyncExternalStore` snapshot. */
  getVersion(): number {
    return version;
  },

  getActiveLocale(): Locale {
    return activeLocale;
  },

  /** Set the active locale, loading its catalog on demand; a no-op if unchanged. */
  setActiveLocale(locale: Locale): void {
    ensureCatalog(locale);
    if (locale === activeLocale) return;
    activeLocale = locale;
    emit();
  },

  /** Resolve a key for a locale, falling back to the pt-PT source. */
  message(locale: Locale, key: MessageKey): string {
    return catalogs.get(locale)?.[key] ?? ptPT[key];
  },
};
