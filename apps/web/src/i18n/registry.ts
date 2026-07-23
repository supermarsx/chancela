/**
 * The locale manifest: which locales ship, at what translation quality, and how each
 * non-source catalog is loaded.
 *
 * Bundle policy: pt-PT is inlined (the eager fallback, imported by the store); every
 * other locale — en-US included — is code-split behind a dynamic `import()` so a session
 * downloads only the catalog it switches to. Vite emits one chunk per locale file. The
 * eager locale is a UX/bundle choice and is deliberately decoupled from the authoring
 * source (t40 Option A): English is the source, pt-PT is still the primary-market default.
 *
 * Quality tiers (the honesty ledger, mirrored in TRANSLATIONS.md):
 *  - `source`  — en-US, the authoring source of truth; its keys define `MessageKey` (t40).
 *  - `human`   — pt-PT (the original hand-authored UI copy, still the eager runtime
 *                fallback) and en-GB, authored by hand (t19-e3a).
 *  - `machine` — the remaining 11, good-faith machine translations pending native
 *                review, authored by t19-e3b/e3c. They ship complete (the `Catalog`
 *                type guarantees it) and are clearly flagged as pending.
 */
import type { Locale } from '../api/types';
import type { Catalog } from './types';

export type TranslationQuality = 'source' | 'human' | 'machine';

/** Every supported locale and its translation quality (the shipped-locale manifest). */
export const LOCALE_QUALITY: Record<Locale, TranslationQuality> = {
  'en-US': 'source',
  'pt-PT': 'human',
  'en-GB': 'human',
  'pt-BR': 'machine',
  'da-DK': 'machine',
  'de-DE': 'machine',
  'fr-FR': 'machine',
  'fi-FI': 'machine',
  'sv-FI': 'machine',
  'it-IT': 'machine',
  'nl-NL': 'machine',
  'pl-PL': 'machine',
  'sv-SE': 'machine',
  'es-ES': 'machine',
};

/** All shipped locales (the completeness matrix iterates this set). */
export const SHIPPED_LOCALES = Object.keys(LOCALE_QUALITY) as Locale[];

/**
 * Dynamic-import loader per non-source locale. pt-PT is intentionally absent — it is
 * inlined by the store as the fallback. A locale without a loader falls back to pt-PT.
 */
export const LOCALE_LOADERS: Partial<Record<Locale, () => Promise<Catalog>>> = {
  'en-US': () => import('./locales/en-US').then((m) => m.enUS),
  'en-GB': () => import('./locales/en-GB').then((m) => m.enGB),
  'pt-BR': () => import('./locales/pt-BR').then((m) => m.ptBR),
  'da-DK': () => import('./locales/da-DK').then((m) => m.daDK),
  'de-DE': () => import('./locales/de-DE').then((m) => m.deDE),
  'fr-FR': () => import('./locales/fr-FR').then((m) => m.frFR),
  'fi-FI': () => import('./locales/fi-FI').then((m) => m.fiFI),
  'sv-FI': () => import('./locales/sv-FI').then((m) => m.svFI),
  'it-IT': () => import('./locales/it-IT').then((m) => m.itIT),
  'nl-NL': () => import('./locales/nl-NL').then((m) => m.nlNL),
  'pl-PL': () => import('./locales/pl-PL').then((m) => m.plPL),
  'sv-SE': () => import('./locales/sv-SE').then((m) => m.svSE),
  'es-ES': () => import('./locales/es-ES').then((m) => m.esES),
};
