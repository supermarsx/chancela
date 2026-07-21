/**
 * Locale negotiation for the `auto` language preference (t71).
 *
 * ## Why this file exists
 * Before t71 the product had **no** language detection at all: the active locale came solely from
 * the instance-wide `settings.documents.locale`. A user preference of `auto` therefore has to mean
 * something real, or a control labelled "detect automatically" pins people to the instance language
 * forever — a control that lies, which is worse than one that does nothing.
 *
 * ## The order, and why each step is needed
 *  1. **Exact tag** — `de-DE` from the browser matches shipped `de-DE`.
 *  2. **Primary subtag** — browsers commonly send bare `sv`, `de`, `pt`, or a region we do not ship
 *     (`en-AU`). Without this step every one of those misses and falls through to the floor, so a
 *     Swedish reader would get Portuguese. This is the step that makes detection actually work.
 *  3. **The next entry** in the caller's preference list, repeating 1–2, before giving up.
 *  4. **The floor** — the instance default.
 *
 * ## Ambiguous primary subtags are resolved by an EXPLICIT table
 * `sv` could be `sv-SE` or `sv-FI`; `en` could be `en-GB` or `en-US`; `pt` could be `pt-PT` or
 * `pt-BR`. Resolving those by "first match in `SHIPPED_LOCALES`" would make the answer depend on
 * the key order of the `LOCALE_QUALITY` object literal — so alphabetising that map, an edit with no
 * apparent behavioural content, would silently move which Swedish a Swede gets.
 * {@link REGION_DEFAULT} states the choice instead, so changing it is a visible decision.
 *
 * ## Translation quality does NOT gate detection — deliberate, and on the record
 * Eleven of the fourteen catalogs are machine-translated pending native review, and there is a real
 * argument that detection should only land on the reviewed ones (pt-PT, en-GB, en-US) because
 * choosing machine translation knowingly differs from being dropped into it by your browser
 * headers. We allow all shipped locales anyway, for two reasons: the instance-wide setting already
 * selects any of them with no quality gate, so gating only here would be inconsistent; and handing
 * a German reader Portuguese because our German is unreviewed is a worse outcome than handing them
 * flagged German. {@link DETECTABLE_LOCALES} is the single place to reverse this.
 */
import type { Locale } from '../api/types';
import { SHIPPED_LOCALES } from './registry';

/**
 * Which locale a bare primary subtag resolves to, where we ship more than one region for it.
 * Stated explicitly so the answer never depends on `SHIPPED_LOCALES` ordering.
 *
 * `pt` → `pt-PT` and `en` → `en-GB`: this is a Portuguese product whose source locale is pt-PT and
 * whose legal domain is Portuguese, so the European variants are the better default for a reader
 * who did not express a region.
 */
export const REGION_DEFAULT: Partial<Record<string, Locale>> = {
  pt: 'pt-PT',
  en: 'en-GB',
  sv: 'sv-SE',
};

/** Locales that automatic detection may select. See the note on translation quality above. */
export const DETECTABLE_LOCALES: readonly Locale[] = SHIPPED_LOCALES;

function isDetectable(locale: string): locale is Locale {
  return (DETECTABLE_LOCALES as readonly string[]).includes(locale);
}

/** Resolve one BCP-47 tag to a shipped locale, or `null` if nothing matches. */
function matchTag(tag: string): Locale | null {
  const trimmed = tag.trim();
  if (trimmed === '') return null;

  // 1. Exact, case-insensitively — browsers may send `pt-pt`.
  const exact = DETECTABLE_LOCALES.find((l) => l.toLowerCase() === trimmed.toLowerCase());
  if (exact) return exact;

  // 2. Primary subtag: the explicit choice first, then any shipped locale in that language.
  const primary = trimmed.split(/[-_]/)[0]?.toLowerCase() ?? '';
  if (primary === '') return null;
  const preferred = REGION_DEFAULT[primary];
  if (preferred && isDetectable(preferred)) return preferred;
  return DETECTABLE_LOCALES.find((l) => l.toLowerCase().split('-')[0] === primary) ?? null;
}

/**
 * Pick the best shipped locale for `preferred` (most-wanted first, e.g. `navigator.languages`),
 * falling back to `floor`.
 *
 * `floor` is the instance's `settings.documents.locale`. Note that setting is the language
 * **generated legal instruments are written in**; it is used here only as the last resort for the
 * UI, and negotiation never writes back to it — see `preserves the document locale` in the tests.
 */
export function negotiateLocale(preferred: readonly string[], floor: Locale): Locale {
  for (const tag of preferred) {
    const match = matchTag(tag);
    if (match) return match;
  }
  return floor;
}

/**
 * The browser's ordered language preferences, or `[]` where there is no browser (SSR, tests,
 * a server-rendered document or e-mail). An empty list makes {@link negotiateLocale} return the
 * floor, which is exactly the server-side rule.
 */
export function browserLanguages(): readonly string[] {
  if (typeof navigator === 'undefined') return [];
  if (Array.isArray(navigator.languages) && navigator.languages.length > 0) {
    return navigator.languages;
  }
  return navigator.language ? [navigator.language] : [];
}
