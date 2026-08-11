/**
 * Client-side code → catalog-key map for the **durable Trusted List cache fallback** marker.
 *
 * # Why a map rather than server prose
 *
 * Same reason as `tslWeakAlgorithms.ts`, and it applies with more force here. The backend emits a
 * stable `code` plus three timestamps and nothing translatable, because `noLiteralUiCopy` and
 * `catalogLeakGate` inspect the web app and are blind by construction to a sentence that arrives
 * over the wire — a server-authored English string would reach a Portuguese operator with no gate
 * able to see it. The wording lives here, in all fourteen catalogs.
 *
 * # The one distinction the wording must preserve
 *
 * Inside the list's own `NextUpdate`, a cached copy is not a compromise: the scheme operator's own
 * document says the list is valid until then, and a Trusted List is *designed* to be cached until
 * it. Past `NextUpdate` it is a different fact — a trust service the scheme operator has withdrawn
 * since can still read as granted on it — and that is the whole reason this marker exists. Two
 * codes, two sentences, two tones; collapsing them would either cry wolf on the ordinary case or
 * whisper through the one that matters.
 *
 * The completeness guard is `tslCacheFallback.test.ts`, which reads `ALL_TSL_CACHE_CODES` out of
 * `crates/chancela-tsl/src/disk_cache.rs` and proves the closed set is exactly what is mapped here,
 * so a backend-added code fails loudly instead of rendering a blank.
 */
import { TSL_CACHE_FALLBACK_CODES } from '../api/types';
import type { TslCacheFallbackCode, TslCacheFallbackView } from '../api/types';
import type { MessageKey } from './types';

/** Every cache-fallback code the server can emit, mapped to the sentence describing what happened. */
export const TSL_CACHE_FALLBACK_SENTENCE_KEYS: Record<TslCacheFallbackCode, MessageKey> = {
  tsl_served_from_cache: 'trust.cacheFallback.withinValidity',
  tsl_served_from_stale_cache: 'trust.cacheFallback.pastValidity',
};

/** Every cache-fallback code, mapped to the short badge it earns in the status line. */
export const TSL_CACHE_FALLBACK_BADGE_KEYS: Record<TslCacheFallbackCode, MessageKey> = {
  tsl_served_from_cache: 'trust.cacheFallback.badge.cached',
  tsl_served_from_stale_cache: 'trust.cacheFallback.badge.stale',
};

/** Whether this is a cache-fallback code this build knows how to word. */
export function isKnownCacheFallbackCode(code: string): code is TslCacheFallbackCode {
  return (TSL_CACHE_FALLBACK_CODES as readonly string[]).includes(code);
}

/**
 * The catalog key for a fallback's sentence, or `undefined` for a code this build does not know.
 *
 * `undefined` is a real outcome, not a defect to paper over: a server newer than this bundle can
 * emit a code that did not exist when these translations were written. The caller renders
 * `trust.cacheFallback.unknown` in its place — which still says the verdict came from a cached
 * list, because that much is certain from the marker's mere presence. Falling back to *silence*
 * would turn a newer backend into a missing warning.
 */
export function cacheFallbackSentenceKey(code: string): MessageKey | undefined {
  return isKnownCacheFallbackCode(code) ? TSL_CACHE_FALLBACK_SENTENCE_KEYS[code] : undefined;
}

/** The badge key for a fallback, or `undefined` for an unrecognised code. */
export function cacheFallbackBadgeKey(code: string): MessageKey | undefined {
  return isKnownCacheFallbackCode(code) ? TSL_CACHE_FALLBACK_BADGE_KEYS[code] : undefined;
}

/**
 * Whether a fallback should be presented as a warning rather than as information.
 *
 * Driven by the backend's `stale` boolean, not by the code, so a code this build does not recognise
 * still lands on the cautious side whenever the server said the copy was stale.
 */
export function isStaleCacheFallback(fallback: TslCacheFallbackView | undefined | null): boolean {
  return fallback?.stale === true;
}
