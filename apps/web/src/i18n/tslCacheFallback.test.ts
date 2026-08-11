/**
 * Completeness contract for the durable Trusted List cache-fallback surface.
 *
 * `tsc` already proves every value in the two maps is a real `MessageKey`. This proves the OTHER
 * direction — that they cover exactly what the SERVER can emit — by reading `ALL_TSL_CACHE_CODES`
 * out of `crates/chancela-tsl/src/disk_cache.rs`. Same shape and same reason as
 * `tslWeakAlgorithms.test.ts`.
 *
 * That direction is the one that matters here. A code added on the backend without a sentence would
 * render the generic "this version does not recognise it" fallback forever — and for the stale arm
 * that means an operator being told a cached list was used without being told it had expired, which
 * is the entire point of the marker. Neither `noLiteralUiCopy` nor `catalogLeakGate` can see it:
 * both inspect the web app and are blind by construction to what arrives over the wire.
 *
 * It also pins the two things that would make the guard hollow:
 *
 *  - **non-vacuity** — the extraction must actually match something, and must not silently halve;
 *  - **all 14 locales** must carry every key, not just the en-US source the compiler checks.
 */
import { describe, expect, it } from 'vitest';
import {
  TSL_CACHE_FALLBACK_BADGE_KEYS,
  TSL_CACHE_FALLBACK_SENTENCE_KEYS,
  cacheFallbackBadgeKey,
  cacheFallbackSentenceKey,
  isKnownCacheFallbackCode,
  isStaleCacheFallback,
} from './tslCacheFallback';
import { TSL_CACHE_FALLBACK_CODES } from '../api/types';
import type { TslCacheFallbackView } from '../api/types';
import { daDK } from './locales/da-DK';
import { deDE } from './locales/de-DE';
import { enGB } from './locales/en-GB';
import { enUS } from './locales/en-US';
import { esES } from './locales/es-ES';
import { fiFI } from './locales/fi-FI';
import { frFR } from './locales/fr-FR';
import { itIT } from './locales/it-IT';
import { nlNL } from './locales/nl-NL';
import { plPL } from './locales/pl-PL';
import { ptBR } from './locales/pt-BR';
import { ptPT } from './locales/pt-PT';
import { svFI } from './locales/sv-FI';
import { svSE } from './locales/sv-SE';

/** Every shipped catalog: the en-US source plus the 13 translations. */
const ALL_CATALOGS: Record<string, Record<string, string>> = {
  'en-US': enUS,
  'en-GB': enGB,
  'pt-PT': ptPT,
  'pt-BR': ptBR,
  'da-DK': daDK,
  'de-DE': deDE,
  'es-ES': esES,
  'fi-FI': fiFI,
  'fr-FR': frFR,
  'it-IT': itIT,
  'nl-NL': nlNL,
  'pl-PL': plPL,
  'sv-FI': svFI,
  'sv-SE': svSE,
};

/** Every key this surface can ask a catalog for, including the ones it renders unconditionally. */
const EVERY_KEY = [
  ...Object.values(TSL_CACHE_FALLBACK_SENTENCE_KEYS),
  ...Object.values(TSL_CACHE_FALLBACK_BADGE_KEYS),
  'trust.cacheFallback.label',
  'trust.cacheFallback.title',
  'trust.cacheFallback.title.stale',
  'trust.cacheFallback.fetchedAt',
  'trust.cacheFallback.expiresAt',
  'trust.cacheFallback.servedAt',
  'trust.cacheFallback.reason',
  'trust.cacheFallback.unknown',
] as const;

/** The `ALL_TSL_CACHE_CODES` set, read out of the Rust source that owns it. */
async function rustCodes(): Promise<string[]> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  const source = readFileSync('../../crates/chancela-tsl/src/disk_cache.rs', 'utf8');

  const declarations = new Map<string, string>();
  for (const match of source.matchAll(/pub const (CODE_TSL_[A-Z0-9_]+): &str = "([^"]+)";/gu)) {
    declarations.set(match[1], match[2]);
  }

  const list = source.match(/pub const ALL_TSL_CACHE_CODES: &\[&str\] =\s*&\[([^\]]*)\];/u);
  expect(list, 'ALL_TSL_CACHE_CODES not found in disk_cache.rs').toBeTruthy();
  // Resolve THROUGH the constants, so a code declared and never listed — or listed under a name
  // that does not exist — is a loud failure rather than a silent omission.
  return list![1]
    .split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0)
    .map((name) => {
      const value = declarations.get(name);
      expect(value, `ALL_TSL_CACHE_CODES names ${name}, which is not declared`).toBeTruthy();
      return value!;
    });
}

describe('the closed code set is read from the Rust source, not restated', () => {
  it('extracts a non-vacuous set (a broken regex must not make this pass over nothing)', async () => {
    const codes = await rustCodes();
    // Two codes today; append-only, so a floor rather than equality.
    expect(codes.length).toBeGreaterThanOrEqual(2);
    for (const code of codes) expect(code.startsWith('tsl_served_from')).toBe(true);
  });

  it('words exactly the codes the cache can emit', async () => {
    const codes = await rustCodes();
    expect([...TSL_CACHE_FALLBACK_CODES].sort()).toEqual([...codes].sort());
    expect(Object.keys(TSL_CACHE_FALLBACK_SENTENCE_KEYS).sort()).toEqual([...codes].sort());
    expect(Object.keys(TSL_CACHE_FALLBACK_BADGE_KEYS).sort()).toEqual([...codes].sort());
    for (const code of codes) {
      expect(isKnownCacheFallbackCode(code)).toBe(true);
      expect(cacheFallbackSentenceKey(code)).toBeTruthy();
      expect(cacheFallbackBadgeKey(code)).toBeTruthy();
    }
  });

  it('keeps the two arms saying different things', () => {
    // Collapsing them would either cry wolf on a cached-but-valid list or whisper through an
    // expired one. Distinct keys is what stops a later edit from merging them by accident.
    expect(TSL_CACHE_FALLBACK_SENTENCE_KEYS.tsl_served_from_cache).not.toBe(
      TSL_CACHE_FALLBACK_SENTENCE_KEYS.tsl_served_from_stale_cache,
    );
    expect(TSL_CACHE_FALLBACK_BADGE_KEYS.tsl_served_from_cache).not.toBe(
      TSL_CACHE_FALLBACK_BADGE_KEYS.tsl_served_from_stale_cache,
    );
  });
});

describe('an unrecognised code still warns', () => {
  it('returns undefined rather than throwing, so the caller can word the generic case', () => {
    expect(isKnownCacheFallbackCode('tsl_served_from_a_future_thing')).toBe(false);
    expect(cacheFallbackSentenceKey('tsl_served_from_a_future_thing')).toBeUndefined();
    expect(cacheFallbackBadgeKey('tsl_served_from_a_future_thing')).toBeUndefined();
  });

  it('takes staleness from the backend boolean, not from the code it may not know', () => {
    const unknownButStale = {
      code: 'tsl_served_from_a_future_thing',
      stale: true,
      fetched_at: '2026-01-15T00:00:00Z',
      expires_at: '2026-07-15T00:00:00Z',
      served_at: '2026-07-24T00:00:00Z',
      fetch_error: 'dns error',
    } as unknown as TslCacheFallbackView;
    expect(isStaleCacheFallback(unknownButStale)).toBe(true);
    expect(isStaleCacheFallback(undefined)).toBe(false);
    expect(isStaleCacheFallback(null)).toBe(false);
  });
});

describe('every locale carries the wording', () => {
  it.each(Object.entries(ALL_CATALOGS))('%s translates every cache-fallback key', (_, catalog) => {
    for (const key of EVERY_KEY) {
      expect(catalog[key], `${key} missing`).toBeTruthy();
      expect(catalog[key]!.trim().length, `${key} blank`).toBeGreaterThan(0);
    }
  });

  it('never interpolates a value into these sentences', () => {
    // The timestamps and the transport error are rendered as their own tokens beside the sentence,
    // never dropped into a clause whose article or adjective would have to agree with them. A
    // placeholder appearing here is that mistake arriving.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const key of EVERY_KEY) {
        expect(catalog[key], `${locale} interpolates into ${key}`).not.toMatch(/\{[^}]+\}/u);
      }
    }
  });
});
