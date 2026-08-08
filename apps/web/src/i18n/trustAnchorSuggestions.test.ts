/**
 * Completeness contract for the trust-anchor suggestion codes (t118).
 *
 * `tsc` already proves every value in `TRUST_ANCHOR_SUGGESTION_KEYS` is a real `MessageKey`. This
 * test proves the OTHER direction — that the map covers exactly what the SERVER can emit — by
 * reading the closed code list out of
 * `crates/chancela-api/src/trust_anchor_suggestion_codes.rs`, exactly as
 * `providerProbeDiagnostics.test.ts` does for the probe vocabulary.
 *
 * That direction is the one that matters here, and rather more than it does for the probe: this
 * endpoint sends NO English sentence alongside the code. A code the client does not know has
 * nothing to fall back to, so it renders as a raw snake_case identifier where a warning about the
 * root of trust should be.
 */
import { describe, expect, it } from 'vitest';
import { TRUST_ANCHOR_SUGGESTION_KEYS, trustAnchorSuggestionKey } from './trustAnchorSuggestions';
import { ptPT } from './locales/pt-PT';
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

const PREFIX = 'settings.signing.anchorSuggest.code.';
const RUST_SOURCE = '../../crates/chancela-api/src/trust_anchor_suggestion_codes.rs';

/**
 * The codes the Rust side can emit, read out of its own closed list.
 *
 * Both the `pub const` declarations and the body of `ALL_TRUST_ANCHOR_SUGGESTION_CODES` are read,
 * so a constant declared and never listed — invisible to a scan of the list alone — is caught.
 */
async function emittedCodes(): Promise<{ declared: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  const source = readFileSync(RUST_SOURCE, 'utf8');

  const declarations = new Map<string, string>();
  for (const match of source.matchAll(/pub const ([A-Z0-9_]+): &str = "([a-z0-9_]+)";/g)) {
    declarations.set(match[1], match[2]);
  }

  const listBody =
    /ALL_TRUST_ANCHOR_SUGGESTION_CODES: &\[&str\] = &\[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/^\s{4}([A-Z0-9_]+),$/gm)) {
    const value = declarations.get(match[1]);
    if (value) listed.add(value);
  }

  return { declared: new Set(declarations.values()), listed };
}

describe('trust-anchor suggestion codes cover every outcome the server can emit', () => {
  it('extracts a non-vacuous code list from the Rust source', async () => {
    const { declared, listed } = await emittedCodes();
    expect(declared.size, 'the constant scan matched nothing').toBeGreaterThan(0);
    expect(
      listed.size,
      'the ALL_TRUST_ANCHOR_SUGGESTION_CODES scan matched nothing',
    ).toBeGreaterThan(0);
    expect(listed.size).toBeGreaterThanOrEqual(12);
  });

  it('lists every declared code (none declared but left out of the closed list)', async () => {
    const { declared, listed } = await emittedCodes();
    expect([...declared].filter((code) => !listed.has(code)).sort()).toEqual([]);
  });

  it('maps every emitted code to a catalog key', async () => {
    const { listed } = await emittedCodes();
    const unmapped = [...listed].filter((code) => TRUST_ANCHOR_SUGGESTION_KEYS[code] === undefined);
    expect(
      unmapped.sort(),
      'a code the backend can emit has no copy, so a trust warning would render as a raw identifier',
    ).toEqual([]);
  });

  it('has no stale entries beyond what the backend emits', async () => {
    const { listed } = await emittedCodes();
    const stale = Object.keys(TRUST_ANCHOR_SUGGESTION_KEYS).filter((code) => !listed.has(code));
    expect(stale.sort(), 'the map claims codes the server no longer emits').toEqual([]);
  });

  it('carries every outcome sentence in all 14 locales, non-empty', () => {
    const keys = Object.values(TRUST_ANCHOR_SUGGESTION_KEYS);
    expect(keys.length).toBeGreaterThanOrEqual(12);
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const missing = keys.filter((key) => !catalog[key]?.trim());
      expect(missing.sort(), `${locale} is missing outcome sentences`).toEqual([]);
    }
  });

  it('has no orphan catalog key under the code prefix', () => {
    const mapped = new Set<string>(Object.values(TRUST_ANCHOR_SUGGESTION_KEYS));
    const orphans = Object.keys(enUS).filter((key) => key.startsWith(PREFIX) && !mapped.has(key));
    expect(orphans.sort()).toEqual([]);
  });

  it('interpolates nothing: an outcome sentence has no values to fill', () => {
    // The varying part of a failure is `detail`, which is rendered by its own key beside the
    // sentence. A stray `{…}` here would print a literal brace forever.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const key of Object.values(TRUST_ANCHOR_SUGGESTION_KEYS)) {
        expect(catalog[key], `${locale} · ${key}`).not.toMatch(/\{\w+\}/);
      }
    }
  });

  it('returns undefined for a code this build does not know, rather than guessing', () => {
    expect(trustAnchorSuggestionKey('a_code_from_the_future')).toBeUndefined();
    expect(trustAnchorSuggestionKey(null)).toBeUndefined();
    expect(trustAnchorSuggestionKey(undefined)).toBeUndefined();
  });

  it('resolves a code it does know', () => {
    expect(trustAnchorSuggestionKey('source_anchors_from_lotl')).toBe(
      `${PREFIX}source_anchors_from_lotl`,
    );
  });

  it('keeps the fallback copy honest in the two catalogs a reviewer reads', () => {
    // The from-the-list-itself candidate is the one place this feature could mislead. Its warning
    // must say all three things: where the value came from, that it proves nothing, and what the
    // operator has to do before accepting it. Asserted on the concepts, not on a phrasing — the
    // grammar is the translator's, the claims are not.
    for (const catalog of [enGB, enUS]) {
      const body = catalog['settings.signing.anchorSuggest.selfAsserted.body'];
      expect(body).toMatch(/proves nothing/i);
      expect(body).toMatch(/fingerprint/i);
      expect(body).toMatch(/publish/i);
    }
  });
});
