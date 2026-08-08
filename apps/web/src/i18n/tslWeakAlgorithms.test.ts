/**
 * Completeness contract for the Trusted List weak-algorithm surface.
 *
 * `tsc` already proves every value in the two maps is a real `MessageKey`. This proves the OTHER
 * direction — that they cover exactly what the SERVER can emit and offer exactly what it will
 * accept — by reading both closed sets out of `crates/chancela-tsl/src/xmldsig.rs`. Same shape and
 * same reason as `providerProbeDiagnostics.test.ts`, which does this for the probe's detail codes.
 *
 * That direction is the one that matters, and it matters twice here:
 *
 *  - a **code** added on the backend without a sentence here would render the generic
 *    "this version does not recognise it" fallback forever, quietly losing the distinction the
 *    backend went to the trouble of reporting;
 *  - an **algorithm** added to `KNOWN_LEGACY_ALGORITHMS` without a checkbox here would be
 *    settable by hand and invisible in the UI — a broken algorithm permitted on a deployment
 *    whose settings screen shows three unticked boxes.
 *
 * Neither `noLiteralUiCopy` nor `catalogLeakGate` can see either: both inspect the web app and are
 * blind by construction to what arrives over the wire. This file is that missing eye.
 *
 * It also pins the two things that would make the guard hollow:
 *
 *  - **non-vacuity** — the extraction must actually match something, and must not silently halve;
 *  - **all 14 locales** must carry every key, not just the en-US source the compiler checks.
 */
import { describe, expect, it } from 'vitest';
import {
  TSL_LEGACY_ALGORITHM_LABEL_KEYS,
  TSL_WEAK_ALGORITHM_SENTENCE_KEYS,
  hasWeakAlgorithms,
  isKnownLegacyAlgorithm,
  isKnownWeakAlgorithmCode,
  legacyAlgorithmLabelKey,
  partitionLegacyAlgorithms,
  weakAlgorithmSentenceKey,
} from './tslWeakAlgorithms';
import { TSL_LEGACY_ALGORITHMS, TSL_WEAK_ALGORITHM_CODES } from '../api/types';
import type { WeakAlgorithmUse } from '../api/types';
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

/** Every key this module can ask a catalog for, including the two it renders unconditionally. */
const EVERY_KEY = [
  ...Object.values(TSL_LEGACY_ALGORITHM_LABEL_KEYS),
  ...Object.values(TSL_WEAK_ALGORITHM_SENTENCE_KEYS),
  'trust.weakAlgorithms.label',
  'trust.weakAlgorithms.badge',
  'trust.weakAlgorithms.title',
  'trust.weakAlgorithms.intro',
  'trust.weakAlgorithms.reference',
  'trust.weakAlgorithms.unknown',
  'settings.signing.tslLegacy.title',
  'settings.signing.tslLegacy.hint',
  'settings.signing.tslLegacy.warning.title',
  'settings.signing.tslLegacy.warning.body',
  'settings.signing.tslLegacy.warning.scope',
  'settings.signing.tslLegacy.none',
  'settings.signing.tslLegacy.unknown.label',
  'settings.signing.tslLegacy.unknown.title',
  'settings.signing.tslLegacy.unknown.body',
] as const;

interface RustSets {
  /** `pub const NAME: &str = "value";` declarations, by name. */
  declarations: Map<string, string>;
  /** The URIs `KNOWN_LEGACY_ALGORITHMS` lists, in declaration order, resolved to their values. */
  known: string[];
  /** Every `CODE_WEAK_*` constant's value. */
  codes: string[];
}

/**
 * The closed sets the Rust side owns, read out of its own source.
 *
 * The constants are read first and the `&[…]` literal is resolved THROUGH them, so a URI declared
 * and never listed, or listed under a name that does not exist, is a loud failure rather than a
 * silent omission — the same cross-check `providerProbeDiagnostics.test.ts` makes.
 */
async function rustSets(): Promise<RustSets> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  const source = readFileSync('../../crates/chancela-tsl/src/xmldsig.rs', 'utf8');

  const declarations = new Map<string, string>();
  for (const match of source.matchAll(
    /pub const ((?:LEGACY|CODE_WEAK)_[A-Z0-9_]+): &str = "([^"]+)";/gu,
  )) {
    declarations.set(match[1], match[2]);
  }

  const list = source.match(/pub const KNOWN_LEGACY_ALGORITHMS: &\[&str\] =\s*&\[([^\]]*)\];/u);
  expect(list, 'KNOWN_LEGACY_ALGORITHMS not found in xmldsig.rs').toBeTruthy();
  const known = list![1]
    .split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0)
    .map((name) => {
      const value = declarations.get(name);
      expect(value, `KNOWN_LEGACY_ALGORITHMS names ${name}, which is not declared`).toBeTruthy();
      return value!;
    });

  const codes = [...declarations]
    .filter(([name]) => name.startsWith('CODE_WEAK_'))
    .map(([, value]) => value);

  return { declarations, known, codes };
}

describe('the closed sets are read from the Rust source, not restated', () => {
  it('extracts a non-vacuous set (a broken regex must not make this pass over nothing)', async () => {
    const { declarations, known, codes } = await rustSets();
    // Three algorithm constants and two codes today; append-only, so a floor rather than equality.
    expect(declarations.size).toBeGreaterThanOrEqual(5);
    expect(known.length).toBeGreaterThanOrEqual(3);
    expect(codes.length).toBeGreaterThanOrEqual(2);
    for (const uri of known) expect(uri.startsWith('http')).toBe(true);
  });

  it('offers exactly the algorithms KNOWN_LEGACY_ALGORITHMS permits, in its order', async () => {
    const { known } = await rustSets();
    // Order matters: it is the order the checkboxes render in, and pinning it means the two files
    // can be read side by side.
    expect([...TSL_LEGACY_ALGORITHMS]).toEqual(known);
    expect(Object.keys(TSL_LEGACY_ALGORITHM_LABEL_KEYS).sort()).toEqual([...known].sort());
  });

  it('words exactly the codes the verifier can emit', async () => {
    const { codes } = await rustSets();
    expect([...TSL_WEAK_ALGORITHM_CODES].sort()).toEqual([...codes].sort());
    expect(Object.keys(TSL_WEAK_ALGORITHM_SENTENCE_KEYS).sort()).toEqual([...codes].sort());
    for (const code of codes) expect(weakAlgorithmSentenceKey(code)).toBeTruthy();
  });

  it('does not offer an algorithm the verifier cannot compute', async () => {
    // MD5 and RIPEMD-160 are permanently unofferable: nothing in the backend's dependency tree
    // computes them, so allowlisting either would name an algorithm it cannot evaluate. Asserted
    // here as well as in Rust, because this is the file that decides what a human can tick.
    const { known } = await rustSets();
    for (const forbidden of ['md5', 'ripemd']) {
      expect(known.some((uri) => uri.toLowerCase().includes(forbidden))).toBe(false);
      expect(TSL_LEGACY_ALGORITHMS.some((uri) => uri.toLowerCase().includes(forbidden))).toBe(
        false,
      );
    }
  });
});

describe('every locale carries the wording', () => {
  it.each(Object.entries(ALL_CATALOGS))('%s translates every weak-algorithm key', (_, catalog) => {
    for (const key of EVERY_KEY) {
      expect(catalog[key], `${key} missing`).toBeTruthy();
      expect(catalog[key]!.trim().length, `${key} blank`).toBeGreaterThan(0);
    }
  });

  it('keeps the position line interpolatable in every locale', () => {
    // The reference arm renders index/total/uri through one sentence. A catalog that dropped a
    // placeholder would print a position with a hole in it rather than failing loudly.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const value = catalog['trust.weakAlgorithms.reference']!;
      for (const placeholder of ['{index}', '{total}', '{uri}']) {
        expect(value, `${locale} lost ${placeholder}`).toContain(placeholder);
      }
    }
  });

  it('never puts an algorithm URI in the catalogs', () => {
    // The URI is a machine identifier rendered verbatim beside the sentence, never inside it: a
    // catalog that embedded one would have to be re-translated whenever the wire value changed,
    // and would fuse an identifier into inflected prose.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const key of EVERY_KEY) {
        for (const uri of TSL_LEGACY_ALGORITHMS) {
          expect(catalog[key], `${locale}:${key}`).not.toContain(uri);
        }
      }
    }
  });
});

describe('the recognisers', () => {
  it('narrows only the three permitted URIs', () => {
    for (const uri of TSL_LEGACY_ALGORITHMS) {
      expect(isKnownLegacyAlgorithm(uri)).toBe(true);
      expect(legacyAlgorithmLabelKey(uri)).toBe(TSL_LEGACY_ALGORITHM_LABEL_KEYS[uri]);
    }
    // Near-misses, not nonsense: a real XML-DSig URI outside the set, and the SHA-1 digest URI
    // with one character changed.
    for (const stray of [
      'http://www.w3.org/2001/04/xmlenc#sha256',
      'http://www.w3.org/2000/09/xmldsig#sha2',
      '',
    ]) {
      expect(isKnownLegacyAlgorithm(stray)).toBe(false);
      expect(legacyAlgorithmLabelKey(stray)).toBeUndefined();
    }
  });

  it('reports an unknown code rather than pretending it is one of the two', () => {
    expect(isKnownWeakAlgorithmCode('tsl_weak_future_permitted')).toBe(false);
    expect(weakAlgorithmSentenceKey('tsl_weak_future_permitted')).toBeUndefined();
    for (const code of TSL_WEAK_ALGORITHM_CODES) expect(isKnownWeakAlgorithmCode(code)).toBe(true);
  });

  it('preserves an unrecognised entry instead of dropping it', () => {
    const stray = 'http://www.w3.org/2001/04/xmldsig-more#rsa-md5';
    const split = partitionLegacyAlgorithms([TSL_LEGACY_ALGORITHMS[1], stray]);
    expect(split.known).toEqual([TSL_LEGACY_ALGORITHMS[1]]);
    // The bucket that must never be silently emptied: a settings screen that stopped displaying a
    // value the deployment is running on would be changing policy without saying so.
    expect(split.unknown).toEqual([stray]);
  });

  it('treats an absent list and an empty list as the same fact', () => {
    // The field is skipped when empty on the wire, so absence IS "nothing weak was relied upon".
    expect(hasWeakAlgorithms(undefined)).toBe(false);
    expect(hasWeakAlgorithms([])).toBe(false);
    const use: WeakAlgorithmUse = {
      code: 'tsl_weak_digest_permitted',
      algorithm: TSL_LEGACY_ALGORITHMS[0],
      site: 'reference',
      index: 1,
      total: 1,
      uri: '#r0',
    };
    expect(hasWeakAlgorithms([use])).toBe(true);
  });
});
