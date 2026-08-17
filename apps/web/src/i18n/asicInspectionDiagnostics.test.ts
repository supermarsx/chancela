/**
 * Completeness contract for the ASiC inspection finding vocabulary.
 *
 * `tsc` already proves every value in `ASIC_FINDING_KEYS` is a real `MessageKey`. This test proves
 * the OTHER direction — that the map covers exactly what the SERVER can emit — by reading the
 * closed code list out of `crates/chancela-api/src/asic_signature_validation.rs`, the same way
 * `providerProbeDiagnostics.test.ts` reads `provider_probe_codes.rs`.
 *
 * That direction is the one that matters. A code added on the backend without a translation here
 * renders the server's raw English in the inspector panel, and neither `noLiteralUiCopy` nor
 * `catalogLeakGate` can see it: both inspect the web app, and are blind by construction to a
 * sentence that arrives over the wire.
 *
 * It also pins the two things that would make the guard hollow:
 *
 *  - **non-vacuity** — the extraction must actually match something, and must not silently halve;
 *  - **all 14 locales** must carry every key, not just the en-US source the compiler checks.
 */
import { describe, expect, it } from 'vitest';
import {
  ASIC_FINDING_KEYS,
  BLOCKER_PENDING_TRANSLATION,
  VERBATIM_REASON_CODES,
  asicFindingKey,
  resolveAsicFinding,
} from './asicInspectionDiagnostics';
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

const PREFIX = 'asicInspector.finding.';

/**
 * The finding codes the Rust side can emit, read out of its own closed list.
 *
 * Both the `pub const` declarations and the `ASIC_INSPECTION_FINDING_CODES` list are read and
 * cross-checked: a constant declared and never listed would be invisible to a scan of the list
 * alone, and it is exactly that constant whose message would reach an operator untranslated.
 */
async function emittedFindingCodes(): Promise<{ declared: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  const source = readFileSync('../../crates/chancela-api/src/asic_signature_validation.rs', 'utf8');

  const declarations = new Map<string, string>();
  for (const match of source.matchAll(
    /pub const (ASIC_FINDING_[A-Z0-9_]+): &str = "([a-z0-9_]+)";/g,
  )) {
    declarations.set(match[1], match[2]);
  }

  const listBody =
    /ASIC_INSPECTION_FINDING_CODES: &\[&str\] = &\[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/^\s{4}(ASIC_FINDING_[A-Z0-9_]+),$/gm)) {
    const value = declarations.get(match[1]);
    if (value) listed.add(value);
  }

  return { declared: new Set(declarations.values()), listed };
}

describe('ASiC inspection findings cover every code the server can emit', () => {
  it('extracts a non-vacuous code list from the Rust source', async () => {
    const { declared, listed } = await emittedFindingCodes();
    // A regex that stopped matching must fail loudly rather than pass on an empty set.
    expect(declared.size, 'the constant scan matched nothing').toBeGreaterThan(0);
    expect(listed.size, 'the ASIC_INSPECTION_FINDING_CODES scan matched nothing').toBeGreaterThan(
      0,
    );
    // A floor at the current count, so a HALF-broken sweep is caught too.
    expect(listed.size).toBeGreaterThanOrEqual(5);
  });

  it('lists every declared code (none declared but left out of the closed list)', async () => {
    const { declared, listed } = await emittedFindingCodes();
    expect([...declared].filter((code) => !listed.has(code)).sort()).toEqual([]);
  });

  it('maps every emitted code to a catalog key', async () => {
    const { listed } = await emittedFindingCodes();
    const unmapped = [...listed].filter((code) => asicFindingKey(code) === undefined);
    expect(
      unmapped.sort(),
      'a code the backend can emit has no translation, so it would render as raw English',
    ).toEqual([]);
  });

  it('has no stale map entries beyond what the backend emits', async () => {
    const { listed } = await emittedFindingCodes();
    const stale = Object.keys(ASIC_FINDING_KEYS).filter((code) => !listed.has(code));
    expect(stale.sort(), 'the map claims codes the server no longer emits').toEqual([]);
  });

  it('carries every mapped key in all 14 locales, non-empty', () => {
    expect(Object.keys(ALL_CATALOGS).length).toBe(14);
    const keys = Object.values(ASIC_FINDING_KEYS);
    expect(keys.length).toBeGreaterThanOrEqual(5);
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const missing = keys.filter((key) => !catalog[key]?.trim());
      expect(missing.sort(), `${locale} is missing finding copy`).toEqual([]);
    }
  });

  it('carries the untranslated-fallback marking in all 14 locales', () => {
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      expect(catalog['asicInspector.untranslatedBadge']?.trim(), locale).toBeTruthy();
      expect(catalog['asicInspector.untranslatedHint']?.trim(), locale).toBeTruthy();
    }
  });

  it('has no orphan catalog key under the finding prefix', () => {
    const mapped = new Set<string>(Object.values(ASIC_FINDING_KEYS));
    const orphans = Object.keys(enUS).filter((key) => key.startsWith(PREFIX) && !mapped.has(key));
    expect(orphans.sort()).toEqual([]);
  });

  it('keeps the interpolation placeholders identical across every locale', () => {
    // A translator who drops `{reasons}` deletes the validator's own account of the failure; one
    // who invents `{reason}` renders a literal brace. Both are caught here.
    const placeholders = (value: string) =>
      [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const key of Object.values(ASIC_FINDING_KEYS)) {
      const expected = placeholders(enUS[key]);
      for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
        expect(placeholders(catalog[key]), `${locale} · ${key}`).toEqual(expected);
      }
    }
  });

  it('uses the placeholder exactly once, never twice', () => {
    // A translator restating the value — 'Motivos: {reasons} (ver {reasons})' — is an ordinary
    // thing to write and it breaks the split: the resolver would put the second sentinel's literal
    // U+0000 into `after` and silently drop that copy of the payload. The resolver degrades to
    // marked English rather than corrupting the page, but the catalog entry is still wrong and
    // this is where it should be caught.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const [code, key] of Object.entries(ASIC_FINDING_KEYS)) {
        const occurrences = catalog[key].split('{reasons}').length - 1;
        expect(occurrences, `${locale} · ${code} repeats {reasons}`).toBeLessThanOrEqual(1);
      }
    }
  });

  it('carries no U+0000 anywhere in any catalog, which the sentinel split assumes', () => {
    // `serverFindingText` splits the rendered frame on U+0000 precisely because catalog copy
    // cannot contain one. That was an assumption; this makes it a checked fact, across the whole
    // catalog rather than only these keys — a NUL anywhere would be a corruption worth failing on.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const offenders = Object.entries(catalog)
        .filter(([, value]) => value.includes('\u0000'))
        .map(([key]) => key);
      expect(offenders.sort(), `${locale} has catalog values containing U+0000`).toEqual([]);
    }
  });

  it('gives exactly the framed codes a {reasons} placeholder, and the others none', () => {
    // The two halves of the design have to agree: a code framed in code but with no placeholder in
    // copy would silently drop the validator's reasons, and a placeholder on an unframed code would
    // render a literal brace because nothing ever fills it.
    for (const [code, key] of Object.entries(ASIC_FINDING_KEYS)) {
      const framed = VERBATIM_REASON_CODES.has(code);
      for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
        expect(catalog[key].includes('{reasons}'), `${locale} · ${code}`).toBe(framed);
      }
    }
  });

  it('keeps the negative conjunction under a negation, which a positive one would weaken', () => {
    // In the Romance locales, a list governed by a preceding negation must be joined with the
    // NEGATIVE conjunction — pt `nem`, es `ni`, fr `ni`, it `né`. The positive one (`ou`, `o`,
    // `ou`, `o`) reads as "an alternative that might hold" rather than "additionally excluded", so
    // a one-word edit turns a disclaimer into a possible claim. That is the worst failure this
    // vocabulary has, in its most compact form.
    //
    // Neither the acronym check below nor the placeholder check above can see it: the sentence
    // stays perfectly well-formed either way.
    // NB: JavaScript's `\b` is ASCII-only, so `/\bné\b/` can NEVER match — `é` is a non-word
    // character to the engine, and the boundary after it does not fire. A whitespace-delimited
    // pattern is required for any accent-final word, and using one everywhere keeps the table
    // uniform rather than leaving a trap for the next accented conjunction added here.
    const surroundedBy = (word: string) => new RegExp(`(^|\\s)${word}(\\s|$)`);
    const NEGATIVE_CONJUNCTION: Record<string, RegExp> = {
      'pt-PT': surroundedBy('nem'),
      'pt-BR': surroundedBy('nem'),
      'es-ES': surroundedBy('ni'),
      'fr-FR': surroundedBy('ni'),
      'it-IT': surroundedBy('né'),
    };
    // Only `xades_not_supported` is listed. Its negation ("does not establish") precedes the whole
    // list in every one of these locales, so the rule applies uniformly.
    //
    // `asic_valid_local_technical` is deliberately ABSENT: after the pt-PT agreement fix its list
    // is the SUBJECT and the negation follows it, where `e`/`y`/`et`/`e` is correct. Asserting
    // `nem` everywhere would pin a grammar error into the guard.
    const key = ASIC_FINDING_KEYS.xades_not_supported;
    for (const [locale, negative] of Object.entries(NEGATIVE_CONJUNCTION)) {
      const value = ALL_CATALOGS[locale][key];
      expect(value, `${locale} lost the negative conjunction ${negative}`).toMatch(negative);
    }
    // And the positive conjunction must not appear inside that negated list.
    const POSITIVE_UNDER_NEGATION: Record<string, RegExp> = {
      'pt-PT': surroundedBy('ou'),
      'pt-BR': surroundedBy('ou'),
      'es-ES': surroundedBy('o'),
      'it-IT': surroundedBy('o'),
    };
    for (const [locale, positive] of Object.entries(POSITIVE_UNDER_NEGATION)) {
      expect(
        ALL_CATALOGS[locale][key],
        `${locale} uses a positive conjunction under a negation, which weakens the disclaimer`,
      ).not.toMatch(positive);
    }
  });

  it('carries a negation marker in the scope notice of every Romance locale', () => {
    // The scope notice is the broadest non-claim in the set. Locales legitimately reach it by
    // different routes — pt-PT fronts "Não … nem …", pt-BR uses "Nada do seguinte é …" — so this
    // asserts that SOME negation survives rather than pinning one construction and forcing a
    // translator into a worse sentence.
    const NEGATION: Record<string, RegExp> = {
      'pt-PT': /\b(não|nem|nada)\b/i,
      'pt-BR': /\b(não|nem|nada)\b/i,
      'es-ES': /\b(no|ni|nada)\b/i,
      'fr-FR': /\b(ne|n’|ni|rien|aucun)\b/i,
      'it-IT': /\b(non|né|nulla)\b/i,
    };
    const key = ASIC_FINDING_KEYS.technical_scope_only;
    for (const [locale, negation] of Object.entries(NEGATION)) {
      expect(
        ALL_CATALOGS[locale][key],
        `${locale} scope notice has no negation left — it now reads as a claim`,
      ).toMatch(negation);
    }
  });

  it('never states the technical scope as a claim the product does make', () => {
    // These sentences exist to say what was NOT assessed. A translation that loses the negation
    // turns a disclaimer into a qualified-signature claim, which is the one failure here that is
    // worse than shipping English.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const scope = catalog[`${PREFIX}technical_scope_only`];
      expect(scope.length, `${locale} scope notice is suspiciously short`).toBeGreaterThan(120);
      // Every locale enumerates the same untranslatable protocol tokens; losing one means the
      // sentence was rewritten rather than translated.
      for (const token of ['TSL/TSA/OCSP/CRL', 'eIDAS', 'B-LT/B-LTA/LTV', 'ASiC/XAdES']) {
        expect(scope, `${locale} scope notice dropped ${token}`).toContain(token);
      }
    }
  });
});

/**
 * The blocker identifiers, read out of `chancela-signing`'s own closed list.
 *
 * A different crate and a different declaration shape from the finding codes — enum variants and
 * an `ALL` array rather than `pub const` strings — so this needs its own extraction rather than a
 * parameterised reuse of the one above.
 */
async function emittedBlockerIds(): Promise<{ variants: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  const source = readFileSync('../../crates/chancela-signing/src/asic.rs', 'utf8');

  // `AsicDiagnosticBlockerId::Variant => "snake_case",` — possibly wrapped onto three lines by
  // rustfmt, which is why this is not anchored to one line.
  const variants = new Map<string, string>();
  for (const match of source.matchAll(
    /AsicDiagnosticBlockerId::([A-Za-z0-9]+) =>\s*\{?\s*"([a-z0-9_]+)"/g,
  )) {
    variants.set(match[1], match[2]);
  }

  const listBody = /pub const ALL: \[Self; \d+\] = \[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/Self::([A-Za-z0-9]+),/g)) {
    const value = variants.get(match[1]);
    if (value) listed.add(value);
  }

  return { variants: new Set(variants.values()), listed };
}

describe('ASiC profile blockers reach the operator accounted for', () => {
  it('extracts a non-vacuous blocker list from the Rust source', async () => {
    const { variants, listed } = await emittedBlockerIds();
    expect(variants.size, 'the as_str scan matched nothing').toBeGreaterThan(0);
    expect(listed.size, 'the ALL scan matched nothing').toBeGreaterThan(0);
    expect(listed.size).toBeGreaterThanOrEqual(25);
  });

  it('lists every variant (none declared but left out of ALL)', async () => {
    const { variants, listed } = await emittedBlockerIds();
    expect([...variants].filter((id) => !listed.has(id)).sort()).toEqual([]);
  });

  it('accounts for every blocker as translated or knowingly pending', async () => {
    const { listed } = await emittedBlockerIds();
    const unaccounted = [...listed].filter(
      (id) => ASIC_FINDING_KEYS[id] === undefined && !BLOCKER_PENDING_TRANSLATION.has(id),
    );
    expect(
      unaccounted.sort(),
      'a blocker the backend can emit is neither translated nor listed as pending',
    ).toEqual([]);
  });

  it('has no stale pending entry beyond what the backend emits', async () => {
    const { listed } = await emittedBlockerIds();
    const stale = [...BLOCKER_PENDING_TRANSLATION].filter((id) => !listed.has(id));
    expect(stale.sort(), 'the pending set claims blockers the server no longer emits').toEqual([]);
  });

  it('does not list a blocker as pending when it is already translated', () => {
    // `xades_not_supported` is both a dedicated finding code and a blocker id. One translation
    // serves both; listing it as pending as well would claim it renders as English when it does
    // not, and would make the pending count a lie.
    const both = [...BLOCKER_PENDING_TRANSLATION].filter((id) => ASIC_FINDING_KEYS[id]);
    expect(both.sort()).toEqual([]);
    expect(ASIC_FINDING_KEYS.xades_not_supported).toBeDefined();
  });
});

describe('resolveAsicFinding', () => {
  const t = ((key: string, params?: Record<string, string | number>) => {
    const raw = enUS[key as keyof typeof enUS] as string;
    return raw.replace(/\{(\w+)\}/g, (whole, name: string) =>
      params && name in params ? String(params[name]) : whole,
    );
  }) as never;

  it('renders a known fixed-sentence code from the catalog', () => {
    const resolved = resolveAsicFinding(
      { code: 'xades_not_supported', message: 'server English' },
      t,
    );
    expect(resolved).toEqual({
      kind: 'translated',
      text: enUS[`${PREFIX}xades_not_supported`],
    });
  });

  it('splits the frame so the validator reasons can be marked as English', () => {
    const reasons = 'META-INF/signature.p7s: digest mismatch; container: unreferenced payload';
    const resolved = resolveAsicFinding(
      { code: 'asic_invalid_local_technical', message: reasons },
      t,
    );
    expect(resolved.kind).toBe('framed');
    if (resolved.kind !== 'framed') return;
    // The validator's own words survive intact, member paths and all, and arrive as their OWN
    // field so the caller can wrap them in lang="en" rather than burying them in a translated
    // sentence.
    expect(resolved.verbatim).toBe(reasons);
    expect(resolved.before).not.toContain(reasons);
    expect(resolved.after).not.toContain(reasons);
    // Reassembling must reproduce the whole sentence — a split that dropped text would be a
    // silent truncation of a failure report.
    expect(resolved.before + resolved.verbatim + resolved.after).toBe(
      enUS[`${PREFIX}asic_invalid_local_technical`].replace('{reasons}', reasons),
    );
    // The frame is real prose, not an empty shell.
    expect(resolved.before.trim().length).toBeGreaterThan(0);
  });

  it('places the split correctly in every locale, wherever that locale puts the placeholder', () => {
    // `before`/`after` come from splitting the RENDERED string, so a locale that fronts
    // `{reasons}` is handled too. Assuming it is sentence-final would break invisibly.
    const reasons = 'boom';
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const localeT = ((key: string, params?: Record<string, string | number>) =>
        catalog[key].replace(/\{(\w+)\}/g, (whole, name: string) =>
          params && name in params ? String(params[name]) : whole,
        )) as never;
      for (const code of VERBATIM_REASON_CODES) {
        const resolved = resolveAsicFinding({ code, message: reasons }, localeT);
        expect(resolved.kind, `${locale} · ${code}`).toBe('framed');
        if (resolved.kind !== 'framed') continue;
        expect(resolved.before + resolved.verbatim + resolved.after, `${locale} · ${code}`).toBe(
          catalog[ASIC_FINDING_KEYS[code]].replace('{reasons}', reasons),
        );
      }
    }
  });

  it('falls back to the server English, MARKED, for a code this build does not know', () => {
    const resolved = resolveAsicFinding(
      { code: 'invented_by_a_newer_server', message: 'A sentence from a newer server.' },
      t,
    );
    // Never blank, never a crash — and never silently passed off as localized copy.
    expect(resolved).toEqual({ kind: 'untranslated', text: 'A sentence from a newer server.' });
  });

  it('degrades to marked English when the frame repeats the placeholder', () => {
    // Two sentinels: `indexOf` + `slice` would leave the SECOND one — a literal U+0000 — in
    // `after`, rendering a control character into the page, and would silently drop that copy of
    // the payload. Neither is acceptable, so the resolver refuses to call it framed.
    const repeated = ((_key: string, params?: Record<string, string>) =>
      `Motivos: ${params?.reasons} (ver ${params?.reasons})`) as never;
    const resolved = resolveAsicFinding(
      { code: 'asic_invalid_local_technical', message: 'digest mismatch' },
      repeated,
    );
    expect(resolved).toEqual({ kind: 'untranslated', text: 'digest mismatch' });
  });

  it('degrades to marked English when the frame lost its placeholder entirely', () => {
    const dropped = (() => 'A frame with nowhere to put the reasons.') as never;
    const resolved = resolveAsicFinding(
      { code: 'asic_invalid_local_technical', message: 'digest mismatch' },
      dropped,
    );
    expect(resolved).toEqual({ kind: 'untranslated', text: 'digest mismatch' });
  });

  it('falls back rather than framing nothing when a framed code carries an empty message', () => {
    const resolved = resolveAsicFinding({ code: 'asic_invalid_local_technical', message: '  ' }, t);
    expect(resolved).toEqual({ kind: 'untranslated', text: '  ' });
  });

  it('marks a profile blocker id, which is a vocabulary this map does not cover', () => {
    // `append_blocker_findings` pushes `AsicDiagnosticBlockerId::as_str()` as the code. Those are
    // deliberately out of scope here, and must be MARKED English rather than pass for pt-PT.
    const resolved = resolveAsicFinding(
      { code: 'asic_e_manifest_digest_mismatch', message: 'English blocker text.' },
      t,
    );
    expect(resolved.kind).toBe('untranslated');
  });
});
