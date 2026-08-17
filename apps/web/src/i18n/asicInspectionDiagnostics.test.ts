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
    expect(resolved.untranslated).toBe(false);
    expect(resolved.text).toBe(enUS[`${PREFIX}xades_not_supported`]);
    expect(resolved.text).not.toContain('server English');
  });

  it('frames a validator reason string verbatim rather than paraphrasing it', () => {
    const reasons = 'META-INF/signature.p7s: digest mismatch; container: unreferenced payload';
    const resolved = resolveAsicFinding(
      { code: 'asic_invalid_local_technical', message: reasons },
      t,
    );
    expect(resolved.untranslated).toBe(false);
    // The validator's own words survive intact, member paths and all.
    expect(resolved.text).toContain(reasons);
    expect(resolved.text).not.toBe(reasons);
  });

  it('falls back to the server English, MARKED, for a code this build does not know', () => {
    const resolved = resolveAsicFinding(
      { code: 'invented_by_a_newer_server', message: 'A sentence from a newer server.' },
      t,
    );
    // Never blank, never a crash — and never silently passed off as localized copy.
    expect(resolved).toEqual({ text: 'A sentence from a newer server.', untranslated: true });
  });

  it('falls back rather than framing nothing when a framed code carries an empty message', () => {
    const resolved = resolveAsicFinding({ code: 'asic_invalid_local_technical', message: '  ' }, t);
    expect(resolved.untranslated).toBe(true);
    expect(resolved.text).toBe('  ');
  });

  it('marks a profile blocker id, which is a vocabulary this map does not cover', () => {
    // `append_blocker_findings` pushes `AsicDiagnosticBlockerId::as_str()` as the code. Those are
    // deliberately out of scope here, and must be MARKED English rather than pass for pt-PT.
    const resolved = resolveAsicFinding(
      { code: 'asic_e_manifest_digest_mismatch', message: 'English blocker text.' },
      t,
    );
    expect(resolved.untranslated).toBe(true);
  });
});
