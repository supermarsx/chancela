/**
 * Completeness contract for the provider-credential probe diagnostics (t112).
 *
 * `tsc` already proves every value in `PROBE_DETAIL_KEYS` is a real `MessageKey`. This test proves
 * the OTHER direction — that the map covers exactly what the SERVER can emit — by reading the
 * closed code list out of `crates/chancela-api/src/provider_probe_codes.rs`, in the spirit of
 * `src/api/labels.test.ts`, which does the same for ledger event kinds.
 *
 * That direction is the one that matters. A code added on the backend without a translation here
 * renders the server's raw English on the settings screen, and neither `noLiteralUiCopy` nor
 * `catalogLeakGate` can see it: both inspect the web app, and are blind by construction to a
 * sentence that arrives over the wire. This file is that missing eye.
 *
 * It also pins the two things that would make the guard hollow:
 *
 *  - **non-vacuity** — the extraction must actually match something, and must not silently halve;
 *  - **all 14 locales** must carry every key, not just the en-US source the compiler checks.
 */
import { describe, expect, it } from 'vitest';
import { PROBE_DETAIL_KEYS, probeDetailKey, resolveProbeDetail } from './providerProbeDiagnostics';
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

const PREFIX = 'settings.providerCredentials.probe.detail.';

/**
 * The detail codes the Rust side can emit, read out of its own closed list.
 *
 * The list is `ALL_PROBE_DETAIL_CODES`, whose entries are the `pub const` names; the values are
 * resolved from their declarations in the same file. Reading the CONSTANTS rather than the
 * `&[...]` literal is deliberate: a code declared and never added to the list would be invisible
 * to a scan of the list alone, so both are read and cross-checked.
 */
async function emittedDetailCodes(): Promise<{ declared: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  const source = readFileSync('../../crates/chancela-api/src/provider_probe_codes.rs', 'utf8');

  // `pub const NAME: &str = "value";` — the declaration of one code.
  const declarations = new Map<string, string>();
  for (const match of source.matchAll(/pub const ([A-Z0-9_]+): &str = "([a-z0-9_]+)";/g)) {
    declarations.set(match[1], match[2]);
  }

  // The body of `ALL_PROBE_DETAIL_CODES`, so a constant declared but never listed is caught.
  const listBody = /ALL_PROBE_DETAIL_CODES: &\[&str\] = &\[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/^\s{4}([A-Z0-9_]+),$/gm)) {
    const value = declarations.get(match[1]);
    if (value) listed.add(value);
  }

  return { declared: new Set(declarations.values()), listed };
}

describe('provider probe diagnostics cover every code the server can emit', () => {
  it('extracts a non-vacuous code list from the Rust source', async () => {
    const { declared, listed } = await emittedDetailCodes();
    // A regex that stopped matching must fail loudly rather than pass on an empty set.
    expect(declared.size, 'the constant scan matched nothing').toBeGreaterThan(0);
    expect(listed.size, 'the ALL_PROBE_DETAIL_CODES scan matched nothing').toBeGreaterThan(0);
    // A floor just under the current count, so a HALF-broken sweep is caught too.
    expect(listed.size).toBeGreaterThanOrEqual(83);
  });

  it('lists every declared code (no code declared but left out of the closed list)', async () => {
    const { declared, listed } = await emittedDetailCodes();
    expect([...declared].filter((code) => !listed.has(code)).sort()).toEqual([]);
  });

  it('maps every emitted code to a catalog key', async () => {
    const { listed } = await emittedDetailCodes();
    const unmapped = [...listed].filter((code) => probeDetailKey(code) === undefined);
    expect(
      unmapped.sort(),
      'a code the backend can emit has no translation, so it would render as raw English',
    ).toEqual([]);
  });

  it('has no stale map entries beyond what the backend emits', async () => {
    const { listed } = await emittedDetailCodes();
    const stale = Object.keys(PROBE_DETAIL_KEYS).filter((code) => !listed.has(code));
    expect(stale.sort(), 'the map claims codes the server no longer emits').toEqual([]);
  });

  it('carries every mapped key in all 14 locales, non-empty', () => {
    expect(Object.keys(ALL_CATALOGS).length).toBe(14);
    const keys = Object.values(PROBE_DETAIL_KEYS);
    expect(keys.length).toBeGreaterThanOrEqual(83);
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      const missing = keys.filter((key) => !catalog[key]?.trim());
      expect(missing.sort(), `${locale} is missing diagnostic copy`).toEqual([]);
    }
  });

  it('has no orphan catalog key under the diagnostics prefix', () => {
    // The prefix namespace is exactly the code vocabulary — the untranslated-fallback copy lives
    // outside it on purpose, so this check can stay an equality rather than a whitelist.
    const mapped = new Set<string>(Object.values(PROBE_DETAIL_KEYS));
    const orphans = Object.keys(enUS).filter((key) => key.startsWith(PREFIX) && !mapped.has(key));
    expect(orphans.sort()).toEqual([]);
  });

  it('keeps the interpolation placeholders identical across every locale', () => {
    // A translator who drops `{certs_setting}` deletes the setting name an operator has to go and
    // fill; one who invents `{cert_setting}` renders a literal brace. Both are caught here.
    const placeholders = (value: string) =>
      [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const key of Object.values(PROBE_DETAIL_KEYS)) {
      const expected = placeholders(enUS[key]);
      for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
        expect(placeholders(catalog[key]), `${locale} · ${key}`).toEqual(expected);
      }
    }
  });
});

describe('resolveProbeDetail', () => {
  const t = ((key: string, params?: Record<string, string | number>) => {
    const raw = enUS[key as keyof typeof enUS] as string;
    return raw.replace(/\{(\w+)\}/g, (whole, name: string) =>
      params && name in params ? String(params[name]) : whole,
    );
  }) as never;

  it('renders a known code from the catalog, with its parameters', () => {
    const resolved = resolveProbeDetail(
      {
        detail: 'The deployment resolves Chave Móvel Digital to the prod environment.',
        detail_code: 'cmd_environment_resolved',
        detail_params: { environment: 'prod' },
      },
      t,
    );
    expect(resolved.untranslated).toBe(false);
    expect(resolved.text).toContain('prod');
  });

  it('keeps a setting path verbatim rather than translating it', () => {
    const resolved = resolveProbeDetail(
      {
        detail: 'unused',
        detail_code: 'tsl_unanchored',
        detail_params: {
          certs_setting: 'signing.tsl_trust_anchor_certs',
          digest_setting: 'signing.tsl_trust_anchor_sha256',
        },
      },
      t,
    );
    expect(resolved.text).toContain('signing.tsl_trust_anchor_certs');
    expect(resolved.text).toContain('signing.tsl_trust_anchor_sha256');
  });

  it('falls back to the server English, MARKED, for a code this build does not know', () => {
    const resolved = resolveProbeDetail(
      { detail: 'A sentence from a newer server.', detail_code: 'invented_by_a_newer_server' },
      t,
    );
    // Never blank, never a crash — and never silently passed off as localized copy.
    expect(resolved.text).toBe('A sentence from a newer server.');
    expect(resolved.untranslated).toBe(true);
  });

  it('falls back the same way for a server too old to send a code at all', () => {
    const resolved = resolveProbeDetail({ detail: 'Legacy English.' }, t);
    expect(resolved.text).toBe('Legacy English.');
    expect(resolved.untranslated).toBe(true);
  });
});
