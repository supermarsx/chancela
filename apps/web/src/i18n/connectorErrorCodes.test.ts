/**
 * Completeness contract for connector probe failure codes.
 *
 * `tsc` already proves every value in `CONNECTOR_ERROR_KEYS` is a real `MessageKey`. This test
 * proves the OTHER direction — that the map covers exactly what the SERVER can emit — by reading
 * the closed list out of `crates/chancela-connectors/src/codes.rs`, exactly as
 * `providerProbeDiagnostics.test.ts` does for the probe diagnostics.
 *
 * That direction is the one that matters, and it is the one `codes.rs` claimed and did not have.
 * Its module doc says `ALL_GATED_TRANSPORTS` is the closed list "so a client-side guard can prove
 * every code maps to a catalog key" — there was no such guard, and a code added on the backend
 * without a translation here renders the server's raw English in the operations screen. Neither
 * `noLiteralUiCopy` nor `catalogLeakGate` can see it: both inspect the web app, and are blind by
 * construction to a sentence that arrives over the wire. This file is that missing eye.
 *
 * It also pins the two things that would make the guard hollow:
 *
 *  - **non-vacuity** — the extraction must actually match something, and must not silently halve;
 *  - **all 14 locales** must carry every key, not just the en-US source the compiler checks.
 */
import { describe, expect, it } from 'vitest';
import {
  CONNECTOR_ERROR_KEYS,
  connectorErrorKey,
  resolveConnectorError,
} from './connectorErrorCodes';
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

const PREFIX = 'operations.connectors.probe.errorCode.';

/**
 * The error codes the Rust side can emit, read out of its own closed list.
 *
 * Read two ways and cross-checked, because the closed list and the codes are one indirection
 * apart: `ALL_GATED_TRANSPORTS` lists *variants*, and `GatedTransport::not_compiled_code` maps each
 * variant to a `pub const`. A constant declared but never reachable from the list would be
 * invisible to a scan of the list alone, and a variant added to the list without a code would be
 * invisible to a scan of the constants alone.
 */
function parseCodes(source: string): { declared: Set<string>; listed: Set<string> } {
  // `pub const NAME: &str = "value";` — the declaration of one code.
  const declarations = new Map<string, string>();
  for (const match of source.matchAll(/pub const ([A-Z0-9_]+): &str = "([a-z0-9_]+)";/g)) {
    declarations.set(match[1], match[2]);
  }

  // `Self::S3 => TRANSPORT_NOT_COMPILED_S3,` — the variant → constant arms.
  // ` {4}` rather than four literal spaces: `no-regex-spaces` rejects a run of them, and it is
  // right to — the closing brace's indentation is load-bearing here (it is what ends the match at
  // the fn's own brace rather than an inner one), so it should be stated as a count, not eyeballed.
  const codeArms = /fn not_compiled_code\(self\) -> &'static str \{([\s\S]*?)\n {4}\}/.exec(
    source,
  )?.[1];
  const perVariant = new Map<string, string>();
  for (const match of (codeArms ?? '').matchAll(/Self::(\w+) => ([A-Z0-9_]+),/g)) {
    const value = declarations.get(match[2]);
    if (value) perVariant.set(match[1], value);
  }

  // The body of `ALL_GATED_TRANSPORTS`, so a variant declared but never listed is caught.
  const listBody =
    /ALL_GATED_TRANSPORTS: &\[GatedTransport\] = &\[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/GatedTransport::(\w+),/g)) {
    const value = perVariant.get(match[1]);
    if (value) listed.add(value);
  }

  return { declared: new Set(declarations.values()), listed };
}

/** {@link parseCodes} applied to the real `codes.rs`. */
async function emittedErrorCodes(): Promise<{ declared: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  // Tests run with cwd = apps/web; the repo root is two levels up.
  return parseCodes(readFileSync('../../crates/chancela-connectors/src/codes.rs', 'utf8'));
}

/** Which of `keys` no catalog entry answers — the predicate the locale checks below apply. */
function missingFrom(catalog: Record<string, string>, keys: string[]): string[] {
  return keys.filter((key) => !catalog[key]?.trim()).sort();
}

describe('connector error codes cover every code the server can emit', () => {
  it('extracts a non-vacuous code list from the Rust source', async () => {
    const { declared, listed } = await emittedErrorCodes();
    // A regex that stopped matching must fail loudly rather than pass on an empty set.
    expect(declared.size, 'the constant scan matched nothing').toBeGreaterThan(0);
    expect(listed.size, 'the ALL_GATED_TRANSPORTS scan matched nothing').toBeGreaterThan(0);
    // The floor is the current count: `codes.rs` is append-only, so it can only ever grow.
    expect(listed.size).toBeGreaterThanOrEqual(4);
  });

  it('reaches every declared code from the closed list', async () => {
    const { declared, listed } = await emittedErrorCodes();
    expect([...declared].filter((code) => !listed.has(code)).sort()).toEqual([]);
  });

  it('maps every emitted code to a catalog key', async () => {
    const { listed } = await emittedErrorCodes();
    const unmapped = [...listed].filter((code) => connectorErrorKey(code) === undefined);
    expect(
      unmapped.sort(),
      'a code the backend can emit has no translation, so it would render as raw English',
    ).toEqual([]);
  });

  it('has no stale map entries beyond what the backend emits', async () => {
    const { listed } = await emittedErrorCodes();
    const stale = Object.keys(CONNECTOR_ERROR_KEYS).filter((code) => !listed.has(code));
    expect(stale.sort(), 'the map claims codes the server no longer emits').toEqual([]);
  });

  it('carries every mapped key in all 14 locales, non-empty', () => {
    expect(Object.keys(ALL_CATALOGS).length).toBe(14);
    const keys = Object.values(CONNECTOR_ERROR_KEYS);
    expect(keys.length).toBeGreaterThanOrEqual(4);
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      expect(missingFrom(catalog, keys), `${locale} is missing connector failure copy`).toEqual([]);
    }
  });

  it('would fail if a backend-added code had no copy', async () => {
    // The guard's own red-proof, on a synthetic `codes.rs` rather than on the shared tree: the one
    // failure this whole file exists to catch is a fifth transport landing with no translation, and
    // a check nobody has seen fire is a check nobody should trust.
    const { listed } = parseCodes(
      [
        'pub const TRANSPORT_NOT_COMPILED_S3: &str = "transport_not_compiled_s3";',
        'pub const TRANSPORT_NOT_COMPILED_NFS: &str = "transport_not_compiled_nfs";',
        'pub const ALL_GATED_TRANSPORTS: &[GatedTransport] = &[',
        '    GatedTransport::S3,',
        '    GatedTransport::Nfs,',
        '];',
        "    pub const fn not_compiled_code(self) -> &'static str {",
        '        match self {',
        '            Self::S3 => TRANSPORT_NOT_COMPILED_S3,',
        '            Self::Nfs => TRANSPORT_NOT_COMPILED_NFS,',
        '        }',
        '    }',
      ].join('\n'),
    );
    expect([...listed].sort()).toEqual(['transport_not_compiled_nfs', 'transport_not_compiled_s3']);
    // The real map covers the one that exists and not the invented one — which is exactly the
    // `[...listed].filter(unmapped)` above going non-empty.
    expect(connectorErrorKey('transport_not_compiled_s3')).toBeDefined();
    expect([...listed].filter((code) => connectorErrorKey(code) === undefined)).toEqual([
      'transport_not_compiled_nfs',
    ]);
  });

  it('would fail if a locale dropped one of the keys', () => {
    // The other half: the same predicate the fourteen-locale check runs, applied to a catalog with
    // one key removed. Proves the check can go red without removing the key from the shared tree,
    // where a concurrent lane would commit the broken catalog.
    const keys = Object.values(CONNECTOR_ERROR_KEYS);
    const dropped = `${PREFIX}transport_not_compiled_smb`;
    const gutted: Record<string, string> = { ...ptPT };
    delete gutted[dropped];
    expect(missingFrom(gutted, keys)).toEqual([dropped]);
    // And an empty string counts as missing too, so a placeholder entry cannot satisfy the gate.
    expect(missingFrom({ ...ptPT, [dropped]: '   ' }, keys)).toEqual([dropped]);
  });

  it('has no orphan catalog key under the connector error-code prefix', () => {
    // The prefix namespace is exactly the code vocabulary — the untranslated-fallback copy lives
    // outside it on purpose, so this check can stay an equality rather than a whitelist.
    const mapped = new Set<string>(Object.values(CONNECTOR_ERROR_KEYS));
    const orphans = Object.keys(enUS).filter((key) => key.startsWith(PREFIX) && !mapped.has(key));
    expect(orphans.sort()).toEqual([]);
  });

  it('names the transport and its cargo feature verbatim in every locale', () => {
    // The two identifiers an operator has to act on: the transport whose client is missing, and
    // the build option that adds it. A translator who localizes either has removed the only
    // actionable content in the sentence. Asserted on the identifier, never on the prose.
    const identifiers: Record<string, [string, string]> = {
      transport_not_compiled_s3: ['S3', 's3'],
      transport_not_compiled_sftp: ['SFTP', 'sftp'],
      transport_not_compiled_smb: ['SMB', 'smb'],
      transport_not_compiled_ftps: ['FTPS', 'ftps'],
    };
    for (const [code, key] of Object.entries(CONNECTOR_ERROR_KEYS)) {
      const [transport, feature] = identifiers[code];
      for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
        expect(catalog[key], `${locale} · ${code}`).toContain(transport);
        expect(catalog[key], `${locale} · ${code}`).toContain(feature);
        expect(catalog[key], `${locale} · ${code}`).toContain('chancela-connectors');
      }
    }
  });

  it('interpolates nothing, in any locale', () => {
    // One code per transport exists precisely so no noun has to be dropped into an inflected
    // sentence. A stray `{…}` here would render a literal brace with no chance of being filled.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      for (const key of Object.values(CONNECTOR_ERROR_KEYS)) {
        expect(catalog[key], `${locale} · ${key}`).not.toMatch(/\{\w+\}/);
      }
    }
  });

  it('carries the untranslated marking in all 14 locales', () => {
    // Without these the fallback path renders unmarked English, which is the failure this whole
    // mechanism exists to make loud.
    for (const [locale, catalog] of Object.entries(ALL_CATALOGS)) {
      expect(catalog['operations.connectors.probe.untranslatedBadge']?.trim(), locale).toBeTruthy();
      expect(catalog['operations.connectors.probe.untranslatedHint']?.trim(), locale).toBeTruthy();
    }
  });
});

describe('resolveConnectorError', () => {
  const t = ((key: string) => enUS[key as keyof typeof enUS] as string) as never;

  it('renders a known code from the catalog', () => {
    const resolved = resolveConnectorError(
      {
        error: 'this build was compiled without the s3 transport; rebuild with …',
        error_code: 'transport_not_compiled_s3',
      },
      t,
    );
    expect(resolved?.untranslated).toBe(false);
    expect(resolved?.text).toBe(enUS[`${PREFIX}transport_not_compiled_s3`]);
  });

  it('falls back to the server English, MARKED, for a code this build does not know', () => {
    const resolved = resolveConnectorError(
      // A server newer than this bundle. `as never` because the wire type is the closed set this
      // build knows, and the point of the test is the value outside it.
      {
        error: 'A sentence from a newer server.',
        error_code: 'invented_by_a_newer_server' as never,
      },
      t,
    );
    // Never blank, never a crash — and never silently passed off as localized copy.
    expect(resolved).toEqual({ text: 'A sentence from a newer server.', untranslated: true });
  });

  it('falls back the same way for the failures that carry no code at all', () => {
    // Most `ConnectorError`s still have `code: None`; only the not-compiled family has one.
    const resolved = resolveConnectorError(
      { error: 'sftp: connection refused', error_code: null },
      t,
    );
    expect(resolved).toEqual({ text: 'sftp: connection refused', untranslated: true });
  });

  it('is null when the probe reported no failure', () => {
    expect(resolveConnectorError({ error: null, error_code: null }, t)).toBeNull();
  });
});
