/**
 * Completeness contract for the PDF/PAdES validation finding vocabulary.
 *
 * Same guard as `asicInspectionDiagnostics.test.ts`, with one difference that matters: this
 * vocabulary is **deliberately untranslated for now**, so the contract is
 * `mapped ∪ pending == what Rust emits` rather than `mapped == what Rust emits`. That keeps a
 * newly added backend code failing loudly while the pending set stays enumerated instead of
 * silently absorbing it.
 */
import { describe, expect, it } from 'vitest';
import {
  PDF_FINDING_KEYS,
  PDF_FINDING_PREFIX,
  PENDING_TRANSLATION,
  VERBATIM_ERROR_CODES,
  resolvePdfFinding,
} from './pdfValidationDiagnostics';
import { enUS } from './locales/en-US';

async function emittedFindingCodes(): Promise<{ declared: Set<string>; listed: Set<string> }> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  const source = readFileSync('../../crates/chancela-api/src/pdf_signature_validation.rs', 'utf8');

  const declarations = new Map<string, string>();
  for (const match of source.matchAll(
    /pub const (PDF_FINDING_[A-Z0-9_]+): &str =\s*\n?\s*"([a-z0-9_]+)";/g,
  )) {
    declarations.set(match[1], match[2]);
  }

  const listBody =
    /PDF_VALIDATION_FINDING_CODES: &\[&str\] = &\[([\s\S]*?)\];/.exec(source)?.[1] ?? '';
  const listed = new Set<string>();
  for (const match of listBody.matchAll(/^\s{4}(PDF_FINDING_[A-Z0-9_]+),$/gm)) {
    const value = declarations.get(match[1]);
    if (value) listed.add(value);
  }

  return { declared: new Set(declarations.values()), listed };
}

describe('PDF validation findings cover every code the server can emit', () => {
  it('extracts a non-vacuous code list from the Rust source', async () => {
    const { declared, listed } = await emittedFindingCodes();
    expect(declared.size, 'the constant scan matched nothing').toBeGreaterThan(0);
    expect(listed.size, 'the PDF_VALIDATION_FINDING_CODES scan matched nothing').toBeGreaterThan(0);
    expect(listed.size).toBeGreaterThanOrEqual(14);
  });

  it('lists every declared code (none declared but left out of the closed list)', async () => {
    const { declared, listed } = await emittedFindingCodes();
    expect([...declared].filter((code) => !listed.has(code)).sort()).toEqual([]);
  });

  it('accounts for every emitted code as either translated or knowingly pending', async () => {
    const { listed } = await emittedFindingCodes();
    const unaccounted = [...listed].filter(
      (code) => PDF_FINDING_KEYS[code] === undefined && !PENDING_TRANSLATION.has(code),
    );
    expect(
      unaccounted.sort(),
      'a code the backend can emit is neither mapped nor listed as pending, so it would render as unexplained English',
    ).toEqual([]);
  });

  it('has no stale entry in either set beyond what the backend emits', async () => {
    const { listed } = await emittedFindingCodes();
    const stale = [...Object.keys(PDF_FINDING_KEYS), ...PENDING_TRANSLATION].filter(
      (code) => !listed.has(code),
    );
    expect(stale.sort(), 'a set claims a code the server no longer emits').toEqual([]);
  });

  it('never has a code in both the mapped and the pending set', () => {
    const both = Object.keys(PDF_FINDING_KEYS).filter((code) => PENDING_TRANSLATION.has(code));
    expect(both.sort(), 'a translated code is still marked pending').toEqual([]);
  });

  it('keeps every verbatim-error code inside the emitted vocabulary', async () => {
    const { listed } = await emittedFindingCodes();
    const unknown = [...VERBATIM_ERROR_CODES].filter((code) => !listed.has(code));
    expect(unknown.sort()).toEqual([]);
  });

  it('has no orphan catalog key under the prefix while the map is empty', () => {
    const mapped = new Set<string>(Object.values(PDF_FINDING_KEYS));
    const orphans = Object.keys(enUS).filter(
      (key) => key.startsWith(PDF_FINDING_PREFIX) && !mapped.has(key),
    );
    expect(orphans.sort(), 'catalog copy exists for a code the map does not claim').toEqual([]);
  });
});

describe('resolvePdfFinding while the vocabulary is untranslated', () => {
  const t = (() => 'should not be called') as never;

  it('marks every emitted code as English rather than passing it off as localized', async () => {
    const { listed } = await emittedFindingCodes();
    for (const code of listed) {
      const resolved = resolvePdfFinding({ code, message: 'server English', params: {} }, t);
      expect(resolved, code).toEqual({ kind: 'untranslated', text: 'server English' });
    }
  });

  it('still marks a code from a newer server', () => {
    const resolved = resolvePdfFinding(
      { code: 'invented_by_a_newer_server', message: 'A newer sentence.' },
      t,
    );
    expect(resolved).toEqual({ kind: 'untranslated', text: 'A newer sentence.' });
  });
});
