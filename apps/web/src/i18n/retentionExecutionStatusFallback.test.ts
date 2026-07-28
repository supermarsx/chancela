/**
 * DIVERGENCE GATE for `retentionExecutionStatusFallback.ts` (t98).
 *
 * The operator-facing copy lives client-side while the authoritative tokens live in Rust. That split
 * is only safe if drift is loud, so this derives the truth from the emitting source itself rather
 * than from a hand-copied list. All five populations of the retention surface, four of them owned by
 * the fallback module and one by the shipped catalog, parsed from
 * `crates/chancela-api/src/privacy.rs`:
 *
 *  - `outcome`         — the `RetentionExecutionOutcome` enum, cross-checked against the exhaustive
 *                        `retention_execution_outcome_wire` match, which is what actually puts the
 *                        token on the wire;
 *  - `evidenceState`   — the `RetentionEvidenceState` enum;
 *  - `disposition`     — the `RetentionCandidateDisposition` enum, cross-checked against the arms of
 *                        its `parse` (the accepted spellings on the way in);
 *  - `dryRunMode`      — the `let mode = if execution_record.is_some()` pair;
 *  - `executionStatus` — the `RetentionExecutionStatus` enum, checked against the exported
 *                        `RETENTION_EXECUTION_STATUSES` union rather than against this module, since
 *                        that population's copy lives in the shipped catalog (see the module header).
 *
 * The enums are read THROUGH `#[serde(rename_all = "snake_case")]`, asserted per enum, rather than
 * by lowercasing alone: `BlockedLegalHold` lowercased is `blockedlegalhold`.
 *
 * Set equality is asserted in BOTH directions per group: a token the emitter gains with no entry in
 * the fallback is red, and an entry for a token the emitter can no longer produce is red.
 *
 * **These assertions are structural on purpose.** Nothing here matches reviewed Portuguese wording.
 * A test that pins a substring of copy turns a correct translation fix red — and a singular/plural
 * slip makes it pass for the wrong reason — so the copy is checked for shape and never for phrasing.
 *
 * The ONE exception is the denial, and it is a claim check rather than a style check. Every arm of
 * the Rust workflow states what did not happen ("no disposal has been executed", "no source document
 * deletion or GDPR erasure was performed", "no duplicate action was recorded"). On a retention
 * surface that is the operator's most important fact, and copy that dropped it would read as though
 * something had been destroyed. So every `outcome` and every `disposition` entry must carry one, in
 * both tiers. The check matches a small curated set of denial clauses, not a specific sentence.
 */
import { describe, expect, it } from 'vitest';

import { RETENTION_EXECUTION_STATUSES } from '../api/types';
import {
  type RetentionStatusEntry,
  type RetentionStatusGroup,
  describeRetentionStatus,
  retentionStatusEnglish,
  retentionStatusPtPT,
} from './retentionExecutionStatusFallback';

const EMITTER = 'crates/chancela-api/src/privacy.rs';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/**
 * Everything above the `#[cfg(test)]` module, so fixtures never become obligations. The length floor
 * keeps the split from silently truncating the search space if one is added with the attribute
 * indented (memory: `grep-the-symbol-not-the-line`).
 */
function productionSection(source: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(
    section.length,
    'the pre-test section is implausibly short — check the split',
  ).toBeGreaterThan(source.length / 4);
  return section;
}

/** Body of the first item whose header matches, by brace matching rather than a line count. */
function braceBody(source: string, header: RegExp): string {
  const match = header.exec(source);
  expect(match, `nothing matching ${String(header)} in ${EMITTER}`).not.toBeNull();
  const open = source.indexOf('{', (match as RegExpExecArray).index);
  expect(open, 'matched header has no opening brace').toBeGreaterThan(-1);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  throw new Error(`unbalanced braces after ${String(header)} in ${EMITTER}`);
}

/** `BlockedLegalHold` -> `blocked_legal_hold`, matching `#[serde(rename_all = "snake_case")]`. */
function snakeCase(variant: string): string {
  return variant.replace(/([a-z0-9])([A-Z])/gu, '$1_$2').toLowerCase();
}

/**
 * A Rust enum's wire tokens: its variants put through the serde rename, with the rename attribute
 * itself asserted so a change of casing scheme is red rather than silent.
 */
function enumWireTokens(source: string, name: string): string[] {
  const declaration = new RegExp(`pub enum ${name}\\b`, 'u');
  const match = declaration.exec(source);
  expect(match, `no \`pub enum ${name}\` in ${EMITTER}`).not.toBeNull();

  const attributes = source.slice(
    Math.max(0, (match as RegExpExecArray).index - 300),
    (match as RegExpExecArray).index,
  );
  expect(
    attributes,
    `${name} is no longer renamed to snake_case — its wire tokens have moved`,
  ).toMatch(/#\[serde\(rename_all\s*=\s*"snake_case"\)\]/u);

  const variants = [
    ...braceBody(source, declaration).matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*,/gmu),
  ].map((m) => m[1] as string);
  expect(variants.length, `parsed no variants of ${name}`).toBeGreaterThan(0);
  return variants.map(snakeCase);
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

/** The five emitted populations, parsed from Rust. */
async function emittedTokens(): Promise<Record<RetentionStatusGroup | 'executionStatus', string[]>> {
  const source = productionSection(await readCrateSource(EMITTER));

  const mode =
    /let mode = if execution_record\.is_some\(\) \{\s*"([a-z0-9_]+)"\s*\} else \{\s*"([a-z0-9_]+)"\s*\}/u.exec(
      source,
    );
  expect(mode, `the dry-run report no longer derives \`mode\` the expected way in ${EMITTER}`)
    .not.toBeNull();

  return {
    outcome: enumWireTokens(source, 'RetentionExecutionOutcome'),
    evidenceState: enumWireTokens(source, 'RetentionEvidenceState'),
    disposition: enumWireTokens(source, 'RetentionCandidateDisposition'),
    dryRunMode: [
      (mode as RegExpExecArray)[1] as string,
      (mode as RegExpExecArray)[2] as string,
    ],
    executionStatus: enumWireTokens(source, 'RetentionExecutionStatus'),
  };
}

/**
 * `as const satisfies` gives each tier a literal type with no index signature, so a token parsed out
 * of Rust — a plain `string` — cannot index it. Widening here keeps the source objects strictly
 * typed while letting the test look tokens up by the value the emitter actually produces.
 */
type WidenedTiers = Record<RetentionStatusGroup, Record<string, RetentionStatusEntry>>;
const PT_PT: WidenedTiers = retentionStatusPtPT;
const ENGLISH: WidenedTiers = retentionStatusEnglish;

const GROUPS: RetentionStatusGroup[] = ['outcome', 'evidenceState', 'disposition', 'dryRunMode'];

function entriesOf(group: RetentionStatusGroup): [string, RetentionStatusEntry][] {
  return Object.entries(PT_PT[group]);
}

describe('the emitted retention tokens are parsed, not assumed', () => {
  it('finds a plausible, distinct population for each of the five groups', async () => {
    const emitted = await emittedTokens();
    // Non-vacuity: a parse that silently matched nothing would make every set comparison below pass
    // trivially against an empty population.
    const expectedSizes = {
      outcome: 11,
      evidenceState: 5,
      disposition: 3,
      dryRunMode: 2,
      executionStatus: 3,
    } as const;
    for (const [group, size] of Object.entries(expectedSizes)) {
      const tokens = emitted[group as keyof typeof expectedSizes];
      expect(tokens.length, `${group} parsed the wrong number of tokens`).toBe(size);
      expect(new Set(tokens).size, `${group} parsed a duplicated token`).toBe(size);
      for (const token of tokens) {
        expect(token, `${group} parsed a token that is not an identifier`).toMatch(
          /^[a-z][a-z0-9_]*$/u,
        );
      }
    }
  });

  it('reads the enum variants through the serde rename, not by lowercasing', async () => {
    // `BlockedLegalHold` lowercased is `blockedlegalhold`. A regression to a bare `toLowerCase()`
    // would produce tokens the server never sends, and this is what catches it.
    const emitted = await emittedTokens();
    expect(emitted.outcome).toContain('blocked_legal_hold');
    expect(emitted.outcome).not.toContain('blockedlegalhold');
  });

  it('cross-checks the outcome enum against the match that puts it on the wire', async () => {
    // The enum is the declaration; `retention_execution_outcome_wire` is what actually serialises.
    // If they ever disagree, the enum is not the emitter and this whole gate is measuring the wrong
    // thing.
    const source = productionSection(await readCrateSource(EMITTER));
    const body = braceBody(source, /fn retention_execution_outcome_wire\(/u);
    const wire = [...body.matchAll(/=>\s*"([a-z0-9_]+)"/gu)].map((m) => m[1] as string);
    const emitted = await emittedTokens();
    expect(sorted([...new Set(wire)])).toEqual(sorted(emitted.outcome));
  });

  it('cross-checks the disposition enum against the spellings its parser accepts', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    const body = braceBody(source, /impl RetentionCandidateDisposition\b/u);
    const emitted = await emittedTokens();
    for (const token of emitted.disposition) {
      expect(body, `${token} is not accepted by RetentionCandidateDisposition::parse`).toContain(
        `"${token}"`,
      );
    }
  });
});

describe('every emitted status has a label, and every label has an emitted status', () => {
  it.each(GROUPS)('%s matches the Rust emitter in both directions', async (group) => {
    const emitted = await emittedTokens();
    expect(sorted(Object.keys(PT_PT[group]))).toEqual(sorted(emitted[group]));
  });

  it('keeps the catalog-owned execution statuses matching the Rust enum in both directions', async () => {
    // This population's copy is in the shipped `Catalog`, not in the fallback module, so what is
    // checked is the exported union the label map is keyed by. It must still not drift from Rust.
    const emitted = await emittedTokens();
    expect(sorted([...RETENTION_EXECUTION_STATUSES])).toEqual(sorted(emitted.executionStatus));
  });

  it('describes every emitted token as known', async () => {
    const emitted = await emittedTokens();
    for (const group of GROUPS) {
      for (const token of emitted[group]) {
        expect(describeRetentionStatus(group, token).known, `${group}/${token}`).toBe(true);
      }
    }
  });

  it('keeps the English tier on the same key set as pt-PT', () => {
    for (const group of GROUPS) {
      expect(sorted(Object.keys(ENGLISH[group]))).toEqual(sorted(Object.keys(PT_PT[group])));
    }
  });
});

describe('the copy has the right shape, whatever its wording', () => {
  it('is a non-empty label and a real sentence, in both tiers', () => {
    for (const group of GROUPS) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as RetentionStatusEntry;
        for (const entry of [pt, en]) {
          expect(entry.label.trim(), `${group}/${token} label`).not.toBe('');
          expect(entry.meaning.trim().length, `${group}/${token} meaning`).toBeGreaterThan(40);
          expect(entry.meaning.trim().endsWith('.'), `${group}/${token} meaning`).toBe(true);
          expect(['ok', 'neutral', 'warn', 'error'], `${group}/${token} tone`).toContain(entry.tone);
        }
      }
    }
  });

  it('never restates its own identifier and never interpolates a noun', () => {
    for (const group of GROUPS) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as RetentionStatusEntry;
        const spelledOut = token.replace(/_/gu, ' ');
        for (const entry of [pt, en]) {
          const copy = `${entry.label} ${entry.meaning}`.toLowerCase();
          // Multi-word tokens only: `blocked` on its own is an ordinary English word that correct
          // copy may legitimately use, and banning it would forbid the accurate sentence. The
          // label-respelling check below still covers the single-word members.
          if (token.includes('_')) {
            expect(copy, `${group}/${token} restates its identifier`).not.toContain(token);
          }
          const normalisedLabel = entry.label
            .toLowerCase()
            .replace(/[^a-z0-9]+/gu, ' ')
            .trim();
          expect(normalisedLabel, `${group}/${token} label just respells its identifier`).not.toBe(
            spelledOut,
          );
          // A noun dropped into an inflected sentence breaks agreement, so no entry carries a slot
          // (memory: `i18n-interpolated-nouns-break-agreement`).
          expect(entry.meaning, `${group}/${token} carries an interpolation slot`).not.toMatch(
            /\{[a-z]/iu,
          );
        }
      }
    }
  });

  it('states what did NOT happen on every outcome and every disposition', () => {
    // The claim check, not a style check — see the header. Rust says it in every arm; so must the
    // copy, or a retention panel reads as though something had been destroyed.
    const DENIAL_PT =
      /nada foi eliminado\.|nada de novo foi eliminado\.|nenhum documento de origem foi apagado|nada foi eliminado nem anonimizado\./u;
    const DENIAL_EN =
      /nothing was deleted\.|nothing new was deleted\.|no source document was deleted|nothing was deleted or anonymised\./u;
    for (const group of ['outcome', 'disposition'] as const) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as RetentionStatusEntry;
        expect(pt.meaning.toLowerCase(), `${group}/${token} pt-PT states no denial`).toMatch(
          DENIAL_PT,
        );
        expect(en.meaning.toLowerCase(), `${group}/${token} English states no denial`).toMatch(
          DENIAL_EN,
        );
      }
    }
  });

  it('does not let a bounded evidence state imply a deletion', () => {
    // `bounded_*` means the executor is evidence-only. Both entries must deny deletion outright.
    for (const token of ['bounded_archive_recorded', 'bounded_no_action_recorded']) {
      expect(
        (PT_PT.evidenceState[token] as RetentionStatusEntry).meaning.toLowerCase(),
      ).toContain('não inclui qualquer eliminação');
      expect(
        (ENGLISH.evidenceState[token] as RetentionStatusEntry).meaning.toLowerCase(),
      ).toContain('no deletion');
    }
  });
});

describe('an unrecognised token still renders something', () => {
  it('returns a non-empty description marked unknown rather than blank space', () => {
    for (const group of GROUPS) {
      const resolved = describeRetentionStatus(group, 'a_token_from_the_future');
      expect(resolved.known, group).toBe(false);
      expect(resolved.label.trim(), group).not.toBe('');
      expect(resolved.meaning.trim(), group).not.toBe('');
    }
  });
});
