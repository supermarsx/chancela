/**
 * DIVERGENCE GATE for `externalValidatorStatusFallback.ts` (t87).
 *
 * The operator-facing copy lives client-side while the authoritative status tokens live in Rust.
 * That split is only safe if drift is loud, so this file derives the truth from the emitting source
 * itself rather than from a hand-copied list. Three independent populations, three separate sites in
 * `crates/chancela-api/src/external_validator_evidence.rs`:
 *
 *  - `metadataStatus`     — the `let status = if reports.is_empty()` pair in `metadata_list_response`,
 *                           cross-checked against the token the create handler hard-codes;
 *  - `preservationStatus` — the literals in `ExternalValidatorRawReportAttachment::preservation_status`;
 *  - `storageMode`        — the literals in `storage_mode`.
 *
 * Set equality is asserted in BOTH directions per group: a token the emitter gains with no entry in
 * the fallback is red, and an entry for a token the emitter can no longer produce is red.
 *
 * **These assertions are structural on purpose.** Nothing here matches Portuguese text. A test that
 * pins a substring of reviewed copy turns a correct translation fix red — and a singular/plural slip
 * makes it pass for the wrong reason — so the copy is checked for shape (non-empty, a real sentence,
 * not a restatement of its own identifier, no interpolation slot) and never for wording.
 */
import { describe, expect, it } from 'vitest';

import {
  type ExternalValidatorStatusEntry,
  type ExternalValidatorStatusGroup,
  describeExternalValidatorStatus,
  externalValidatorStatusEnglish,
  externalValidatorStatusPtPT,
} from './externalValidatorStatusFallback';

const EMITTER = 'crates/chancela-api/src/external_validator_evidence.rs';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/**
 * Everything above the `#[cfg(test)]` module, so fixtures never become obligations. The emitter has
 * no test module today; this is prophylactic, and the length floor keeps it from silently
 * truncating the search space if one is added with the attribute indented (memory:
 * `grep-the-symbol-not-the-line`).
 */
function productionSection(source: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(
    section.length,
    'the pre-test section is implausibly short — check the split',
  ).toBeGreaterThan(source.length / 2);
  return section;
}

/** Body of the first fn whose header matches, by brace matching rather than a line count. */
function fnBody(source: string, header: RegExp): string {
  const match = header.exec(source);
  expect(match, `no fn matching ${String(header)} in ${EMITTER}`).not.toBeNull();
  const open = source.indexOf('{', (match as RegExpExecArray).index);
  expect(open, 'matched fn header has no opening brace').toBeGreaterThan(-1);
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

/** Every snake_case string literal in a fragment, in source order, deduplicated. */
function snakeCaseLiterals(fragment: string): string[] {
  const found = [...fragment.matchAll(/"([a-z][a-z0-9_]*)"/gu)].map((m) => m[1] as string);
  return [...new Set(found)];
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

/**
 * `as const satisfies` gives each tier a literal type with no index signature, so a token parsed
 * out of Rust — a plain `string` — cannot index it. Widening here keeps the source objects strictly
 * typed while letting the test look tokens up by the value the emitter actually produces.
 */
type WidenedTiers = Record<
  ExternalValidatorStatusGroup,
  Record<string, ExternalValidatorStatusEntry>
>;
const PT_PT: WidenedTiers = externalValidatorStatusPtPT;
const ENGLISH: WidenedTiers = externalValidatorStatusEnglish;

function entriesOf(group: ExternalValidatorStatusGroup): [string, ExternalValidatorStatusEntry][] {
  return Object.entries(PT_PT[group]);
}

/** The three emitted populations, parsed from Rust. */
async function emittedTokens(): Promise<Record<ExternalValidatorStatusGroup, string[]>> {
  const source = productionSection(await readCrateSource(EMITTER));

  const listStatus =
    /let status = if reports\.is_empty\(\) \{\s*"([a-z0-9_]+)"\s*\} else \{\s*"([a-z0-9_]+)"\s*\}/u.exec(
      source,
    );
  expect(
    listStatus,
    `metadata_list_response no longer assigns status the expected way in ${EMITTER}`,
  ).not.toBeNull();

  return {
    metadataStatus: [
      (listStatus as RegExpExecArray)[1] as string,
      (listStatus as RegExpExecArray)[2] as string,
    ],
    preservationStatus: snakeCaseLiterals(
      fnBody(source, /pub fn preservation_status\(&self\) -> &'static str/u),
    ),
    storageMode: snakeCaseLiterals(
      fnBody(source, /fn storage_mode\(durable: bool\) -> &'static str/u),
    ),
  };
}

describe('the emitted status tokens are parsed, not assumed', () => {
  it('finds a distinct token pair for each of the three populations', async () => {
    const emitted = await emittedTokens();
    // Non-vacuity: a parse that silently matched nothing would make every set comparison below
    // trivially pass against an empty population.
    for (const [group, tokens] of Object.entries(emitted)) {
      expect(tokens.length, `${group} parsed no tokens from ${EMITTER}`).toBe(2);
      expect(new Set(tokens).size, `${group} parsed a duplicated token`).toBe(2);
    }
    expect(new Set(Object.values(emitted).flat()).size).toBe(6);
  });

  it('cross-checks the create handler against the list status population', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    const created =
      /ExternalValidatorReportMetadataCreateResponse \{[\s\S]{0,400}?status: "([a-z0-9_]+)"/u.exec(
        source,
      );
    expect(
      created,
      `the create handler no longer hard-codes a status in ${EMITTER}`,
    ).not.toBeNull();
    const token = (created as RegExpExecArray)[1] as string;
    const emitted = await emittedTokens();
    expect(
      emitted.metadataStatus,
      'the create handler emits a status the list endpoint cannot produce',
    ).toContain(token);
  });
});

describe('every emitted status has a label, and every label has an emitted status', () => {
  const groups: ExternalValidatorStatusGroup[] = [
    'metadataStatus',
    'preservationStatus',
    'storageMode',
  ];

  it.each(groups)('%s matches the Rust emitter in both directions', async (group) => {
    const emitted = await emittedTokens();
    expect(sorted(Object.keys(PT_PT[group]))).toEqual(sorted(emitted[group]));
  });

  it('describes every emitted token as known', async () => {
    const emitted = await emittedTokens();
    for (const group of groups) {
      for (const token of emitted[group]) {
        expect(describeExternalValidatorStatus(group, token).known, `${group}/${token}`).toBe(true);
      }
    }
  });

  it('keeps the English tier on the same key set as pt-PT', () => {
    for (const group of groups) {
      expect(sorted(Object.keys(ENGLISH[group]))).toEqual(sorted(Object.keys(PT_PT[group])));
    }
  });
});

describe('the copy has the right shape, whatever its wording', () => {
  const groups: ExternalValidatorStatusGroup[] = [
    'metadataStatus',
    'preservationStatus',
    'storageMode',
  ];

  it('is a non-empty label and a real sentence, in both tiers', () => {
    for (const group of groups) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as ExternalValidatorStatusEntry;
        for (const entry of [pt, en]) {
          expect(entry.label.trim(), `${group}/${token} label`).not.toBe('');
          expect(entry.meaning.trim().length, `${group}/${token} meaning`).toBeGreaterThan(40);
          expect(entry.meaning.trim().endsWith('.'), `${group}/${token} meaning`).toBe(true);
          expect(['ok', 'neutral', 'warn'], `${group}/${token} tone`).toContain(entry.tone);
        }
      }
    }
  });

  it('never restates its own identifier and never interpolates a noun', () => {
    for (const group of groups) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as ExternalValidatorStatusEntry;
        const spelledOut = token.replace(/_/gu, ' ');
        for (const entry of [pt, en]) {
          const copy = `${entry.label} ${entry.meaning}`.toLowerCase();
          expect(copy, `${group}/${token} restates its identifier`).not.toContain(token);
          // Exact match, not a substring: for a short token like `data_dir` the natural English
          // words ARE "data directory", so a substring test flags correct copy. What is worth
          // catching is a label that is nothing but the token with its underscores removed.
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
});

describe('an unrecognised token still renders something', () => {
  it('returns a non-empty description marked unknown rather than blank space', () => {
    const resolved = describeExternalValidatorStatus('metadataStatus', 'a_token_from_the_future');
    expect(resolved.known).toBe(false);
    expect(resolved.label.trim()).not.toBe('');
    expect(resolved.meaning.trim()).not.toBe('');
  });
});
