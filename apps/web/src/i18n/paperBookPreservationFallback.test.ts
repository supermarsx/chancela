/**
 * DIVERGENCE GATE for `paperBookPreservationFallback.ts` (t98).
 *
 * The operator-facing copy lives client-side while the authoritative token lives in Rust. That split
 * is only safe if drift is loud, so this derives the truth from the emitting source itself rather
 * than from a hand-copied list.
 *
 * `preservation_status` has no enum behind it — it is a `&'static str` field on
 * `PaperBookCandidateClassification`, hard-coded at each struct construction. So the population is
 * parsed by finding every `PaperBookCandidateClassification { … }` literal by brace matching (never
 * a line count — line numbers drift on a shared tree, memory: `grep-the-symbol-not-the-line`) and
 * reading the `preservation_status:` assignment out of each.
 *
 * Set equality is asserted in BOTH directions: a token the emitter gains with no entry in the
 * fallback is red, and an entry for a token the emitter can no longer produce is red.
 *
 * **These assertions are structural on purpose.** Nothing here matches Portuguese text. A test that
 * pins a substring of reviewed copy turns a correct translation fix red — and a singular/plural slip
 * makes it pass for the wrong reason — so the copy is checked for shape (non-empty, a real sentence,
 * not a restatement of its own identifier, no interpolation slot) and never for wording.
 *
 * The no-claims siblings are pinned too, in the opposite direction: this asserts the four
 * `*_claimed` fields are still hard-coded `false` at every construction, so a build that started
 * asserting one of them would go red here rather than silently changing what the neighbouring
 * «Validade legal declarada: não» sentence means.
 */
import { describe, expect, it } from 'vitest';

import {
  type PaperBookPreservationEntry,
  describePaperBookPreservation,
  paperBookPreservationEnglish,
  paperBookPreservationPtPT,
} from './paperBookPreservationFallback';

const EMITTER = 'crates/chancela-api/src/paper_import.rs';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/**
 * Everything above the `#[cfg(test)]` module, so fixtures never become obligations. The length floor
 * keeps the split from silently truncating the search space.
 */
function productionSection(source: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(
    section.length,
    'the pre-test section is implausibly short — check the split',
  ).toBeGreaterThan(source.length / 3);
  return section;
}

/**
 * Every `PaperBookCandidateClassification { … }` CONSTRUCTION body, by brace matching.
 *
 * `pub struct PaperBookCandidateClassification { … }` matches the same header shape but declares
 * `pub preservation_status: &'static str` rather than assigning a literal, so the definition is
 * excluded by looking at the text immediately before the name. Skipping it by "no literal found"
 * instead would make the parse silently tolerant of a construction that stopped hard-coding one.
 */
function classificationLiterals(source: string): string[] {
  const header = /PaperBookCandidateClassification\s*\{/gu;
  const bodies: string[] = [];
  for (const match of source.matchAll(header)) {
    if (/\b(struct|impl)\s+$/u.test(source.slice(Math.max(0, match.index - 24), match.index))) {
      continue;
    }
    const open = source.indexOf('{', match.index);
    let depth = 0;
    let closed = false;
    for (let i = open; i < source.length; i += 1) {
      if (source[i] === '{') depth += 1;
      else if (source[i] === '}') {
        depth -= 1;
        if (depth === 0) {
          bodies.push(source.slice(open + 1, i));
          closed = true;
          break;
        }
      }
    }
    expect(closed, `unbalanced braces in a classification literal in ${EMITTER}`).toBe(true);
  }
  return bodies;
}

/** The emitted `preservation_status` population, parsed from Rust. */
async function emittedTokens(): Promise<string[]> {
  const source = productionSection(await readCrateSource(EMITTER));
  const bodies = classificationLiterals(source);
  expect(
    bodies.length,
    `no PaperBookCandidateClassification literal found in ${EMITTER} — check the parse`,
  ).toBeGreaterThan(0);

  const tokens = bodies.map((body) => {
    const assigned = /preservation_status:\s*"([a-z0-9_]+)"/u.exec(body);
    expect(
      assigned,
      `a PaperBookCandidateClassification literal in ${EMITTER} no longer hard-codes preservation_status`,
    ).not.toBeNull();
    return (assigned as RegExpExecArray)[1] as string;
  });
  return [...new Set(tokens)];
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

/**
 * `as const satisfies` gives each tier a literal type with no index signature, so a token parsed out
 * of Rust — a plain `string` — cannot index it. Widening here keeps the source objects strictly
 * typed while letting the test look tokens up by the value the emitter actually produces.
 */
type WidenedTable = Record<string, PaperBookPreservationEntry>;
const PT_PT: WidenedTable = paperBookPreservationPtPT;
const ENGLISH: WidenedTable = paperBookPreservationEnglish;

describe('the emitted preservation tokens are parsed, not assumed', () => {
  it('finds both construction sites and a distinct token from each', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    // Non-vacuity: a parse that silently matched nothing would make the set comparison below pass
    // trivially against an empty population.
    expect(classificationLiterals(source).length).toBeGreaterThanOrEqual(2);
    const tokens = await emittedTokens();
    expect(tokens.length, `parsed no distinct token from ${EMITTER}`).toBe(2);
    for (const token of tokens) {
      expect(token, 'parsed a token that is not a snake_case identifier').toMatch(
        /^[a-z][a-z0-9_]*$/u,
      );
    }
  });

  it('keeps the no-claims siblings hard-coded false at every construction', async () => {
    // Not this module's copy, but the sentence next to it on screen depends on these staying false.
    const source = productionSection(await readCrateSource(EMITTER));
    const noClaims = [
      'canonical_minutes_claimed',
      'legal_validity_claimed',
      'signature_validity_claimed',
      'qualified_signature_claimed',
    ];
    for (const body of classificationLiterals(source)) {
      for (const field of noClaims) {
        expect(body, `${field} is no longer hard-coded false in ${EMITTER}`).toMatch(
          new RegExp(`${field}:\\s*false`, 'u'),
        );
      }
    }
  });
});

describe('every emitted token has a label, and every label has an emitted token', () => {
  it('matches the Rust emitter in both directions', async () => {
    expect(sorted(Object.keys(PT_PT))).toEqual(sorted(await emittedTokens()));
  });

  it('describes every emitted token as known', async () => {
    for (const token of await emittedTokens()) {
      expect(describePaperBookPreservation(token).known, token).toBe(true);
    }
  });

  it('keeps the English tier on the same key set as pt-PT', () => {
    expect(sorted(Object.keys(ENGLISH))).toEqual(sorted(Object.keys(PT_PT)));
  });
});

describe('the copy has the right shape, whatever its wording', () => {
  it('is a non-empty label and a real sentence, in both tiers', () => {
    for (const [token, pt] of Object.entries(PT_PT)) {
      const en = ENGLISH[token] as PaperBookPreservationEntry;
      for (const entry of [pt, en]) {
        expect(entry.label.trim(), `${token} label`).not.toBe('');
        expect(entry.meaning.trim().length, `${token} meaning`).toBeGreaterThan(40);
        expect(entry.meaning.trim().endsWith('.'), `${token} meaning`).toBe(true);
        expect(['ok', 'neutral', 'warn'], `${token} tone`).toContain(entry.tone);
      }
    }
  });

  it('never restates its own identifier and never interpolates a noun', () => {
    for (const [token, pt] of Object.entries(PT_PT)) {
      const en = ENGLISH[token] as PaperBookPreservationEntry;
      const spelledOut = token.replace(/_/gu, ' ');
      for (const entry of [pt, en]) {
        const copy = `${entry.label} ${entry.meaning}`.toLowerCase();
        expect(copy, `${token} restates its identifier`).not.toContain(token);
        const normalisedLabel = entry.label
          .toLowerCase()
          .replace(/[^a-z0-9]+/gu, ' ')
          .trim();
        expect(normalisedLabel, `${token} label just respells its identifier`).not.toBe(spelledOut);
        // A noun dropped into an inflected sentence breaks agreement, so no entry carries a slot
        // (memory: `i18n-interpolated-nouns-break-agreement`).
        expect(entry.meaning, `${token} carries an interpolation slot`).not.toMatch(/\{[a-z]/iu);
      }
    }
  });

  it('keeps the non-canonical qualifier the preserved token carries', () => {
    // The one wording constraint worth pinning: `preserved_non_canonical_package` means preserved AS
    // NON-CANONICAL EVIDENCE. Copy that says only "preserved" would upgrade the state on screen.
    // Asserted as a denial being present, not as a phrasing.
    expect(
      (PT_PT.preserved_non_canonical_package as PaperBookPreservationEntry).meaning.toLowerCase(),
    ).toMatch(/não constitui|não substitui/u);
    expect(
      (ENGLISH.preserved_non_canonical_package as PaperBookPreservationEntry).meaning.toLowerCase(),
    ).toMatch(/is not|does not/u);
  });
});

describe('an unrecognised token still renders something', () => {
  it('returns a non-empty description marked unknown rather than blank space', () => {
    const resolved = describePaperBookPreservation('a_token_from_the_future');
    expect(resolved.known).toBe(false);
    expect(resolved.label.trim()).not.toBe('');
    expect(resolved.meaning.trim()).not.toBe('');
  });
});
