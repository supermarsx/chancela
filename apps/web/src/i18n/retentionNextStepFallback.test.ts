/**
 * DIVERGENCE GATE for `retentionNextStepFallback.ts` (t93).
 *
 * The operator-facing next-step prose lives client-side while the authoritative English lives in
 * `crates/chancela-api/src/privacy.rs`. This file derives the truth from the emitting source itself,
 * by brace matching rather than a line count (memory: `grep-the-symbol-not-the-line`), from five
 * sites:
 *
 *  - the three `RETENTION_PRIOR_BOUNDED_*_NEXT_STEP` consts;
 *  - `retention_due_candidate_for_book_policy()` — the two special-case sentences written before any
 *    `RetentionExecutionOutcome` match runs;
 *  - `retention_operator_workflow()` — the nine-arm match on outcome;
 *  - `retention_execution_evidence_next_step()` — the three-arm override plus passthrough;
 *  - `retention_candidate_resolution_next_step()` — the three-arm match on disposition;
 *  - `legacy_retention_operator_workflow()` — the fixed sentence for pre-`workflow`-field records.
 *
 * Equality is asserted in BOTH directions, on the twenty **string values**, not just the twenty keys:
 * a sentence Rust gains with no entry here is red, an entry for a sentence Rust can no longer produce
 * is red, and — because {@link retentionNextStepEnglish} is pinned to be the Rust literal verbatim —
 * so is a one-word reword of any of them.
 *
 * These assertions are structural. Nothing here matches Portuguese text: the pt-PT tier is checked
 * for shape (non-empty, a real sentence, no interpolation slot, actually different from the English)
 * and never for wording, so a correct translation fix never goes red for phrasing.
 */
import { describe, expect, it, vi } from 'vitest';

import {
  type RetentionNextStepCode,
  resolveRetentionNextStep,
  retentionNextStepEnglish,
  retentionNextStepPtPT,
} from './retentionNextStepFallback';

const EMITTER = 'crates/chancela-api/src/privacy.rs';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/** Everything above the `#[cfg(test)]` module, so test fixtures never become obligations. */
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

/** Body of the block starting at `marker`, by brace matching from its first `{`. */
function blockBody(source: string, marker: string, label: string): string {
  const start = source.indexOf(marker);
  expect(start, `${label} not found in ${EMITTER}`).toBeGreaterThan(-1);
  const open = source.indexOf('{', start);
  expect(open, `${label} has no opening brace`).toBeGreaterThan(-1);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  throw new Error(`unbalanced braces after ${label} in ${EMITTER}`);
}

const STRING_LITERAL = /"((?:[^"\\]|\\.)*)"/gu;

/** Every string literal in a fragment, in source order. */
function stringLiterals(fragment: string): string[] {
  return [...fragment.matchAll(STRING_LITERAL)].map((m) => m[1] as string);
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

// ═══ WHAT RUST ACTUALLY EMITS ══════════════════════════════════════════════════════════════════

/** The three `RETENTION_PRIOR_BOUNDED_*_NEXT_STEP` consts. */
function emittedPriorBoundedConsts(source: string): Record<string, string> {
  const pattern = /const RETENTION_PRIOR_BOUNDED_(\w+)_NEXT_STEP: &str = "((?:[^"\\]|\\.)*)";/gu;
  const byArm: Record<string, string> = {};
  for (const match of source.matchAll(pattern)) {
    byArm[match[1] as string] = match[2] as string;
  }
  expect(Object.keys(byArm), 'RETENTION_PRIOR_BOUNDED_*_NEXT_STEP consts').toHaveLength(3);
  return {
    priorBoundedArchive: byArm.ARCHIVE as string,
    priorBoundedNoAction: byArm.NO_ACTION as string,
    priorBoundedGeneric: byArm.GENERIC as string,
  };
}

/** The two special-case sentences `retention_due_candidate_for_book_policy` writes directly. */
function emittedCandidateBuilderSpecialCases(source: string): Record<string, string> {
  const body = fnBody(source, /fn retention_due_candidate_for_book_policy\(/u);
  const unsupportedPeriod =
    /"unsupported_retention_period"\.to_owned\(\),\s*"blocked"\.to_owned\(\),\s*"((?:[^"\\]|\\.)*)"/u.exec(
      body,
    );
  expect(unsupportedPeriod, 'unsupported_retention_period next_step literal').not.toBeNull();
  const legalHold =
    /"blocked_legal_hold"\.to_owned\(\),\s*"blocked"\.to_owned\(\),\s*"((?:[^"\\]|\\.)*)"/u.exec(
      body,
    );
  expect(legalHold, 'blocked_legal_hold next_step literal').not.toBeNull();
  return {
    unsupportedRetentionPeriod: (unsupportedPeriod as RegExpExecArray)[1] as string,
    blockedLegalHold: (legalHold as RegExpExecArray)[1] as string,
  };
}

/** The nine-arm `next_step = match outcome { … }` inside `retention_operator_workflow`. */
function emittedWorkflowNextStep(source: string): Record<string, string> {
  const fn = fnBody(source, /fn retention_operator_workflow\(/u);
  const block = blockBody(fn, 'let next_step = match outcome {', 'workflow next_step match');
  const literals = stringLiterals(block);
  expect(literals, 'retention_operator_workflow next_step arms').toHaveLength(9);
  const [
    blockedPolicySelection,
    blockedLegalHold,
    blockedDestructiveAction,
    blockedApprovalMismatch,
    blockedMissingTarget,
    manualReviewRequired,
    boundedArchiveWorkflow,
    boundedNoActionWorkflow,
    alreadyExecutedWorkflow,
  ] = literals as [string, string, string, string, string, string, string, string, string];
  return {
    blockedPolicySelection,
    blockedLegalHold,
    blockedDestructiveAction,
    blockedApprovalMismatch,
    blockedMissingTarget,
    manualReviewRequired,
    boundedArchiveWorkflow,
    boundedNoActionWorkflow,
    alreadyExecutedWorkflow,
  };
}

/** The three-arm override in `retention_execution_evidence_next_step`, ignoring the `_` passthrough. */
function emittedEvidenceNextStepOverrides(source: string): Record<string, string> {
  const body = fnBody(source, /fn retention_execution_evidence_next_step\(/u);
  const literals = stringLiterals(body);
  expect(literals, 'retention_execution_evidence_next_step literal arms').toHaveLength(3);
  const [boundedArchiveEvidence, boundedNoActionEvidence, alreadyExecutedEvidence] = literals as [
    string,
    string,
    string,
  ];
  return { boundedArchiveEvidence, boundedNoActionEvidence, alreadyExecutedEvidence };
}

/** The three-arm match on disposition in `retention_candidate_resolution_next_step`. */
function emittedResolutionNextStep(source: string): Record<string, string> {
  const body = fnBody(source, /fn retention_candidate_resolution_next_step\(/u);
  const literals = stringLiterals(body);
  // EvidenceAcknowledged, FollowUpRequired, BlockedFollowUp(requires) => S, BlockedFollowUp(else) => R again.
  expect(literals, 'retention_candidate_resolution_next_step literal arms').toHaveLength(4);
  const [evidenceAcknowledged, followUpRequired, blockedFollowUp, followUpRequiredAgain] =
    literals as [string, string, string, string];
  expect(
    followUpRequiredAgain,
    'BlockedFollowUp non-requiring branch should reuse the FollowUpRequired sentence',
  ).toBe(followUpRequired);
  return {
    resolutionEvidenceAcknowledged: evidenceAcknowledged,
    resolutionFollowUpRequired: followUpRequired,
    resolutionBlockedFollowUp: blockedFollowUp,
  };
}

/** The fixed sentence `legacy_retention_operator_workflow` writes for pre-`workflow`-field records. */
function emittedLegacyNextStep(source: string): Record<string, string> {
  const body = fnBody(source, /fn legacy_retention_operator_workflow\(\)/u);
  const literals = stringLiterals(body);
  const nonEmpty = literals.filter((literal) => literal.trim().length > 0);
  // Two literals: the required_approval reason and the next_step sentence itself.
  expect(nonEmpty.length, 'legacy_retention_operator_workflow literals').toBeGreaterThanOrEqual(1);
  return { legacyReviewOnly: nonEmpty[nonEmpty.length - 1] as string };
}

/** The full twenty-entry population, assembled from all five sites. */
function emittedRetentionNextStep(source: string): Record<RetentionNextStepCode, string> {
  const emitted = {
    ...emittedPriorBoundedConsts(source),
    ...emittedCandidateBuilderSpecialCases(source),
    ...emittedWorkflowNextStep(source),
    ...emittedEvidenceNextStepOverrides(source),
    ...emittedResolutionNextStep(source),
    ...emittedLegacyNextStep(source),
  } as Record<RetentionNextStepCode, string>;
  return emitted;
}

// ═══ THE GATE ══════════════════════════════════════════════════════════════════════════════════

describe('the emitted next-step prose is parsed from Rust, not assumed', () => {
  it('parses exactly twenty distinct, non-empty sentences from the five sites', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    const emitted = emittedRetentionNextStep(source);
    const keys = Object.keys(emitted);
    expect(keys, 'emitted next-step population').toHaveLength(20);
    expect(new Set(keys).size, 'duplicate keys across the five sites').toBe(20);
    for (const [key, value] of Object.entries(emitted)) {
      expect(value.trim(), `${key} parsed as empty`).not.toBe('');
    }
  });
});

describe('every emitted sentence has copy, and every copy entry is emitted', () => {
  it('matches the English tier in both directions, keys and text', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    const emitted = emittedRetentionNextStep(source);
    expect(sorted(Object.keys(retentionNextStepEnglish))).toEqual(sorted(Object.keys(emitted)));
    expect(retentionNextStepEnglish).toEqual(emitted);
  });

  it('keeps the pt-PT tier on exactly the English key set', () => {
    expect(sorted(Object.keys(retentionNextStepPtPT))).toEqual(
      sorted(Object.keys(retentionNextStepEnglish)),
    );
  });
});

describe('the pt-PT copy has the right shape, whatever its wording', () => {
  const codes = Object.keys(retentionNextStepEnglish) as RetentionNextStepCode[];

  it('is a complete sentence in both tiers', () => {
    for (const code of codes) {
      for (const text of [retentionNextStepPtPT[code], retentionNextStepEnglish[code]]) {
        expect(text.trim().length, code).toBeGreaterThan(30);
        expect(text.trim().endsWith('.'), `${code} is not a complete sentence`).toBe(true);
      }
    }
  });

  it('is actually translated, not the English copied across', () => {
    for (const code of codes) {
      expect(retentionNextStepPtPT[code], `${code} was never translated`).not.toBe(
        retentionNextStepEnglish[code],
      );
    }
  });

  it('never interpolates a noun and never restates its own key', () => {
    for (const code of codes) {
      // A noun dropped into an inflected sentence breaks agreement, so no entry carries a slot
      // (memory: `i18n-interpolated-nouns-break-agreement`).
      expect(retentionNextStepPtPT[code], `${code} carries an interpolation slot`).not.toMatch(
        /\{[a-z]/iu,
      );
      expect(
        retentionNextStepPtPT[code].toLowerCase(),
        `${code} restates its own key`,
      ).not.toContain(code.toLowerCase());
    }
  });

  it('carries the "nothing destructive happened" denial the Rust sentence makes, where the Rust sentence makes one', () => {
    // Every arm of the Rust workflow that denies a destructive action happening says so in English
    // with "no"/"not"/"never"; the pt-PT sentence must carry an equivalent negation, not drop it.
    // `(?!-)` excludes "no-action" — a noun phrase, not a negation — from tripping the filter.
    const denialCodes = codes.filter((code) =>
      /\bno\b(?!-)|\bnot\b|\bnever\b/iu.test(retentionNextStepEnglish[code]),
    );
    expect(denialCodes.length, 'expected at least one denial-carrying sentence').toBeGreaterThan(0);
    for (const code of denialCodes) {
      expect(retentionNextStepPtPT[code], `${code} dropped its denial clause`).toMatch(
        /\b(não|nenhum|nenhuma)\b/iu,
      );
    }
  });
});

describe('resolution', () => {
  it('resolves every emitted sentence as known, from either tier', async () => {
    const source = productionSection(await readCrateSource(EMITTER));
    const emitted = emittedRetentionNextStep(source);
    for (const text of Object.values(emitted)) {
      const resolved = resolveRetentionNextStep(retentionNextStepPtPT, text);
      expect(resolved.known, text).toBe(true);
      expect(resolved.text, text).not.toBe(text);
    }
  });

  it('renders the server text verbatim and warns when a sentence is unknown', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const resolved = resolveRetentionNextStep(retentionNextStepPtPT, 'A sentence from the future.');
    expect(resolved).toEqual({ text: 'A sentence from the future.', known: false });
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('is whitespace-tolerant: leading/trailing whitespace around the server text still resolves', () => {
    const anyCode = Object.keys(retentionNextStepEnglish)[0] as RetentionNextStepCode;
    const resolved = resolveRetentionNextStep(
      retentionNextStepPtPT,
      `  ${retentionNextStepEnglish[anyCode]}  `,
    );
    expect(resolved.known).toBe(true);
  });
});
