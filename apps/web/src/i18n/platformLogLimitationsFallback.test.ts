/**
 * DIVERGENCE GATE for `platformLogLimitationsFallback.ts` (t97).
 *
 * The operator-facing copy lives client-side while the authoritative English lives in Rust. That
 * split is only safe if drift is loud, so this file derives the truth from `limitations(durable:
 * bool)` in `crates/chancela-api/src/platform_logs.rs` itself, rather than from a hand-copied list.
 *
 * Three of the four sentences are fixed string literals and are compared by exact text, in both
 * directions, the same as `platformServiceFallback.test.ts`. The fourth — the retention sentence —
 * is built with `format!` and interpolates `PLATFORM_LOG_RETENTION_LIMIT`, so no fixed English string
 * exists to match against (module header explains why). For that one this gate asserts on the
 * structured shape instead: the literal must still contain the `{PLATFORM_LOG_RETENTION_LIMIT}` slot,
 * and the text AROUND the slot — with both sides' placeholders normalised to a common marker — must
 * match {@link platformLogLimitationsEnglish}. A reword of the surrounding words still goes red; only
 * the number itself is allowed to vary.
 */
import { describe, expect, it } from 'vitest';

import {
  type PlatformLogLimitationsCopy,
  platformLogLimitationsEnglish,
  platformLogLimitationsPtPT,
  resolvePlatformLogLimitations,
} from './platformLogLimitationsFallback';

const EMITTER = 'crates/chancela-api/src/platform_logs.rs';
const RUST_PLACEHOLDER = '{PLATFORM_LOG_RETENTION_LIMIT}';
const OUR_PLACEHOLDER = '{retentionLimit}';
const COMMON_PLACEHOLDER = '{N}';

async function readCrateSource(relative: string): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(`../../${relative}`, 'utf8');
}

/** Everything above the `#[cfg(test)]` module, so fixtures never become obligations. */
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

/** The span between an opening `{` (at `openIdx`, inclusive of the brace) and its matching `}`. */
function balancedSpan(source: string, openIdx: number): { start: number; end: number } {
  let depth = 0;
  for (let i = openIdx; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return { start: openIdx + 1, end: i };
    }
  }
  throw new Error('unbalanced braces while scanning limitations() branches');
}

const STRING_LITERAL = /"((?:[^"\\]|\\.)*)"/gu;

/** Every string literal in a fragment, in source order. */
function stringLiterals(fragment: string): string[] {
  return [...fragment.matchAll(STRING_LITERAL)].map((m) => m[1] as string);
}

interface EmittedLimitations {
  /** The `if durable { … }` branch: expected [tail sentence, retention template-with-Rust-slot]. */
  durableBranch: string[];
  /** The `} else { … }` branch: expected [in-memory sentence]. */
  memoryBranch: string[];
  /** The `limitations.push(…)` literal appended in both branches. */
  appended: string;
}

/** Parse `fn limitations(durable: bool) -> Vec<String>` structurally, not by line number. */
async function emittedLimitations(): Promise<EmittedLimitations> {
  const source = productionSection(await readCrateSource(EMITTER));
  const body = fnBody(source, /fn limitations\(durable: bool\) -> Vec<String>/u);

  const ifIdx = body.indexOf('if durable {');
  expect(ifIdx, 'limitations() lost its `if durable` branch').toBeGreaterThan(-1);
  const durableOpen = body.indexOf('{', ifIdx);
  const durableSpan = balancedSpan(body, durableOpen);
  const durableBranch = body.slice(durableSpan.start, durableSpan.end);

  const elseMarker = '} else {';
  const elseIdx = body.indexOf(elseMarker, durableSpan.end);
  expect(elseIdx, 'limitations() lost its `else` branch').toBeGreaterThan(-1);
  const memoryOpen = elseIdx + elseMarker.length - 1;
  const memorySpan = balancedSpan(body, memoryOpen);
  const memoryBranch = body.slice(memorySpan.start, memorySpan.end);

  const pushMatch = /limitations\.push\(\s*"((?:[^"\\]|\\.)*)"/u.exec(body.slice(memorySpan.end));
  expect(pushMatch, 'limitations() lost its `limitations.push(...)` appended sentence').not.toBeNull();

  const durableLiterals = stringLiterals(durableBranch);
  const memoryLiterals = stringLiterals(memoryBranch);
  expect(durableLiterals.length, 'durable branch must parse exactly 2 literals').toBe(2);
  expect(memoryLiterals.length, 'else branch must parse exactly 1 literal').toBe(1);

  return {
    durableBranch: durableLiterals,
    memoryBranch: memoryLiterals,
    appended: (pushMatch as RegExpExecArray)[1] as string,
  };
}

/** Normalise both sides' interpolation slot to one shared placeholder for text comparison. */
function normalizeRetentionSlot(text: string): string {
  return text.split(RUST_PLACEHOLDER).join(COMMON_PLACEHOLDER).split(OUR_PLACEHOLDER).join(COMMON_PLACEHOLDER);
}

describe('the emitted copy is parsed from Rust, not assumed', () => {
  it('parses a distinct, non-empty literal for each of the four sentences', async () => {
    const emitted = await emittedLimitations();
    for (const text of [...emitted.durableBranch, ...emitted.memoryBranch, emitted.appended]) {
      expect(text.trim(), 'parsed an empty string literal out of the emitter').not.toBe('');
    }
    const allFour = [...emitted.durableBranch, ...emitted.memoryBranch, emitted.appended];
    expect(new Set(allFour).size, 'the four parsed literals must all be distinct').toBe(4);
  });

  it('the retention literal still carries the PLATFORM_LOG_RETENTION_LIMIT slot', async () => {
    const emitted = await emittedLimitations();
    const retention = emitted.durableBranch[1] as string;
    expect(retention, 'the retention sentence lost its interpolation slot').toContain(
      RUST_PLACEHOLDER,
    );
  });
});

describe('every emitted sentence has copy, and every copy entry is emitted', () => {
  it('matches the durable-basis sentence exactly', async () => {
    const emitted = await emittedLimitations();
    expect(emitted.durableBranch[0]).toBe(platformLogLimitationsEnglish['basis.durable']);
  });

  it('matches the in-memory-basis sentence exactly', async () => {
    const emitted = await emittedLimitations();
    expect(emitted.memoryBranch[0]).toBe(platformLogLimitationsEnglish['basis.memory']);
  });

  it('matches the always-appended scope sentence exactly', async () => {
    const emitted = await emittedLimitations();
    expect(emitted.appended).toBe(platformLogLimitationsEnglish['scope.notStdoutStderr']);
  });

  it('matches the retention template, slot normalised, in both directions', async () => {
    const emitted = await emittedLimitations();
    const rustTemplate = emitted.durableBranch[1] as string;
    expect(normalizeRetentionSlot(rustTemplate)).toBe(
      normalizeRetentionSlot(platformLogLimitationsEnglish['retention.limit']),
    );
  });

  it('keeps the pt-PT tier on exactly the English key set', () => {
    expect([...Object.keys(platformLogLimitationsPtPT)].sort()).toEqual(
      [...Object.keys(platformLogLimitationsEnglish)].sort(),
    );
  });
});

describe('the pt-PT copy has the right shape, whatever its wording', () => {
  const groups: PlatformLogLimitationsCopy[] = [platformLogLimitationsPtPT, platformLogLimitationsEnglish];

  it('is a real, complete sentence in both tiers', () => {
    for (const copy of groups) {
      for (const [key, text] of Object.entries(copy)) {
        expect(text.trim().length, key).toBeGreaterThan(40);
        expect(text.trim().endsWith('.'), `${key} is not a complete sentence`).toBe(true);
      }
    }
  });

  it('is actually translated, not the English copied across', () => {
    for (const [key, pt] of Object.entries(platformLogLimitationsPtPT)) {
      const en = platformLogLimitationsEnglish[key as keyof PlatformLogLimitationsCopy];
      expect(pt, `${key} was never translated`).not.toBe(en);
    }
  });

  it('carries the interpolation slot only where the key says it will, and never another', () => {
    for (const copy of groups) {
      for (const [key, text] of Object.entries(copy)) {
        if (key === 'retention.limit') {
          expect(text, key).toContain(OUR_PLACEHOLDER);
        } else {
          expect(text, `${key} carries an unexpected interpolation slot`).not.toMatch(/\{[a-z]/iu);
        }
      }
    }
  });
});

describe('resolvePlatformLogLimitations', () => {
  it('builds [basis.durable, retention.limit, scope] when durable, retention interpolated', () => {
    const items = resolvePlatformLogLimitations(platformLogLimitationsPtPT, true, 512, [
      'irrelevant',
      'irrelevant',
      'irrelevant',
    ]);
    expect(items).toEqual([
      platformLogLimitationsPtPT['basis.durable'],
      'A retenção é determinística: são guardadas apenas as 512 entradas mais recentes do registo de plataforma gerido pela API.',
      platformLogLimitationsPtPT['scope.notStdoutStderr'],
    ]);
  });

  it('builds [basis.memory, scope] when not durable, with no retention sentence at all', () => {
    const items = resolvePlatformLogLimitations(platformLogLimitationsPtPT, false, 512, [
      'irrelevant',
      'irrelevant',
    ]);
    expect(items).toEqual([
      platformLogLimitationsPtPT['basis.memory'],
      platformLogLimitationsPtPT['scope.notStdoutStderr'],
    ]);
  });

  it('substitutes the retention limit as a bare integer, never a formatted noun phrase', () => {
    const items = resolvePlatformLogLimitations(platformLogLimitationsEnglish, true, 7, ['a', 'b', 'c']);
    expect(items[1]).toBe(
      'Retention is deterministic: only the newest 7 API-owned platform log entries are kept.',
    );
  });
});
