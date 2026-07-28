/**
 * DIVERGENCE GATE for `dataRecoveryStatusFallback.ts` (t98).
 *
 * The operator-facing copy lives client-side while the authoritative status tokens live in Rust.
 * That split is only safe if drift is loud, so this derives the truth from the emitting sources
 * themselves rather than from a hand-copied list. Four independent populations, three files, and
 * three different SHAPES of emitter — which is the reason each is parsed separately:
 *
 *  - `sidecarStorageMode`    — the `SidecarStorageMode` enum in `data_status.rs`, variants put on
 *                              the wire by `#[serde(rename_all = "snake_case")]`;
 *  - `backendFamily`         — the `DurableBackendFamily` enum in the same file, same rename;
 *  - `readinessStatus`       — the `let readiness_status = if …` chain in `sync_handoff.rs`;
 *  - `isolatedRestoreStatus` — the `ISOLATED_RESTORE_STATUS_*` consts in `backup_recovery.rs`.
 *
 * The two enums are read through the serde rename rather than by lowercasing alone: `InMemory`
 * lowercased is `inmemory`, not `in_memory`, so a guard that skipped the rename would compare
 * against tokens the server never sends. The rename attribute itself is asserted, so switching it to
 * `camelCase` goes red here rather than silently shifting every token.
 *
 * Set equality is asserted in BOTH directions per group: a token the emitter gains with no entry in
 * the fallback is red, and an entry for a token the emitter can no longer produce is red.
 *
 * `active_backend_family` is `Option<DurableBackendFamily>`, so its `null` is a real emitted state
 * rather than a hole. The optionality is asserted from the Rust field declaration, so a build that
 * made it non-optional would go red rather than leaving a sentence for a state that cannot occur.
 *
 * **These assertions are structural on purpose.** Nothing here matches Portuguese text. A test that
 * pins a substring of reviewed copy turns a correct translation fix red — and a singular/plural slip
 * makes it pass for the wrong reason — so the copy is checked for shape (non-empty, a real sentence,
 * not a restatement of its own identifier, no interpolation slot) and never for wording. The two
 * exceptions are the load-bearing scoping clauses on `local_review_ready` and `verified`, checked as
 * a denial being present rather than as a phrasing, because dropping them would let the copy claim
 * more than the emitter does.
 */
import { describe, expect, it } from 'vitest';

import {
  type DataRecoveryStatusEntry,
  type DataRecoveryStatusGroup,
  dataRecoveryStatusEnglish,
  dataRecoveryStatusPtPT,
  describeDataRecoveryStatus,
} from './dataRecoveryStatusFallback';

const DATA_STATUS = 'crates/chancela-api/src/data_status.rs';
const SYNC_HANDOFF = 'crates/chancela-api/src/sync_handoff.rs';
const BACKUP_RECOVERY = 'crates/chancela-api/src/backup_recovery.rs';

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
function productionSection(source: string, label: string): string {
  const section = source.split(/^#\[cfg\(test\)\]/mu)[0] as string;
  expect(
    section.length,
    `the pre-test section of ${label} is implausibly short — check the split`,
  ).toBeGreaterThan(source.length / 4);
  return section;
}

/** Body of the first item whose header matches, by brace matching rather than a line count. */
function braceBody(source: string, header: RegExp, label: string): string {
  const match = header.exec(source);
  expect(match, `nothing matching ${String(header)} in ${label}`).not.toBeNull();
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
  throw new Error(`unbalanced braces after ${String(header)} in ${label}`);
}

/** `InMemory` -> `in_memory`, matching `#[serde(rename_all = "snake_case")]`. */
function snakeCase(variant: string): string {
  return variant.replace(/([a-z0-9])([A-Z])/gu, '$1_$2').toLowerCase();
}

/**
 * A Rust enum's wire tokens: its variants put through the serde rename, with the rename attribute
 * itself asserted so a change of casing scheme is red rather than silent.
 */
function enumWireTokens(source: string, name: string, label: string): string[] {
  const declaration = new RegExp(`pub enum ${name}\\b`, 'u');
  const match = declaration.exec(source);
  expect(match, `no \`pub enum ${name}\` in ${label}`).not.toBeNull();

  const attributes = source.slice(
    Math.max(0, (match as RegExpExecArray).index - 300),
    (match as RegExpExecArray).index,
  );
  expect(
    attributes,
    `${name} in ${label} is no longer renamed to snake_case — the wire tokens have moved`,
  ).toMatch(/#\[serde\(rename_all\s*=\s*"snake_case"\)\]/u);

  const body = braceBody(source, declaration, label);
  const variants = [...body.matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*,/gmu)].map((m) => m[1] as string);
  expect(variants.length, `parsed no variants of ${name} from ${label}`).toBeGreaterThan(0);
  return variants.map(snakeCase);
}

/** The four emitted populations, parsed from Rust. */
async function emittedTokens(): Promise<Record<DataRecoveryStatusGroup, string[]>> {
  const dataStatus = productionSection(await readCrateSource(DATA_STATUS), DATA_STATUS);
  const syncHandoff = productionSection(await readCrateSource(SYNC_HANDOFF), SYNC_HANDOFF);
  const backupRecovery = productionSection(await readCrateSource(BACKUP_RECOVERY), BACKUP_RECOVERY);

  const readiness =
    /let readiness_status = if !blockers\.is_empty\(\) \{\s*"([a-z0-9_]+)"\s*\} else if !missing_evidence\.is_empty\(\) \{\s*"([a-z0-9_]+)"\s*\} else \{\s*"([a-z0-9_]+)"\s*\}/u.exec(
      syncHandoff,
    );
  expect(
    readiness,
    `sync_handoff.rs no longer derives readiness_status the expected way in ${SYNC_HANDOFF}`,
  ).not.toBeNull();

  const isolated = [
    ...backupRecovery.matchAll(/const ISOLATED_RESTORE_STATUS_[A-Z_]+: &str = "([a-z0-9_]+)";/gu),
  ].map((m) => m[1] as string);

  return {
    sidecarStorageMode: enumWireTokens(dataStatus, 'SidecarStorageMode', DATA_STATUS),
    backendFamily: enumWireTokens(dataStatus, 'DurableBackendFamily', DATA_STATUS),
    readinessStatus: (readiness as RegExpExecArray).slice(1, 4) as string[],
    isolatedRestoreStatus: [...new Set(isolated)],
  };
}

const sorted = (values: readonly string[]): string[] => [...values].sort();

/**
 * `as const satisfies` gives each tier a literal type with no index signature, so a token parsed out
 * of Rust — a plain `string` — cannot index it. Widening here keeps the source objects strictly
 * typed while letting the test look tokens up by the value the emitter actually produces.
 */
type WidenedTiers = Record<DataRecoveryStatusGroup, Record<string, DataRecoveryStatusEntry>>;
const PT_PT: WidenedTiers = dataRecoveryStatusPtPT;
const ENGLISH: WidenedTiers = dataRecoveryStatusEnglish;

const GROUPS: DataRecoveryStatusGroup[] = [
  'sidecarStorageMode',
  'backendFamily',
  'readinessStatus',
  'isolatedRestoreStatus',
];

function entriesOf(group: DataRecoveryStatusGroup): [string, DataRecoveryStatusEntry][] {
  return Object.entries(PT_PT[group]);
}

describe('the emitted status tokens are parsed, not assumed', () => {
  it('finds a plausible, distinct population for each of the four groups', async () => {
    const emitted = await emittedTokens();
    // Non-vacuity: a parse that silently matched nothing would make every set comparison below pass
    // trivially against an empty population.
    const expectedSizes: Record<DataRecoveryStatusGroup, number> = {
      sidecarStorageMode: 3,
      backendFamily: 2,
      readinessStatus: 3,
      isolatedRestoreStatus: 3,
    };
    for (const group of GROUPS) {
      expect(emitted[group].length, `${group} parsed the wrong number of tokens`).toBe(
        expectedSizes[group],
      );
      expect(new Set(emitted[group]).size, `${group} parsed a duplicated token`).toBe(
        expectedSizes[group],
      );
      for (const token of emitted[group]) {
        expect(token, `${group} parsed a token that is not an identifier`).toMatch(
          /^[a-z][a-z0-9_]*$/u,
        );
      }
    }
  });

  it('reads the enum variants through the serde rename, not by lowercasing', async () => {
    // `InMemory` lowercased is `inmemory`. If this ever regresses to a bare `toLowerCase()`, the
    // multi-word variant is the one that catches it.
    const emitted = await emittedTokens();
    expect(emitted.sidecarStorageMode).toContain('in_memory');
    expect(emitted.sidecarStorageMode).not.toContain('inmemory');
  });

  it('keeps active_backend_family optional, so the absent state is real', async () => {
    const source = productionSection(await readCrateSource(DATA_STATUS), DATA_STATUS);
    expect(
      source,
      `active_backend_family is no longer Option<…> in ${DATA_STATUS}; the absent-state sentence describes a state that cannot occur`,
    ).toMatch(/pub active_backend_family:\s*Option<DurableBackendFamily>/u);
  });
});

describe('every emitted status has a label, and every label has an emitted status', () => {
  it.each(GROUPS)('%s matches the Rust emitter in both directions', async (group) => {
    const emitted = await emittedTokens();
    expect(sorted(Object.keys(PT_PT[group]))).toEqual(sorted(emitted[group]));
  });

  it('describes every emitted token as known', async () => {
    const emitted = await emittedTokens();
    for (const group of GROUPS) {
      for (const token of emitted[group]) {
        expect(describeDataRecoveryStatus(group, token).known, `${group}/${token}`).toBe(true);
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
        const en = ENGLISH[group][token] as DataRecoveryStatusEntry;
        for (const entry of [pt, en]) {
          expect(entry.label.trim(), `${group}/${token} label`).not.toBe('');
          expect(entry.meaning.trim().length, `${group}/${token} meaning`).toBeGreaterThan(40);
          expect(entry.meaning.trim().endsWith('.'), `${group}/${token} meaning`).toBe(true);
          expect(['ok', 'neutral', 'warn', 'error'], `${group}/${token} tone`).toContain(
            entry.tone,
          );
        }
      }
    }
  });

  it('never restates its own identifier and never interpolates a noun', () => {
    for (const group of GROUPS) {
      for (const [token, pt] of entriesOf(group)) {
        const en = ENGLISH[group][token] as DataRecoveryStatusEntry;
        const spelledOut = token.replace(/_/gu, ' ');
        for (const entry of [pt, en]) {
          const copy = `${entry.label} ${entry.meaning}`.toLowerCase();
          // Only for MULTI-WORD tokens. Half this population is a single ordinary word — `file`,
          // `database`, `blocked`, `verified`, `failed` — and correct copy for those necessarily
          // uses the word: "Files in the data directory" is the right English for `file`, not a
          // restatement. A blanket substring ban would forbid the accurate sentence and push the
          // author towards a worse one. Where the token is multi-word, its appearance verbatim
          // really does mean the identifier leaked into the prose.
          if (token.includes('_')) {
            expect(copy, `${group}/${token} restates its identifier`).not.toContain(token);
          }
          // Exact match, not a substring: for a short token the natural words often ARE the token's
          // words. What is worth catching is a label that is nothing but the token respelled — which
          // is exactly the trap the two product-name entries would fall into.
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

  it('keeps the scoping clause on the two states that sit next to a no-claims block', () => {
    // `local_review_ready` must not read as "ready to synchronise": the emitter hard-codes
    // `production_sync_ready`, `external_connector_ready` and `active_sync_performed` to false.
    // `verified` must not read as certification: the Rust next_step it travels with says
    // "preflight-only … authorize any recovery execution separately".
    // Asserted as a denial being present, not as a phrasing.
    expect(
      (PT_PT.readinessStatus.local_review_ready as DataRecoveryStatusEntry).meaning.toLowerCase(),
    ).toMatch(/não sincroniza|não afirma/u);
    expect(
      (ENGLISH.readinessStatus.local_review_ready as DataRecoveryStatusEntry).meaning.toLowerCase(),
    ).toMatch(/synchronises nothing|no claim/u);
    expect(
      (PT_PT.isolatedRestoreStatus.verified as DataRecoveryStatusEntry).meaning.toLowerCase(),
    ).toMatch(/não uma certificação|autorização separada/u);
    expect(
      (ENGLISH.isolatedRestoreStatus.verified as DataRecoveryStatusEntry).meaning.toLowerCase(),
    ).toMatch(/not certification|separate authorisation/u);
  });
});

describe('the states that are not a token still render something', () => {
  it('gives the absent durable backend its own sentence, marked known', () => {
    // `null` here is `Option::None`, a real state of the installation — not an unrecognised token.
    const resolved = describeDataRecoveryStatus('backendFamily', null);
    expect(resolved.known).toBe(true);
    expect(resolved.label.trim()).not.toBe('');
    expect(resolved.meaning.trim()).not.toBe('');
  });

  it('returns a non-empty description marked unknown for a token from the future', () => {
    for (const group of GROUPS) {
      const resolved = describeDataRecoveryStatus(group, 'a_token_from_the_future');
      expect(resolved.known, group).toBe(false);
      expect(resolved.label.trim(), group).not.toBe('');
      expect(resolved.meaning.trim(), group).not.toBe('');
    }
  });

  it('does not invent an absent state for the groups that have no optional field', () => {
    for (const group of GROUPS.filter((g) => g !== 'backendFamily')) {
      expect(describeDataRecoveryStatus(group, null).known, group).toBe(false);
    }
  });
});
