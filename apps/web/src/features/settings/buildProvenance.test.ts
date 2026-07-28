/**
 * Build-provenance derivation (t100).
 *
 * Two things are worth pinning here and nothing else is:
 *
 *  - the codename is DETERMINISTIC and reproducible by hand from the documented rule, so the
 *    comment in `buildProvenance.ts` can be checked rather than trusted;
 *  - every way a build can fail to have provenance ends in `null`, never in a fabricated or
 *    half-filled value. That is the absent-git path, the one least likely to be exercised.
 *
 * `BUILD_COMMIT` itself is not asserted on: it is whatever repository the suite happens to run in,
 * which is exactly the input these pure functions are tested against directly.
 */
import { describe, expect, it } from 'vitest';
import { BUILD_CODENAMES, buildCodename, describeBuildCommit } from './buildProvenance';

/** A full, well-formed object name. `74…` is the worked example in the derivation comment. */
const HASH = '744f82f2c0161eab7b13f4b0d9a1e5c6a7b8c9d0';
const COMMITTED_AT = '2026-07-27T18:03:11+01:00';

describe('BUILD_CODENAMES', () => {
  it('is the sixty-four entries the modulo in buildCodename() depends on', () => {
    expect(BUILD_CODENAMES).toHaveLength(64);
  });

  it('holds no duplicate, so a codename names one slot in the list', () => {
    expect(new Set(BUILD_CODENAMES).size).toBe(BUILD_CODENAMES.length);
  });

  it('is alphabetically ordered, as the comment states and a reader counting by hand relies on', () => {
    const sorted = [...BUILD_CODENAMES].sort((a, b) => a.localeCompare(b, 'pt-PT'));
    expect([...BUILD_CODENAMES]).toEqual(sorted);
  });

  it('claims no assurance about the release', () => {
    // A codename that reads as a guarantee is worse than no codename. Rocks and minerals only.
    const forbidden = /est[áa]vel|final|certificad|seguro|válid|aprovad|garant|oficial|definitiv/i;
    expect(BUILD_CODENAMES.filter((name) => forbidden.test(name))).toEqual([]);
  });
});

describe('buildCodename', () => {
  it('reproduces the worked example from the derivation comment', () => {
    // 0x74 = 116; 116 mod 64 = 52; entry 52 of the alphabetical list.
    expect(buildCodename(HASH)).toBe(BUILD_CODENAMES[52]);
  });

  it('follows first-byte-modulo-length for every possible first byte', () => {
    // The whole rule, checked exhaustively rather than sampled: 256 first bytes, each landing on
    // the entry the documented arithmetic names.
    for (let byte = 0; byte < 256; byte += 1) {
      const hash = byte.toString(16).padStart(2, '0') + '0'.repeat(38);
      expect(buildCodename(hash)).toBe(BUILD_CODENAMES[byte % BUILD_CODENAMES.length]);
    }
  });

  it('is stable: the same commit always yields the same codename', () => {
    expect(buildCodename(HASH)).toBe(buildCodename(HASH));
  });

  it('uses every entry in the list across the byte space', () => {
    const reached = new Set(
      Array.from({ length: 256 }, (_, byte) =>
        buildCodename(byte.toString(16).padStart(2, '0') + '0'.repeat(38)),
      ),
    );
    expect(reached.size).toBe(BUILD_CODENAMES.length);
  });

  it('returns null rather than an arbitrary name for anything that is not a full hash', () => {
    expect(buildCodename('')).toBeNull();
    expect(buildCodename('744f82f2')).toBeNull();
    expect(buildCodename(`${HASH}0`)).toBeNull();
    expect(buildCodename(HASH.toUpperCase())).toBeNull();
    expect(buildCodename('main')).toBeNull();
    expect(buildCodename('z'.repeat(40))).toBeNull();
  });
});

describe('describeBuildCommit', () => {
  it('describes a well-formed commit, keeping the full hash reachable beside the short one', () => {
    const described = describeBuildCommit({ hash: HASH, committedAt: COMMITTED_AT });
    expect(described).toEqual({
      hash: HASH,
      shortHash: HASH.slice(0, 12),
      committedAt: COMMITTED_AT,
      codename: BUILD_CODENAMES[52],
    });
  });

  it('returns null for a build with no repository behind it', () => {
    // The Docker / source-tarball / no-git-on-PATH path: vite.config.ts inlines a literal null.
    expect(describeBuildCommit(null)).toBeNull();
  });

  it('returns null for every other shape the global could carry', () => {
    expect(describeBuildCommit(undefined)).toBeNull();
    expect(describeBuildCommit('744f82f2')).toBeNull();
    expect(describeBuildCommit(42)).toBeNull();
    expect(describeBuildCommit({})).toBeNull();
    expect(describeBuildCommit({ hash: HASH })).toBeNull();
    expect(describeBuildCommit({ committedAt: COMMITTED_AT })).toBeNull();
    expect(describeBuildCommit({ hash: 123, committedAt: COMMITTED_AT })).toBeNull();
    expect(describeBuildCommit({ hash: HASH, committedAt: 123 })).toBeNull();
  });

  it('rejects a half-truth rather than rendering it', () => {
    // A truncated hash, a branch name where a hash belongs, a date with no offset, a date that is
    // not a date: each would look like real provenance on screen. None of them is.
    expect(describeBuildCommit({ hash: '744f82f2', committedAt: COMMITTED_AT })).toBeNull();
    expect(describeBuildCommit({ hash: 'HEAD', committedAt: COMMITTED_AT })).toBeNull();
    expect(describeBuildCommit({ hash: HASH, committedAt: '2026-07-27T18:03:11' })).toBeNull();
    expect(describeBuildCommit({ hash: HASH, committedAt: '2026-07-27' })).toBeNull();
    expect(describeBuildCommit({ hash: HASH, committedAt: 'unknown' })).toBeNull();
    expect(describeBuildCommit({ hash: HASH, committedAt: '' })).toBeNull();
  });

  it('accepts the offset forms git can emit, including UTC and fractional seconds', () => {
    expect(describeBuildCommit({ hash: HASH, committedAt: '2026-07-27T17:03:11Z' })).not.toBeNull();
    expect(
      describeBuildCommit({ hash: HASH, committedAt: '2026-07-27T14:03:11-03:00' }),
    ).not.toBeNull();
    expect(
      describeBuildCommit({ hash: HASH, committedAt: '2026-07-27T17:03:11.250Z' }),
    ).not.toBeNull();
  });

  it('normalises an env-supplied hash so it derives the same codename git would', () => {
    // `CHANCELA_BUILD_COMMIT` is typed by a human or pasted from a UI that upper-cases; the same
    // commit must not answer to two different names depending on which path supplied it.
    const fromEnv = describeBuildCommit({
      hash: `  ${HASH.toUpperCase()}  `,
      committedAt: `  ${COMMITTED_AT}  `,
    });
    expect(fromEnv).toEqual(describeBuildCommit({ hash: HASH, committedAt: COMMITTED_AT }));
  });
});
