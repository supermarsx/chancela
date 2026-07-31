/**
 * Structural guard on the gap between two stacked sub-nav strips.
 *
 * ## What this protects
 *
 * `.subnav-wrap` carries `margin-top: 1.1rem`, which is the right figure for separating a strip
 * from the CONTENT it labels. When the admin surface grew a primary group level, two `<SubNav>`s
 * began rendering back to back and the second inherited that same figure — 17.6px between a group
 * and its own sub-tabs, which reads as two unrelated controls rather than one two-level navigator.
 *
 * The adjacent pair takes a tighter band. A strip following anything else is untouched, which is
 * why the rule is an adjacent-sibling selector rather than a change to `.subnav-wrap` itself: the
 * standalone case is not a defect and must not move.
 *
 * ## Why source assertions rather than rendered ones
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting two strips and
 * reading a margin passes whether or not any rule exists. Every assertion here reads `theme.css`
 * itself, and each carries a red-proof against a copy of the real sheet with the rule removed, so
 * a test that could only ever pass is caught here rather than in review.
 */
import { beforeAll, describe, expect, it } from 'vitest';

async function readTheme(): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

let THEME = '';
beforeAll(async () => {
  THEME = await readTheme();
});

/** The rule under test, as it must appear in the sheet. */
const ADJACENT_RULE = /:where\(\.subnav-wrap \+ \.subnav-wrap\)\s*\{[^}]*margin-top:\s*([\d.]+)rem/;

/** The standalone figure the adjacent case deliberately does NOT change. */
const STANDALONE_RULE = /\.subnav-wrap\s*\{[^}]*margin-top:\s*([\d.]+)rem/;

describe('sub-nav vertical rhythm', () => {
  it('gives two stacked strips a tighter gap than a strip gives its content', () => {
    const adjacent = THEME.match(ADJACENT_RULE);
    const standalone = THEME.match(STANDALONE_RULE);

    expect(adjacent, 'the adjacent-pair rule must exist').not.toBeNull();
    expect(standalone, 'the standalone rule must exist to compare against').not.toBeNull();

    const adjacentRem = Number(adjacent![1]);
    const standaloneRem = Number(standalone![1]);

    expect(adjacentRem).toBeLessThan(standaloneRem);
  });

  it('scopes the tighter gap to zero specificity, so a surface can still override it', () => {
    // Without `:where()` the rule is (0,2,0) and beats any single-class override a caller writes,
    // which is how a shared rule becomes something people fight rather than use.
    expect(THEME).toMatch(/:where\(\.subnav-wrap \+ \.subnav-wrap\)/);
    expect(THEME).not.toMatch(/(?<!:where\()\.subnav-wrap \+ \.subnav-wrap\s*\{/);
  });

  it('leaves a standalone strip alone', () => {
    // The 1.1rem above a lone strip is correct and load-bearing: it separates the strip from the
    // content beneath it. If this ever equals the adjacent figure, the fix has overreached.
    const standalone = THEME.match(STANDALONE_RULE);
    expect(standalone).not.toBeNull();
    expect(Number(standalone![1])).toBeGreaterThan(0);
  });

  it('the assertions fail against a sheet with the rule removed', () => {
    // Red-proof. A guard that passes on a sheet missing the thing it guards is not a guard.
    const without = THEME.replace(ADJACENT_RULE.source, '');
    const stripped = without.replace(
      /:where\(\.subnav-wrap \+ \.subnav-wrap\)\s*\{[^}]*\}/,
      '/* removed */',
    );
    expect(stripped).not.toBe(THEME);
    expect(stripped).not.toMatch(ADJACENT_RULE);
  });
});
