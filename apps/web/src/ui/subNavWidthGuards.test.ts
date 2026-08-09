/**
 * Structural guard on the sub-nav rail's WIDTH — the rule that keeps a sub-tab strip scrolling
 * inside the viewport instead of widening it.
 *
 * ## What this protects
 *
 * `.subnav-rail` is a flex ITEM: `.page-header` is `display: flex; flex-direction: column`, so the
 * rail's width is the flex CROSS size. Per CSS Flexbox §9.6 an auto cross-axis margin suppresses
 * `align-self: stretch`, so the `margin-inline: auto` the centring needs also opted the rail out of
 * filling its container — leaving it sized by its own max-content and clamped only by the fixed
 * `calc(var(--app-measure) - 2 * var(--app-gutter))` cap. A FIXED pixel cap cannot constrain
 * anything narrower than itself, so on a narrow shell nothing capped the rail at all.
 *
 * Measured in Chromium against the running app, that produced one defect with two faces:
 *
 *   - Ferramentas (7 tabs) and Definições (8 tabs) held a 1040px rail at every width. From a
 *     1079px viewport down the rail exceeded its own `.page-header`; from 1037px down it burst
 *     the shell. `.app-scroll` is `overflow-x: hidden`, so the excess was CLIPPED, not scrolled:
 *     at 320px five of Ferramentas' seven tabs were unreachable by scroll, keyboard or the edge
 *     arrows — the arrows had been carried off-screen with the rail.
 *   - Registo (2 tabs) shrink-wrapped to 230px and the auto margins CENTRED it, floating it 377px
 *     right of the page title at every width — the opposite of the left edge the rail exists to
 *     reproduce.
 *
 * `width: 100%` gives the rail a definite width, which restores stretch behaviour without giving
 * up the centring: the cap still binds on a wide shell and the auto margins still centre the
 * leftover. The `.subnav` scroller was never at fault — it can only scroll within the box it is
 * given, and it was being given a 1040px box.
 *
 * ## Why source assertions rather than rendered ones
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting a strip and
 * reading a width passes whether or not any rule exists — and this defect is a *layout* outcome
 * jsdom does not compute at all. Every assertion here reads `theme.css` itself, and the suite
 * carries a red-proof against an in-memory copy of the real sheet with the declaration removed, so
 * a test that could only ever pass is caught here rather than in review.
 *
 * @see subNavRhythmGuards.test.ts — the same idiom, guarding the strip's vertical rhythm.
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

/**
 * The `.subnav-rail` declaration block. Anchored at column 0 (`^` under `m`) so the prose above
 * the rule — which necessarily names `.subnav-rail` and quotes its declarations — can never be
 * mistaken for the rule itself. Comments in this sheet are always indented.
 */
const RAIL_BLOCK = /^\.subnav-rail\s*\{([^}]*)\}/m;

function railBlock(sheet: string): string {
  const match = sheet.match(RAIL_BLOCK);
  expect(match, 'the `.subnav-rail` rule must exist in theme.css').not.toBeNull();
  return match![1];
}

describe('sub-nav rail width', () => {
  it('gives the rail a definite width, so it tracks its container and not its content', () => {
    // Without this the rail is max-content-sized (auto cross margins suppress stretch) and a
    // strip longer than the reading measure widens the page instead of scrolling inside it.
    expect(railBlock(THEME)).toMatch(/(?:^|\n)\s*width:\s*100%\s*;/);
  });

  it('keeps the reading-measure cap, derived from the shell tokens rather than re-typed', () => {
    // The cap is what centres the strip at the reading box on a wide shell. It must stay
    // expressed in `--app-measure`/`--app-gutter`: a hard-coded pixel value here would silently
    // stop tracking the shell the next time the measure moves.
    const block = railBlock(THEME);
    expect(block).toMatch(/max-width:\s*calc\(var\(--app-measure\) - 2 \* var\(--app-gutter\)\)/);
    expect(block).toMatch(/margin-inline:\s*auto/);
  });

  it('records the flex context that makes the definite width load-bearing', () => {
    // `width: 100%` only looks redundant if you assume the rail is a block-level box in a block
    // container. It is not — it is a flex item in a column flex container, which is the whole
    // reason the auto margin could suppress stretch. If `.page-header` ever stops being a column
    // flex container, this rule's reasoning has to be re-derived rather than assumed.
    const headerBlocks = [...THEME.matchAll(/^\.page-header\s*\{([^}]*)\}/gm)].map((m) => m[1]);
    expect(headerBlocks.length).toBeGreaterThan(0);
    expect(headerBlocks.some((b) => /display:\s*flex/.test(b))).toBe(true);
    expect(headerBlocks.some((b) => /flex-direction:\s*column/.test(b))).toBe(true);
  });

  it('the width assertion fails against a sheet with the declaration removed', () => {
    // Red-proof, against an in-memory copy — never by mutating the shared tree. A guard that
    // passes on a sheet missing the thing it guards is not a guard.
    const stripped = THEME.replace(RAIL_BLOCK, (block) =>
      block.replace(/\n\s*width:\s*100%\s*;/, ''),
    );
    expect(stripped, 'the red-proof must actually change the sheet').not.toBe(THEME);
    // The rule still exists, and still has its cap…
    expect(stripped).toMatch(RAIL_BLOCK);
    expect(railBlock(stripped)).toMatch(/max-width:\s*calc\(var\(--app-measure\)/);
    // …but the declaration under test is gone, and the guard sees that.
    expect(railBlock(stripped)).not.toMatch(/(?:^|\n)\s*width:\s*100%\s*;/);
  });
});
