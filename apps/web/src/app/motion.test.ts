/**
 * The shared motion language (t39): one set of tokens in `theme.css` drives every content
 * swap — route change, sub-tab change, panel swap — and both kill-switches collapse it.
 *
 * These assertions read the stylesheet directly rather than measuring pixels: jsdom has no
 * cascade, no animation clock and no media-query evaluation, so a rendered assertion here
 * would prove nothing. The stylesheet IS the contract. Sibling precedent: the will-change
 * budget and reduced-motion checks in `ui/Skeleton.test.tsx`.
 */
import { describe, expect, it } from 'vitest';

/**
 * The web tsconfig has no `@types/node`, so `node:fs` is reached through the indirect
 * dynamic-import convention used by `LedgerPage.test.tsx` / `Skeleton.test.tsx`.
 */
async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

/** The stylesheet with comments stripped, so prose about a value never satisfies a match. */
async function rules(): Promise<string> {
  return (await themeCss()).replace(/\/\*[\s\S]*?\*\//g, '');
}

/** The declaration block for the first rule whose selector list contains `selector`. */
function block(css: string, selector: string): string {
  const blocks = css.split('}');
  const found = blocks.find((b) => {
    const head = b.slice(0, b.indexOf('{'));
    return b.includes('{') && head.includes(selector);
  });
  expect(found, `no rule found for ${selector}`).toBeTruthy();
  return (found as string).slice((found as string).indexOf('{') + 1);
}

describe('motion tokens', () => {
  it('defines the shared duration and easing tokens on :root', async () => {
    const css = await rules();
    for (const token of [
      '--motion-page-duration',
      '--motion-panel-duration',
      '--motion-ease-enter',
      '--motion-ease-glide',
      '--motion-page-rise',
    ]) {
      expect(css).toMatch(new RegExp(`${token}\\s*:`));
    }
  });

  it('keeps both durations inside the honest 150-300ms band', async () => {
    const css = await rules();
    for (const token of ['--motion-page-duration', '--motion-panel-duration']) {
      const ms = Number(new RegExp(`${token}\\s*:\\s*(\\d+)ms`).exec(css)?.[1]);
      // Long enough to register as deliberate, short enough that nobody waits on it. A
      // transition that makes the app feel slower has failed.
      expect(ms).toBeGreaterThanOrEqual(150);
      expect(ms).toBeLessThanOrEqual(300);
    }
  });

  it('every content-swap rule consumes the tokens rather than a hand-written value', async () => {
    const css = await rules();
    for (const selector of ['.route-transition', '.subnav__indicator']) {
      const decls = block(css, selector);
      // No literal duration or cubic-bezier survives in these rules — that is what made
      // three surfaces drift apart in the first place.
      expect(decls).not.toMatch(/\d+m?s(?![\w-])/);
      expect(decls).not.toMatch(/cubic-bezier/);
      expect(decls).toMatch(/var\(--motion-/);
    }
  });
});

describe('nested panel motion', () => {
  it('a nested .route-transition falls back to the riseless panel fade', async () => {
    const css = await rules();
    // The sub-tabbed pages put their keyed wrapper inside the Layout's keyed <main>, so a
    // navigation into one mounts both levels at once. Without this rule the opacity ramps
    // compound and the two rises stack into a double-height slide.
    expect(css).toMatch(/\.route-transition\s+\.route-transition\s*,?[\s\S]{0,40}\{/);
    const decls = block(css, '.route-transition .route-transition');
    expect(decls).toMatch(/animation:\s*panel-enter/);
    expect(decls).toMatch(/var\(--motion-panel-duration\)/);
  });

  it('panel-enter animates opacity only, so nesting can never compound a translate', async () => {
    const css = await rules();
    const frames = /@keyframes\s+panel-enter\s*\{([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
    expect(frames).toMatch(/opacity/);
    expect(frames).not.toMatch(/transform|translate/);
  });

  it('.panel-transition is the same motion under an explicit name', async () => {
    const css = await rules();
    expect(css).toMatch(/\.panel-transition/);
    expect(block(css, '.panel-transition')).toMatch(/animation:\s*panel-enter/);
  });
});

describe('motion kill-switches', () => {
  it('prefers-reduced-motion collapses animations and transitions globally', async () => {
    const css = await rules();
    const query = /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}\n/.exec(css)?.[1];
    expect(query).toBeTruthy();
    // The universal block covers `route-enter` and `panel-enter` without either needing to
    // opt in, which is why a new keyframe can never escape the policy by omission.
    expect(query).toMatch(/\*\s*,/);
    expect(query).toMatch(/animation-duration:\s*0\.01ms\s*!important/);
    expect(query).toMatch(/transition-duration:\s*0\.01ms\s*!important/);
  });

  it('safe mode zeroes animation on every element too', async () => {
    const css = await rules();
    const decls = block(css, ":root[data-safe-mode='on'] *");
    expect(decls).toMatch(/animation[^;]*none|animation-duration:\s*0/);
  });
});

describe('compositor budget', () => {
  it('neither content-swap class takes a permanent will-change promotion', async () => {
    const css = await rules();
    // `.route-transition` nests, so a base-rule hint costs stacked full-content-area layers
    // against Firefox's document-surface x 3 budget — and past the budget the hints are
    // ignored outright (see t17-skeletons). These are one-shot enters that start on mount;
    // the engine promotes for the life of a running animation without being asked.
    for (const selector of ['.route-transition', '.panel-transition']) {
      expect(block(css, selector)).not.toMatch(/will-change/);
    }
  });
});
