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

/**
 * Every declaration block whose selector line is EXACTLY `selector` (`.modal`, not the
 * `.modal-backdrop` / `.modal__head` rules that merely start with it, and not one arbitrary
 * hit when a selector is styled by several rules). `block` above matches on a substring, which
 * is fine for the unique content-swap selectors but wrong for `.modal` and for the three
 * migrated surfaces that each own a layout rule and a separate transition rule.
 */
function baseRules(css: string, selector: string): string[] {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`, 'g');
  const out: string[] = [];
  for (let m = re.exec(css); m; m = re.exec(css)) out.push(m[1]);
  return out;
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

  it('defines the additive micro-interaction tokens without disturbing the five', async () => {
    const css = await rules();
    // The consolidation added a small orthogonal clock for hover/focus/press so ~40 rules stop
    // hand-typing 0.12-0.24s. These sit deliberately below the 150-300ms content-swap band, so
    // the band assertion above must keep covering ONLY the two page/panel tokens.
    for (const token of [
      '--motion-quick',
      '--motion-micro',
      '--motion-slow',
      '--motion-ease-standard',
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
    const query = /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}\n/.exec(
      css,
    )?.[1];
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

describe('modal enter', () => {
  it('the backdrop and dialog animate in on mount off the shared tokens', async () => {
    const css = await rules();
    // Modals were the one abrupt surface — they mounted instantly. The enter is CSS-only
    // (the component returns null when closed, so mount alone triggers it) and reads its clock
    // and curve off tokens, the same "arriving" gesture as a panel swap, with no hand-typed
    // duration or curve to drift.
    const backdrop = baseRules(css, '.modal-backdrop').find((b) => /animation\s*:/.test(b)) ?? '';
    expect(backdrop, 'no animated .modal-backdrop rule').toBeTruthy();
    expect(backdrop).toMatch(/animation:\s*modal-backdrop-in/);
    expect(backdrop).toMatch(/var\(--motion-panel-duration\)/);
    expect(backdrop).toMatch(/var\(--motion-ease-enter\)/);
    expect(backdrop).not.toMatch(/\d+m?s(?![\w-])/);
    expect(backdrop).not.toMatch(/cubic-bezier/);

    const dialog = baseRules(css, '.modal').find((b) => /animation\s*:/.test(b)) ?? '';
    expect(dialog, 'no animated .modal rule').toBeTruthy();
    expect(dialog).toMatch(/animation:\s*modal-in/);
    expect(dialog).toMatch(/var\(--motion-/);
    expect(dialog).not.toMatch(/\d+m?s(?![\w-])/);
    expect(dialog).not.toMatch(/cubic-bezier/);
  });

  it('both enter keyframes exist and stay compositor-only', async () => {
    const css = await rules();
    const backdropFrames = /@keyframes\s+modal-backdrop-in\s*\{([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
    expect(backdropFrames, 'no @keyframes modal-backdrop-in').toBeTruthy();
    // The dim layer is a pure opacity fade — no transform to fight the centred layout.
    expect(backdropFrames).toMatch(/opacity/);
    expect(backdropFrames).not.toMatch(/transform|translate/);

    const dialogFrames = /@keyframes\s+modal-in\s*\{([\s\S]*?)\n\}/.exec(css)?.[1] ?? '';
    expect(dialogFrames, 'no @keyframes modal-in').toBeTruthy();
    // The dialog fades and settles up — opacity + a single translate, both on the compositor.
    expect(dialogFrames).toMatch(/opacity/);
    expect(dialogFrames).toMatch(/translate3d|translate/);
  });

  it('descends from both kill-switches with no modal-level opt-out', async () => {
    const css = await rules();
    // Because both kill-switches are universal `*` rules that zero `animation`, the mount
    // enter is collapsed to an instant appearance without `.modal` opting in — the same reason
    // route-enter / panel-enter are safe. Guard the other direction: the modal rules must not
    // carry a `!important` animation or a `will-change` that would let them escape that collapse.
    for (const selector of ['.modal-backdrop', '.modal']) {
      for (const decls of baseRules(css, selector)) {
        expect(decls, `${selector} must not force animation past a kill-switch`).not.toMatch(
          /animation[^;]*!important/,
        );
        expect(decls).not.toMatch(/will-change/);
      }
    }
    // And the universal blocks that do the collapsing still zero animation on every element.
    const reduced = /@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*?)\n\}\n/.exec(
      css,
    )?.[1];
    expect(reduced).toMatch(/\*\s*,/);
    expect(reduced).toMatch(/animation-duration:\s*0\.01ms\s*!important/);
    const safe = block(css, ":root[data-safe-mode='on'] *");
    expect(safe).toMatch(/animation[^;]*none/);
  });
});

describe('micro-interaction consolidation', () => {
  it('the migrated surfaces read their clock off the tokens, not hand-typed values', async () => {
    const css = await rules();
    // Spot-check a representative slice of the ~40 rules folded onto the micro tokens: a button,
    // a form control, a titlebar button. Each transition must reference a `--motion-*` token and
    // hand-type no duration — the drift the consolidation exists to remove. (Every one of these
    // selectors also owns a separate layout-only rule, which `baseRules` returns and the filter
    // skips, so the assertion lands on the transition rule specifically.)
    for (const selector of ['.btn', '.control', '.titlebar__btn']) {
      const transitions = baseRules(css, selector).filter((b) => /transition\s*:/.test(b));
      expect(transitions.length, `${selector} should declare a transition`).toBeGreaterThan(0);
      for (const decls of transitions) {
        expect(decls, `${selector} transition should use a motion token`).toMatch(/var\(--motion-/);
        expect(decls, `${selector} transition should not hand-type a duration`).not.toMatch(
          /\d+m?s(?![\w-])/,
        );
      }
    }
  });
});
