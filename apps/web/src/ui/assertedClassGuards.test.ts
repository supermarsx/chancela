/**
 * Binds class names that component tests trust to a RULE that actually styles them.
 *
 * ## The gap this closes
 *
 * `trustConcerns.test.tsx` proves the banner picks the right modifier —
 * `expect(banner().className).toContain('inline-warning--warn')` — and that assertion is honest: it
 * is the component's severity decision, rendered. But nothing bound `inline-warning--warn` to a
 * rule. Delete or typo that selector in `theme.css` and every test in this repo stays green while
 * the banner silently loses the colour that is the whole point of computing a severity. The same
 * held for the 116 lines of trust-concern styling and the 33 lines of passkey styling that landed
 * with no test reading `theme.css` at all.
 *
 * jsdom does not apply stylesheet declarations, so no amount of rendering can close this: a mounted
 * banner has the same `getComputedStyle` output whether or not the rule exists. The only place the
 * binding can be checked is the sheet's source text — the idiom `subNavWidthGuards.test.ts` uses,
 * and the reason this file reads `theme.css` rather than a DOM.
 *
 * ## Why an explicit inventory rather than a sweep over every test file
 *
 * A mechanical sweep — collect every class literal reachable from a `querySelector` call in a test
 * and require a rule for each — was measured before this file was written: of 196 such classes, 18
 * legitimately have NO rule. Two honest reasons, neither of which the literal distinguishes:
 *
 *   - **Absence assertions.** `expect(document.querySelector('.error-note')).toBeNull()` names a
 *     class precisely because it must not be in the document. Requiring a rule for it is nonsense.
 *   - **Structural hooks.** `.pdf-validator-verdict__label` is a `<span>` that exists to be found,
 *     not to be painted. An unstyled class is a legitimate design, not a defect.
 *
 * A sweep would therefore need an 18-entry exception list on day one — a list that grows by
 * exception rather than by intent, and whose first entry teaches the next person that the way past
 * this gate is to add a line to it. An inventory inverts that: each entry names a class whose
 * styling is load-bearing, and adding one is a deliberate act. The cost is that a NEW styled class
 * is not covered until someone adds it; the sweep does not actually fix that either, since a new
 * class with a rule passes it trivially.
 *
 * @see subNavWidthGuards.test.ts — same source-assertion idiom, guarding a declaration rather than
 *      a selector's existence.
 */
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Classes whose STYLING is load-bearing, grouped by the sheet that must carry the rule.
 *
 * Everything here is either asserted by name in a test, or emitted by a component through string
 * interpolation — which is the more fragile of the two, because `trust-concern--${severity}` means
 * a grep for `trust-concern--warn` across the app finds the sheet and nothing else, and a sheet
 * whose only reference is itself looks exactly like dead CSS.
 */
const GUARDED: Readonly<Record<string, readonly string[]>> = {
  'src/theme.css': [
    // --- InlineWarning tones. `inline-warning--${tone}` (InlineWarning.tsx) — never written out in
    // the app. The tone IS the message: `--warn` and `--info` are what stop a routine unverified
    // transport from shouting as loudly as a broken algorithm.
    // Asserted by: trustConcerns.test.tsx (`--warn`, `--info`), certidaoLookup.test.tsx (`--error`).
    'inline-warning--warn',
    'inline-warning--info',
    'inline-warning--error',

    // --- Trust concerns (4b69a87f). The marker in the status line, and the banner below the lists.
    // Asserted by name in trustConcerns.test.tsx.
    'trust-statusline__item--concerns',
    'trust-concern-markers',
    'trust-concerns',
    'trust-concern',
    'trust-concern__heading',
    'trust-fact-cell--marked',
    // Reached in tests only through `data-severity`, so no assertion names them: the severity a test
    // reads off the dataset is carried to the eye by these two families alone.
    'trust-concern-marker',
    'trust-concern-marker--warn',
    'trust-concern-marker--info',
    'trust-concern--warn',
    'trust-concern--info',

    // --- Passkey sign-in block (f34339b4). The modifier flips the base `.signin__alt` column to a
    // row and moves its hairline from top to bottom, because the block LEADS the card. Without the
    // rule the separator fences the card's own heading off from its contents — a purely visual
    // regression, invisible to every test that mounts the component.
    'signin__alt--passkey',
  ],
};

async function readSheet(path: string): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(path, 'utf8').replace(/\r\n/gu, '\n');
}

/**
 * Every class that appears in SELECTOR position anywhere in a sheet.
 *
 * Two things this deliberately is not:
 *
 *   - It is not a substring search. `theme.css` names classes constantly in its comments — the
 *     passkey rule is introduced by a comment that quotes `.signin__alt--passkey` twenty lines
 *     earlier — so a `sheet.includes('.signin__alt--passkey')` guard would pass against a sheet
 *     with the rule deleted and only the prose left behind. Comments are stripped first.
 *   - It is not anchored at column 0. `.inline-warning` is only ever declared inside `:where(…)`
 *     (deliberately, to keep its specificity at zero), and `.trust-concern-markers` appears as the
 *     right-hand side of a child combinator. Both are rules; both would be missed by an anchor.
 *
 * Class names are tokenised whole, so `.trust-concern-markers` can never satisfy a demand for
 * `.trust-concern` — pinned by a red-proof below.
 */
function selectorClasses(sheet: string): Set<string> {
  const code = sheet.replace(/\/\*[\s\S]*?\*\//gu, '');
  const classes = new Set<string>();
  for (const rule of code.matchAll(/(?:^|[{};])([^{};]*)\{/gu)) {
    const prelude = rule[1];
    // `@media`/`@supports` preludes are conditions, not selector lists.
    if (prelude.trimStart().startsWith('@')) continue;
    for (const cls of prelude.matchAll(/\.(-?[_a-zA-Z][\w-]*)/gu)) classes.add(cls[1]);
  }
  return classes;
}

const SHEETS = new Map<string, string>();
beforeAll(async () => {
  for (const path of Object.keys(GUARDED)) SHEETS.set(path, await readSheet(path));
});

describe('classes tests trust are classes some rule styles', () => {
  for (const [path, classes] of Object.entries(GUARDED)) {
    describe(path, () => {
      it.each(classes)('`.%s` exists as a selector', (cls) => {
        expect(selectorClasses(SHEETS.get(path)!)).toContain(cls);
      });
    });
  }

  it('reads rules, not prose — a class named only in a comment does not count', () => {
    // `.signin__alt--passkey` is quoted in the comment above `.signin__alt`, so this sheet is the
    // real thing rather than a contrived one: rename the RULE and the substring survives.
    const theme = SHEETS.get('src/theme.css')!;
    const typoed = theme.replace(/^\.signin__alt--passkey(\s*\{)/mu, '.signin__alt--passkeyy$1');
    expect(typoed, 'the red-proof must actually change the sheet').not.toBe(theme);
    expect(typoed, 'the comment mentioning the class must survive the rename').toContain(
      '`.signin__alt--passkey`',
    );
    expect(selectorClasses(typoed)).not.toContain('signin__alt--passkey');
    // …and the base rule the modifier overrides is untouched, so this is a targeted red and not a
    // wholesale failure of the extractor.
    expect(selectorClasses(typoed)).toContain('signin__alt');
  });

  it('goes red when a guarded rule is deleted outright', () => {
    const theme = SHEETS.get('src/theme.css')!;
    const stripped = theme.replace(/^\.inline-warning--warn\s*\{[^}]*\}/mu, '');
    expect(stripped, 'the red-proof must actually change the sheet').not.toBe(theme);
    expect(selectorClasses(stripped)).not.toContain('inline-warning--warn');
    // The sibling tone is still there: deleting one rule reddens one entry, not the file.
    expect(selectorClasses(stripped)).toContain('inline-warning--info');
  });

  it('tokenises class names whole, so a longer neighbour cannot stand in for a missing rule', () => {
    // `.trust-concern-markers` and `.trust-concern__heading` both contain `trust-concern` as a
    // prefix. A substring check would call `.trust-concern` present with its rules gone — and that
    // rule is the concern row itself.
    const theme = SHEETS.get('src/theme.css')!;
    const stripped = theme.replace(/^\.trust-concern(?![\w-])[^{]*\{[^}]*\}/gmu, '');
    expect(stripped, 'the red-proof must actually change the sheet').not.toBe(theme);
    expect(stripped, 'the neighbours whose names contain it must survive').toContain(
      '.trust-concern-markers',
    );
    expect(selectorClasses(stripped)).toContain('trust-concern-markers');
    expect(selectorClasses(stripped)).toContain('trust-concern__heading');
    expect(selectorClasses(stripped)).not.toContain('trust-concern');
  });
});
