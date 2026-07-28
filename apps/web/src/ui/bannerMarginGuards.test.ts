/**
 * Structural guards on the inline banner's margins (t89).
 *
 * ## What kept going wrong
 *
 * `InlineWarning` is a padded box (`padding: 0.85rem 1rem`) whose `__body` renders whatever the
 * caller passed. 62 of its 238 call sites pass block-level content — `<p>`, `<ul>`, `<dl>` — and
 * those carry the UA stylesheet's own `margin-block: 1em`, which lands *inside* the padding and
 * blows the box out vertically. The defect was reported, fixed, and reported again, because each
 * fix was written against the surface someone happened to be looking at:
 * `.external-signing-workflows .inline-warning__body > p { margin: 0 }` repaired exactly one page
 * of the sixty-two and, at (0,3,0), outranked any global rule that might later be written.
 *
 * So the rule these guards encode is not "the margin is 0.5rem". It is **where the rule is allowed
 * to live**: next to the primitive, at zero specificity, once. A surface-scoped margin patch on
 * this component is the regression, and {@link surfaceScopedOffences} fails on it by construction.
 *
 * ## Why source analysis rather than a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so a test that mounts a
 * banner and reads its margin passes whether or not the rule exists — a guard that cannot go red
 * is not a guard. These read the two sources the behaviour actually comes from: the stylesheet
 * (do the rules exist, and are they global?) and the component tree (does every banner go through
 * the component the rules target?).
 *
 * ## Why the guards are tested against mutated copies of the real sources
 *
 * The last section of this file feeds each predicate a copy of the real input with the fix taken
 * back out — the `:where` rules deleted, the historical page-scoped patch reinstated, a hand-rolled
 * banner added — and asserts it reports the offence. That is deliberate. A guard is only worth its
 * runtime if it goes red, and "I checked once by hand" decays the moment someone refactors the
 * walker; doing it in-memory also means proving it never requires writing a knowingly broken
 * stylesheet into a tree other lanes are editing. Non-vacuity bounds cover the other failure
 * shape, where a broken glob makes a sweep pass over nothing.
 */
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The app project has no `@types/node`, so `import { readFileSync } from 'node:fs'` does not
 * typecheck here. This indirection is the shape the rest of the suite already uses to read a real
 * file from a test (see `ExternalSigningWorkflowsPage.test.tsx`).
 */
async function readTheme(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

const OUTER_SELECTOR = ':where(.inline-warning__body) > *';
const BETWEEN_SELECTOR = ':where(.inline-warning__body) > * + *';

interface CssRule {
  selector: string;
  body: string;
}

/**
 * Every style rule in the sheet, flattened out of any `@media`/`@supports` nesting.
 *
 * Hand-rolled rather than pulled from `postcss`: postcss is present only transitively (via Vite),
 * and a guard that exists to stop a recurring regression should not be the first thing to break
 * when the dependency tree is re-hoisted. The shape it has to cope with is a prettier-formatted
 * stylesheet, and the sentinel assertion below checks the walk actually found the sheet.
 */
function parseRules(css: string): CssRule[] {
  // Comments first: they contain braces and selector-shaped text (this header would parse as one).
  const source = css.replace(/\/\*[\s\S]*?\*\//gu, '');
  const rules: CssRule[] = [];
  let prelude = '';
  let depth = 0;
  let block = '';

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (depth === 0) {
      if (ch === '{') {
        depth = 1;
        block = '';
      } else if (ch === '}') {
        prelude = ''; // closing an at-rule container
      } else {
        prelude += ch;
      }
      continue;
    }
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        const selector = prelude.trim();
        prelude = '';
        // An at-rule container (`@media …`) holds rules rather than declarations: recurse into it.
        if (selector.startsWith('@')) rules.push(...parseRules(block));
        else if (selector) rules.push({ selector, body: block });
        continue;
      }
    }
    block += ch;
  }
  return rules;
}

/** One comma-separated selector at a time — `a, b { … }` is two rules wearing one coat. */
function selectorList(rule: CssRule): string[] {
  return rule.selector
    .split(',')
    .map((s) => s.trim().replace(/\s+/gu, ' '))
    .filter(Boolean);
}

function rulesFor(rules: CssRule[], selector: string): CssRule[] {
  return rules.filter((rule) => selectorList(rule).includes(selector));
}

function declaresMargin(body: string): boolean {
  return /(^|[;{\s])margin(-top|-bottom|-block|-block-start|-block-end)?\s*:/u.test(body);
}

/** Remove balanced `:where(…)` groups — what is left is what still carries specificity. */
function stripWhere(selector: string): string {
  let out = selector;
  for (;;) {
    const start = out.indexOf(':where(');
    if (start === -1) return out;
    let depth = 0;
    let end = -1;
    for (let i = start + ':where'.length; i < out.length; i += 1) {
      if (out[i] === '(') depth += 1;
      if (out[i] === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end === -1) return out; // unbalanced; leave it visible to the caller
    out = `${out.slice(0, start)}${out.slice(end + 1)}`;
  }
}

const COMBINATOR = /[\s>+~]/u;

/**
 * Margin rules that reach the banner while still carrying specificity of their own — i.e. the
 * page-scoped patch shape. Two things are deliberately NOT offences: a selector that is entirely
 * `:where()`-wrapped (the global treatment), and a single compound selector with no combinator,
 * which is the primitive describing its own parts (`.inline-warning__title { margin: … }`) rather
 * than a surface reaching in from outside.
 */
function surfaceScopedOffences(rules: CssRule[]): string[] {
  return rules.flatMap((rule) =>
    selectorList(rule)
      .filter((selector) => {
        if (!/\.inline-warning\b|\.inline-warning__/u.test(selector)) return false;
        if (!declaresMargin(rule.body)) return false;
        const carrying = stripWhere(selector);
        if (!/[.#[]|:[a-z]/u.test(carrying)) return false;
        if (!COMBINATOR.test(selector.trim())) return false;
        return true;
      })
      .map((selector) => `${selector} { ${rule.body.trim().replace(/\s+/gu, ' ')} }`),
  );
}

interface BannerScan {
  /** Markup outside the primitive that spells the banner's own class names. */
  strays: string[];
  banners: number;
  files: number;
}

function scanBanners(sources: Record<string, string>): BannerScan {
  const strays: string[] = [];
  let banners = 0;
  let files = 0;

  for (const [file, source] of Object.entries(sources)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    files += 1;
    const parsed = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    const ownsTheMarkup = /\/InlineWarning\.tsx$/u.test(file);
    const inspect = (node: ts.Node): void => {
      const opening = ts.isJsxElement(node)
        ? node.openingElement
        : ts.isJsxSelfClosingElement(node)
          ? node
          : undefined;
      if (opening && ts.isIdentifier(opening.tagName) && opening.tagName.text === 'InlineWarning') {
        banners += 1;
      }
      if (!ownsTheMarkup && ts.isStringLiteralLike(node) && /\binline-warning/u.test(node.text)) {
        const line = parsed.getLineAndCharacterOfPosition(node.getStart(parsed)).line + 1;
        strays.push(`${file}:${line} "${node.text}"`);
      }
      ts.forEachChild(node, inspect);
    };
    inspect(parsed);
  }
  return { strays, banners, files };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const SCAN = scanBanners(PRODUCTION_SOURCES);

let THEME = '';
let RULES: CssRule[] = [];

beforeAll(async () => {
  THEME = await readTheme();
  RULES = parseRules(THEME);
});

describe('inline banner margins — structural guards', () => {
  it('parses the stylesheet it is guarding, so a broken walk cannot pass vacuously', () => {
    expect(RULES.length).toBeGreaterThan(1000);
    // A sentinel the sheet has carried since the primitive existed: if the walk stops finding
    // this, it is mis-tokenising rather than reporting a real absence.
    expect(rulesFor(RULES, '.inline-warning__title')).toHaveLength(1);
  });

  it('gives the banner body a global, zero-specificity margin treatment', () => {
    const outer = rulesFor(RULES, OUTER_SELECTOR);
    const between = rulesFor(RULES, BETWEEN_SELECTOR);

    expect(
      outer,
      'The banner is a padded box; block-level children arrive with the UA stylesheet’s own ' +
        '1em block margins, which stack on top of that padding. Collapse them so the padding is ' +
        'the only thing setting the inset.',
    ).toHaveLength(1);
    expect(outer[0]?.body).toMatch(/margin-top:\s*0;/u);
    expect(outer[0]?.body).toMatch(/margin-bottom:\s*0;/u);

    expect(
      between,
      'Collapsing every margin glues consecutive paragraphs together — 20 call sites pass more ' +
        'than one block. Zeroing the outer edge and spacing siblings are two different jobs.',
    ).toHaveLength(1);
    expect(between[0]?.body).toMatch(/margin-top:\s*0\.5rem;/u);
  });

  it('never lets a surface re-patch the banner’s margins at its own specificity', () => {
    expect(
      surfaceScopedOffences(RULES),
      'A margin rule that reaches the banner through a page/surface class outranks the global ' +
        'treatment next to the primitive, so it fixes one screen and freezes the other sixty-one. ' +
        'That is the exact regression this file exists to stop: delete the scoped rule and change ' +
        'the `:where(.inline-warning__body)` rules instead. If a surface genuinely needs its own ' +
        'rhythm, it is a change to the primitive or a new variant class — not a descendant patch.',
    ).toEqual([]);
  });

  it('routes every banner through the component the treatment targets', () => {
    expect(
      SCAN.strays,
      'The margin treatment is attached to the class names `InlineWarning` emits. Markup that ' +
        'spells those class names itself is a banner the primitive does not know about, so it ' +
        'silently opts out of every future fix to them — which is how this defect survived one ' +
        'round of repair already. Render `<InlineWarning>` instead.',
    ).toEqual([]);

    // Bounds, so a broken glob or a renamed component cannot make the sweep above pass over
    // nothing. 238 banners across 210 production files at the time of writing.
    expect(SCAN.files).toBeGreaterThan(150);
    expect(SCAN.banners).toBeGreaterThan(200);
  });
});

/**
 * The guards, run against the real sources with the fix taken back out. Each case is a regression
 * that actually happened or plausibly will; if one of these stops reporting an offence, the
 * corresponding guard above has quietly become decorative.
 */
describe('inline banner margins — the guards go red without the fix', () => {
  /** Delete a whole `selector { … }` rule from the sheet, the way a revert would. */
  function withoutRule(css: string, selector: string): string {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    const stripped = css.replace(new RegExp(`\\n${escaped}\\s*\\{[^}]*\\}\\n`, 'u'), '\n');
    expect(stripped, `fixture did not remove \`${selector}\``).not.toBe(css);
    return stripped;
  }

  it('reports the body treatment missing when the global rules are reverted', () => {
    const reverted = parseRules(withoutRule(THEME, BETWEEN_SELECTOR));
    expect(rulesFor(reverted, BETWEEN_SELECTOR)).toHaveLength(0);
    // …and the outer rule is found independently, so the two assertions cannot share one failure.
    expect(rulesFor(parseRules(withoutRule(THEME, OUTER_SELECTOR)), OUTER_SELECTOR)).toHaveLength(
      0,
    );
  });

  it('reports the page-scoped patch this fix replaced', () => {
    // Verbatim the rule that shipped as `.external-signing-workflows .inline-warning__body > p`:
    // one page repaired, sixty-one left, and at (0,3,0) it beat the global rule besides.
    const patched = `${THEME}\n.external-signing-workflows .inline-warning__body > p {\n  margin: 0;\n}\n`;
    expect(surfaceScopedOffences(parseRules(patched))).toEqual([
      '.external-signing-workflows .inline-warning__body > p { margin: 0; }',
    ]);
  });

  it('reports a scoped patch hidden inside a media query', () => {
    const patched = `${THEME}\n@media (max-width: 620px) {\n  .some-page .inline-warning { margin-top: 0; }\n}\n`;
    expect(surfaceScopedOffences(parseRules(patched))).toEqual([
      '.some-page .inline-warning { margin-top: 0; }',
    ]);
  });

  it('does not mistake the primitive describing its own parts for a surface patch', () => {
    // `.inline-warning__title { margin: 0 0 0.35rem }` is real and must stay legal, or the guard
    // would push people towards `!important` instead of towards the shared rule.
    expect(surfaceScopedOffences(parseRules(THEME))).toEqual([]);
    expect(rulesFor(RULES, '.inline-warning__title')[0]?.body).toMatch(/margin:/u);
  });

  it('reports a hand-rolled banner that spells the class names itself', () => {
    const scan = scanBanners({
      '../features/example/ExamplePage.tsx':
        'export function Example() {\n' +
        '  return <div className="inline-warning inline-warning--info">hand-rolled</div>;\n' +
        '}\n',
    });
    expect(scan.strays).toHaveLength(1);
    expect(scan.strays[0]).toContain('ExamplePage.tsx:2');
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanBanners({});
    expect(empty.files).toBe(0);
    expect(empty.banners).toBe(0);
    // The bounds in the guard above are what turn this into a failure there.
    expect(empty.files).not.toBeGreaterThan(150);
  });
});
