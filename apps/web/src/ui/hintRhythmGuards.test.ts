/**
 * Structural guards on the field hint's vertical rhythm (t101, Pass 3 of docs/ui-spacing.md).
 *
 * ## The defect, and why it was deferred rather than patched
 *
 * `.field__hint { margin: 0 }` is (0,1,0). So is every container rhythm — `.stack > * + *`,
 * `.stack--tight > * + *`, `.form > * + *` — and the hint's zero is declared LATER in the sheet
 * than all three, so it won on source order. Consecutive hints therefore rendered at **0px**, text
 * touching text: the diagnostics card's three sentences and the language card's four notes were
 * both measured that way, and the tree walk below finds 23 adjacent hint pairs. (The bound it
 * asserts is deliberately looser than that count, at 13: the point of a bound is to fail an empty
 * or shrunken sweep, not to re-freeze a number that legitimately grows with the app.)
 *
 * The obvious repair — pinning the hint's zero to `:where()` so any rhythm owner outranks it —
 * had a named conflict, which is why `docs/ui-spacing.md` sent it to the product owner instead of
 * landing it: it would also loosen the preservation-package row's hint, whose tightness under its
 * `Toggle` is deliberate, and there is a third patch in the same family
 * (`.signing-evidence .field__hint`).
 *
 * ## The shape that resolves it, and what these guards hold
 *
 * **A hint following another hint and a hint following the control it describes are two different
 * relationships.** The sheet expressed only the second. The fix expresses the first, and does it
 * through the SUBJECT of the selector: the predecessor sits in `:where()` and contributes nothing,
 * so `:where(.field__hint, .field__error) + .field__hint` stays (0,1,0) — the same weight as the
 * zero it overrides. Three consequences, and each is a guard below:
 *
 *  1. it beats `.field__hint`'s `margin: 0` **on source order**, being declared directly under it.
 *     Move it above and the fix silently reverts, which is why the order is pinned;
 *  2. it matches nothing that follows a control, so the caption case is untouched by construction
 *     rather than by exception — no per-surface patch had to be retired to get there;
 *  3. it still LOSES to a container that declares its own hint rhythm further down the sheet.
 *     `.settings-rows > * + *` (0.9rem plus a hairline) is the one that does, and keeps it — so
 *     the rule must also stay ABOVE that, and that order is pinned too.
 *
 * The remaining guard is the gap-container one: on a `gap` container a margin ADDS rather than
 * competing, so the rule needed a neutraliser for `.modal__body` (measured 13.59px → 21.59px
 * without it). Rather than pre-empt the other gap containers with a second copy of a frozen list,
 * the population is walked from the tree — the shape that found `.chronology-analytics` for Pass 4
 * — so a hint run landing in an uncovered gap container fails here instead of double-spacing.
 *
 * ## Why source analysis rather than a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting a card and
 * reading a hint's margin passes whether or not any rule exists. These read the two sources that
 * decide the outcome — the stylesheet and the component tree — and the last section proves each
 * predicate goes red against a copy of the real sources with the fix removed. The pixel figures
 * quoted throughout were measured separately, in headless Chromium against the real sheet, in both
 * colour schemes.
 */
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

async function readTheme(): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

interface CssRule {
  selector: string;
  body: string;
}

/** Brace-depth tokeniser: a flat regex mis-parses `@media` nesting (docs/ui-spacing.md). */
function parseRules(css: string): CssRule[] {
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
        prelude = '';
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
        if (selector.startsWith('@')) rules.push(...parseRules(block));
        else if (selector) rules.push({ selector, body: block });
        continue;
      }
    }
    block += ch;
  }
  return rules;
}

/** Split a selector list on TOP-LEVEL commas only — `:where(a, b)` must survive intact. */
function selectorList(rule: CssRule): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of rule.selector) {
    if (ch === '(' || ch === '[') depth += 1;
    else if (ch === ')' || ch === ']') depth -= 1;
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts.map((s) => s.trim().replace(/\s+/gu, ' ')).filter(Boolean);
}

// ---------------------------------------------------------------------------------------------
// The rules under guard
// ---------------------------------------------------------------------------------------------

const HINT_CLASSES = ['field__hint', 'field__error'] as const;

/**
 * The hint-run rule, exactly.
 *
 * Two selectors, one per subject, because a byte-counter line switches between the two classes as
 * it crosses its limit and a gap that vanishes when text turns red is the same defect wearing the
 * error's class.
 */
const HINT_RUN_SELECTORS: readonly string[] = [
  ':where(.field__hint, .field__error) + .field__error',
  ':where(.field__hint, .field__error) + .field__hint',
];

/**
 * The step. NOT a ninth value: it is `:where(.inline-warning__body) > * + *` (2a538e87), what this
 * sheet already gives consecutive explanatory paragraphs inside a primitive — the same
 * relationship, one primitive over.
 */
const HINT_RUN_VALUE = '0.5rem';

/**
 * The gap containers the rule is neutralised in, and the value it is neutralised WITH.
 *
 * `.field` is in this list because the tree walk found `ServerEnvSection` rendering two hints as
 * adjacent children of a `Field` — 5.59px → 13.59px without it. It was not on anybody's list.
 */
const HINT_RUN_NEUTRALISER_SELECTORS: readonly string[] = [
  ':where(.field, .modal__body) > :where(.field__hint, .field__error) + .field__error',
  ':where(.field, .modal__body) > :where(.field__hint, .field__error) + .field__hint',
];

/**
 * Rules other than the two above whose SUBJECT is a hint and which give it a block margin.
 *
 * FROZEN, and unlike the container-rhythm inventory this one is deliberately **not empty**. Each
 * entry is a different relationship from the hint run, which is why the fix supersedes none of
 * them:
 *
 *  - `.field__hint` / `.field__error` — the primitive's own zero. Load-bearing: it is what keeps a
 *    hint tight under the control it captions, and what keeps a `<p>`'s UA `margin-block: 1em` out
 *    of `.field`'s 0.35rem `gap`, where a margin ADDS.
 *  - `.settings-rows > .toggle + .field__hint` (twice — the grid form and its narrow-viewport
 *    copy) — a caption under a switch. Measured unchanged at 4.8px.
 *  - `.signing-evidence .field__hint` — a hint after a `<dl>`, not after a hint. 11.19px, unchanged.
 *
 * A new entry is the per-surface repair this guard family exists to catch: it buys one screen and
 * outranks the shared rule on exactly that screen.
 */
const KNOWN_HINT_MARGIN_RULES: readonly string[] = [
  '.field__error',
  '.field__hint',
  '.settings-rows > .toggle + .field__hint',
  '.settings-rows > .toggle + .field__hint',
  '.signing-evidence .field__hint',
];

function declaresBlockMargin(body: string): boolean {
  return /(?:^|[;{\s])margin(?:-top|-block|-block-start|-bottom|-block-end)?\s*:/u.test(body);
}

function marginTop(body: string): string | undefined {
  return (
    /(?:^|[;{\s])margin-top\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim() ??
    /(?:^|[;{\s])margin-block-start\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim()
  );
}

/** The last compound of a selector — the element the rule actually styles. */
function subjectOf(selector: string): string {
  return (
    selector
      .split(/(?<![(,]\s*)[\s>+~]+/u)
      .filter(Boolean)
      .pop() ?? ''
  );
}

/** Is this selector's subject a hint or an error, as a plain class (not inside `:where()`)? */
function targetsHint(selector: string): boolean {
  const subject = subjectOf(selector);
  return HINT_CLASSES.some((c) => new RegExp(`\\.${c}(?![\\w-])`, 'u').test(subject));
}

/** Every rule whose subject is a hint and which brings it a block margin. */
function hintMarginRules(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter((s) => targetsHint(s) && declaresBlockMargin(rule.body)),
    )
    .sort();
}

// ---------------------------------------------------------------------------------------------
// Gap containers — where a margin adds instead of competing
// ---------------------------------------------------------------------------------------------

/** `display: flex|grid` **and** a block-axis `gap`. `gap` alone does nothing in normal flow. */
function gapOf(body: string): string | undefined {
  if (!/display:\s*(?:inline-)?(?:flex|grid)/u.test(body)) return undefined;
  return /(?:^|[;{\s])(?:gap|row-gap)\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
}

/** Single-class rules, merged, so `.field { display: flex }` and `.field { gap }` read as one. */
function singleClassRules(rules: CssRule[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const rule of rules) {
    for (const selector of selectorList(rule)) {
      const m = /^\.([\w-]+)$/u.exec(selector);
      if (m?.[1]) out.set(m[1], `${out.get(m[1]) ?? ''}\n${rule.body}`);
    }
  }
  return out;
}

/** Container classes the hint-run rule is neutralised inside of. */
function neutralisedHintHosts(rules: CssRule[]): Set<string> {
  const out = new Set<string>();
  for (const rule of rules) {
    if (marginTop(rule.body) !== '0') continue;
    for (const selector of selectorList(rule)) {
      const m =
        /^:where\(([^)]*)\)\s*>\s*:where\([^)]*\)\s*\+\s*\.(?:field__hint|field__error)$/u.exec(
          selector,
        );
      if (!m) continue;
      for (const part of (m[1] as string).split(',')) {
        const cls = /^\s*\.([\w-]+)\s*$/u.exec(part)?.[1];
        if (cls) out.add(cls);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The population: every run of consecutive hints in the component tree
// ---------------------------------------------------------------------------------------------

function classesOf(node: ts.Node): string[] {
  if (!ts.isJsxElement(node) && !ts.isJsxSelfClosingElement(node)) return [];
  const attrs = ts.isJsxElement(node) ? node.openingElement.attributes : node.attributes;
  const attr = attrs.properties.find(
    (p): p is ts.JsxAttribute =>
      ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === 'className',
  );
  const init = attr?.initializer;
  if (!init) return [];
  if (ts.isStringLiteral(init)) return init.text.split(/\s+/u).filter(Boolean);
  // A conditional or template className: every literal class it can produce counts, because the
  // byte-counter line really does switch between `field__hint` and `field__error` at runtime.
  return [...init.getText().matchAll(/['"`]([^'"`]+)['"`]/gu)].flatMap((m) =>
    (m[1] as string).split(/\s+/u).filter(Boolean),
  );
}

const isHint = (node: ts.Node): boolean =>
  classesOf(node).some((c) => (HINT_CLASSES as readonly string[]).includes(c));

/** Child ELEMENTS in source order, unwrapping `{cond ? <x/> : null}` and `{cond && <x/>}`. */
function childElements(children: readonly ts.JsxChild[]): (ts.Node | undefined)[] {
  const out: (ts.Node | undefined)[] = [];
  const unwrap = (child: ts.JsxChild): ts.Node | undefined => {
    if (ts.isJsxText(child)) return child.text.trim() ? child : undefined;
    if (!ts.isJsxExpression(child)) return child;
    let expr: ts.Expression | undefined = child.expression;
    while (expr && ts.isParenthesizedExpression(expr)) expr = expr.expression;
    if (!expr) return undefined;
    const nullish = (n: ts.Node): boolean =>
      n.kind === ts.SyntaxKind.NullKeyword || n.getText() === 'undefined';
    if (ts.isConditionalExpression(expr)) {
      let branch: ts.Expression | undefined = nullish(expr.whenFalse)
        ? expr.whenTrue
        : nullish(expr.whenTrue)
          ? expr.whenFalse
          : undefined;
      while (branch && ts.isParenthesizedExpression(branch)) branch = branch.expression;
      return branch ?? expr;
    }
    if (
      ts.isBinaryExpression(expr) &&
      expr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
    ) {
      let right: ts.Expression = expr.right;
      while (ts.isParenthesizedExpression(right)) right = right.expression;
      return right;
    }
    return expr;
  };
  for (const child of children) {
    const node = unwrap(child);
    if (node === undefined) continue;
    // Anything we cannot resolve to an element breaks adjacency rather than being assumed away.
    out.push(ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) ? node : undefined);
  }
  return out;
}

/**
 * Every run of two adjacent hints, and the classes of the element that holds them.
 *
 * Walked from the tree rather than grepped for class names, because the interesting case is the
 * one nobody wrote down: a container that acquires its FIRST hint run tomorrow has to fail this
 * guard, and it can only do that if the population is found by what the markup does.
 */
function scanHintRuns(sources: Record<string, string>): {
  runs: number;
  hints: number;
  holderClasses: Set<string>;
} {
  let runs = 0;
  let hints = 0;
  const holderClasses = new Set<string>();
  for (const [file, source] of Object.entries(sources)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
        if (isHint(node)) hints += 1;
      }
      if (ts.isJsxElement(node) || ts.isJsxFragment(node)) {
        const kids = childElements(node.children);
        for (let i = 1; i < kids.length; i += 1) {
          const prev = kids[i - 1];
          const cur = kids[i];
          if (!prev || !cur || !isHint(prev) || !isHint(cur)) continue;
          runs += 1;
          // A fragment is not an element: the run's real holder is whatever encloses it, so walk
          // out to the nearest element rather than losing the site.
          let holder: ts.Node | undefined = node;
          while (holder && !ts.isJsxElement(holder)) holder = holder.parent;
          if (holder) for (const c of classesOf(holder)) holderClasses.add(c);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { runs, hints, holderClasses };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const HINT_RUNS = scanHintRuns(PRODUCTION_SOURCES);

let THEME = '';
/** Comments stripped, for the source-ORDER assertions: this sheet documents its rules by quoting
 *  their selectors, so a raw `indexOf` can find the prose instead of the rule. */
let THEME_RULES_ONLY = '';
let RULES: CssRule[] = [];

beforeAll(async () => {
  THEME = await readTheme();
  THEME_RULES_ONLY = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
  RULES = parseRules(THEME);
});

/**
 * Where a selector is declared, in the comment-stripped sheet.
 *
 * Two things this has to get right, both learned by going red:
 *
 *  - a selector may be the first of a LIST, so it is followed by `,` rather than by ` {`. Both
 *    hint-run rules are. Matching only ` {` returns -1 and turns an ordering assertion into a
 *    comparison against a rule the walk could not find;
 *  - the anchor must be the start of a LINE. `:where(.field__hint, .field__error) + .field__hint`
 *    is a literal substring of the neutraliser's own selector, so an unanchored search finds the
 *    neutraliser and reports the wrong rule's position.
 */
function positionOf(selector: string): number {
  const at = Math.min(
    ...[`\n${selector} {`, `\n${selector},`]
      .map((form) => THEME_RULES_ONLY.indexOf(form))
      .filter((i) => i > -1),
  );
  expect(Number.isFinite(at), `rule not found in the sheet: ${selector}`).toBe(true);
  return at;
}

describe('field hint rhythm — structural guards', () => {
  it('parses the sources it is guarding, so a broken walk cannot pass vacuously', () => {
    expect(RULES.length).toBeGreaterThan(1000);
    // The bound that catches a walk which stops recognising hints and passes over nothing — the
    // `menuitemradio` lesson (docs/ui-spacing.md): a recogniser used as a filter cannot see what
    // it fails to recognise, so an empty sweep has to fail rather than pass.
    expect(HINT_RUNS.hints).toBeGreaterThanOrEqual(250);
    expect(HINT_RUNS.runs).toBeGreaterThanOrEqual(13);
    expect(HINT_RUNS.holderClasses.size).toBeGreaterThanOrEqual(6);
  });

  it('gives a hint that follows another hint a real gap, at the frozen step', () => {
    const rule = RULES.find((r) =>
      selectorList(r).some((s) => (HINT_RUN_SELECTORS as readonly string[]).includes(s)),
    );
    expect(
      rule && selectorList(rule).sort(),
      'The hint-run rule is gone. Without it `.field__hint { margin: 0 }` wins its (0,1,0) tie ' +
        'with every container rhythm on source order and consecutive hints render at 0px — the ' +
        'diagnostics intro and the language card’s notes, measured touching.',
    ).toEqual([...HINT_RUN_SELECTORS]);
    expect(marginTop(rule?.body ?? '')).toBe(HINT_RUN_VALUE);
  });

  it('keeps the predecessor at zero specificity and the subject at one class', () => {
    // This is the whole mechanism. `:is(...)` on both sides would be (0,2,0) and would beat
    // `.settings-rows > * + *`, dropping two settings surfaces from 0.9rem to 0.5rem. `:where()`
    // on the SUBJECT would be (0,0,0) and lose to `.field__hint`'s own zero, making it inert.
    for (const selector of HINT_RUN_SELECTORS) {
      expect(selector).toMatch(/^:where\(\.field__hint, \.field__error\) \+ \.[\w-]+$/u);
      expect(subjectOf(selector)).not.toMatch(/:where|:is/u);
    }
  });

  it('never matches a hint that follows a CONTROL, which is a different relationship', () => {
    // A hint under its `Toggle` is a caption, and `ff0a5f6c`'s preservation-package row wants it
    // tight. The predecessor list is what keeps that true by construction: widen it to `*` and
    // the row goes 0px → 8px. Measured unchanged at 0px.
    for (const selector of HINT_RUN_SELECTORS) {
      const predecessor = /^:where\(([^)]*)\)/u.exec(selector)?.[1] ?? '';
      expect(
        predecessor
          .split(',')
          .map((s) => s.trim())
          .sort(),
        'The hint run must be spaced only after ANOTHER hint. A `*` or a control in this list ' +
          'turns the rule into the `:where()` pin that Pass 3 was deferred for.',
      ).toEqual(HINT_CLASSES.map((c) => `.${c}`).sort());
    }
  });

  it('orders the hint run BELOW the zero it has to outrank', () => {
    // Both are (0,1,0), so source order alone decides. Move this rule above `.field__hint` and the
    // fix silently reverts to 0px with nothing else in the sheet changing.
    expect(positionOf(HINT_RUN_SELECTORS[1] as string)).toBeGreaterThan(positionOf('.field__hint'));
    expect(positionOf(HINT_RUN_SELECTORS[1] as string)).toBeGreaterThan(
      positionOf('.field__error'),
    );
  });

  it('orders the hint run ABOVE the container that is meant to keep its own band', () => {
    // Same tie, opposite direction, and this is the half that would go unnoticed: at (0,1,0) the
    // hint run loses to `.settings-rows > * + *` only because that rule is declared later. Measured
    // 14.39px there, before and after. Move the hint run below it and two settings surfaces drop
    // from the 0.9rem row band to 0.5rem while keeping the hairline that band draws.
    expect(positionOf(HINT_RUN_SELECTORS[1] as string)).toBeLessThan(
      positionOf('.settings-rows > * + *'),
    );
  });

  it('neutralises the hint run in `.modal__body`, where a margin ADDS to the gap', () => {
    const rule = RULES.find((r) =>
      selectorList(r).some((s) =>
        (HINT_RUN_NEUTRALISER_SELECTORS as readonly string[]).includes(s),
      ),
    );
    expect(
      rule && selectorList(rule).sort(),
      'On a `gap` container a child’s margin adds to the gap instead of competing in the cascade, ' +
        'and `:where(.modal__body) > *` is (0,0,0) so it cannot outrank the hint run. Measured ' +
        'without this: a dialog’s hint run at 21.59px against the 13.59px every other child uses.',
    ).toEqual([...HINT_RUN_NEUTRALISER_SELECTORS]);
    expect(neutralisedHintHosts(RULES)).toEqual(new Set(['field', 'modal__body']));
    expect(
      marginTop(rule?.body ?? ''),
      '`0`, not `revert`. The subject here is always a hint, whose own rule zeroes the UA’s ' +
        '`margin-block: 1em` on purpose — `revert` would hand a `<p>` back 16px and make the ' +
        'double-gap worse, which is the opposite of what the boxed primitives’ neutraliser needs.',
    ).toBe('0');
    expect(positionOf(HINT_RUN_NEUTRALISER_SELECTORS[1] as string)).toBeGreaterThan(
      positionOf(HINT_RUN_SELECTORS[1] as string),
    );
  });

  it('covers every gap container that actually holds a hint run', () => {
    const byClass = singleClassRules(RULES);
    const covered = neutralisedHintHosts(RULES);
    const uncovered = [...HINT_RUNS.holderClasses]
      .filter((c) => gapOf(byClass.get(c) ?? '') !== undefined)
      .filter((c) => !covered.has(c))
      .sort();
    expect(
      uncovered,
      'A hint run has landed in a `gap` container that does not neutralise it, so the run’s ' +
        '0.5rem now ADDS to that container’s gap instead of replacing nothing. Neutralise it ' +
        'beside `.modal__body`, or move the run out of the gap container.',
    ).toEqual([]);
    expect(covered).toContain('modal__body');
    // Not a hypothetical entry: `ServerEnvSection` really does put a run inside a `Field`.
    expect([...HINT_RUNS.holderClasses]).toContain('field');
    expect(covered).toContain('field');
  });

  it('does not let a surface patch a hint’s margin for itself', () => {
    const patches = hintMarginRules(RULES).filter(
      (s) =>
        !(HINT_RUN_SELECTORS as readonly string[]).includes(s) &&
        !(HINT_RUN_NEUTRALISER_SELECTORS as readonly string[]).includes(s),
    );
    expect(
      patches,
      'This inventory is frozen. Every entry in it is a DIFFERENT relationship from a hint run — ' +
        'the primitive’s own zero, a caption under a switch, a hint after a `<dl>` — which is why ' +
        'the hint-run rule supersedes none of them. A new entry is a per-surface repair: it buys ' +
        'one screen, and at its specificity it also shadows the shared rule on that screen.',
    ).toEqual([...KNOWN_HINT_MARGIN_RULES].sort());
  });
});

describe('field hint rhythm — the guards go red without the fix', () => {
  /** The real sheet with the fix taken back out, one way at a time. Comments first: the sheet
   *  quotes these selectors in prose, and a `replace` over the raw text would edit the prose and
   *  prove nothing. Each edit asserts it changed something, so a drifted selector fails here. */
  function withoutFix(edit: (css: string) => string): string {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    const edited = edit(bare);
    expect(edited).not.toBe(bare);
    return edited;
  }

  const HINT_RUN_BLOCK =
    /:where\(\.field__hint, \.field__error\) \+ \.field__hint,\n:where\(\.field__hint, \.field__error\) \+ \.field__error \{[^}]*\}/u;

  it('reports the hint-run rule being deleted', () => {
    const reverted = parseRules(withoutFix((css) => css.replace(HINT_RUN_BLOCK, '')));
    expect(
      reverted.filter((r) =>
        selectorList(r).some((s) => (HINT_RUN_SELECTORS as readonly string[]).includes(s)),
      ),
    ).toEqual([]);
  });

  it('reports the rule being pinned to `:where()`, which would make it inert', () => {
    const reverted = parseRules(
      withoutFix((css) =>
        css.replace(
          HINT_RUN_BLOCK,
          ':where(.field__hint, .field__error) + :where(.field__hint),\n' +
            ':where(.field__hint, .field__error) + :where(.field__error) { margin-top: 0.5rem; }',
        ),
      ),
    );
    const found = reverted.flatMap((r) =>
      selectorList(r).filter((s) => (HINT_RUN_SELECTORS as readonly string[]).includes(s)),
    );
    expect(found).toEqual([]);
    // …and the shape assertion catches it directly, at the subject.
    expect(subjectOf(':where(.field__hint, .field__error) + :where(.field__hint)')).toMatch(
      /:where/u,
    );
  });

  it('reports the predecessor being widened to every element', () => {
    // `* + .field__hint` is the naive version, and it is the one that breaks the caption case:
    // the preservation-package row's hint would go 0px → 8px under its `Toggle`.
    const widened = ':where(*) + .field__hint';
    const predecessor = /^:where\(([^)]*)\)/u.exec(widened)?.[1] ?? '';
    expect(predecessor.split(',').map((s) => s.trim())).not.toEqual(
      HINT_CLASSES.map((c) => `.${c}`),
    );
  });

  /** Where the hint-run block starts in an arbitrary sheet. Its first selector is followed by a
   *  comma, never by ` {`, and it is a substring of the neutraliser's — hence the line anchor. */
  const runAt = (css: string): number =>
    css.indexOf('\n:where(.field__hint, .field__error) + .field__hint,');

  it('reports the rule being moved above the zero it has to outrank', () => {
    const moved = withoutFix((css) => {
      const block = HINT_RUN_BLOCK.exec(css)?.[0] ?? '';
      expect(block).not.toBe('');
      return css.replace(block, '').replace('.field__hint {', `${block}\n.field__hint {`);
    });
    expect(runAt(moved)).toBeGreaterThan(-1);
    expect(runAt(moved)).toBeLessThan(moved.indexOf('.field__hint {'));
    // …against the real sheet, where it is below and therefore wins the tie.
    expect(runAt(THEME_RULES_ONLY)).toBeGreaterThan(THEME_RULES_ONLY.indexOf('.field__hint {'));
  });

  it('reports the rule being moved below the container that must keep its own band', () => {
    const moved = withoutFix((css) => {
      const block = HINT_RUN_BLOCK.exec(css)?.[0] ?? '';
      expect(block).not.toBe('');
      // Appended at the very end, which is unambiguously below `.settings-rows > * + *`.
      return `${css.replace(block, '')}\n${block}\n`;
    });
    // The failure: it now sits BELOW `.settings-rows > * + *` and wins the tie there, dropping
    // two settings surfaces from the 0.9rem row band to 0.5rem while keeping the hairline.
    expect(runAt(moved)).toBeGreaterThan(moved.indexOf('.field__hint {'));
    expect(runAt(moved)).toBeGreaterThan(moved.indexOf('.settings-rows > * + * {'));
    // …against the real sheet, where it is above and therefore loses.
    expect(runAt(THEME_RULES_ONLY)).toBeLessThan(
      THEME_RULES_ONLY.indexOf('.settings-rows > * + * {'),
    );
  });

  it('reports the gap-container neutraliser being deleted', () => {
    const reverted = parseRules(
      withoutFix((css) =>
        css.replace(
          /:where\(\.field, \.modal__body\) > :where\(\.field__hint, \.field__error\) \+ \.field__hint,\n:where\(\.field, \.modal__body\) > :where\(\.field__hint, \.field__error\) \+ \.field__error \{[^}]*\}/u,
          '',
        ),
      ),
    );
    expect([...neutralisedHintHosts(reverted)]).toEqual([]);
  });

  it('reports a neutraliser that says `revert` instead of `0`', () => {
    const wrong = parseRules(
      ':where(.modal__body) > :where(.field__hint, .field__error) + .field__hint { margin-top: revert; }',
    );
    expect([...neutralisedHintHosts(wrong)]).toEqual([]);
    const right = parseRules(
      ':where(.modal__body) > :where(.field__hint, .field__error) + .field__hint { margin-top: 0; }',
    );
    expect([...neutralisedHintHosts(right)]).toEqual(['modal__body']);
  });

  it('reports a gap container that acquires a hint run with no neutraliser', () => {
    const byClass = singleClassRules(RULES);
    // `.modal__body` is a real gap container that is covered today. Drop it from the neutraliser
    // and hand the sweep a run in one, and it must be reported rather than silently double-spaced.
    expect(gapOf(byClass.get('modal__body') ?? '')).toBe('0.85rem');
    const holders = new Set([...HINT_RUNS.holderClasses, 'modal__body']);
    const covered = new Set([...neutralisedHintHosts(RULES)].filter((c) => c !== 'modal__body'));
    expect(
      [...holders].filter((c) => gapOf(byClass.get(c) ?? '') !== undefined && !covered.has(c)),
    ).toEqual(['modal__body']);
  });

  it('recognises a gap container only when it has BOTH a flex/grid display and a gap', () => {
    expect(gapOf('display: flex; flex-direction: column; gap: 0.35rem;')).toBe('0.35rem');
    expect(gapOf('display: grid; row-gap: 1rem;')).toBe('1rem');
    expect(gapOf('gap: 1rem;')).toBeUndefined(); // `gap` alone does nothing in normal flow
    expect(gapOf('display: flex;')).toBeUndefined();
    expect(gapOf('column-gap: 1rem; display: flex;')).toBeUndefined(); // inline axis only
  });

  it('reports a per-surface hint margin, including inside a media query', () => {
    const patched = parseRules(
      `${THEME}\n.some-page .field__hint { margin-top: 1.25rem; }\n` +
        '@media (max-width: 620px) {\n  .other-page .field__error { margin-block-start: 0.4rem; }\n}\n',
    );
    const patches = hintMarginRules(patched).filter(
      (s) =>
        !(HINT_RUN_SELECTORS as readonly string[]).includes(s) &&
        !(HINT_RUN_NEUTRALISER_SELECTORS as readonly string[]).includes(s),
    );
    expect(patches).toContain('.some-page .field__hint');
    expect(patches).toContain('.other-page .field__error');
    expect(patches).not.toEqual([...KNOWN_HINT_MARGIN_RULES].sort());
  });

  it('reads the subject off the last compound, not off anywhere in the selector', () => {
    // A rule whose subject is a BUTTON after a hint is a third relationship again, and must not be
    // counted as a hint patch — `ff0a5f6c`'s kept `* + .btn` is exactly that.
    expect(targetsHint('.book-export-table .stack--tight > * + .btn')).toBe(false);
    expect(targetsHint('.field__hint + .btn')).toBe(false);
    expect(targetsHint('.signing-evidence .field__hint')).toBe(true);
    expect(targetsHint('.settings-rows > .toggle + .field__hint')).toBe(true);
    expect(targetsHint(':where(.field__hint, .field__error) + .field__error')).toBe(true);
  });

  it('splits a selector list on top-level commas only', () => {
    expect(
      selectorList({
        selector:
          ':where(.field__hint, .field__error) + .field__hint,\n:where(.field__hint, .field__error) + .field__error',
        body: '',
      }),
    ).toEqual([...HINT_RUN_SELECTORS].reverse());
  });

  it('finds a hint run through a fragment and through a conditional child', () => {
    const scanned = scanHintRuns({
      '../features/x/Frag.tsx':
        'const A = () => (<td><><p className="field__hint">a</p><p className="field__hint">b</p></></td>);',
      '../features/x/Cond.tsx':
        'const B = () => (<div className="stack--tight"><p className="field__hint">a</p>{n ? (<p className={over ? "field__error" : "field__hint"}>b</p>) : null}</div>);',
      '../features/x/None.tsx':
        'const C = () => (<div className="stack--tight"><p className="field__hint">a</p><button className="btn">b</button></div>);',
    });
    expect(scanned.runs).toBe(2);
    expect(scanned.hints).toBe(5);
    // The fragment's run is attributed to the `<td>` that encloses it, not lost with the fragment.
    expect([...scanned.holderClasses].sort()).toEqual(['stack--tight']);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanHintRuns({});
    expect(empty.runs).toBe(0);
    expect(empty.hints).toBe(0);
    expect(empty.holderClasses.size).toBe(0);
    expect(empty.runs).toBeLessThan(13);
  });
});
