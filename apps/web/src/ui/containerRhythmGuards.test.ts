/**
 * Structural guards on container vertical rhythm (t89, Pass 2 landed).
 *
 * ## What this protects
 *
 * `.panel__body` and `.card` own padding, and now also own their child spacing. Before Pass 2 they
 * did not, so the gap between a card's children was a property of which TAG each child happened to
 * be: a `<p>` brought the user agent's own `margin-block: 1em` and looked right by accident, a
 * `<div>` — which is every action row — brought nothing. 156 of the app's 262 `<Card>`s do not wrap
 * their children in a rhythm owner, and 68 of those have more than one child, so the gap was
 * visibly wrong on all of them. See `docs/ui-spacing.md` for the full diagnosis and the numbers.
 *
 * The recurrence mechanism was the sprawl of per-surface repairs: each one bought exactly one
 * screen, and each one outranked the shared rule at higher specificity — so a global fix would have
 * applied everywhere EXCEPT the screens people had already complained about. Pass 2 added the
 * shared rule AND retired every patch it supersedes; these guards keep both halves true. They
 * assert:
 *
 *  1. the shared container rhythm **exists**, at `:where()` zero specificity, on both containers,
 *     at a frozen value — deleting or rescoping it fails here;
 *  2. the inventory of surface-scoped patches reaching container children is **frozen at empty**,
 *     so a fifth surface patch fails at test time instead of quietly shadowing the shared rule;
 *  3. the set of distinct rhythm values is **frozen**, so nobody invents a ninth.
 *
 * ## Why source analysis rather than a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting a card and
 * reading a child's margin passes whether or not any rule exists. The last section proves each
 * predicate goes red by running it against copies of the real sources with the fix removed — the
 * same shape as `bannerMarginGuards.test.ts`, for the same reason.
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

/**
 * Split a selector list on its TOP-LEVEL commas only.
 *
 * A naive `split(',')` tears `:where(.panel__body, .card) > * + *` in half and hands the
 * predicates below two selectors that appear nowhere in the sheet — which is how a zero-specificity
 * shared rule would read as a surface patch. Depth tracking is the whole fix; the sheet's other
 * comma-carrying functional selectors (`:where(input:not(…), textarea, …)`) were being shredded the
 * same way and simply happened not to declare anything these predicates look at.
 */
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

/** A spacing declaration on the rule — the properties that create vertical rhythm. */
function declaresSpacing(body: string): boolean {
  return /(^|[;{\s])(margin|margin-top|margin-bottom|margin-block|margin-block-start|gap|row-gap)\s*:/u.test(
    body,
  );
}

function rhythmValue(body: string): string | undefined {
  const m =
    /(?:^|[;{\s])margin-top\s*:\s*([^;]+);/u.exec(body) ??
    /(?:^|[;{\s])margin-block-start\s*:\s*([^;]+);/u.exec(body);
  return m?.[1]?.trim();
}

/** Selectors that reach INTO a `.panel__body`/`.card` (a descendant or child of it). */
function reachesContainerChildren(selector: string): boolean {
  if (!/\.panel__body(?![\w-])|\.card(?![\w-])/u.test(selector)) return false;
  // The container's own rule (`.panel__body { padding }`) is not reaching into anything; a
  // selector only reaches children if something follows the container in the compound chain.
  return /\.(?:panel__body|card)(?![\w-])[^,]*[\s>+~]/u.test(selector);
}

/**
 * The shared container rhythm itself — the two selectors Pass 2 added, and nothing else.
 *
 * Deliberately exact rather than a prefix test: `:where(.panel__body) .some-page > * + *` also
 * starts with a zero-specificity container, but it is a surface patch wearing the shared rule's
 * clothes, and it must fall through to {@link surfacePatches}.
 */
const SHARED_CONTAINER_RHYTHM =
  /^:where\(\s*\.(?:panel__body|card)(?:\s*,\s*\.(?:panel__body|card))*\s*\)\s*>\s*\*(?:\s*\+\s*\*)?$/u;

/** The container rhythm's step. One of {@link KNOWN_RHYTHM_VALUES}, and `.form > * + *`'s band. */
const CONTAINER_RHYTHM_VALUE = '1rem';

function isSharedContainerRhythm(selector: string): boolean {
  return SHARED_CONTAINER_RHYTHM.test(selector);
}

/**
 * Every surface-scoped rule that gives (or removes) spacing on a container's children.
 *
 * This is the per-surface-patch family, and it is FROZEN AT EMPTY. Pass 2 retired all three that
 * existed — `.email-card .panel__body > * + *` and the two
 * `.external-signing-workflows .panel__body > …` resets — because the shared rule does the same
 * job for all 262 cards. A new entry means someone has repaired one screen and left the other 155,
 * at a specificity that also shadows the shared rule on precisely that screen.
 */
const KNOWN_SURFACE_PATCHES: readonly string[] = [];

function surfacePatches(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter(
        (selector) =>
          reachesContainerChildren(selector) &&
          !isSharedContainerRhythm(selector) &&
          declaresSpacing(rule.body),
      ),
    )
    .sort();
}

/**
 * Every shared rhythm owner (`… > * + *`) and the step it sets.
 *
 * FROZEN as a value SET, not as a list: reusing any existing step is free, inventing a ninth is
 * what this catches. There is no `--space` scale to appeal to (the token exists and is referenced
 * five times in the whole sheet), so the existing steps are the de facto scale.
 */
const KNOWN_RHYTHM_VALUES = [
  '0',
  '0.5rem',
  '0.55rem',
  '0.75rem',
  '0.8rem',
  '1.5rem',
  '1rem',
  'var(--settings-row-gap)',
] as const;

function rhythmOwners(rules: CssRule[]): { selector: string; value: string | undefined }[] {
  return rules.flatMap((rule) =>
    selectorList(rule)
      .filter((selector) => /(?:^|[\s>])[^,]*>\s*\*\s*\+\s*\*/u.test(selector))
      .map((selector) => ({ selector, value: rhythmValue(rule.body) })),
  );
}

/**
 * ## The `.modal__body` family — the same defect, the opposite mechanism
 *
 * `.modal__body` is `display: flex; flex-direction: column; gap: 0.85rem`, so unlike
 * `.panel__body` it DOES own its child spacing. That inverts the failure mode: a child's own
 * block margin does not compete with the container in the cascade, it **adds** to the gap. So a
 * `:where()` rule cannot fix it the way it fixes a card, and a per-surface margin does not merely
 * shadow the shared rhythm — it silently doubles it.
 *
 * Measured across all eight dialogs before the fix, `.modal__body` produced SIX different child
 * gaps: 13.6px (the intended one), 19.98px above every button row (`.modal__foot`'s own
 * `margin-top`), 25.6px and 37.6px in the two dialogs that put a `.stack`/`.stack--tight` on the
 * body itself, 29.59px above an `InlineWarning` (the banner primitive's standalone margin), and
 * 34.38px under a `<p>` intro carrying the UA's own margins.
 *
 * Two invariants, therefore, and neither is expressible as a selector sweep: the offending rules
 * (`.modal__foot { margin-top }`) never mention `.modal__body` at all. Both work from the AST
 * instead — the set of classes actually used as a modal body's children.
 */
const MODAL_BODY_CLASS = 'modal__body';

/** Block-axis margin values a declaration block sets, normalised. `[]` when it sets none. */
function blockMargins(body: string): string[] {
  const out: string[] = [];
  const shorthand = /(?:^|[;{\s])margin\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
  if (shorthand) {
    const parts = shorthand.split(/\s+/u);
    // `margin: a` / `a b` / `a b c` / `a b c d` — block axis is the 1st and (3rd ?? 1st).
    out.push(parts[0] as string, (parts[2] ?? parts[0]) as string);
  }
  const block = /(?:^|[;{\s])margin-block\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
  if (block) {
    const parts = block.split(/\s+/u);
    out.push(parts[0] as string, (parts[1] ?? parts[0]) as string);
  }
  for (const prop of ['margin-top', 'margin-bottom', 'margin-block-start', 'margin-block-end']) {
    const m = new RegExp(`(?:^|[;{\\s])${prop}\\s*:\\s*([^;]+);`, 'u').exec(body)?.[1]?.trim();
    if (m) out.push(m);
  }
  return out;
}

/** Does this rule put a NON-ZERO block margin on whatever it matches? `margin: 0` is fine. */
function addsBlockMargin(body: string): boolean {
  return blockMargins(body).some((v) => v !== '0' && v !== '0px' && v !== '0rem');
}

/** Single-class rules, by class name, so a child class can be looked up. */
function singleClassRules(rules: CssRule[]): Map<string, string> {
  const byClass = new Map<string, string>();
  for (const rule of rules) {
    for (const selector of selectorList(rule)) {
      const m = /^\.([\w-]+)$/u.exec(selector);
      if (m?.[1]) byClass.set(m[1], (byClass.get(m[1]) ?? '') + rule.body);
    }
  }
  return byClass;
}

/**
 * Every `.modal__body` in the app: the extra classes on the body itself, and the classes of the
 * direct children it renders — including those inside `{cond ? <X/> : null}`, which are direct
 * children in the DOM too.
 */
function scanModalBodies(sources: Record<string, string>): {
  bodies: number;
  withExtraRhythm: string[];
  childClasses: Set<string>;
} {
  let bodies = 0;
  const withExtraRhythm: string[] = [];
  const childClasses = new Set<string>();
  const classOf = (node: ts.JsxElement | ts.JsxSelfClosingElement): string => {
    const attrs = ts.isJsxElement(node) ? node.openingElement.attributes : node.attributes;
    const attr = attrs.properties.find(
      (p): p is ts.JsxAttribute =>
        ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === 'className',
    );
    const init = attr?.initializer;
    return init && ts.isStringLiteral(init) ? init.text : '';
  };
  for (const [file, source] of Object.entries(sources)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxElement(node)) {
        const classes = classOf(node).split(/\s+/u).filter(Boolean);
        if (classes.includes(MODAL_BODY_CLASS)) {
          bodies += 1;
          for (const c of classes) {
            if (c !== MODAL_BODY_CLASS && /^(?:stack|stack--tight|form)$/u.test(c)) {
              withExtraRhythm.push(`${file}: .${c}`);
            }
          }
          const kids: (ts.JsxElement | ts.JsxSelfClosingElement)[] = [];
          const collect = (n: ts.Node): void => {
            if (ts.isJsxElement(n) || ts.isJsxSelfClosingElement(n)) {
              kids.push(n);
              return;
            }
            ts.forEachChild(n, collect);
          };
          for (const child of node.children) {
            if (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child)) kids.push(child);
            else if (ts.isJsxExpression(child) && child.expression) collect(child.expression);
          }
          for (const kid of kids) {
            for (const c of classOf(kid).split(/\s+/u).filter(Boolean)) childClasses.add(c);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { bodies, withExtraRhythm, childClasses };
}

/** `<Card>` elements, and whether each wraps its children in a single rhythm-owning child. */
function scanCards(sources: Record<string, string>): {
  cards: number;
  unwrapped: number;
  files: number;
} {
  let cards = 0;
  let unwrapped = 0;
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
    const visit = (node: ts.Node): void => {
      if (ts.isJsxElement(node)) {
        const tag = node.openingElement.tagName;
        if (ts.isIdentifier(tag) && tag.text === 'Card') {
          cards += 1;
          const elementKids = node.children.filter(
            (c): c is ts.JsxElement | ts.JsxSelfClosingElement =>
              ts.isJsxElement(c) || ts.isJsxSelfClosingElement(c),
          );
          let wrapped = false;
          const only = elementKids.length === 1 ? elementKids[0] : undefined;
          if (only && ts.isJsxElement(only)) {
            const attr = only.openingElement.attributes.properties.find(
              (p): p is ts.JsxAttribute =>
                ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === 'className',
            );
            const init = attr?.initializer;
            const text = init && ts.isStringLiteral(init) ? init.text : '';
            if (/\b(?:stack|stack--tight|form)\b/u.test(text)) wrapped = true;
          }
          if (!wrapped) unwrapped += 1;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
  }
  return { cards, unwrapped, files };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const CARDS = scanCards(PRODUCTION_SOURCES);
const MODALS = scanModalBodies(PRODUCTION_SOURCES);

let THEME = '';
let RULES: CssRule[] = [];

beforeAll(async () => {
  THEME = await readTheme();
  RULES = parseRules(THEME);
});

describe('container vertical rhythm — structural guards', () => {
  it('parses the sources it is guarding, so a broken walk cannot pass vacuously', () => {
    expect(RULES.length).toBeGreaterThan(1000);
    expect(rhythmOwners(RULES).length).toBeGreaterThan(10);
    expect(CARDS.files).toBeGreaterThan(150);
    expect(CARDS.cards).toBeGreaterThan(200);
    // The bound that catches a walk which stops recognising modal bodies and passes over nothing.
    expect(MODALS.bodies).toBeGreaterThanOrEqual(8);
    expect(MODALS.childClasses.size).toBeGreaterThanOrEqual(10);
  });

  it('does not let a new surface patch the container rhythm for itself', () => {
    expect(
      surfacePatches(RULES),
      'A surface-scoped rule that spaces a `.panel__body`/`.card`’s children repairs exactly one ' +
        'screen and leaves the other 155, and at its own specificity it also outranks the shared ' +
        'rule — so the global fix would apply everywhere EXCEPT the screens people already ' +
        'complained about. That is the mechanism behind three separate spacing complaints; see ' +
        'docs/ui-spacing.md. If a card needs breathing room, wrap its children in ' +
        '`.stack`/`.stack--tight`, or change the shared rule for everyone.',
    ).toEqual([...KNOWN_SURFACE_PATCHES].sort());
  });

  it('does not let a surface invent a new vertical rhythm value', () => {
    const values = new Set(
      rhythmOwners(RULES)
        .map((o) => o.value)
        .filter((v): v is string => v !== undefined),
    );
    const invented = [...values].filter(
      (v) => !(KNOWN_RHYTHM_VALUES as readonly string[]).includes(v),
    );
    expect(
      invented,
      'There is no spacing scale to appeal to (`--space` exists and is referenced five times in ' +
        'the whole sheet), so these eight steps ARE the de facto scale. Reusing any of them is ' +
        'free; adding a ninth is how twelve separate rhythm rules ended up at seven different ' +
        'values. Pick an existing step, or change the shared rule.',
    ).toEqual([]);
  });

  it('keeps the shared container rhythm, on both containers, at the frozen step', () => {
    const owner = rhythmOwners(RULES).filter((o) => isSharedContainerRhythm(o.selector));
    expect(
      owner.map((o) => o.selector),
      'The shared container rhythm is gone, or no longer covers both containers. It is the whole ' +
        'of Pass 2 (docs/ui-spacing.md): 156 of 262 cards do not wrap their children in a ' +
        '`.stack`/`.form`, so without it the gap between a card’s children is decided by which ' +
        'TAG each child happens to be. Do not replace it with a per-surface patch.',
    ).toEqual([':where(.panel__body, .card) > * + *']);
    expect(
      owner[0]?.value,
      'The container rhythm’s step moved. 1rem is the value every per-surface patch of this same ' +
        'defect already used (`.settings-notes`, `.email-card .panel__body > * + *`, ' +
        '`:where(.inline-warning)`) and it is `.form > * + *`’s band, so a card of loose children ' +
        'reads like one whose children sit in a form.',
    ).toBe(CONTAINER_RHYTHM_VALUE);
  });

  it('keeps the companion rule that collapses the container’s outer edge', () => {
    // Two declarations, because collapsing the outer edge and spacing siblings are different jobs:
    // without this one a `<p>` first child lands its UA `margin-block: 1em` INSIDE the container's
    // padding and blows the box out — the banner defect (2a538e87), one level up.
    const collapse = RULES.filter((rule) =>
      selectorList(rule).some((s) => isSharedContainerRhythm(s) && !/\+/u.test(s)),
    );
    expect(collapse.map((r) => selectorList(r))).toEqual([[':where(.panel__body, .card) > *']]);
    expect(collapse[0]?.body).toMatch(/margin-top:\s*0;/u);
    expect(collapse[0]?.body).toMatch(/margin-bottom:\s*0;/u);
  });

  it('keeps `.modal__body` a gap container with its child margins neutralised', () => {
    const body = RULES.find((r) => selectorList(r).includes(`.${MODAL_BODY_CLASS}`))?.body ?? '';
    expect(
      body,
      '`.modal__body` stopped being a gap container. Everything below assumes `gap` owns the ' +
        'rhythm — without it, zeroing the children’s margins leaves every dialog flush.',
    ).toMatch(/gap:\s*0\.85rem;/u);

    const reset = RULES.filter((r) =>
      selectorList(r).some((s) => /^:where\(\.modal__body\)\s*>\s*\*$/u.test(s)),
    );
    expect(
      reset.map((r) => selectorList(r)),
      'The zero-specificity reset is what stops a child’s own margin ADDING to the gap — the UA ' +
        'margins on a `<p>` intro (measured 34.38px against a 13.6px baseline) and the banner ' +
        'primitive’s standalone `margin-top` (29.59px).',
    ).toEqual([[':where(.modal__body) > *']]);
    expect(reset[0]?.body).toMatch(/margin-block:\s*0;/u);
  });

  it('orders the modal reset after the banner primitive, which it has to outrank', () => {
    // Both are (0,0,0), so this is decided by source order alone and by nothing else. If the
    // banner rule ever moves below this one, `InlineWarning`s in dialogs silently regain 1rem
    // on top of the gap. Measured: 29.59px before the reset, 13.59px after.
    const banner = THEME.indexOf(':where(.inline-warning) {');
    const reset = THEME.indexOf(':where(.modal__body) > * {');
    expect(banner).toBeGreaterThan(-1);
    expect(reset).toBeGreaterThan(-1);
    expect(reset).toBeGreaterThan(banner);
  });

  it('does not let a modal child bring a margin that adds to the gap', () => {
    const byClass = singleClassRules(RULES);
    const offenders = [...MODALS.childClasses]
      .filter((c) => addsBlockMargin(byClass.get(c) ?? ''))
      .sort();
    expect(
      offenders,
      'On a flex container with `gap`, a child’s block margin ADDS to the gap instead of ' +
        'competing with it, so this cannot be fixed by specificity and the `:where()` reset ' +
        'cannot reach it either — the rule does not mention `.modal__body`. This is how ' +
        '`.modal__foot { margin-top: 0.4rem }` put every dialog’s button row 19.98px from its ' +
        'content while everything else sat at 13.6px. Let the gap own it.',
    ).toEqual([]);
  });

  it('does not let a modal body stack a second rhythm on top of its own gap', () => {
    expect(
      MODALS.withExtraRhythm,
      'A `.stack`/`.stack--tight`/`.form` on the same element as `.modal__body` does not replace ' +
        'the body’s `gap`, it ADDS to it — measured 37.6px and 25.6px against the 13.6px every ' +
        'other dialog uses. The body already owns the rhythm.',
    ).toEqual([]);
  });

  it('keeps every rhythm owner a card can opt into above the shared rule', () => {
    // `:where()` is the entire override story, and it only works while the opt-in helpers stay at
    // (0,1,0). A card that asks for `.stack` must keep 1.5rem, not silently collapse to the shared
    // 1rem — so these three have to remain single-class rules with their own steps.
    const owners = new Map(rhythmOwners(RULES).map((o) => [o.selector, o.value]));
    expect(owners.get('.stack > * + *')).toBe('1.5rem');
    expect(owners.get('.stack--tight > * + *')).toBe('0.75rem');
    expect(owners.get('.form > * + *')).toBe('1rem');
  });
});

describe('container vertical rhythm — the guards go red without the fix', () => {
  it('reports a new per-surface container patch', () => {
    const patched = parseRules(
      `${THEME}\n.some-page .panel__body > * + * {\n  margin-top: 1rem;\n}\n`,
    );
    expect(surfacePatches(patched)).toContain('.some-page .panel__body > * + *');
    expect(surfacePatches(patched)).not.toEqual([...KNOWN_SURFACE_PATCHES].sort());
  });

  it('reports a scoped container patch hidden inside a media query', () => {
    const patched = parseRules(
      `${THEME}\n@media (max-width: 620px) {\n  .some-page .card > * + * { margin-top: 0; }\n}\n`,
    );
    expect(surfacePatches(patched)).toContain('.some-page .card > * + *');
  });

  it('does not mistake a container’s own rule for reaching into its children', () => {
    // `.panel__body { padding }` and `.card { padding }` are the containers describing themselves.
    expect(reachesContainerChildren('.panel__body')).toBe(false);
    expect(reachesContainerChildren('.card')).toBe(false);
    expect(reachesContainerChildren('.card__label')).toBe(false);
    expect(reachesContainerChildren('.email-card .panel__body > * + *')).toBe(true);
  });

  it('reports an invented ninth rhythm value', () => {
    const patched = parseRules(`${THEME}\n.some-block > * + * {\n  margin-top: 1.37rem;\n}\n`);
    const values = new Set(
      rhythmOwners(patched)
        .map((o) => o.value)
        .filter((v): v is string => v !== undefined),
    );
    const invented = [...values].filter(
      (v) => !(KNOWN_RHYTHM_VALUES as readonly string[]).includes(v),
    );
    expect(invented).toEqual(['1.37rem']);
  });

  /**
   * The real sheet with the fix taken back out, one way at a time.
   *
   * Comments go first, deliberately: the sheet documents the shared rule by quoting its selector,
   * and a `replace` over the raw text would edit the prose instead of the rule and prove nothing.
   * Each edit asserts it actually changed something, so a selector that drifts turns these red
   * rather than silently reverting them to no-ops.
   */
  function withoutFix(edit: (css: string) => string): CssRule[] {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    const edited = edit(bare);
    expect(edited).not.toBe(bare);
    return parseRules(edited);
  }

  it('reports the shared container rhythm being deleted', () => {
    const reverted = withoutFix((css) =>
      css.replace(/:where\(\.panel__body, \.card\) > \* \+ \* \{[^}]*\}/u, ''),
    );
    expect(rhythmOwners(reverted).filter((o) => isSharedContainerRhythm(o.selector))).toEqual([]);
  });

  it('reports the shared container rhythm being rescoped away from `.card`', () => {
    const narrowed = withoutFix((css) =>
      css.replace(/:where\(\.panel__body, \.card\)/gu, ':where(.panel__body)'),
    );
    const owner = rhythmOwners(narrowed).filter((o) => isSharedContainerRhythm(o.selector));
    expect(owner.map((o) => o.selector)).not.toEqual([':where(.panel__body, .card) > * + *']);
  });

  it('reports the outer-edge companion being deleted', () => {
    const reverted = withoutFix((css) =>
      css.replace(/:where\(\.panel__body, \.card\) > \* \{[^}]*\}/u, ''),
    );
    const collapse = reverted.filter((rule) =>
      selectorList(rule).some((s) => isSharedContainerRhythm(s) && !/\+/u.test(s)),
    );
    expect(collapse).toEqual([]);
  });

  it('reports the shared rule losing its `:where()`, which would outrank `.stack`', () => {
    // (0,1,0) instead of (0,0,0) TIES `.stack > * + *` and wins on source order, so every card
    // that opted into a rhythm would silently collapse to the shared step. It must read as a
    // surface patch, not as the shared rule.
    const specific = withoutFix((css) =>
      css.replace(/:where\(\.panel__body, \.card\) > \* \+ \*/u, '.panel__body > * + *'),
    );
    expect(surfacePatches(specific)).toContain('.panel__body > * + *');
    expect(surfacePatches(specific)).not.toEqual([...KNOWN_SURFACE_PATCHES].sort());
  });

  it('does not mistake a surface patch dressed in `:where()` for the shared rule', () => {
    expect(isSharedContainerRhythm(':where(.panel__body, .card) > *')).toBe(true);
    expect(isSharedContainerRhythm(':where(.panel__body, .card) > * + *')).toBe(true);
    expect(isSharedContainerRhythm(':where(.panel__body) .some-page > * + *')).toBe(false);
    expect(isSharedContainerRhythm(':where(.panel__body) > .some-block + *')).toBe(false);
    expect(isSharedContainerRhythm('.some-page :where(.panel__body) > * + *')).toBe(false);
  });

  it('splits a selector list on top-level commas only', () => {
    // A naive `split(',')` yields `:where(.panel__body` and `.card) > * + *`, neither of which is
    // the shared rule — so the shared rule reads as two surface patches and the guard inverts.
    expect(selectorList({ selector: ':where(.panel__body, .card) > * + *', body: '' })).toEqual([
      ':where(.panel__body, .card) > * + *',
    ]);
    expect(selectorList({ selector: '.a, .b', body: '' })).toEqual(['.a', '.b']);
    expect(selectorList({ selector: 'a[href*=","], .b', body: '' })).toEqual([
      'a[href*=","]',
      '.b',
    ]);
  });

  it('reports a modal child that brings a margin, and ignores a zeroing one', () => {
    // `.modal__foot`'s own rule, exactly as it was — the regression this predicate exists for.
    const byClass = singleClassRules(
      parseRules(
        '.modal__foot { display: flex; gap: 0.6rem; margin-top: 0.4rem; }\n' +
          '.modal__note { display: flex; margin: 0; }\n',
      ),
    );
    expect(addsBlockMargin(byClass.get('modal__foot') ?? '')).toBe(true);
    expect(addsBlockMargin(byClass.get('modal__note') ?? '')).toBe(false);
  });

  it('reads the block axis out of every margin spelling', () => {
    // A shorthand hides the block axis behind its position, and the inline axis must not trip it.
    expect(addsBlockMargin('margin: 0;')).toBe(false);
    expect(addsBlockMargin('margin: 0 auto;')).toBe(false);
    expect(addsBlockMargin('margin: 0 0 0 1rem;')).toBe(false);
    expect(addsBlockMargin('margin: 0.4rem 0 0;')).toBe(true);
    expect(addsBlockMargin('margin: 0 0 1rem;')).toBe(true);
    expect(addsBlockMargin('margin-block: 0;')).toBe(false);
    expect(addsBlockMargin('margin-block: 0 1rem;')).toBe(true);
    expect(addsBlockMargin('margin-bottom: 2px;')).toBe(true);
    expect(addsBlockMargin('padding-top: 1rem;')).toBe(false);
  });

  it('reports the modal reset being deleted, and a body stacking a second rhythm', () => {
    const reverted = withoutFix((css) =>
      css.replace(/:where\(\.modal__body\) > \* \{[^}]*\}/u, ''),
    );
    expect(
      reverted.filter((r) =>
        selectorList(r).some((s) => /^:where\(\.modal__body\)\s*>\s*\*$/u.test(s)),
      ),
    ).toEqual([]);

    const stacked = scanModalBodies({
      '../features/x/Dlg.tsx': '<div className="modal__body stack--tight"><p /></div>;',
    });
    expect(stacked.bodies).toBe(1);
    expect(stacked.withExtraRhythm).toEqual(['../features/x/Dlg.tsx: .stack--tight']);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanCards({});
    expect(empty.cards).toBe(0);
    expect(empty.files).toBe(0);
    expect(parseRules('')).toEqual([]);
    const noModals = scanModalBodies({});
    expect(noModals.bodies).toBe(0);
    expect(noModals.childClasses.size).toBe(0);
  });
});
