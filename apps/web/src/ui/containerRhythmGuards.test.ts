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

/**
 * ## The boxed-primitive family — `.inline-warning` and `.table-wrap` (Pass 4)
 *
 * The third instance of the container-rhythm defect, and the one the operator reported globally:
 * *"table and banners with alerts dont have global neat margins and such theyre glued to
 * everything or anything that comes next and before."*
 *
 * Measured in Chromium against the real sheet, before the fix: `.table-wrap` declared NO margin at
 * all, and `:where(.inline-warning)` declared a `margin-top` and nothing for its bottom edge. So
 * both boxes were spaced only when they happened to be the DIRECT child of a container that owns a
 * rhythm. Wrapped one level down — a plain `<div>`, a bare `<section>`, a `<details>`, or a bespoke
 * surface class — a table read **0px** above and below; a banner followed by a `<div>` action row
 * read **0px** below; a table followed by an `EmptyState` read **0px**.
 *
 * Three invariants, and the second is the interesting one:
 *
 *  1. both primitives own an outer rhythm at `:where()` zero specificity, at the frozen step;
 *  2. **neither may declare a block-END margin.** Adjacent siblings' margins collapse to the MAX,
 *     and collapsing does not consult specificity — so a `margin-bottom` on the primitive cannot be
 *     outranked by a container the way a `margin-top` can, and would silently raise every band
 *     tighter than 1rem (`.stack--tight`'s 0.75rem under 62 call sites). The bottom edge is
 *     therefore expressed as the NEXT SIBLING's `margin-top`, which a container rhythm does outrank;
 *  3. every gap container that holds one of the primitives neutralises that sibling rule, because
 *     on a `gap` container a child margin ADDS instead of competing — the `.modal__body` mechanism,
 *     which now has five more instances.
 */
const PRIMITIVE_CLASSES = ['inline-warning', 'table-wrap'] as const;
const PRIMITIVE_TAGS = ['Table', 'InlineWarning'] as const;

/** The step both primitives use, and the container rhythm's own. Not a ninth value. */
const PRIMITIVE_RHYTHM_VALUE = '1rem';

/** `display: flex|grid` **and** a `gap` — the containers where a child margin adds. */
function gapOf(body: string): string | undefined {
  if (!/display:\s*(?:inline-)?(?:flex|grid)/u.test(body)) return undefined;
  return /(?:^|[;{\s])(?:gap|row-gap)\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
}

/** Block-END margin only — the axis a container cannot outrank. */
function addsBlockEndMargin(body: string): boolean {
  const out: string[] = [];
  const shorthand = /(?:^|[;{\s])margin\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
  if (shorthand) {
    const parts = shorthand.split(/\s+/u);
    out.push((parts[2] ?? parts[0]) as string);
  }
  const block = /(?:^|[;{\s])margin-block\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
  if (block) {
    const parts = block.split(/\s+/u);
    out.push((parts[1] ?? parts[0]) as string);
  }
  for (const prop of ['margin-bottom', 'margin-block-end']) {
    const m = new RegExp(`(?:^|[;{\\s])${prop}\\s*:\\s*([^;]+);`, 'u').exec(body)?.[1]?.trim();
    if (m) out.push(m);
  }
  return out.some((v) => v !== '0' && v !== '0px' && v !== '0rem');
}

/** Is this selector's SUBJECT (its last compound) one of the primitives itself? */
function targetsPrimitive(selector: string): boolean {
  const subject =
    selector
      .split(/[\s>+~]+/u)
      .filter(Boolean)
      .pop() ?? '';
  return PRIMITIVE_CLASSES.some((c) => new RegExp(`\\.${c}(?![\\w-])`, 'u').test(subject));
}

/**
 * Every class that hosts a primitive as a DIRECT child, and every class a caller passes to
 * `<Table>` (which lands on `.table-wrap` itself, so a margin rule on it patches the primitive).
 *
 * Enumerated by walking the tree rather than by grepping class names: the population has to be
 * found by what the markup DOES, or a container that acquires its first banner tomorrow silently
 * drops out of the sweep instead of failing it — the `menuitemradio` lesson, restated.
 */
function scanPrimitiveHosts(sources: Record<string, string>): {
  primitives: number;
  hostClasses: Set<string>;
  tableClasses: Set<string>;
} {
  let primitives = 0;
  const hostClasses = new Set<string>();
  const tableClasses = new Set<string>();
  const classesOf = (node: ts.JsxElement | ts.JsxSelfClosingElement): string[] => {
    const attrs = ts.isJsxElement(node) ? node.openingElement.attributes : node.attributes;
    const attr = attrs.properties.find(
      (p): p is ts.JsxAttribute =>
        ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === 'className',
    );
    const init = attr?.initializer;
    return init && ts.isStringLiteral(init) ? init.text.split(/\s+/u).filter(Boolean) : [];
  };
  const tagOf = (node: ts.JsxElement | ts.JsxSelfClosingElement): string =>
    (ts.isJsxElement(node) ? node.openingElement.tagName : node.tagName).getText();

  for (const [file, source] of Object.entries(sources)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
        const classes = classesOf(node);
        const tag = tagOf(node);
        // The primitive by component name, OR hand-rolled markup wearing its class (3 in the app).
        const isPrimitive =
          (PRIMITIVE_TAGS as readonly string[]).includes(tag) ||
          classes.some((c) => (PRIMITIVE_CLASSES as readonly string[]).includes(c));
        if (isPrimitive) {
          primitives += 1;
          if (tag === 'Table') for (const c of classes) tableClasses.add(c);
          let parent: ts.Node | undefined = node.parent;
          while (parent && !ts.isJsxElement(parent)) parent = parent.parent;
          if (parent && ts.isJsxElement(parent))
            for (const c of classesOf(parent)) hostClasses.add(c);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { primitives, hostClasses, tableClasses };
}

/**
 * ## The wide-pane measure family — the same defect on the horizontal axis
 *
 * `WIDE_SUBSECTIONS` (SettingsPage.tsx) lifts five panes past the 1080px reading measure because
 * each holds a six- or seven-column grid that scrolls sideways at the normal measure. Its own
 * comment records the counter-case in the same breath: sibling panes were kept OUT of the list
 * because widening hurt them — *"Política de assinatura is label/control rows (measured 78ch →
 * 126ch when widened)"*.
 *
 * That comment has the principle right and could only apply it at whole-pane granularity. A pane
 * holding BOTH a grid and label/control rows had to choose, and choosing width dragged the prose
 * out with it. Measured at 1920px on all five panes, before the fix: prose 166–171ch, control rows
 * 128ch, banners 132ch — against 117–122ch / 90ch / 94ch for the identical markup on a
 * normal-width page. Reported twice by the operator, on the two panes they happened to be looking
 * at, which is the per-surface recurrence pattern in the horizontal axis.
 *
 * Three shared rules beside `.app:has(.wide-page)` cap prose, the label/control grid, and the
 * control itself, all at `calc(var(--app-measure) - 2 * var(--app-gutter))` — the expression
 * `.page-header` is already pinned to, so the target is "the width this would have had on a
 * normal page" rather than a number somebody picked. These guards freeze that:
 *
 *  1. all three exist, at `:where()` zero specificity, anchored to the shared token — a re-typed
 *     literal fails, because it stops tracking if the measure ever moves;
 *  2. the per-pane width-override inventory is **frozen at empty**, so the sixth pane cannot
 *     repair itself at a specificity that also shadows the shared rules;
 *  3. no rule caps `.table-wrap` inside a wide pane — that would restore the sideways scroll the
 *     widening exists to prevent, trading this defect for the one before it.
 */
const WIDE_MEASURE_EXPR = 'calc(var(--app-measure) - 2 * var(--app-gutter))';

/** Content that must be held to the reading measure inside a wide pane. */
const MEASURED_CONTENT = [
  'field',
  'field__hint',
  'field__error',
  'control',
  'input-reset',
  'settings-rows',
  'inline-warning',
] as const;

/** The three shared caps, exactly. Anything else touching the family is a per-pane patch. */
const SHARED_WIDE_CAPS: readonly string[] = [
  ':where(.wide-page) :where(.control, .input-reset)',
  ':where(.wide-page) :where(.field, .field__hint, .field__error, .inline-warning, p)',
  ':where(.wide-page) :where(.settings-rows):not(:has(.table-wrap))',
];

/**
 * Per-pane width overrides on the measured-content family.
 *
 * FROZEN AT EMPTY. An entry means one pane has been repaired and the other four left — and at a
 * plain-class specificity that also outranks the shared rules on exactly that pane, so the next
 * global fix would apply everywhere EXCEPT the screen someone complained about. That is the
 * mechanism this whole file exists to prevent, restated for the horizontal axis.
 */
const KNOWN_WIDE_PANE_PATCHES: readonly string[] = [];

function declaresMaxInline(body: string): boolean {
  return /(?:^|[;{\s])max-(?:inline-size|width)\s*:/u.test(body);
}

function maxInlineValue(body: string): string | undefined {
  return /(?:^|[;{\s])max-(?:inline-size|width)\s*:\s*([^;]+);/u.exec(body)?.[1]?.trim();
}

/** Does this selector's subject belong to the measured-content family? */
function targetsMeasuredContent(selector: string): boolean {
  const subject =
    selector
      .split(/[\s>+~]+/u)
      .filter(Boolean)
      .pop() ?? '';
  return MEASURED_CONTENT.some((c) => new RegExp(`\\.${c}(?![\\w-])`, 'u').test(subject));
}

/**
 * Root classes of the wide panes that have one, so a patch written without the `.wide-page`
 * marker is still caught.
 *
 * `signing:tsl`, `signing:tsa` and `signing:providers` are deliberately absent: their content is
 * a generic `.settings-rows` inside a `Card` with no root class of its own, so there is nothing
 * to enumerate. They are covered by the `.wide-page` marker alone, and a patch reaching them
 * without naming it would have to be written against `.settings-rows` — which is not a per-pane
 * patch at all but a change to every settings tab in the app, and a different review.
 */
const WIDE_PANE_ROOTS = ['search-admin-panel', 'template-preview-samples'] as const;

/** Is this selector scoped to a wide pane at all? Filter bars and toolbars are not. */
function scopedToWidePane(selector: string): boolean {
  if (/\.wide-page(?![\w-])/u.test(selector)) return true;
  return WIDE_PANE_ROOTS.some((c) => new RegExp(`\\.${c}(?![\\w-])`, 'u').test(selector));
}

/**
 * Per-pane width overrides on the measured-content family, INSIDE a wide pane.
 *
 * The scope is load-bearing. An unscoped sweep reports 20-odd pre-existing rules —
 * `.users-filters .control`, `.privacy-filterbar__primary .field`, `.templates-filters .field` —
 * which are filter toolbars sizing their own inputs. That is a different, legitimate thing, and a
 * guard that demanded they be removed would be demanding a regression to satisfy a predicate.
 */
function widePanePatches(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter(
        (selector) =>
          scopedToWidePane(selector) &&
          targetsMeasuredContent(selector) &&
          declaresMaxInline(rule.body) &&
          !SHARED_WIDE_CAPS.includes(selector),
      ),
    )
    .sort();
}

/**
 * Remove balanced `:not(…)` / `:has(…)` groups, so what is left is what the rule actually MATCHES.
 *
 * Load-bearing for {@link cappedGrids}: the container cap's own selector ends
 * `:not(:has(.table-wrap))`, which mentions `.table-wrap` in order to *exclude* it. Testing the
 * raw selector reports the one rule whose entire purpose is to avoid the regression.
 */
function stripConditionals(selector: string): string {
  let out = selector;
  for (;;) {
    const m = /:(?:not|has)\(/u.exec(out);
    if (!m) return out;
    const start = m.index;
    let depth = 0;
    let end = -1;
    for (let i = start; i < out.length; i += 1) {
      if (out[i] === '(') depth += 1;
      else if (out[i] === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end === -1) return out;
    out = `${out.slice(0, start)}${out.slice(end + 1)}`;
  }
}

/** Rules that would cap a grid wrapper inside a wide pane — the regression, not the fix. */
function cappedGrids(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter((selector) => {
        const matched = stripConditionals(selector);
        const subject =
          matched
            .split(/[\s>+~]+/u)
            .filter(Boolean)
            .pop() ?? '';
        return (
          /\.wide-page(?![\w-])/u.test(matched) &&
          /\.table-wrap(?![\w-])/u.test(subject) &&
          declaresMaxInline(rule.body)
        );
      }),
    )
    .sort();
}

/**
 * Gap containers that hold a primitive as a direct child, where the sibling rule must be a no-op.
 *
 * FROZEN. A seventh entry means a container that owns its children's spacing through `gap` has
 * acquired a banner or a table, and the sibling rule is now ADDING to that gap instead of being
 * outranked by it — the `.modal__foot` failure, 19.98px against a 13.6px baseline. Add it to the
 * neutraliser beside the primitives rather than patching the surface.
 */
const NEUTRALISED_GAP_HOSTS: readonly string[] = [
  // `display: grid; gap: 0.8rem`, and it holds HAND-ROLLED `.table-wrap` markup rather than a
  // `<Table>` — which is why a by-hand sweep of the two component tags missed it and this walk
  // did not. Left in place as the standing argument for enumerating by what the markup does.
  'chronology-analytics',
  'field',
  'modal__body',
  'onboarding__body',
  'pdf-validator-report',
  'signin__form',
  'signing-provider-list',
];

/**
 * Classes passed to `<Table>` — they land on `.table-wrap` itself — that declare a block margin.
 *
 * FROZEN at one, and that one is KEPT rather than retired. `.data-status-table { margin-top:
 * 0.1rem }` is not a repair of a missing gap: it is a deliberate TIGHTENING that pins each storage
 * table to its own `.data-status-section__head` (measured 1.59px, and 12.8px without it), the same
 * shape as `.data-status-section > * + *`'s deliberately tighter nested band — which
 * docs/ui-spacing.md already corrected itself about once. A NEW entry is the other thing: a surface
 * repairing its own table at (0,1,0) and shadowing the shared rule exactly where it is needed.
 */
const KNOWN_PRIMITIVE_MARGIN_PATCHES: readonly string[] = ['data-status-table'];

/** Gap containers that actually hold a primitive today, derived from the tree, not from a list. */
function gapHostsHoldingAPrimitive(rules: CssRule[], hosts: Set<string>): string[] {
  const byClass = singleClassRules(rules);
  return [...hosts].filter((c) => gapOf(byClass.get(c) ?? '') !== undefined).sort();
}

/**
 * Gap containers the sheet actually neutralises — and only those neutralised on BOTH edges.
 *
 * A container covered for the successor's margin but not for the primitive's own is still
 * double-spaced above the box; a half-neutralised container must not read as covered.
 */
function neutralisedGapHosts(rules: CssRule[]): Set<string> {
  const own = new Set<string>();
  const successor = new Set<string>();
  const hostsIn = (list: string): string[] =>
    list
      .split(',')
      .map((part) => /^\s*\.([\w-]+)\s*$/u.exec(part)?.[1])
      .filter((c): c is string => c !== undefined);
  for (const rule of rules) {
    for (const selector of selectorList(rule)) {
      // (a) the shared neutraliser beside the primitives, in its two forms.
      const shared = /^:where\(([^)]*)\)\s*>\s*:where\([^)]*\)(\s*\+\s*\*)?$/u.exec(selector);
      if (shared && /margin-top:\s*revert;/u.test(rule.body)) {
        const into = shared[2] === undefined ? own : successor;
        for (const cls of hostsIn(shared[1] as string)) into.add(cls);
      }
      // (b) a container that neutralises ALL its children's block margins — `.modal__body`.
      const blanket = /^:where\(\.([\w-]+)\)\s*>\s*\*$/u.exec(selector);
      if (blanket?.[1] && /margin-block:\s*0;/u.test(rule.body)) {
        own.add(blanket[1]);
        successor.add(blanket[1]);
      }
    }
  }
  return new Set([...own].filter((c) => successor.has(c)));
}

/** Rules whose SUBJECT is a primitive and which give it a block-end margin. */
function primitiveBottomMargins(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter((s) => targetsPrimitive(s) && addsBlockEndMargin(rule.body)),
    )
    .sort();
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const CARDS = scanCards(PRODUCTION_SOURCES);
const MODALS = scanModalBodies(PRODUCTION_SOURCES);
const PRIMITIVES = scanPrimitiveHosts(PRODUCTION_SOURCES);

/**
 * EVERY stylesheet, not just `theme.css`.
 *
 * The per-pane width patch this file freezes at empty would not land in `theme.css` — it would
 * land in `SearchSettingsPanel.css` or `TemplatePreviewSamplesPanel.css`, next to the pane that
 * wanted it. A sweep that reads only the shared sheet would freeze an inventory it cannot see.
 *
 * Read through `node:fs`, NOT `import.meta.glob(…, { query: '?raw' })`. Measured: the glob
 * resolves the paths but Vite's CSS pipeline claims the modules first, so every value comes back
 * as the empty string — the sweep finds three stylesheets, parses zero rules out of them, and
 * passes vacuously. The `readTheme` indirection below is the idiom that actually works here.
 */
async function readStylesheets(): Promise<Record<string, string>> {
  const nodeFs = 'node:fs';
  const { readFileSync, readdirSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
    readdirSync(
      path: string,
      opts: { withFileTypes: true },
    ): { name: string; isDirectory(): boolean }[];
  };
  const out: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}/${entry.name}`;
      if (entry.isDirectory()) walk(path);
      else if (path.endsWith('.css'))
        out[path] = readFileSync(path, 'utf8').replace(/\r\n/gu, '\n');
    }
  };
  walk('src');
  return out;
}

let THEME = '';
let RULES: CssRule[] = [];
let STYLESHEETS: Record<string, string> = {};
let ALL_RULES: CssRule[] = [];

beforeAll(async () => {
  THEME = await readTheme();
  RULES = parseRules(THEME);
  STYLESHEETS = await readStylesheets();
  ALL_RULES = Object.values(STYLESHEETS).flatMap((css) => parseRules(css));
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
    // Same bound for the boxed primitives. A recogniser used as a filter cannot see what it fails
    // to recognise, so an empty or shrunken sweep must fail here rather than pass over nothing —
    // `menuItemGuards.test.ts`’s `menuitemradio` lesson, restated (docs/ui-spacing.md).
    expect(PRIMITIVES.primitives).toBeGreaterThanOrEqual(200);
    expect(PRIMITIVES.hostClasses.size).toBeGreaterThanOrEqual(30);
    expect(PRIMITIVES.tableClasses.size).toBeGreaterThanOrEqual(10);
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

  it('keeps both boxed primitives owning their outer rhythm at zero specificity', () => {
    const own = RULES.filter((r) => selectorList(r).includes(':where(.table-wrap)'));
    expect(
      own.map((r) => rhythmValue(r.body)),
      '`.table-wrap` owned NO margin at all, so a table was spaced only when it happened to be ' +
        'the direct child of a rhythm owner. Wrapped in a plain `<div>`, a `<section>`, a ' +
        '`<details>` or a bespoke surface class it measured 0px above AND below. The wrappers ' +
        'have no name to hang a container rule on, so the primitive’s own margin is the only ' +
        'lever that reaches them — see docs/ui-spacing.md.',
    ).toEqual([PRIMITIVE_RHYTHM_VALUE]);

    // Flush against the container's own padding when nothing precedes it, exactly as the banner.
    const firstChild = RULES.filter((r) =>
      selectorList(r).includes(':where(.table-wrap:first-child)'),
    );
    expect(firstChild.map((r) => rhythmValue(r.body))).toEqual(['0']);
    expect(
      THEME.indexOf(':where(.inline-warning:first-child)'),
      'The banner’s own `:first-child` guard is the precedent this copies; if it is gone the two ' +
        'primitives no longer behave alike.',
    ).toBeGreaterThan(-1);
  });

  it('sets the primitives’ bottom edge on the NEXT SIBLING, never as a margin-bottom', () => {
    const sibling = RULES.filter((r) =>
      selectorList(r).includes(':where(.inline-warning, .table-wrap) + *'),
    );
    expect(
      sibling.map((r) => rhythmValue(r.body)),
      'The rule that gives a banner or a table a gap to what FOLLOWS it is gone. Without it, ' +
        'both boxes sit flush against the next `<div>` — measured 0px for a banner then an ' +
        'action row, a table then an action row, and a table then an `EmptyState`. That is the ' +
        'reported defect ("glued to anything that comes next").',
    ).toEqual([PRIMITIVE_RHYTHM_VALUE]);

    expect(
      primitiveBottomMargins(RULES),
      'A block-END margin on either primitive cannot be outranked. Adjacent siblings’ margins ' +
        'COLLAPSE TO THE MAX, and collapsing is a layout rule that never consults specificity — ' +
        'so `margin-bottom: 1rem` here would beat every container band tighter than 1rem, ' +
        'silently raising `.stack--tight`’s 0.75rem under all 62 banners and tables it holds and ' +
        '`.data-status-section`’s deliberately tighter 0.8rem. `:where()` does not help. Express ' +
        'the bottom edge as the next sibling’s `margin-top`, where specificity does decide.',
    ).toEqual([]);
  });

  it('neutralises the sibling rule in exactly the gap containers that hold a primitive', () => {
    const hosts = gapHostsHoldingAPrimitive(RULES, PRIMITIVES.hostClasses);
    expect(
      hosts,
      'A gap container has gained (or lost) a banner or a table. On a `gap` container a child ' +
        'margin ADDS to the gap instead of competing with it, so the sibling rule has to be a ' +
        'no-op there — this is the `.modal__body` mechanism with five more instances. Add the ' +
        'container to the neutraliser beside the primitives, and to this list.',
    ).toEqual([...NEUTRALISED_GAP_HOSTS].sort());

    const covered = neutralisedGapHosts(RULES);
    expect(
      hosts.filter((c) => !covered.has(c)),
      'These gap containers hold a primitive and nothing neutralises the sibling rule for them, ' +
        'so the gap and the margin now ADD. Measured without the neutraliser: `.signin__form` ' +
        '14.25px → 30.09px, `.pdf-validator-report` 16px → 32px.',
    ).toEqual([]);
  });

  it('neutralises BOTH edges in a gap container, not just the successor', () => {
    // A container covered only for the successor is still double-spaced ABOVE the box: the
    // primitive's own `margin-top` adds to the gap exactly as `.modal__foot`'s did.
    const halfCovered = parseRules(
      ':where(.x) > :where(.inline-warning, .table-wrap) + * { margin-top: revert; }',
    );
    expect([...neutralisedGapHosts(halfCovered)]).toEqual([]);
    const bothEdges = parseRules(
      ':where(.x) > :where(.inline-warning, .table-wrap),\n' +
        ':where(.x) > :where(.inline-warning, .table-wrap) + * { margin-top: revert; }',
    );
    expect([...neutralisedGapHosts(bothEdges)]).toEqual(['x']);
  });

  it('reverts rather than zeroes in a gap container, so nothing else is stripped', () => {
    // `margin-top: 0` is an author declaration and therefore also beats the USER AGENT's. Measured
    // regression: a `<p class="signing-provider-list__note">` after a banner collapsed 27.39px →
    // 10.39px, because its own UA `margin-block: 1em` was zeroed along with our rule. `revert`
    // undoes only the author layer, so these five containers render exactly as they did before.
    const neutraliser = RULES.filter((r) =>
      selectorList(r).some((s) =>
        /^:where\([^)]*\)\s*>\s*:where\(\.inline-warning, \.table-wrap\)\s*\+\s*\*$/u.test(s),
      ),
    );
    expect(neutraliser).toHaveLength(1);
    expect(neutraliser[0]?.body).toMatch(/margin-top:\s*revert;/u);
    expect(neutraliser[0]?.body).not.toMatch(/margin-top:\s*0/u);
    // Both edges live in the one rule, so the `revert` covers the box's own margin as well.
    expect(selectorList(neutraliser[0] as CssRule)).toHaveLength(2);
  });

  it('orders both primitive rules above the modal reset, which has to outrank them', () => {
    // Every one of these is (0,0,0), so source order alone decides. If either primitive rule ever
    // moves below the modal reset, dialogs silently regain a margin on top of their `gap`.
    const reset = THEME.indexOf(':where(.modal__body) > * {');
    expect(THEME.indexOf(':where(.table-wrap) {')).toBeGreaterThan(-1);
    expect(THEME.indexOf(':where(.table-wrap) {')).toBeLessThan(reset);
    expect(THEME.indexOf(':where(.inline-warning, .table-wrap) + * {')).toBeLessThan(reset);
    // …and the neutraliser must sit below the rule it neutralises, for the same reason.
    expect(THEME.indexOf('margin-top: revert;')).toBeGreaterThan(
      THEME.indexOf(':where(.inline-warning, .table-wrap) + * {'),
    );
  });

  it('does not let a surface give its own table a margin the shared rule cannot outrank', () => {
    const byClass = singleClassRules(RULES);
    const patched = [...PRIMITIVES.tableClasses]
      .filter((c) => declaresSpacing(byClass.get(c) ?? ''))
      .sort();
    expect(
      patched,
      'A class passed to `<Table>` lands on `.table-wrap` itself, so a margin on it is (0,1,0) ' +
        'and outranks the shared `:where(.table-wrap)` rule on exactly that surface — the ' +
        'recurrence mechanism docs/ui-spacing.md names. The one registered entry is a deliberate ' +
        'TIGHTENING and is kept; a new one almost certainly is not.',
    ).toEqual([...KNOWN_PRIMITIVE_MARGIN_PATCHES].sort());
  });

  it('keeps the three shared wide-pane caps, anchored to the reading-measure token', () => {
    const caps = ALL_RULES.filter((r) => selectorList(r).some((s) => SHARED_WIDE_CAPS.includes(s)));
    expect(
      caps.flatMap((r) => selectorList(r)).sort(),
      'A wide pane means "the GRID in here needs room", not "everything in here should be 128ch". ' +
        'Without these, prose measured 166–171ch and label/control rows 128ch on all five ' +
        '`WIDE_SUBSECTIONS` panes — the figure that pane list’s own comment already records as ' +
        'the broken one. See docs/ui-spacing.md.',
    ).toEqual([...SHARED_WIDE_CAPS].sort());

    for (const cap of caps) {
      expect(
        maxInlineValue(cap.body),
        'The cap stopped tracking the reading measure. It must stay ' +
          `\`${WIDE_MEASURE_EXPR}\` — the same expression \`.page-header\` is pinned to — so the ` +
          'target is by construction "the width this content has on a normal-width page". A ' +
          're-typed literal silently stops moving when `--app-measure` does.',
      ).toContain(WIDE_MEASURE_EXPR);
    }
  });

  it('does not let a wide pane cap its own prose or controls instead', () => {
    expect(
      widePanePatches(ALL_RULES),
      'A per-pane width override repairs one pane and leaves the other four, at a specificity ' +
        'that also outranks the shared caps on exactly that pane — so the next global fix would ' +
        'apply everywhere EXCEPT the screen someone complained about. That is this file’s whole ' +
        'subject, restated on the horizontal axis. Widen the shared rule, or wrap the content.',
    ).toEqual([...KNOWN_WIDE_PANE_PATCHES].sort());
  });

  it('never caps a grid inside a wide pane, which is what the pane is wide for', () => {
    expect(
      cappedGrids(ALL_RULES),
      'Capping `.table-wrap` inside a wide pane restores the sideways-scrolling six- and ' +
        'seven-column grids that `WIDE_SUBSECTIONS` was opened to fix — trading this defect for ' +
        'the one before it. The caps are deliberately scoped to prose and control rows only.',
    ).toEqual([]);
  });

  it('leaves the two panes whose grid shares the label/control container uncapped', () => {
    // `:not(:has(.table-wrap))` is load-bearing, not defensive. On `signing:tsl` and `signing:tsa`
    // the seven-column table is a `grid-column: 1 / -1` child of the SAME `.settings-rows` grid
    // that holds the fields, so capping that container would shrink the table too. Measured: the
    // row stays 128ch there on purpose, while its prose (166 → 122ch) and control (117 → 96ch)
    // still come back. A guard that demanded uniformity here would demand the regression.
    const container = ALL_RULES.filter((r) =>
      selectorList(r).some((s) => s.includes('.settings-rows') && s.includes('.wide-page')),
    );
    expect(container).toHaveLength(1);
    expect(selectorList(container[0] as CssRule)[0]).toContain(':not(:has(.table-wrap))');
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

  it('reports the primitives’ outer rhythm being deleted', () => {
    const reverted = withoutFix((css) =>
      css
        .replace(/:where\(\.table-wrap\) \{[^}]*\}/u, '')
        .replace(/:where\(\.inline-warning, \.table-wrap\) \+ \* \{[^}]*\}/u, ''),
    );
    expect(reverted.filter((r) => selectorList(r).includes(':where(.table-wrap)'))).toEqual([]);
    expect(
      reverted.filter((r) => selectorList(r).includes(':where(.inline-warning, .table-wrap) + *')),
    ).toEqual([]);
  });

  it('reports a block-end margin put back on either primitive', () => {
    // The regression this predicate exists for: it looks harmless and it is not outrankable.
    for (const patch of [
      ':where(.inline-warning) { margin-bottom: 1rem; }',
      '.table-wrap { margin-block: 1rem; }',
      '.acts-table .table-wrap { margin: 0 0 1rem; }',
    ]) {
      expect(primitiveBottomMargins(parseRules(patch))).toHaveLength(1);
    }
    // …and a block-START margin, which IS outrankable, must not trip it.
    expect(primitiveBottomMargins(parseRules(':where(.table-wrap) { margin-top: 1rem; }'))).toEqual(
      [],
    );
    expect(addsBlockEndMargin('margin: 1rem 0 0;')).toBe(false);
    expect(addsBlockEndMargin('margin: 1rem 0;')).toBe(true);
    expect(addsBlockEndMargin('margin-block: 1rem 0;')).toBe(false);
    expect(addsBlockEndMargin('margin-block: 0 1rem;')).toBe(true);
    expect(addsBlockEndMargin('padding-bottom: 1rem;')).toBe(false);
  });

  it('does not mistake a descendant of a primitive for the primitive itself', () => {
    // `.inline-warning__title { margin: 0 0 0.35rem }` is the TITLE's own bottom margin, inside the
    // box; it is not the box's outer edge and must not read as one.
    expect(targetsPrimitive('.inline-warning__title')).toBe(false);
    expect(targetsPrimitive(':where(.inline-warning__body) > * + *')).toBe(false);
    expect(targetsPrimitive(':where(.inline-warning)')).toBe(true);
    expect(targetsPrimitive('.acts-table .table-wrap')).toBe(true);
    expect(targetsPrimitive(':where(.inline-warning, .table-wrap) + *')).toBe(false);
  });

  it('reports a gap container that acquires a primitive with no neutraliser', () => {
    const hosts = gapHostsHoldingAPrimitive(RULES, new Set([...PRIMITIVES.hostClasses, 'toast']));
    expect(hosts).toContain('toast');
    expect(hosts.filter((c) => !neutralisedGapHosts(RULES).has(c))).toEqual(['toast']);
  });

  it('reports the neutraliser being deleted', () => {
    const reverted = withoutFix((css) =>
      css.replace(/:where\(\s*\.chronology-analytics,[\s\S]*?\+ \* \{[^}]*\}/u, ''),
    );
    const covered = neutralisedGapHosts(reverted);
    // `.modal__body` survives on its own `> *` reset; the other six lose their only cover.
    expect([...covered].sort()).toEqual(['modal__body']);
  });

  it('recognises both neutralising mechanisms, and neither without its declaration', () => {
    const shared =
      ':where(.a, .b) > :where(.inline-warning, .table-wrap),\n' +
      ':where(.a, .b) > :where(.inline-warning, .table-wrap) + * { margin-top: revert; }';
    expect([...neutralisedGapHosts(parseRules(shared))].sort()).toEqual(['a', 'b']);
    expect([...neutralisedGapHosts(parseRules(shared.replace(/revert/gu, '1rem')))].sort()).toEqual(
      [],
    );
    expect([...neutralisedGapHosts(parseRules(':where(.c) > * { margin-block: 0; }'))]).toEqual([
      'c',
    ]);
    expect([...neutralisedGapHosts(parseRules(':where(.c) > * { gap: 0; }'))]).toEqual([]);
  });

  it('recognises a gap container only when it has BOTH a flex/grid display and a gap', () => {
    expect(gapOf('display: flex; flex-direction: column; gap: 0.35rem;')).toBe('0.35rem');
    expect(gapOf('display: grid; row-gap: 1rem;')).toBe('1rem');
    expect(gapOf('gap: 1rem;')).toBeUndefined(); // `gap` alone does nothing in normal flow
    expect(gapOf('display: flex;')).toBeUndefined();
    expect(gapOf('column-gap: 1rem; display: flex;')).toBeUndefined(); // inline axis only
  });

  it('reports a per-pane width override, in a per-pane stylesheet', () => {
    // Where a real one would land: beside the pane that wanted it, not in `theme.css`.
    const patched = parseRules('.search-admin-panel .field { max-inline-size: 60rem; }');
    expect(widePanePatches(patched)).toEqual(['.search-admin-panel .field']);
    expect(
      widePanePatches(parseRules('.template-preview-samples .control { max-width: 40rem; }')),
    ).toEqual(['.template-preview-samples .control']);
    // …and the shared caps themselves must never read as patches.
    expect(widePanePatches(ALL_RULES)).toEqual([]);
  });

  it('reports the shared cap being re-typed as a literal', () => {
    const literal = withoutFix((css) =>
      css.replace(
        /:where\(\.wide-page\) :where\(\.field, [^{]*\{[^}]*\}/u,
        ':where(.wide-page) :where(.field, .field__hint) {\n  max-inline-size: 984px;\n}',
      ),
    );
    const cap = literal.find((r) =>
      selectorList(r).some((s) => s.startsWith(':where(.wide-page) :where(.field')),
    );
    expect(maxInlineValue(cap?.body ?? '')).not.toContain(WIDE_MEASURE_EXPR);
  });

  it('reports a grid capped inside a wide pane', () => {
    expect(cappedGrids(parseRules('.wide-page .table-wrap { max-inline-size: 60rem; }'))).toEqual([
      '.wide-page .table-wrap',
    ]);
    // A cap on a table cell is not the same thing and must stay legal — it is how a prose column
    // inside a grid is kept readable (`.template-preview-sample-table td { max-inline-size }`).
    expect(cappedGrids(parseRules('.wide-page .table td { max-inline-size: 38rem; }'))).toEqual([]);
    // …and a selector that names `.table-wrap` only to EXCLUDE it is the fix, not the regression.
    expect(
      stripConditionals(':where(.wide-page) :where(.settings-rows):not(:has(.table-wrap))'),
    ).toBe(':where(.wide-page) :where(.settings-rows)');
    expect(
      cappedGrids(
        parseRules(
          ':where(.wide-page) :where(.settings-rows):not(:has(.table-wrap)) { max-inline-size: 60rem; }',
        ),
      ),
    ).toEqual([]);
  });

  it('reads the measured-content family off the selector’s subject, not anywhere in it', () => {
    expect(targetsMeasuredContent('.some-pane .field')).toBe(true);
    expect(targetsMeasuredContent(':where(.wide-page) :where(.control, .input-reset)')).toBe(true);
    // The subject here is the TABLE, not the field that scopes it.
    expect(targetsMeasuredContent('.field .table-wrap')).toBe(false);
    expect(targetsMeasuredContent('.field__labelrow')).toBe(false);
  });

  it('sweeps every stylesheet, not only the shared one', () => {
    // A per-pane patch lands beside its pane. Freezing an inventory read only from `theme.css`
    // would freeze something the walk cannot see — vacuously green. The bound is what caught
    // `import.meta.glob(…, '?raw')` returning three empty strings for CSS.
    expect(Object.keys(STYLESHEETS).length).toBeGreaterThanOrEqual(4);
    expect(ALL_RULES.length).toBeGreaterThan(RULES.length);
    expect(Object.keys(STYLESHEETS)).toContain('src/theme.css');
    for (const [file, css] of Object.entries(STYLESHEETS)) {
      expect(css.length, `${file} read as empty`).toBeGreaterThan(0);
    }
  });

  it('does not report a filter toolbar sizing its own inputs', () => {
    // The unscoped version of this predicate reported ~20 of these. They are not wide-pane
    // content and removing them would be the regression, not the fix.
    const toolbars = parseRules(
      '.users-filters .control { max-inline-size: 18rem; }\n' +
        '.privacy-filterbar__primary .field { max-width: 20rem; }\n',
    );
    expect(widePanePatches(toolbars)).toEqual([]);
    expect(scopedToWidePane('.users-filters .control')).toBe(false);
    expect(scopedToWidePane('.wide-page .field')).toBe(true);
    expect(scopedToWidePane('.search-admin-panel .field')).toBe(true);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanCards({});
    expect(empty.cards).toBe(0);
    expect(empty.files).toBe(0);
    expect(parseRules('')).toEqual([]);
    const noModals = scanModalBodies({});
    expect(noModals.bodies).toBe(0);
    expect(noModals.childClasses.size).toBe(0);
    const noPrimitives = scanPrimitiveHosts({});
    expect(noPrimitives.primitives).toBe(0);
    expect(noPrimitives.hostClasses.size).toBe(0);
    expect(noPrimitives.tableClasses.size).toBe(0);
    // A file with a primitive but no walk into it would also pass over nothing: prove the walk
    // finds a host class through a conditional expression, which is where most banners live.
    const found = scanPrimitiveHosts({
      '../features/x/P.tsx': '<div className="signin__form">{ok ? <InlineWarning/> : null}</div>;',
    });
    expect(found.primitives).toBe(1);
    expect([...found.hostClasses]).toEqual(['signin__form']);
  });
});
