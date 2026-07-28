/**
 * Structural guards on container vertical rhythm (t89).
 *
 * ## What this protects, and what it deliberately does not
 *
 * `.panel__body` and `.card` own padding but declare no child-spacing rule. The gap between a
 * card's children is therefore a property of which TAG each child happens to be: a `<p>` brings the
 * user agent's own `margin-block: 1em` and looks right by accident, a `<div>` — which is every
 * action row — brings nothing. 156 of the app's 262 `<Card>`s do not wrap their children in a
 * rhythm owner, and 68 of those have more than one child, so the gap is visibly wrong today.
 * See `docs/ui-spacing.md` for the full diagnosis and the numbers.
 *
 * Fixing that (Pass 2) is a product decision, because it moves spacing on ~156 cards at once. It
 * may not happen. **These guards are therefore written against what is true today**, and their job
 * is to stop the sprawl growing while the decision is open — because the sprawl is the recurrence
 * mechanism. Every previous repair was a per-surface patch, each one bought exactly one screen, and
 * each one outranks the eventual shared rule at higher specificity.
 *
 * So this file does NOT assert that a container rhythm exists — that would be a guard that only
 * becomes meaningful after a decision that may not come, which is worse than no guard. It asserts:
 *
 *  1. the inventory of surface-scoped patches reaching container children is **frozen**;
 *  2. the set of distinct rhythm values is **frozen**, so nobody invents a ninth;
 *  3. the current absence of a container rhythm is stated explicitly, so landing Pass 2 is a
 *     deliberate one-line edit here rather than something that silently drifts past the guard.
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

function selectorList(rule: CssRule): string[] {
  return rule.selector
    .split(',')
    .map((s) => s.trim().replace(/\s+/gu, ' '))
    .filter(Boolean);
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
 * Every surface-scoped rule that gives (or removes) spacing on a container's children.
 *
 * This is the per-surface-patch family. It is FROZEN: the three below are the ones that exist, and
 * a fourth means someone has repaired one screen and left the other 155.
 */
const KNOWN_SURFACE_PATCHES = [
  // Adds the rhythm `.panel__body` does not provide — for one card.
  '.email-card .panel__body > * + *',
  // Removes stray margins from nested helpers — for one page.
  '.external-signing-workflows .panel__body > .stack--tight',
  '.external-signing-workflows .panel__body > .form',
] as const;

function surfacePatches(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule)
        .filter((selector) => reachesContainerChildren(selector) && declaresSpacing(rule.body))
        .map((selector) => selector),
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
  });

  it('does not let a new surface patch the container rhythm for itself', () => {
    expect(
      surfacePatches(RULES),
      'A surface-scoped rule that spaces a `.panel__body`/`.card`’s children repairs exactly one ' +
        'screen and leaves the other 155, and at its own specificity it will also outrank the ' +
        'shared rule if one is ever added — so the eventual global fix would apply everywhere ' +
        'EXCEPT the screens people already complained about. That is the mechanism behind three ' +
        'separate spacing complaints; see docs/ui-spacing.md. If a card needs breathing room, ' +
        'wrap its children in `.stack`/`.stack--tight`, or make the case for Pass 2.',
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

  it('states that no container rhythm exists yet, so Pass 2 cannot land silently', () => {
    // A characterisation assertion, not an endorsement: it records today's state so the guard is
    // meaningful now rather than only after a decision that may never come. When Pass 2 lands,
    // THIS is the one line that changes — flip it to expect the shared rule, and the two guards
    // above keep doing their job unchanged.
    const containerRhythm = rhythmOwners(RULES).filter((o) =>
      /^:where\(\.panel__body\)|^\.panel__body\b|^:where\(\.card\)|^\.card\b/u.test(o.selector),
    );
    expect(
      containerRhythm,
      'A container rhythm rule has appeared. That is Pass 2 (see docs/ui-spacing.md) and it is a ' +
        'product decision, not a drive-by: it moves spacing on ~156 cards. If it was approved, ' +
        'update this assertion to require the rule and retire the per-surface patches in ' +
        'KNOWN_SURFACE_PATCHES — they shadow it at higher specificity and would keep the ' +
        'complained-about screens on the old spacing.',
    ).toEqual([]);
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

  it('reports a container rhythm appearing, which is Pass 2 landing', () => {
    const passTwo = parseRules(
      `${THEME}\n:where(.panel__body) > * + * {\n  margin-top: 1rem;\n}\n`,
    );
    const containerRhythm = passTwo
      .flatMap(selectorList)
      .filter((s) => /^:where\(\.panel__body\)/u.test(s) && /\*\s*\+\s*\*/u.test(s));
    expect(containerRhythm).toHaveLength(1);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanCards({});
    expect(empty.cards).toBe(0);
    expect(empty.files).toBe(0);
    expect(parseRules('')).toEqual([]);
  });
});
