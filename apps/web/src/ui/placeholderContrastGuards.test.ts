/**
 * Structural guards on placeholder contrast (t101).
 *
 * ## The defect
 *
 * Nothing in this app declared a `::placeholder` colour, so every placeholder in it was drawn by
 * the user agent. Measured in headless Chromium against the real sheet, that came out as
 * `rgb(117, 117, 117)` in BOTH themes — **4.16:1** on the light field fill (`#f7f3ea`) and
 * **3.53:1** on the dark one (`#10241b`), against the 4.5:1 WCAG 1.4.3 asks of text. Identical on
 * inputs and textareas, because it was never a per-surface defect: it was `.control`-wide, and one
 * rule beside the primitive is the whole population.
 *
 * ## What these guards hold
 *
 *  1. `--field-placeholder` exists, is declared **once**, and is anchored to `--text-muted` rather
 *     than to a re-typed colour — a literal computes the same today and stops tracking the theme
 *     tomorrow, which is precisely how a two-theme token drifts into a one-theme token;
 *  2. `.control::placeholder` consumes it and pins `opacity: 1`, so a user agent that mutes
 *     placeholders cannot silently undo the measured ratio on an engine nobody measured on;
 *  3. the inventory of OTHER placeholder rules, across every stylesheet, is **frozen at empty** —
 *     the per-surface repair is the recurrence mechanism this guard family exists to stop;
 *  4. every element in the component tree that carries a `placeholder` is a `.control`, so the one
 *     rule really is the whole population, behind a non-vacuity bound;
 *  5. **the ratio itself**, computed from the sheet's own token values in both themes: ≥ 4.5:1
 *     against the field fill, and still clearly LIGHTER than entered text. A placeholder darkened
 *     until it reads as a filled value trades an accessibility defect for a usability one, so both
 *     ends are asserted, not just the floor.
 *
 * ## Why source analysis rather than a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`: mount an `<input>` and read
 * its `::placeholder` colour and you get the same answer whether or not the rule exists. So the
 * ratio is asserted from the token values in the sheet, which is where the decision is, and the
 * rendered figures those values produce were measured separately in Chromium (6.83:1 light /
 * 7.86:1 dark, against 14.7:1 for entered text) and are pinned below as the expected result of the
 * same arithmetic. The last section proves every predicate goes red against a mutated copy.
 */
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

async function readFile(path: string): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(path, 'utf8').replace(/\r\n/gu, '\n');
}

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
// The rule and its token
// ---------------------------------------------------------------------------------------------

const PLACEHOLDER_TOKEN = '--field-placeholder';
/** The token's value. NOT a colour: the existing "secondary text" decision, so both themes move
 *  together and neither can be updated without the other. */
const PLACEHOLDER_TOKEN_VALUE = 'var(--text-muted)';
const PLACEHOLDER_SELECTOR = '.control::placeholder';

/**
 * Every rule anywhere in the app that colours a placeholder, other than the shared one.
 *
 * FROZEN AT EMPTY. A surface that repairs its own field's placeholder repairs exactly that field
 * and, at a plain-class specificity, also shadows the shared rule on precisely the screen someone
 * complained about — the recurrence mechanism `docs/ui-spacing.md` was written about, restated for
 * colour. If a placeholder needs to look different, move the token.
 */
const KNOWN_PLACEHOLDER_PATCHES: readonly string[] = [];

function placeholderRules(rules: CssRule[]): string[] {
  return rules
    .flatMap((rule) =>
      selectorList(rule).filter(
        (selector) =>
          /::(?:-\w+-(?:input-)?)?placeholder\b/u.test(selector) && /color\s*:/u.test(rule.body),
      ),
    )
    .sort();
}

// ---------------------------------------------------------------------------------------------
// Token resolution and WCAG arithmetic
// ---------------------------------------------------------------------------------------------

/**
 * The four blocks that define the palette, and the two themes they add up to.
 *
 * `:root` carries light; the dark media query and the two `[data-theme]` blocks (the operator's
 * explicit override) restate it. All four are read, because a token that is only correct on the
 * media-query path is only correct for operators who never touched the appearance setting.
 */
const THEME_BLOCKS = {
  light: [':root', ":root[data-theme='light']"],
  dark: [':root', ":root[data-theme='dark']"],
} as const;

/** Custom-property declarations per selector, later declarations winning. */
function tokenTable(rules: CssRule[]): Map<string, Map<string, string>> {
  const out = new Map<string, Map<string, string>>();
  for (const rule of rules) {
    for (const selector of selectorList(rule)) {
      const table = out.get(selector) ?? new Map<string, string>();
      for (const m of rule.body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/gu)) {
        table.set(m[1] as string, (m[2] as string).trim());
      }
      out.set(selector, table);
    }
  }
  return out;
}

/** Resolve a token for one theme, following `var()` indirection as the cascade would. */
function resolveToken(
  table: Map<string, Map<string, string>>,
  theme: 'light' | 'dark',
  name: string,
  seen = new Set<string>(),
): string | undefined {
  if (seen.has(name)) return undefined;
  seen.add(name);
  let value: string | undefined;
  for (const selector of THEME_BLOCKS[theme]) value = table.get(selector)?.get(name) ?? value;
  if (value === undefined) return undefined;
  const ref = /^var\(\s*(--[\w-]+)\s*\)$/u.exec(value.trim());
  return ref ? resolveToken(table, theme, ref[1] as string, seen) : value.trim();
}

function hexToRgb(hex: string): [number, number, number] | undefined {
  const m = /^#([0-9a-f]{6})$/iu.exec(hex.trim());
  if (!m) return undefined;
  const n = Number.parseInt(m[1] as string, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function relativeLuminance([r, g, b]: [number, number, number]): number {
  const channel = (c: number): number => {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/** WCAG 2.x contrast ratio between two opaque colours. */
function contrastRatio(a: [number, number, number], b: [number, number, number]): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

/** WCAG 1.4.3 for body-sized text. A placeholder is text, not an incidental decoration. */
const TEXT_CONTRAST_MINIMUM = 4.5;

/**
 * The ratios the tokens above produce, as MEASURED in Chromium against the real sheet.
 *
 * Pinned, not merely bounded, so a change that still clears 4.5:1 is still a decision somebody has
 * to make on purpose. Also the non-vacuity check on the arithmetic: if the resolver ever returns
 * the wrong colours these stop matching, instead of quietly comparing black against black.
 */
const EXPECTED = {
  light: { placeholder: 6.83, text: 14.7 },
  dark: { placeholder: 7.86, text: 14.7 },
} as const;

/**
 * The floor on how different the two inks are from EACH OTHER.
 *
 * The other half of the job, and the one a naive "just darken it" fix fails: a placeholder pushed
 * far enough for 4.5:1 can land close enough to the entered-text ink that a user reads an empty
 * field as a filled one. Measured at 2.15:1 (light) and 1.87:1 (dark) — comfortably above 1.0,
 * which would mean the two are the same colour.
 */
const PLACEHOLDER_VS_TEXT_MINIMUM = 1.5;

// ---------------------------------------------------------------------------------------------
// The population: everything in the tree that carries a `placeholder`
// ---------------------------------------------------------------------------------------------

/** The shared controls, all of which render `class="control …"` (see `ui/index.tsx`). */
const SHARED_CONTROLS = ['Input', 'TextArea', 'Select', 'DateInput'] as const;

/**
 * Every element that takes a `placeholder`, split by whether `.control` reaches it.
 *
 * Walked from the tree rather than grepped, for the reason `menuItemGuards.test.ts` records: a
 * recogniser used as a filter cannot see what it fails to recognise, so a hand-written `<input>`
 * that never gets the class has to fall OUT of the covered set and INTO the offences, not vanish.
 */
function scanPlaceholders(sources: Record<string, string>): {
  total: number;
  viaSharedControl: number;
  uncovered: string[];
} {
  let total = 0;
  let viaSharedControl = 0;
  const uncovered: string[] = [];
  for (const [file, source] of Object.entries(sources)) {
    if (/\.(?:test|spec)\.tsx$/u.test(file)) continue;
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
        const open = ts.isJsxElement(node) ? node.openingElement : node;
        const attrs = open.attributes.properties;
        const named = (name: string): ts.JsxAttribute | undefined =>
          attrs.find(
            (p): p is ts.JsxAttribute =>
              ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === name,
          );
        if (named('placeholder')) {
          total += 1;
          const tag = open.tagName.getText();
          if ((SHARED_CONTROLS as readonly string[]).includes(tag)) viaSharedControl += 1;
          else {
            const init = named('className')?.initializer;
            const text = init && ts.isStringLiteral(init) ? init.text : (init?.getText() ?? '');
            if (!/\bcontrol\b/u.test(text)) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;
              uncovered.push(`${file}:${line} <${tag}>`);
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { total, viaSharedControl, uncovered: uncovered.sort() };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const PLACEHOLDERS = scanPlaceholders(PRODUCTION_SOURCES);

let THEME = '';
let RULES: CssRule[] = [];
let TOKENS: Map<string, Map<string, string>> = new Map();
let STYLESHEETS: Record<string, string> = {};
let ALL_RULES: CssRule[] = [];

beforeAll(async () => {
  THEME = await readFile('src/theme.css');
  RULES = parseRules(THEME);
  TOKENS = tokenTable(RULES);
  STYLESHEETS = await readStylesheets();
  ALL_RULES = Object.values(STYLESHEETS).flatMap((css) => parseRules(css));
});

function ratios(theme: 'light' | 'dark'): { placeholder: number; text: number; between: number } {
  const bg = hexToRgb(resolveToken(TOKENS, theme, '--bg') ?? '');
  const text = hexToRgb(resolveToken(TOKENS, theme, '--text') ?? '');
  const placeholder = hexToRgb(resolveToken(TOKENS, theme, PLACEHOLDER_TOKEN) ?? '');
  if (!bg || !text || !placeholder) {
    throw new Error(`could not resolve the ${theme} palette from the sheet`);
  }
  return {
    placeholder: contrastRatio(placeholder, bg),
    text: contrastRatio(text, bg),
    between: contrastRatio(placeholder, text),
  };
}

describe('placeholder contrast — structural guards', () => {
  it('parses the sources it is guarding, so a broken walk cannot pass vacuously', () => {
    expect(RULES.length).toBeGreaterThan(1000);
    expect(Object.keys(STYLESHEETS).length).toBeGreaterThan(15);
    expect(ALL_RULES.length).toBeGreaterThan(RULES.length);
    // The bound that catches a walk which stops recognising placeholders and passes over nothing.
    expect(PLACEHOLDERS.total).toBeGreaterThanOrEqual(100);
    expect(PLACEHOLDERS.viaSharedControl).toBeGreaterThanOrEqual(100);
    // …and that the palette really resolves, rather than defaulting to two identical colours.
    expect(resolveToken(TOKENS, 'light', '--bg')).not.toBe(resolveToken(TOKENS, 'dark', '--bg'));
  });

  it('keeps the placeholder ink in one token, anchored to the muted-text decision', () => {
    const declared = RULES.flatMap((rule) =>
      selectorList(rule)
        .filter(() => new RegExp(`${PLACEHOLDER_TOKEN}\\s*:`, 'u').test(rule.body))
        .map((selector) => ({
          selector,
          value: new RegExp(`${PLACEHOLDER_TOKEN}\\s*:\\s*([^;]+);`, 'u')
            .exec(rule.body)?.[1]
            ?.trim(),
        })),
    );
    expect(
      declared,
      'The placeholder ink must be declared exactly once, on `:root`. `--text-muted` is redefined ' +
        'by the dark media query AND by both `[data-theme]` blocks, and `var()` resolves on the ' +
        'element, so one declaration covers all four paths. A second copy in a theme block is a ' +
        'second decision, and the two will disagree the first time either moves.',
    ).toEqual([{ selector: ':root', value: PLACEHOLDER_TOKEN_VALUE }]);
  });

  it('keeps the shared rule beside `.control`, consuming the token, at full opacity', () => {
    const rule = RULES.find((r) => selectorList(r).includes(PLACEHOLDER_SELECTOR));
    expect(
      rule,
      'The one rule that colours every placeholder in the app is gone. Without it the user agent ' +
        'decides, and what it decided measured 4.16:1 light / 3.53:1 dark.',
    ).toBeDefined();
    expect(rule?.body).toMatch(new RegExp(`color:\\s*var\\(${PLACEHOLDER_TOKEN}\\)`, 'u'));
    expect(
      rule?.body,
      '`opacity: 1` is what makes the measured ratio the ratio that renders. A user agent that ' +
        'draws placeholders at reduced opacity would re-mute this below the floor, and this app ' +
        'ships to Gecko and WebKit through Tauri as well as to the Chromium it was measured in.',
    ).toMatch(/opacity:\s*1;/u);
  });

  it('does not let a surface colour its own placeholder', () => {
    expect(
      placeholderRules(ALL_RULES).filter((s) => s !== PLACEHOLDER_SELECTOR),
      'A second placeholder colour repairs one field and leaves the rest, at a specificity that ' +
        'also shadows the shared rule on exactly that screen. Move `--field-placeholder` instead.',
    ).toEqual([...KNOWN_PLACEHOLDER_PATCHES].sort());
  });

  it('keeps every placeholder in the app on a `.control`, so one rule is the population', () => {
    expect(
      PLACEHOLDERS.uncovered,
      'These elements take a `placeholder` and are not `.control`s, so the shared rule does not ' +
        'reach them and they are back on the user agent’s 4.16:1 / 3.53:1. Use the shared ' +
        '`Input`/`TextArea`, or give the element the `control` class.',
    ).toEqual([]);
  });

  it('clears 4.5:1 for placeholder text against the field fill, in BOTH themes', () => {
    for (const theme of ['light', 'dark'] as const) {
      const r = ratios(theme);
      expect(
        Number(r.placeholder.toFixed(2)),
        `The ${theme} placeholder is under WCAG 1.4.3's 4.5:1 against the field fill. This is the ` +
          'defect the token was introduced for; it measured 4.16:1 light / 3.53:1 dark before it.',
      ).toBeGreaterThanOrEqual(TEXT_CONTRAST_MINIMUM);
      expect(Number(r.placeholder.toFixed(2))).toBe(EXPECTED[theme].placeholder);
      expect(Number(r.text.toFixed(2))).toBe(EXPECTED[theme].text);
    }
  });

  it('keeps a placeholder visibly lighter than an entered value, in BOTH themes', () => {
    for (const theme of ['light', 'dark'] as const) {
      const r = ratios(theme);
      expect(
        r.placeholder,
        'A placeholder as contrasty as entered text is an empty field that reads as a filled ' +
          'one — an accessibility fix traded for a usability defect. It must stay the lighter ink.',
      ).toBeLessThan(r.text);
      expect(
        Number(r.between.toFixed(2)),
        `The ${theme} placeholder and the entered-text ink are too close to tell apart.`,
      ).toBeGreaterThanOrEqual(PLACEHOLDER_VS_TEXT_MINIMUM);
    }
  });
});

describe('placeholder contrast — the guards go red without the fix', () => {
  /** The real sheet with the fix taken back out, one way at a time. Comments go first: the sheet
   *  documents these rules by quoting them, and a `replace` over the raw text would edit the prose
   *  and prove nothing. Each edit asserts it changed something, so a drifted selector fails here
   *  rather than silently reverting the proof to a no-op. */
  function withoutFix(edit: (css: string) => string): string {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    const edited = edit(bare);
    expect(edited).not.toBe(bare);
    return edited;
  }

  it('reports the shared rule being deleted', () => {
    const reverted = parseRules(
      withoutFix((css) => css.replace(/\.control::placeholder \{[^}]*\}/u, '')),
    );
    expect(reverted.find((r) => selectorList(r).includes(PLACEHOLDER_SELECTOR))).toBeUndefined();
  });

  it('reports the opacity pin being dropped', () => {
    const reverted = parseRules(
      withoutFix((css) => css.replace(/(\.control::placeholder \{[^}]*?)\n\s*opacity: 1;/u, '$1')),
    );
    const rule = reverted.find((r) => selectorList(r).includes(PLACEHOLDER_SELECTOR));
    expect(rule?.body).not.toMatch(/opacity:\s*1;/u);
  });

  it('reports the token being re-typed as a literal that stops tracking the theme', () => {
    // The value is #5c5344 in light today, so this computes IDENTICALLY in light and only
    // diverges in dark — which is exactly why a literal has to fail on sight rather than on ratio.
    const reverted = tokenTable(
      parseRules(
        withoutFix((css) =>
          css.replace(
            `${PLACEHOLDER_TOKEN}: ${PLACEHOLDER_TOKEN_VALUE};`,
            `${PLACEHOLDER_TOKEN}: #5c5344;`,
          ),
        ),
      ),
    );
    expect(reverted.get(':root')?.get(PLACEHOLDER_TOKEN)).toBe('#5c5344');
    expect(reverted.get(':root')?.get(PLACEHOLDER_TOKEN)).not.toBe(PLACEHOLDER_TOKEN_VALUE);
  });

  it('reports a second declaration of the token in a theme block', () => {
    const patched = parseRules(
      `${THEME}\n:root[data-theme='dark'] {\n  ${PLACEHOLDER_TOKEN}: #808080;\n}\n`,
    );
    const declared = patched.flatMap((rule) =>
      selectorList(rule).filter(() => new RegExp(`${PLACEHOLDER_TOKEN}\\s*:`, 'u').test(rule.body)),
    );
    expect(declared).toEqual([':root', ":root[data-theme='dark']"]);
  });

  it('reports a surface colouring its own placeholder, including inside a media query', () => {
    const patched = parseRules(
      `${THEME}\n.books-filters .control::placeholder { color: #999; }\n` +
        `@media (max-width: 620px) {\n  .signin .control::-webkit-input-placeholder { color: #aaa; }\n}\n`,
    );
    expect(placeholderRules(patched).filter((s) => s !== PLACEHOLDER_SELECTOR)).toEqual([
      '.books-filters .control::placeholder',
      '.signin .control::-webkit-input-placeholder',
    ]);
  });

  it('does not mistake a placeholder rule that sets no colour for a patch', () => {
    // Letter-spacing on a placeholder is a typographic choice, not a contrast decision.
    const patched = parseRules(`${THEME}\n.x .control::placeholder { letter-spacing: 0.02em; }\n`);
    expect(placeholderRules(patched).filter((s) => s !== PLACEHOLDER_SELECTOR)).toEqual([]);
  });

  it('reports a hand-written input that the shared rule cannot reach', () => {
    const scanned = scanPlaceholders({
      '../features/x/Page.tsx': '<input className="filter-box" placeholder="Procurar" />;',
      '../features/y/Ok.tsx': '<input className="control mono" placeholder="Procurar" />;',
      '../features/z/Shared.tsx': '<Input placeholder="Procurar" />;',
    });
    expect(scanned.total).toBe(3);
    expect(scanned.viaSharedControl).toBe(1);
    expect(scanned.uncovered).toEqual(['../features/x/Page.tsx:1 <input>']);
  });

  it('reports the user agent’s own placeholder colour as the failure it was', () => {
    // The measured before-state, run back through the same arithmetic that guards the after-state.
    const ua: [number, number, number] = [117, 117, 117];
    expect(Number(contrastRatio(ua, [247, 243, 234]).toFixed(2))).toBe(4.16);
    expect(Number(contrastRatio(ua, [16, 36, 27]).toFixed(2))).toBe(3.53);
    expect(contrastRatio(ua, [247, 243, 234])).toBeLessThan(TEXT_CONTRAST_MINIMUM);
    expect(contrastRatio(ua, [16, 36, 27])).toBeLessThan(TEXT_CONTRAST_MINIMUM);
  });

  it('reports a placeholder darkened until it reads as entered text', () => {
    // The other failure mode: 21:1 clears 4.5:1 comfortably and is still wrong.
    const asText = contrastRatio([16, 36, 27], [16, 36, 27]);
    expect(asText).toBeLessThan(PLACEHOLDER_VS_TEXT_MINIMUM);
    expect(Number(contrastRatio([92, 83, 68], [16, 36, 27]).toFixed(2))).toBe(2.15);
    expect(Number(contrastRatio([169, 184, 172], [247, 243, 234]).toFixed(2))).toBe(1.87);
  });

  it('resolves a token through `var()` indirection, and reports one that does not resolve', () => {
    const table = tokenTable(
      parseRules(
        ':root { --paper: #f7f3ea; --bg: var(--paper); --loop: var(--loop); }\n' +
          ":root[data-theme='dark'] { --bg: #10241b; }",
      ),
    );
    expect(resolveToken(table, 'light', '--bg')).toBe('#f7f3ea');
    expect(resolveToken(table, 'dark', '--bg')).toBe('#10241b');
    expect(resolveToken(table, 'light', '--missing')).toBeUndefined();
    expect(resolveToken(table, 'light', '--loop')).toBeUndefined();
  });
});
