/**
 * Structural guards on the hand-built menus' entry spacing (t89).
 *
 * ## The asymmetry these exist to hold
 *
 * A native `<select>` draws its options in the operating system's own chrome, so the app styles
 * none of them — `.control--select` dresses only the closed box. That makes the native select the
 * app's de facto reference for how an option row should feel, and it is the one operators singled
 * out as reading well. The hand-built menus cannot inherit any of that, so each one invented its
 * own entry padding: four menus, four values, none of them the reference's.
 *
 * The fix put the row metric in one place (`.menu-item`, sized from `.control`'s own padding).
 * These guards keep it there. The failure they exist to catch is not "the padding changed" — it is
 * **a fifth menu being added that never opts in**, which is how the first four diverged.
 *
 * ## Why the AST, and why not a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting a menu and
 * reading its padding passes whether or not the rule exists. Instead this asks the two questions
 * that actually determine the outcome: does every menu entry carry the shared class, and is that
 * class still the only thing that sets the metric? The last section proves each predicate goes red
 * by running it against mutated copies of the real sources — see `bannerMarginGuards.test.ts` for
 * the reasoning behind that shape.
 *
 * A menu entry is identified by its ARIA role (`menuitem` / `option`), not by its class name. The
 * class name is the thing under test; using it to find the population would make the guard
 * tautological — a new menu that forgot the class would also be invisible to the search.
 */
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

/** The stylesheets that carry menu-entry styling. */
const SHEETS = [
  'src/theme.css',
  'src/features/templates/templateEditor.css',
  'src/features/admin/AdminConfigurationFinder.css',
] as const;

/** The per-menu classes that used to state their own padding, and must no longer. */
const MENU_ENTRY_CLASSES = [
  'topbar__menu-item',
  'session-picker__item',
  'template-block-add__menu-item',
  'admin-config-finder__result',
] as const;

const SHARED_CLASS = 'menu-item';

/**
 * Every ARIA role that makes an element a selectable row inside a menu or listbox.
 *
 * All four are listed on purpose. An earlier draft checked only `menuitem`/`option` and silently
 * skipped the session picker, whose rows are `menuitemradio` — the recogniser was being used as a
 * filter, so the menu it could not name simply vanished from the population instead of failing.
 * The count bound below is what surfaced it; keep both.
 */
const ENTRY_ROLES = new Set(['menuitem', 'menuitemradio', 'menuitemcheckbox', 'option']);

async function readSheet(path: string): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync(path, 'utf8').replace(/\r\n/gu, '\n');
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

function declaresPadding(body: string): boolean {
  return /(^|[;{\s])padding(-top|-bottom|-block|-inline|-left|-right)?\s*:/u.test(body);
}

/** Per-menu rules that state a padding of their own, i.e. that have left the shared metric. */
function paddingOffenders(rules: CssRule[]): string[] {
  return rules.flatMap((rule) =>
    selectorList(rule)
      .filter((selector) => {
        if (!MENU_ENTRY_CLASSES.some((cls) => selector.includes(`.${cls}`))) return false;
        // Only the entry element itself; its inner parts may pad freely.
        if (
          !MENU_ENTRY_CLASSES.some((cls) => new RegExp(`\\.${cls}(?![\\w-])`, 'u').test(selector))
        )
          return false;
        return declaresPadding(rule.body);
      })
      .map((selector) => `${selector} { ${rule.body.trim().replace(/\s+/gu, ' ')} }`),
  );
}

interface EntryScan {
  /** Menu entries (by ARIA role) whose className does not include the shared class. */
  missing: string[];
  entries: number;
  files: number;
}

/** Every JSX element with role="menuitem"/"option", and whether it opts into the shared class. */
function scanEntries(sources: Record<string, string>): EntryScan {
  const missing: string[] = [];
  let entries = 0;
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

    const attrText = (opening: ts.JsxOpeningLikeElement, name: string): string | undefined => {
      const attr = opening.attributes.properties.find(
        (p): p is ts.JsxAttribute =>
          ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === name,
      );
      const init = attr?.initializer;
      if (!init) return undefined;
      if (ts.isStringLiteral(init)) return init.text;
      // `className={`a b${cond ? ' c' : ''}`}` — the whole expression's source text is enough to
      // answer "is the shared class named here?", and avoids half-evaluating template literals.
      if (ts.isJsxExpression(init) && init.expression) return init.expression.getText(parsed);
      return undefined;
    };

    const inspect = (node: ts.Node): void => {
      const opening = ts.isJsxElement(node)
        ? node.openingElement
        : ts.isJsxSelfClosingElement(node)
          ? node
          : undefined;
      if (opening) {
        const role = attrText(opening, 'role');
        if (role !== undefined && ENTRY_ROLES.has(role)) {
          entries += 1;
          const className = attrText(opening, 'className') ?? '';
          if (!new RegExp(`\\b${SHARED_CLASS}\\b`, 'u').test(className)) {
            const line = parsed.getLineAndCharacterOfPosition(opening.getStart(parsed)).line + 1;
            missing.push(`${file}:${line} role=${role} className=${className || '(none)'}`);
          }
        }
      }
      ts.forEachChild(node, inspect);
    };
    inspect(parsed);
  }
  return { missing, entries, files };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const SCAN = scanEntries(PRODUCTION_SOURCES);

let sheets: Record<string, string> = {};
let allRules: CssRule[] = [];

beforeAll(async () => {
  sheets = Object.fromEntries(
    await Promise.all(SHEETS.map(async (p) => [p, await readSheet(p)] as const)),
  );
  allRules = Object.values(sheets).flatMap(parseRules);
});

describe('hand-built menu entries — structural guards', () => {
  it('reads the stylesheets it is guarding, so a broken walk cannot pass vacuously', () => {
    expect(Object.keys(sheets)).toHaveLength(SHEETS.length);
    for (const [path, css] of Object.entries(sheets)) {
      expect(css.length, `${path} is empty`).toBeGreaterThan(200);
    }
    expect(allRules.length).toBeGreaterThan(1000);
  });

  it('defines the shared row metric exactly once, and lifts it from the reference control', () => {
    const shared = allRules.filter((r) => selectorList(r).includes(`.${SHARED_CLASS}`));
    expect(
      shared,
      'The point of the shared class is that one rule owns the metric. Two rules means two ' +
        'owners and the drift starts again.',
    ).toHaveLength(1);

    const control = allRules.filter((r) => selectorList(r).includes('.control'));
    const controlPadding = control
      .map((r) => r.body.match(/(?:^|[;{\s])padding\s*:\s*([^;]+);/u)?.[1]?.trim())
      .find(Boolean);
    const sharedPadding = shared[0]?.body.match(/(?:^|[;{\s])padding\s*:\s*([^;]+);/u)?.[1]?.trim();

    expect(controlPadding, 'no `.control { padding }` found to anchor against').toBeTruthy();
    expect(
      sharedPadding,
      'The row metric is deliberately not a new number: it is `.control`’s own padding, the ' +
        'control a native <select> — the reference the menus are being matched to — drops out of. ' +
        'If `.control` changes, this should change with it rather than being re-invented.',
    ).toBe(controlPadding);
  });

  it('never lets a menu restate its own entry padding', () => {
    expect(
      paddingOffenders(allRules),
      'A per-menu padding on the entry element takes that menu back off the shared metric — ' +
        'which is exactly how four menus ended up with four different values. Change ' +
        '`.menu-item` instead; if one menu genuinely needs a different row height, that is a ' +
        'variant class, not a redeclaration.',
    ).toEqual([]);
  });

  it('gives every menu entry the shared class', () => {
    expect(
      SCAN.missing,
      'This entry is a menu row by its ARIA role but does not carry the shared class, so it ' +
        'renders with no row padding at all and will drift from the other menus. Add ' +
        `\`${SHARED_CLASS}\` alongside its own class.`,
    ).toEqual([]);

    // Bounds: the four enumerated menus. Zero would mean the role-based search broke.
    expect(SCAN.entries).toBeGreaterThanOrEqual(4);
    expect(SCAN.files).toBeGreaterThan(150);
  });
});

describe('hand-built menu entries — the guards go red without the fix', () => {
  it('reports a menu that restates its own padding', () => {
    const regressed = parseRules(
      `.topbar__menu-item {\n  padding: 0.5rem 0.6rem;\n  color: red;\n}\n`,
    );
    expect(paddingOffenders(regressed)).toEqual([
      '.topbar__menu-item { padding: 0.5rem 0.6rem; color: red; }',
    ]);
  });

  it('does not mistake an entry’s inner parts for the entry itself', () => {
    // `.topbar__menu-item-icon` may pad freely; only the row element is constrained.
    const inner = parseRules(`.topbar__menu-item-icon {\n  padding: 0.2rem;\n}\n`);
    expect(paddingOffenders(inner)).toEqual([]);
  });

  it('reports a new menu entry that never opted into the shared class', () => {
    const scan = scanEntries({
      '../features/example/ExampleMenu.tsx':
        'export function Example() {\n' +
        '  return <button role="menuitem" className="example__item">x</button>;\n' +
        '}\n',
    });
    expect(scan.entries).toBe(1);
    expect(scan.missing).toHaveLength(1);
    expect(scan.missing[0]).toContain('ExampleMenu.tsx:2');
  });

  it('accepts an entry that opts in through a template literal', () => {
    const scan = scanEntries({
      '../features/example/ExampleMenu.tsx':
        'export function Example({ on }: { on: boolean }) {\n' +
        '  return <a role="menuitem" className={`menu-item x__item${on ? " is-on" : ""}`}>x</a>;\n' +
        '}\n',
    });
    expect(scan.entries).toBe(1);
    expect(scan.missing).toEqual([]);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanEntries({});
    expect(empty.entries).toBe(0);
    expect(empty.files).toBe(0);
  });
});
